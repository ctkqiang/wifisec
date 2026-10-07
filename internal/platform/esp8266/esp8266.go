// Package esp8266 通过 USB 串口驱动 ESP8266 协处理器完成 2.4GHz 帧注入。
//
// 宿主机只把 ESP8266 当作普通串口设备，射频完全由板载芯片执行，
// 因此该适配器在 macOS / Linux / Windows / Termux 上行为一致，
// 是 macOS 等不开放帧注入平台的唯一注入路径。
//
// 与固件（core/esp/esp.ino）之间的协议为定长头小端帧：
//
//	主机→ESP: [0xA5][cmd][len_lo][len_hi][payload]
//	ESP→主机: [0x5A][cmd][len_lo][len_hi][payload]
package esp8266

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"go.bug.st/serial"
	"go.bug.st/serial/enumerator"
)

const (
	// frameHeadHost / frameHeadESP 是帧头魔数，双向各占一个取值，
	// 方向错乱的帧可被对端立即丢弃。
	frameHeadHost = 0xA5
	frameHeadESP  = 0x5A

	// 命令字：主机侧有握手、扫描、注入三类请求。
	cmdPing   = 0x00 // 握手；固件回 repPong 携带协议版本
	cmdScan   = 0x01 // 主机请求扫描；ESP 逐条回 scanEntry，最后回 scanDone
	cmdInject = 0x02 // payload = 信道(1) + 802.11 帧（不含 radiotap）

	// 回复字：握手应答 / 扫描条目 / 扫描结束 / 错误。
	repPong      = 0x00 // payload = 协议版本(1)
	repScanEntry = 0x01 // payload = bssid(6) + channel(1) + rssi(1,有符号) + ssidLen(1) + ssid
	repScanDone  = 0x02
	repError     = 0x04 // payload = 出错命令(1) + 错误码(1)

	// scanReadTimeout 是单帧回复的读取预算；覆盖 ESP8266 一次完整扫描
	//（约 2-3 秒）加串口回传绰绰有余。
	scanReadTimeout = 15 * time.Second

	// 打开串口会触发板子复位重启，boot 期间主机发来的命令全部丢失，
	// 因此握手需要重试：每次发 PING 后等 handshakeTimeout，整体覆盖冷启动。
	handshakeAttempts = 15
	handshakeTimeout  = 500 * time.Millisecond

	// baudRate 与固件 Serial.begin 保持一致。
	baudRate = 115200
)

// errFrameTimeout 表示在预算内没有收到完整的一帧回复。
var errFrameTimeout = errors.New("读取回复帧超时")

// Network 是 ESP8266 扫描到的一个 2.4GHz 接入点。
type Network struct {
	SSID    string
	BSSID   string
	Channel int
	RSSI    int
}

// Injector 封装串口句柄，实现 deauther 的 frameWriter / channelSetter 契约。
type Injector struct {
	port    serial.Port
	channel int    // 当前注入信道；ESP8266 逐帧携带信道，这里仅缓存
	rx      []byte // 跨 Read 调用累积的未解析字节流
}

// Open 打开指定串口并完成固件握手后才返回。
// 串口访问在 macOS/Linux 无需 root（Linux 要求用户在 dialout 组），
// 这是 ESP 路径与 AF_PACKET 路径的关键差异。
func Open(portName string) (*Injector, error) {
	mode := &serial.Mode{BaudRate: baudRate}

	port, err := serial.Open(portName, mode)
	if err != nil {
		return nil, fmt.Errorf("打开串口 %s 失败：%w", portName, err)
	}

	// 读取必须带超时，否则固件未响应时会永久阻塞。
	if err := port.SetReadTimeout(scanReadTimeout); err != nil {
		_ = port.Close()
		return nil, fmt.Errorf("配置串口读超时失败：%w", err)
	}

	injector := &Injector{port: port, channel: 1}

	// 打开串口会复位板子，boot 完成前发出的命令必丢，先握手确认固件就位。
	if err := injector.handshake(); err != nil {
		_ = port.Close()
		return nil, err
	}

	return injector, nil
}

// DefaultPort 枚举 USB 串口设备：恰好一个时直接返回，
// 零个或多个时给出可操作的中文错误。
func DefaultPort() (string, error) {
	ports, err := enumerator.GetDetailedPortsList()
	if err != nil {
		return "", fmt.Errorf("枚举串口失败：%w", err)
	}

	var usbPorts []string
	for _, p := range ports {
		if p.IsUSB {
			usbPorts = append(usbPorts, p.Name)
		}
	}

	switch len(usbPorts) {
	case 0:
		return "", errors.New("未发现 USB 串口设备，请确认 ESP8266 已插入（驱动：CH340/CP2102）")
	case 1:
		return usbPorts[0], nil
	default:
		return "", fmt.Errorf("发现多个 USB 串口设备 %s，请把端口名作为第二参数传入", strings.Join(usbPorts, "、"))
	}
}

// SetChannel 缓存注入信道；实际切信道随每帧注入命令下发，
// 避免在多目标轮发时产生两倍串口流量。
func (i *Injector) SetChannel(channel int) error {
	i.channel = channel
	return nil
}

// Write 把一帧带 radiotap 头的 802.11 数据经串口交给固件注入。
// ESP8266 的自由帧 API 只接受纯 802.11 帧，这里剥掉前 8 字节 radiotap 头。
func (i *Injector) Write(frame []byte) error {
	const radiotapHeaderLen = 8 // 与 ieee80211.RadiotapHeaderLen 保持一致

	if len(frame) <= radiotapHeaderLen {
		return errors.New("帧长度不足，缺少 radiotap 头")
	}

	payload := make([]byte, 0, 1+len(frame)-radiotapHeaderLen)
	payload = append(payload, byte(i.channel))
	payload = append(payload, frame[radiotapHeaderLen:]...)

	_, err := i.port.Write(EncodeCommand(cmdInject, payload))
	return err
}

// Scan 请求固件扫描周边 2.4GHz 网络，流式读取条目直到收到结束帧。
func (i *Injector) Scan() ([]Network, error) {
	if _, err := i.port.Write(EncodeCommand(cmdScan, nil)); err != nil {
		return nil, fmt.Errorf("发送扫描命令失败：%w", err)
	}

	var networks []Network

	for {
		cmd, payload, err := i.readFrame(scanReadTimeout)
		if err != nil {
			return nil, errors.New("扫描超时：固件已连接但未回传结果")
		}

		switch cmd {
		case repScanEntry:
			network, err := ParseScanEntry(payload)
			if err == nil {
				networks = append(networks, network)
			}
		case repScanDone:
			return networks, nil
		case repPong:
			// 开串口复位后固件会主动上报一次 PONG，残留在流里属正常，忽略。
		case repError:
			if len(payload) >= 2 {
				return nil, fmt.Errorf("固件执行命令 0x%02X 失败，错误码 %d", payload[0], payload[1])
			}
		}
	}
}

// Close 关闭串口。
func (i *Injector) Close() error {
	if i.port == nil {
		return nil
	}
	return i.port.Close()
}

// EncodeCommand 按协议打包主机→固件命令帧。导出供 tests/ 验证帧布局。
func EncodeCommand(cmd byte, payload []byte) []byte {
	frame := make([]byte, 0, 4+len(payload))
	frame = append(frame, frameHeadHost, cmd, byte(len(payload)), byte(len(payload)>>8))
	return append(frame, payload...)
}

// ParseScanEntry 解析一条扫描条目载荷。导出供 tests/ 做表驱动测试。
func ParseScanEntry(payload []byte) (Network, error) {
	if len(payload) < 9 {
		return Network{}, errors.New("扫描条目长度不足 9 字节")
	}

	var entry Network
	entry.BSSID = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		payload[0], payload[1], payload[2], payload[3], payload[4], payload[5])
	entry.Channel = int(payload[6])
	entry.RSSI = int(int8(payload[7]))

	ssidLen := int(payload[8])
	if len(payload) < 9+ssidLen {
		return Network{}, errors.New("扫描条目 SSID 长度越界")
	}
	entry.SSID = string(payload[9 : 9+ssidLen])

	return entry, nil
}

// DecodeReply 从字节流中拆出一帧固件回复；流不足一帧时返回 ok=false。
// 帧头之前的杂散字节会被丢弃后重新同步——ESP8266 上电时以 74880 波特
// 输出启动日志，在 115200 下呈现为随机噪声，若不跳过会永远卡住解析。
// 导出供 tests/ 验证重同步行为。
func DecodeReply(stream []byte) (cmd byte, payload, rest []byte, ok bool) {
	for len(stream) > 0 && stream[0] != frameHeadESP {
		stream = stream[1:]
	}

	if len(stream) < 4 {
		return 0, nil, stream, false
	}

	frameLen := 4 + int(stream[2]) | int(stream[3])<<8
	if len(stream) < frameLen {
		return 0, nil, stream, false
	}

	return stream[1], stream[4:frameLen], stream[frameLen:], true
}

// handshake 通过 PING/PONG 确认固件就绪。
// 打开串口触发板子复位后，固件需 1-2 秒完成 boot（含 WiFi 初始化），
// 期间发出的命令全部丢失，因此以固定节奏重试直到拿到 PONG。
func (i *Injector) handshake() error {
	// 清掉驱动层可能缓存的旧字节（上次会话残留、boot 噪声）。
	_ = i.port.ResetInputBuffer()

	for range handshakeAttempts {
		if _, err := i.port.Write(EncodeCommand(cmdPing, nil)); err != nil {
			return fmt.Errorf("发送握手命令失败：%w", err)
		}

		cmd, _, err := i.readFrame(handshakeTimeout)
		if err == nil && cmd == repPong {
			return nil
		}
	}

	return errors.New("固件握手失败：请确认已烧录 wifisec 固件（core/esp/esp.ino），且波特率为 115200")
}

// readFrame 读取一帧回复，timeout 是本帧的整体预算；
// go.bug.st/serial 的读超时按次生效，这里逐次收缩剩余预算实现整体截止。
func (i *Injector) readFrame(timeout time.Duration) (byte, []byte, error) {
	deadline := time.Now().Add(timeout)
	chunk := make([]byte, 128)

	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0, nil, errFrameTimeout
		}

		if err := i.port.SetReadTimeout(remaining); err != nil {
			return 0, nil, err
		}

		n, err := i.port.Read(chunk)
		if err != nil {
			return 0, nil, err
		}
		if n == 0 {
			return 0, nil, errFrameTimeout
		}

		i.rx = append(i.rx, chunk[:n]...)

		cmd, payload, rest, ok := DecodeReply(i.rx)
		if !ok {
			continue
		}

		i.rx = rest
		return cmd, payload, nil
	}
}
