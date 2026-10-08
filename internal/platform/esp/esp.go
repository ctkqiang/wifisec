// Package esp 通过 USB 串口驱动 ESP 系列协处理器完成 802.11 帧注入。
//
// 支持 ESP8266、ESP32 经典/C2/C3/S2/S3（2.4GHz）与 ESP32-C5（2.4+5GHz 双频）。
// 宿主机只把开发板当作普通串口设备，射频完全由板载芯片执行，
// 因此该适配器在 macOS / Linux / Windows / Termux 上行为一致，
// 是 macOS 等不开放帧注入平台的唯一注入路径。
// Arduino UNO + WiFi Shield（NINA/WINC 模组）不开放原始帧注入 API，
// 固件侧以编译期 #error 显式拒绝，不在本包能力范围内。
//
// 与固件（core/esp/esp.ino）之间的协议为定长头小端帧：
//
//	主机→ESP: [0xA5][cmd][len_lo][len_hi][payload]
//	ESP→主机: [0x5A][cmd][len_lo][len_hi][payload]
package esp

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
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
	cmdPing   = 0x00 // 握手；固件回 repPong 携带协议版本与能力位图
	cmdScan   = 0x01 // 主机请求扫描；ESP 逐条回 scanEntry，最后回 scanDone
	cmdInject = 0x02 // payload = 信道(1) + 802.11 帧（不含 radiotap）

	// 回复字：握手应答 / 扫描条目 / 扫描结束 / 错误。
	repPong      = 0x00 // payload = 协议版本(1) + 能力位图(1，旧固件可缺省)
	repScanEntry = 0x01 // payload = bssid(6) + channel(1) + rssi(1,有符号) + ssidLen(1) + ssid
	repScanDone  = 0x02
	repError     = 0x04 // payload = 出错命令(1) + 错误码(1)

	// protoVersion 是本程序支持的固件协议版本。不一致说明固件过旧或过新，
	// 命令语义可能对不上，必须拒绝并要求重新烧录，而不是带病运行。
	protoVersion = 1

	// CapBand5GHz 是能力位图 bit0：固件声明具备 5GHz 注入能力。
	// 乐鑫全系当前只有 ESP32-C5 是双频芯片，其余（含全部 ESP8266）
	// 射频物理上只覆盖 2.4GHz。导出供 tests/ 验证位图解析。
	CapBand5GHz byte = 0x01

	// scanReadTimeout 是单帧回复的读取预算；覆盖一次完整扫描
	//（2.4GHz 约 2-3 秒，双频芯片扫 5GHz 更久）加串口回传绰绰有余。
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

// Network 是 ESP 协处理器扫描到的一个接入点。
type Network struct {
	SSID    string
	BSSID   string
	Channel int
	RSSI    int
}

// Injector 封装串口句柄，实现 deauther 的 frameWriter / channelSetter 契约。
type Injector struct {
	port       serial.Port
	channel    int    // 当前注入信道；逐帧随注入命令下发，这里仅缓存
	version    byte   // 握手时固件上报的协议版本
	caps       byte   // 握手时固件上报的能力位图（CapBand5GHz 等）
	rx         []byte // 跨 Read 调用累积的未解析字节流
	observedRx bool   // 握手期间是否收到过任何字节；用于区分「固件不对」与「链路不通」
}

// Open 打开指定串口并完成固件握手后才返回。
// 串口访问在 macOS/Linux 无需 root（Linux 要求用户在 dialout 组），
// 这是 ESP 路径与 AF_PACKET 路径的关键差异。
func Open(portName string) (*Injector, error) {
	mode := &serial.Mode{BaudRate: baudRate}

	port, err := serial.Open(portName, mode)
	if err != nil {
		return nil, fmt.Errorf("打开串口 %s 失败：%w%s", portName, err, busyHint(portName, err))
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
		return "", errors.New("未发现 USB 串口设备，请确认开发板已插入（驱动：CH340/CP2102）")
	case 1:
		return usbPorts[0], nil
	default:
		return "", fmt.Errorf("发现多个 USB 串口设备 %s，请把端口名作为第二参数传入", strings.Join(usbPorts, "、"))
	}
}

// Supports5GHz 报告固件是否声明了 5GHz 注入能力。
// 频段策略以固件能力位图为准，而不是宿主机猜测板型。
func (i *Injector) Supports5GHz() bool {
	return i.caps&CapBand5GHz != 0
}

// FirmwareVersion 返回握手时固件上报的协议版本，用于日志与排错。
func (i *Injector) FirmwareVersion() byte {
	return i.version
}

// SetChannel 缓存注入信道；实际切信道随每帧注入命令下发，
// 避免在多目标轮发时产生两倍串口流量。
func (i *Injector) SetChannel(channel int) error {
	i.channel = channel
	return nil
}

// Write 把一帧带 radiotap 头的 802.11 数据经串口交给固件注入。
// 固件的自由帧 API 只接受纯 802.11 帧，这里剥掉前 8 字节 radiotap 头。
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

// Scan 请求固件扫描周边网络，流式读取条目直到收到结束帧。
// 返回的频段范围取决于固件能力：2.4GHz 芯片只回 2.4GHz 结果，
// ESP32-C5 会同时回 5GHz 结果。
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
	var entry Network

	if len(payload) < 9 {
		return Network{}, errors.New("扫描条目长度不足 9 字节")
	}

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

// ParsePong 解析握手应答载荷：协议版本(1) + 能力位图(1)。
// 能力位图是协议 v1 的尾部扩展，旧固件只回版本号一个字节，
// 此时按「无扩展能力」（仅 2.4GHz）处理，保持向后兼容。
// 导出供 tests/ 做表驱动测试。
func ParsePong(payload []byte) (version, caps byte, err error) {
	if len(payload) < 1 {
		return 0, 0, errors.New("PONG 载荷为空，固件未上报协议版本")
	}

	version = payload[0]
	if len(payload) >= 2 {
		caps = payload[1]
	}

	return version, caps, nil
}

// DecodeReply 从字节流中拆出一帧固件回复；流不足一帧时返回 ok=false。
// 帧头之前的杂散字节会被丢弃后重新同步——ESP 芯片上电时以非工作波特率
// 输出启动日志（ESP8266 为 74880），在 115200 下呈现为随机噪声，
// 若不跳过会永远卡住解析。导出供 tests/ 验证重同步行为。
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

// handshake 通过 PING/PONG 确认固件就绪，并记录协议版本与能力位图。
// 打开串口触发板子复位后，固件需 1-2 秒完成 boot（含 WiFi 初始化），
// 期间发出的命令全部丢失，因此以固定节奏重试直到拿到 PONG。
func (i *Injector) handshake() error {
	// 清掉驱动层可能缓存的旧字节（上次会话残留、boot 噪声）。
	_ = i.port.ResetInputBuffer()

	for range handshakeAttempts {
		if _, err := i.port.Write(EncodeCommand(cmdPing, nil)); err != nil {
			return fmt.Errorf("发送握手命令失败：%w", err)
		}

		cmd, payload, err := i.readFrame(handshakeTimeout)
		if err != nil || cmd != repPong {
			continue
		}

		version, caps, err := ParsePong(payload)
		if err != nil {
			continue
		}

		// 版本不一致说明固件不是当前配套版本，重试不会改变结果，
		// 直接失败并指出修复路径。
		if version != protoVersion {
			return fmt.Errorf("固件协议版本 v%d 与本程序支持的 v%d 不兼容，请重新烧录 core/esp/esp.ino 最新固件", version, protoVersion)
		}

		i.version = version
		i.caps = caps
		return nil
	}

	// 握手期间收到过字节，说明板子和串口链路是通的，
	// 问题在固件内容：没烧录、烧的是别的 sketch、或版本过旧。
	if i.observedRx {
		return errors.New("固件握手失败：串口有数据但不是有效 PONG，固件可能未烧录或版本过旧，请烧录 core/esp/esp.ino 最新固件")
	}

	// 一个字节都没收到，问题在链路层：板子没跑起来（供电不足、
	// 处于下载模式）或串口根本没对上（线材、hub、选错端口）。
	return errors.New("固件握手失败：串口完全无数据；请确认板载 LED 有 3 次快闪 + 0.5 秒心跳（无则说明固件未运行），数据线直连电脑而非经 hub，并用 wifisec serial 确认端口")
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

		// 只要收到过字节就记录：握手失败时据此区分
		// 「固件在说话但内容不对」与「链路层面一片死寂」。
		i.observedRx = true

		i.rx = append(i.rx, chunk[:n]...)

		cmd, payload, rest, ok := DecodeReply(i.rx)
		if !ok {
			continue
		}

		i.rx = rest
		return cmd, payload, nil
	}
}

// busyHint 在「端口被占用」时追加占用者身份信息。
// 典型场景：Arduino IDE 串口监视器、上次异常退出的本程序仍持有端口，
// 用户看到「busy」却不知道是谁占的，点名进程才能直接行动。
func busyHint(portName string, openErr error) string {
	if !strings.Contains(strings.ToLower(openErr.Error()), "busy") {
		return ""
	}

	owner := portOwner(portName)
	if owner == "" {
		return "；端口被其他进程占用（可用 lsof " + portName + " 查看）"
	}
	return "；端口正被 " + owner + " 占用，关闭该进程后重试"
}

// portOwner 用 lsof 反查占用串口的进程名与 PID；仅 macOS/Linux 有效，
// Windows 没有等价的无依赖命令，查不到时静默降级为通用提示。
func portOwner(portName string) string {
	if runtime.GOOS == "windows" {
		return ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "lsof", "-nP", "--", portName).Output()
	if err != nil {
		return ""
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		return ""
	}

	fields := strings.Fields(lines[1])
	if len(fields) < 2 {
		return ""
	}

	return fmt.Sprintf("%s (PID %s)", fields[0], fields[1])
}
