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
	"sync"
	"time"

	"go.bug.st/serial"
	"go.bug.st/serial/enumerator"
)

const (
	// frameHeadHost / frameHeadESP 是帧头魔数，双向各占一个取值，
	// 方向错乱的帧可被对端立即丢弃。
	frameHeadHost = 0xA5
	frameHeadESP  = 0x5A

	// 命令字：主机侧有握手、扫描、注入、关联尝试、克隆 AP 五类请求。
	cmdPing   = 0x00 // 握手；固件回 repPong 携带协议版本与能力位图
	cmdScan   = 0x01 // 主机请求扫描；ESP 逐条回 scanEntry，最后回 scanDone
	cmdInject = 0x02 // payload = 信道(1) + 802.11 帧（不含 radiotap）
	cmdAssoc  = 0x03 // payload = ssidLen(1) + ssid + passLen(1) + password；尝试关联 AP

	// 命令字（克隆）：0x04 保留给错误帧方向，克隆从 0x05 起编。
	cmdClone       = 0x05 // payload = op(1) + channel(1) + ssidLen(1) + ssid + passLen(1) + password
	cmdCloneStatus = 0x06 // 无 payload；查询克隆 AP 的在线设备

	// 克隆操作码（cmdClone payload 首字节）。
	cloneOpDown = 0x00
	cloneOpUp   = 0x01

	// 回复字：握手应答 / 扫描条目 / 扫描结束 / 关联结果 / 错误。
	repPong        = 0x00 // payload = 协议版本(1) + 能力位图(1，旧固件可缺省)
	repScanEntry   = 0x01 // payload = bssid(6) + channel(1) + rssi(1,有符号) + ssidLen(1) + ssid
	repScanDone    = 0x02
	repAssocResult = 0x03 // payload = result(1)：0 失败 1 成功
	repError       = 0x04 // payload = 出错命令(1) + 错误码(1)

	// 回复字（克隆）。
	repCloneResult = 0x05 // payload = result(1) + apMAC(6)；down 回复 MAC 全零
	repCloneStatus = 0x06 // payload = count(1) + count×MAC(6)

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

	// cloneReplyTimeout 覆盖克隆开关与状态查询的回复预算：
	// SoftAP 开关是亚秒级调用，轮询为即时应答，5 秒已富余。
	cloneReplyTimeout = 5 * time.Second

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
	mu sync.Mutex // 串口是严格请求-应答流，事务级互斥保证 kick 注入与状态轮询等并发调用不交错

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

	// NodeMCU / ESP 开发板的自动复位电路把 DTR 接到 GPIO0、RTS 接到 EN。
	// 多数平台的串口驱动打开端口时默认置位 DTR/RTS，使 GPIO0 在复位瞬间
	// 为低，芯片锁死在 ROM 下载模式——该模式在 115200 下完全静默，
	// 现象就是 esptool 能连而本程序一个字节都收不到。
	// 这里显式输出「GPIO0 拉高 → EN 拉低复位 → 释放 EN」时序，
	// 强制芯片从 Flash 正常启动；无自动复位电路的板子上这些操作无害。
	if err := resetIntoRun(port); err != nil {
		_ = port.Close()
		return nil, fmt.Errorf("复位开发板失败：%w", err)
	}

	injector := &Injector{port: port, channel: 1}

	// 打开串口会复位板子，boot 完成前发出的命令必丢，先握手确认固件就位。
	if err := injector.handshake(); err != nil {
		_ = port.Close()
		return nil, err
	}

	return injector, nil
}

// resetIntoRun 通过 DTR/RTS 时序让 ESP 从 Flash 正常启动。
//
// 自动复位电路上：DTR 置位（线低）→ GPIO0 被拉低；RTS 置位（线低）→ EN 被拉低。
// 下载模式要求复位释放瞬间 GPIO0 为低，正常启动要求 GPIO0 为高。
// 因此先保证 GPIO0 高（DTR 断开），再拉低 EN 保持 100ms，
// 最后释放 EN，芯片即从 Flash 启动。
func resetIntoRun(port serial.Port) error {
	if err := port.SetDTR(false); err != nil {
		return err
	}
	if err := port.SetRTS(true); err != nil {
		return err
	}

	time.Sleep(100 * time.Millisecond)

	return port.SetRTS(false)
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
	i.mu.Lock()
	defer i.mu.Unlock()

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

	i.mu.Lock()
	defer i.mu.Unlock()

	_, err := i.port.Write(EncodeCommand(cmdInject, payload))
	return err
}

// Scan 请求固件扫描周边网络，流式读取条目直到收到结束帧。
// 返回的频段范围取决于固件能力：2.4GHz 芯片只回 2.4GHz 结果，
// ESP32-C5 会同时回 5GHz 结果。
func (i *Injector) Scan() ([]Network, error) {
	i.mu.Lock()
	defer i.mu.Unlock()

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

// Associate 让固件尝试用给定 SSID 与密码关联 AP，返回是否成功。
// 关联成功与否固件侧都会立即 WiFi.disconnect，不真正上网；
// 本方法用于在线密码字典爆破：每个密码尝试一次，命中即返回 true。
//
// 固件侧 WiFi.begin 最长阻塞 12 秒，超时按失败处理，
// 因此主机侧读取预算需覆盖该窗口并留串口回传余量。
func (i *Injector) Associate(ssid, password string) (bool, error) {
	i.mu.Lock()
	defer i.mu.Unlock()

	ssidBytes := []byte(ssid)
	passBytes := []byte(password)

	if len(ssidBytes) > 32 {
		return false, errors.New("SSID 长度超过 32 字节上限")
	}

	payload := make([]byte, 0, 1+len(ssidBytes)+1+len(passBytes))
	payload = append(payload, byte(len(ssidBytes)))
	payload = append(payload, ssidBytes...)
	payload = append(payload, byte(len(passBytes)))
	payload = append(payload, passBytes...)

	if _, err := i.port.Write(EncodeCommand(cmdAssoc, payload)); err != nil {
		return false, fmt.Errorf("发送关联命令失败：%w", err)
	}

	// 固件侧最长等 12 秒，加 3 秒余量覆盖串口回传与调度抖动。
	cmd, reply, err := i.readFrame(15 * time.Second)
	if err != nil {
		return false, fmt.Errorf("等待关联结果超时：%w", err)
	}

	switch cmd {
	case repAssocResult:
		if len(reply) < 1 {
			return false, errors.New("关联结果帧载荷为空")
		}
		return reply[0] == 1, nil
	case repError:
		if len(reply) >= 2 {
			return false, fmt.Errorf("固件执行关联命令失败，错误码 %d", reply[1])
		}
		return false, errors.New("固件执行关联命令失败")
	default:
		return false, fmt.Errorf("关联命令收到意外回复帧 0x%02X", cmd)
	}
}

// CloneAPUp 让固件在指定信道开启克隆 AP（SoftAP，同名同密码）。
// 固件切 AP+STA 双模：AP 侧承载克隆网络，STA 接口保留给 kick 注入。
// 返回克隆 AP 自身的 MAC——对客户端而言它就是克隆网络的 BSSID。
// 密码传空串即开放网络；合法性（8-63 字节 WPA2 规则）由应用层校验，
// 协议层只负责打包传输。
func (i *Injector) CloneAPUp(ssid, password string, channel int) (string, error) {
	i.mu.Lock()
	defer i.mu.Unlock()

	payload, err := buildClonePayload(cloneOpUp, channel, ssid, password)
	if err != nil {
		return "", err
	}

	if _, err := i.port.Write(EncodeCommand(cmdClone, payload)); err != nil {
		return "", fmt.Errorf("发送克隆命令失败：%w", err)
	}

	cmd, reply, err := i.readFrame(cloneReplyTimeout)
	if err != nil {
		return "", fmt.Errorf("等待克隆结果超时：%w", err)
	}

	switch cmd {
	case repCloneResult:
		ok, apMAC, err := ParseCloneResult(reply)
		if err != nil {
			return "", err
		}
		if !ok {
			return "", errors.New("固件开启 SoftAP 失败（信道超出射频能力或参数非法）")
		}
		return apMAC, nil
	case repError:
		return "", cloneFirmwareError("克隆", reply)
	default:
		return "", fmt.Errorf("克隆命令收到意外回复帧 0x%02X", cmd)
	}
}

// CloneAPDown 停止固件上的克隆 AP 并恢复 STA 模式。
// 对未运行克隆 AP 的固件同样安全：softAPdisconnect 为空操作。
func (i *Injector) CloneAPDown() error {
	i.mu.Lock()
	defer i.mu.Unlock()

	payload, err := buildClonePayload(cloneOpDown, 1, "", "")
	if err != nil {
		return err
	}

	if _, err := i.port.Write(EncodeCommand(cmdClone, payload)); err != nil {
		return fmt.Errorf("发送停止克隆命令失败：%w", err)
	}

	cmd, reply, err := i.readFrame(cloneReplyTimeout)
	if err != nil {
		return fmt.Errorf("等待停止克隆结果超时：%w", err)
	}

	switch cmd {
	case repCloneResult:
		ok, _, err := ParseCloneResult(reply)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("固件停止 SoftAP 失败")
		}
		return nil
	case repError:
		return cloneFirmwareError("停止克隆", reply)
	default:
		return fmt.Errorf("停止克隆命令收到意外回复帧 0x%02X", cmd)
	}
}

// CloneStatus 查询克隆 AP 当前接入的设备 MAC 列表。
// 供会话循环按固定节奏轮询，差分出设备接入/离开事件。
func (i *Injector) CloneStatus() ([]string, error) {
	i.mu.Lock()
	defer i.mu.Unlock()

	if _, err := i.port.Write(EncodeCommand(cmdCloneStatus, nil)); err != nil {
		return nil, fmt.Errorf("发送克隆状态查询失败：%w", err)
	}

	cmd, reply, err := i.readFrame(cloneReplyTimeout)
	if err != nil {
		return nil, fmt.Errorf("等待克隆状态超时：%w", err)
	}

	switch cmd {
	case repCloneStatus:
		return ParseCloneStatus(reply)
	case repError:
		return nil, cloneFirmwareError("克隆状态", reply)
	default:
		return nil, fmt.Errorf("克隆状态查询收到意外回复帧 0x%02X", cmd)
	}
}

// buildClonePayload 打包克隆命令载荷：op(1) + channel(1) + ssidLen(1) + ssid
// + passLen(1) + password。down 指令以信道 1、空 SSID 占位，固件忽略其余字段，
// 固定布局让固件解析器无需按操作码分支。
func buildClonePayload(op byte, channel int, ssid, password string) ([]byte, error) {
	ssidBytes := []byte(ssid)
	passBytes := []byte(password)

	if op == cloneOpUp {
		if len(ssidBytes) < 1 || len(ssidBytes) > 32 {
			return nil, errors.New("SSID 长度需在 1-32 字节之间")
		}
	}
	if len(passBytes) > 63 {
		return nil, errors.New("密码长度超过 63 字节上限")
	}

	payload := make([]byte, 0, 3+len(ssidBytes)+1+len(passBytes))
	payload = append(payload, op, byte(channel), byte(len(ssidBytes)))
	payload = append(payload, ssidBytes...)
	payload = append(payload, byte(len(passBytes)))
	payload = append(payload, passBytes...)
	return payload, nil
}

// cloneFirmwareError 把 repError 载荷翻译成可操作错误。
// 错误码 0xFF 是固件命令分发的兜底回复，意味着固件里根本没有这条命令
// （版本过旧），重试无意义，直接引导重烧固件。
func cloneFirmwareError(op string, reply []byte) error {
	if len(reply) >= 2 && reply[1] == 0xFF {
		return fmt.Errorf("固件不支持%s命令（错误码 255），请重新烧录 core/esp/esp.ino 最新固件", op)
	}
	if len(reply) >= 2 {
		return fmt.Errorf("固件执行%s命令失败，错误码 %d", op, reply[1])
	}
	return fmt.Errorf("固件执行%s命令失败", op)
}

// EncodeCommand 按协议打包主机→固件命令帧。导出供 tests/ 验证帧布局。
func EncodeCommand(cmd byte, payload []byte) []byte {
	frame := make([]byte, 0, 4+len(payload))
	frame = append(frame, frameHeadHost, cmd, byte(len(payload)), byte(len(payload)>>8))
	return append(frame, payload...)
}

// ParseCloneResult 解析克隆结果载荷：result(1) + apMAC(6)。
// up 成功时 MAC 为固件 SoftAP 的自身地址；down 回复 MAC 全零。
// 导出供 tests/ 做表驱动测试。
func ParseCloneResult(payload []byte) (ok bool, apMAC string, err error) {
	if len(payload) < 7 {
		return false, "", errors.New("克隆结果载荷长度不足 7 字节")
	}
	return payload[0] == 1, macString(payload[1:7]), nil
}

// ParseCloneStatus 解析克隆状态载荷：count(1) + count×MAC(6)。
// 导出供 tests/ 做表驱动测试。
func ParseCloneStatus(payload []byte) ([]string, error) {
	if len(payload) < 1 {
		return nil, errors.New("克隆状态载荷为空")
	}

	count := int(payload[0])
	if len(payload) < 1+6*count {
		return nil, errors.New("克隆状态 MAC 列表越界")
	}

	macs := make([]string, 0, count)
	for k := range count {
		macs = append(macs, macString(payload[1+k*6:7+k*6]))
	}
	return macs, nil
}

// macString 把 6 字节 MAC 格式化为小写冒号分隔串。
func macString(b []byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
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
		// 先消费缓冲区内的完整帧，再向串口读取新数据。
		// 固件批量回传时一次读取常携带多个帧（扫描条目可达几十条），
		// 若每轮先阻塞读再解析，残留帧会在固件发完静默后无谓等到超时。
		if cmd, payload, rest, ok := DecodeReply(i.rx); ok {
			i.rx = rest
			return cmd, payload, nil
		}

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
