package functions

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"wifisec/internal/constants"
	platformlinux "wifisec/internal/platform/linux"
	platformwindows "wifisec/internal/platform/windows"
	"wifisec/internal/utilities"
)

const (
	columnGap   = 2   // 列间空格数
	placeholder = "-" // 平台取不到的字段占位

	commandTimeout = 10 * time.Second // 外部命令超时
	minShrinkWidth = 8                // 可收缩列在窄终端下的最小可读宽度
)

// 正则只保留仍由 macOS profiler / IORegistry 解析与通用数值提取使用的部分；
// iw 与 netsh 的解析正则已随各自 adapter 迁出 internal/platform。
var (
	airportNodePattern = regexp.MustCompile(`"IONetworkRootType"\s*=\s*"airport"`)
	driverIDPattern    = regexp.MustCompile(`"(?:CFBundleIdentifier|IOPersonalityPublisher)"\s*=\s*"([^"]+)"`)
	channelPattern     = regexp.MustCompile(`(\d+)\s*\((\d+GHz)(?:,\s*(\d+)MHz)?`)
	intPattern         = regexp.MustCompile(`(-?\d+)`)
)

var interfaceColumns = []tableColumn[WirelessInterface]{
	{
		Header: "PHY",
		Value: func(d WirelessInterface) string {
			return d.PHY
		},
		Priority: 3,
	},
	{
		Header: "接口",
		Value: func(d WirelessInterface) string {
			return d.Name
		},
	},
	{
		Header: "索引",
		Value: func(d WirelessInterface) string {
			return number(d.Index)
		},
		Priority: 4,
	},
	{
		Header: "类型",
		Value: func(d WirelessInterface) string {
			return d.Mode
		},
		Priority: 2,
	},
	{
		Header: "状态",
		Value: func(d WirelessInterface) string {
			return d.State
		},
		Color: stateColor,
	},
	{
		Header: "MAC 地址",
		Value: func(d WirelessInterface) string {
			return d.HardwareAddr
		},
	},
	{
		Header: "驱动",
		Value: func(d WirelessInterface) string {
			return d.Driver
		},
		Priority: 5,
	},
	{
		Header: "芯片组",
		Value: func(d WirelessInterface) string {
			return d.Chipset
		},
		Priority: 4,
	},
}

// networkColumns 同时呈现已连接与未连接的网络。
// BSSID 与加密套件由 macOS 的 profiler 不提供，渲染时会显示占位符。
var networkColumns = []tableColumn[WiFiNetwork]{
	{
		Header: "连接",
		Value:  connLabel,
		Color:  connColor,
	},
	{
		Header: "ESSID",
		Value: func(n WiFiNetwork) string {
			return n.ESSID
		},
		Shrink: true, // 窄终端的最后兜底：优先截断名称而不是丢列
	},
	{
		Header: "BSSID",
		Value: func(n WiFiNetwork) string {
			return n.BSSID
		},
	},
	{
		Header: "PHY",
		Value: func(n WiFiNetwork) string {
			return n.PHY
		},
		Priority: 4,
	},
	{
		Header: "信道",
		Value: func(n WiFiNetwork) string {
			return number(n.Channel)
		},
	},
	{
		Header: "频段",
		Value: func(n WiFiNetwork) string {
			return n.Freq
		},
		Priority: 3,
	},
	{
		Header: "带宽",
		Value: func(n WiFiNetwork) string {
			if n.ChannelWidth == 0 {
				return ""
			}

			return fmt.Sprintf("%d MHz", n.ChannelWidth)
		},
		Priority: 4,
	},
	{
		Header: "加密",
		Value: func(n WiFiNetwork) string {
			return n.Enc
		},
		Color:    encryptionColor,
		Priority: 1,
	},
	{
		Header: "加密套件",
		Value: func(n WiFiNetwork) string {
			return n.Cipher
		},
		Priority: 5,
	},
	{
		Header: "认证",
		Value: func(n WiFiNetwork) string {
			return n.Auth
		},
		Priority: 5,
	},
	{
		Header: "信号",
		Value: func(n WiFiNetwork) string {
			label := signalLabel(n.Signal)
			if label == "" {
				return ""
			}

			return label + " " + signalBar(n.Signal)
		},
		Color: signalColor,
	},
	{
		Header: "噪声",
		Value: func(n WiFiNetwork) string {
			return signalLabel(n.NoiseFloor)
		},
		Priority: 5,
	},
	{
		Header: "SNR",
		Value: func(n WiFiNetwork) string {
			if n.SNR == 0 {
				return ""
			}

			return fmt.Sprintf("%d dB", n.SNR)
		},
		Priority: 4,
	},
	{
		Header: "MCS",
		Value: func(n WiFiNetwork) string {
			return number(n.MCSIndex)
		},
		Priority: 5,
	},
	{
		Header: "速率",
		Value: func(n WiFiNetwork) string {
			return rateLabel(n.Rate)
		},
		Priority: 3,
	},
}

// hardwarePort 是 networksetup 输出的一个硬件端口。
type hardwarePort struct {
	Port            string
	Device          string
	EthernetAddress string
}

// tableColumn 描述表格的一列；Color 返回空串表示该列不着色。
// Priority 数值越大，终端过窄时越先被省略，0 为必列；
// Shrink 标记允许截断内容兜底的列（如 ESSID）。
type tableColumn[T any] struct {
	Header   string
	Value    func(T) string
	Color    func(string) string
	Priority int
	Shrink   bool
}

// gridCell 是网格布局中的一个单元：文本加可选颜色（空串不着色）。
type gridCell struct {
	Text, Color string
}

// WirelessInterface 描述一块无线网卡，字段覆盖 airmon-ng 展示的信息。
type WirelessInterface struct {
	PHY          string // 物理设备编号，如 phy0
	Name         string // 接口名，如 wlan0 / en0
	Index        int    // 内核接口索引
	HardwareAddr string // 硬件 MAC 地址
	Mode         string // managed / monitor
	State        string // UP / DOWN
	Driver       string // 内核驱动
	Chipset      string // 芯片型号
}

type WiFiNetwork struct {
	Id      int    `json:"id"`      // 网络ID
	BSSID   string `json:"bssid"`   // AP 的 MAC 地址
	Channel int    `json:"channel"` // WiFi 信道
	Signal  int    `json:"signal"`  // 信号强度（单位：dBm）
	Rate    int    `json:"rate"`    // 最大数据速率（单位：Mbps）
	Enc     string `json:"enc"`     // 加密类型（WPA2、WEP、OPEN）
	Cipher  string `json:"cipher"`  // 加密方式（CCMP、TKIP、WEP）
	Auth    string `json:"auth"`    // 认证方式（PSK、OPEN、802.1X）
	ESSID   string `json:"ssid"`    // 网络名称
	Device  string `json:"device"`  // 无线接口名称
	Freq    string `json:"freq"`    // 频段（例如：5GHz）
	PHY     string `json:"phy"`     // 802.11 模式（例如：802.11ax）

	// 物理层与链路质量
	ChannelWidth int `json:"channel_width"` // 信道带宽（单位：MHz）
	NoiseFloor   int `json:"noise_floor"`   // 噪声底（单位：dBm）
	SNR          int `json:"snr"`           // 信噪比（单位：dB）
	MCSIndex     int `json:"mcs_index"`     // 调制编码方案索引

	Connected bool `json:"connected"` // 是否当前已连接
}

// number 把数值渲染为文本，0 视为未知。
func number(value int) string {
	if value == 0 {
		return ""
	}

	return strconv.Itoa(value)
}

// connLabel 标记网络是否为当前连接。
func connLabel(network WiFiNetwork) string {
	if network.Connected {
		return "【已连接】"
	}

	return "【未连接】"
}

// connColor 让已连接的网络突出显示。
func connColor(label string) string {
	if label == "【已连接】" {
		return constants.ColorGreen
	}

	return constants.ColorGray
}

// signalLabel 把 dBm 渲染为可读信号。
func signalLabel(dbm int) string {
	if dbm == 0 {
		return ""
	}

	return fmt.Sprintf("%d dBm", dbm)
}

// signalColor 按强度给信号着色，阈值沿用无线勘测的通行经验：
// -50 dBm 以上为强信号，-70 dBm 以下连接质量已不可靠。
func signalColor(label string) string {
	switch dbm := leadingInt(label); {
	case dbm == 0:
		return ""
	case dbm >= -50:
		return constants.ColorGreen
	case dbm >= -70:
		return constants.ColorYellow
	default:
		return constants.ColorRed
	}
}

// signalBar 把信号强度渲染为 ▂▄▆█ 强度条，弱网一眼可辨。
func signalBar(dbm int) string {
	switch {
	case dbm >= -50:
		return "▂▄▆█"
	case dbm >= -60:
		return "▂▄▆"
	case dbm >= -67:
		return "▂▄"
	case dbm >= -75:
		return "▂"
	default:
		return "▁"
	}
}

// encryptionColor 按加密代际做威胁分色，弱加密目标一眼可辨：
// OPEN 与 WEP 危险红、WPA 过渡黄、WPA3 现代青，WPA2 保持默认不抢眼。
func encryptionColor(enc string) string {
	switch enc {
	case "OPEN", "WEP":
		return constants.ColorRed
	case "WPA":
		return constants.ColorYellow
	case "WPA3":
		return constants.ColorCyan
	default:
		return ""
	}
}

// rateLabel 把速率渲染为可读文本。
func rateLabel(mbps int) string {
	if mbps == 0 {
		return ""
	}

	return fmt.Sprintf("%d Mbps", mbps)
}

// WifiList 列出无线接口与周边网络，已连接的网络会一并标出。
// 传入 ESSID 或 BSSID 时进入锁定模式，类似 airodump-ng --bssid：
// 跳过接口表，只呈现命中的目标网络。
func WifiList(arguments []string) error {
	target := ""
	if len(arguments) > 0 {
		target = strings.TrimSpace(arguments[0])
	}

	// 锁定模式不枚举接口：扫描数据来自系统级查询，与接口枚举无关，
	// 直奔目标也贴近 airodump-ng 锁定信道后的纯粹画面。
	if target == "" {
		devices, err := FindAllWirelessInterfaces()
		if err != nil {
			return err
		}

		if len(devices) == 0 {
			utilities.Warn("未发现可用无线接口")
		} else {
			renderTable(fmt.Sprintf("无线接口 · 共 %d 个", len(devices)), interfaceColumns, devices)
		}
	}

	started := time.Now()
	networks, err := scanNetworks()
	if err != nil {
		// 各平台权限/能力差异较大，错误信息由扫描器给出可直接执行的建议。
		utilities.Warn("%s", err)
		return nil
	}

	if len(networks) == 0 {
		// macOS 在 Wi-Fi 关闭时会省略 SSID，导致扫不到可命名的网络。
		utilities.Warn("未扫描到无线网络，请确认 Wi-Fi 已开启")
		return nil
	}

	if target != "" {
		networks = filterNetworks(networks, target)
		if len(networks) == 0 {
			utilities.Warn("未找到目标 %s，请传入完整 ESSID 或 BSSID", target)
			return nil
		}
	} else {
		sortNetworks(networks)
	}

	renderScanStatus(networks, time.Since(started))
	renderTable(fmt.Sprintf("无线网络 · 共 %d 个", len(networks)), networkColumns, networks)

	// 锁定模式追加目标深度解读：法规合规、DFS、安全态势与链路质量。
	// 可选第二参数为国码（如 list CafeGuest MY），只从该法规域视角展开；
	// 全量扫描不做解读，否则满屏网络会刷屏。
	if target != "" {
		country := ""
		if len(arguments) > 1 {
			country = arguments[1]
		}

		ExplainNetworks(networks, country)
	}

	return nil
}

// scanNetworks 扫描周边网络；已连接的网络也在结果中并带标记。
// 各平台数据源不同：Linux 用 iw、Windows 用 netsh、macOS 用 system_profiler，
// Termux 只能走 termux-api。返回的错误用于给出平台对应的操作建议。
func scanNetworks() ([]WiFiNetwork, error) {
	switch {
	case utilities.GetOS() == utilities.Darwin:
		_, networks := parseMacOSProfile(macOSProfile())
		enrichMacOSConnectedBSSID(networks)
		// CoreWLAN 补全未连接网络的 BSSID：macOS 要求定位授权，首次运行会弹窗。
		enrichMacOSBSSID(networks)
		return dedupeNetworks(networks), nil
	case utilities.GetOS() == utilities.Windows:
		return scanWindowsNetworks()
	case isTermux():
		// Termux 里 go build 的 runtime.GOOS 仍是 linux，必须在纯 Linux 分支前识别。
		return scanTermuxNetworks()
	case utilities.GetOS() == utilities.Linux:
		return scanLinuxNetworks()
	default:
		return nil, fmt.Errorf("当前平台 %s 暂不支持无线网络扫描", utilities.GetOS())
	}
}

// isTermux 判断是否运行于 Android Termux：官方 GOOS=android 构建，
// 或环境带有 Termux 标记（PREFIX / TERMUX_VERSION），或安装了 termux-api 命令。
func isTermux() bool {
	if utilities.GetOS() == utilities.Android {
		return true
	}

	if strings.Contains(os.Getenv("PREFIX"), "com.termux") || os.Getenv("TERMUX_VERSION") != "" {
		return true
	}

	_, err := exec.LookPath("termux-wifi-connection-info")
	return err == nil
}

// markConnectedBSSID 按 BSSID 标记当前已连接的网络；BSSID 缺失时不做处理。
func markConnectedBSSID(networks []WiFiNetwork, bssid string) {
	bssid = normalizeMAC(bssid)
	if bssid == "" {
		return
	}

	for i := range networks {
		if normalizeMAC(networks[i].BSSID) == bssid {
			networks[i].Connected = true
		}
	}
}

// freqToChannel 按 802.11 信道编号与中心频率的固定关系换算；
// 2.4GHz：ch1=2412，每信道 +5；5GHz：ch36=5180，每信道 +5。
func freqToChannel(freq int) int {
	switch {
	case freq == 2484:
		return 14
	case freq >= 2412 && freq <= 2472:
		return (freq - 2407) / 5
	case freq >= 5000 && freq < 6000:
		return (freq - 5000) / 5
	default:
		return 0
	}
}

// bandLabel 按中心频率标注频段，与 macOS 解析结果保持同一套取值。
func bandLabel(freq int) string {
	switch {
	case freq >= 2400 && freq < 2500:
		return "2GHz"
	case freq >= 4900 && freq < 6000:
		return "5GHz"
	default:
		return ""
	}
}

// macOS 增强：root 下用 wdutil 补当前已连接网络的 BSSID

// enrichMacOSConnectedBSSID 在 root 运行时解析 `wdutil info`，
// 把已连接网络的 BSSID 补上；普通权限下 wdutil 直接报错，静默忽略。
// 周边未连接网络的 BSSID 被 macOS 隐私框架封禁，任何 CLI 都无法获取。
func enrichMacOSConnectedBSSID(networks []WiFiNetwork) {
	output, err := runCommand("wdutil", "info")
	if err != nil {
		return
	}

	bssid := ""
	for line := range strings.SplitSeq(output, "\n") {
		key, value, found := strings.Cut(line, ":")
		if !found || !strings.EqualFold(strings.TrimSpace(key), "BSSID") {
			continue
		}

		if mac := normalizeMAC(value); mac != "" {
			bssid = mac
			break
		}
	}

	if bssid == "" {
		return
	}

	for i := range networks {
		if networks[i].Connected {
			networks[i].BSSID = bssid
		}
	}
}

// dedupeNetworks 按 ESSID+信道去重。macOS 会把同一网络同时列在
// “当前网络”与“其他网络”里且不提供 BSSID，无法再细分；
// 当前网络先被解析，因此去重后保留的是带已连接标记的那一条。
func dedupeNetworks(networks []WiFiNetwork) []WiFiNetwork {
	seen := make(map[string]bool, len(networks))
	unique := make([]WiFiNetwork, 0, len(networks))

	for _, network := range networks {
		key := fmt.Sprintf("%s|%d|%s", network.ESSID, network.Channel, network.Freq)
		if seen[key] {
			continue
		}

		seen[key] = true
		unique = append(unique, network)
	}

	return unique
}

// sortNetworks 已连接的置顶，其余按信号从强到弱排序。
func sortNetworks(networks []WiFiNetwork) {
	sort.Slice(networks, func(i, j int) bool {
		if networks[i].Connected != networks[j].Connected {
			return networks[i].Connected
		}

		return networks[i].Signal > networks[j].Signal
	})
}

// filterNetworks 按目标筛选网络：ESSID 忽略大小写精确匹配；
// BSSID 去冒号后同样比较，方便少敲几个分隔符也能锁定。
// macOS 暂不提供 BSSID，该分支在补齐 Linux/Windows 扫描后自然生效。
func filterNetworks(networks []WiFiNetwork, target string) []WiFiNetwork {
	compact := strings.ReplaceAll(target, ":", "")
	matches := make([]WiFiNetwork, 0, 1)

	for _, network := range networks {
		bssid := strings.ReplaceAll(network.BSSID, ":", "")
		if strings.EqualFold(network.ESSID, target) || (bssid != "" && strings.EqualFold(bssid, compact)) {
			matches = append(matches, network)
		}
	}

	return matches
}

// renderScanStatus 输出 airodump-ng 风格的状态栏，作为扫描画面的视觉签名：
// 已连接时显示所在信道，否则显示 hop 表示系统在多信道间跳变扫描。
func renderScanStatus(networks []WiFiNetwork, elapsed time.Duration) {
	channel := "hop"
	for _, network := range networks {
		if network.Connected && network.Channel != 0 {
			channel = strconv.Itoa(network.Channel)
			break
		}
	}

	// 反显整行模拟 airodump-ng 的表头高亮，是扫描画面的视觉签名；
	// 已连接时显示所在信道，否则显示 hop 表示系统在多信道间跳变扫描。
	line := fmt.Sprintf(
		"CH %s ][ Elapsed: %d s ][ %s",
		channel,
		int(elapsed.Seconds()),
		time.Now().Format("2006-01-02 15:04:05"),
	)

	fmt.Printf(
		"\n %s%s%s\n\n",
		constants.ColorInverse,
		line,
		constants.ColorReset,
	)
}

// FindAllWirelessInterfaces 按当前平台枚举无线接口。
func FindAllWirelessInterfaces() ([]WirelessInterface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("获取网络接口失败：%w", err)
	}

	switch utilities.GetOS() {
	case utilities.Linux:
		// 真实 Linux：允许 iw 查询工作模式。
		return mapLinuxInterfaces(platformlinux.DiscoverInterfaces(true)), nil
	case utilities.Android:
		// Termux（GOOS=android）：内核同源，但通常无 iw、无 sysfs 读取权限。
		return mapLinuxInterfaces(platformlinux.DiscoverInterfaces(false)), nil
	case utilities.Darwin:
		return findMacOSWireless(interfaces)
	case utilities.Windows:
		scanned, err := platformwindows.DiscoverInterfaces()
		if err != nil {
			return nil, err
		}
		return mapWindowsInterfaces(scanned), nil
	default:
		return nil, fmt.Errorf("当前平台 %s 暂不支持无线接口枚举", utilities.GetOS())
	}
}

// FindWirelessInterface 返回第一个无线接口，供单接口操作选择目标。
func FindWirelessInterface() (*WirelessInterface, error) {
	devices, err := FindAllWirelessInterfaces()
	if err != nil {
		return nil, err
	}

	if len(devices) == 0 {
		return nil, errors.New("未发现可用无线接口")
	}

	return &devices[0], nil
}

// findMacOSWireless 通过 networksetup 与 system_profiler 枚举无线接口。
func findMacOSWireless(interfaces []net.Interface) ([]WirelessInterface, error) {
	output, err := runCommand("networksetup", "-listallhardwareports")
	if err != nil {
		return nil, fmt.Errorf("枚举无线端口失败：%w", err)
	}

	ports := parseHardwarePorts(output)
	if len(ports) == 0 {
		return nil, errors.New("未发现无线硬件端口")
	}

	cardTypes, _ := parseMacOSProfile(macOSProfile())
	driver := macOSDriver()

	devices := make([]WirelessInterface, 0, len(ports))
	for _, port := range ports {
		device := WirelessInterface{
			Name: port.Device,
			// networksetup 给出硬件地址；net 包给出的是随网络变化的随机私有地址。
			HardwareAddr: normalizeMAC(port.EthernetAddress),
			Mode:         "managed", // macOS 原生不支持 monitor 模式
			Driver:       driver,
			Chipset:      cardTypes[port.Device],
		}

		if iface, err := findInterface(interfaces, port.Device); err == nil {
			device.Index = iface.Index
			device.State = stateOf(iface.Flags)
			if device.HardwareAddr == "" {
				device.HardwareAddr = normalizeMAC(iface.HardwareAddr.String())
			}
		}

		devices = append(devices, device)
	}

	sortInterfaces(devices)

	return devices, nil
}

// findInterface 按名称查找系统接口，供 networksetup 端口补全索引与状态。
func findInterface(interfaces []net.Interface, name string) (net.Interface, error) {
	for _, iface := range interfaces {
		if iface.Name == name {
			return iface, nil
		}
	}

	return net.Interface{}, fmt.Errorf("未找到接口 %s", name)
}

// stateOf 把接口标志转换为 UP / DOWN。
func stateOf(flags net.Flags) string {
	if flags&net.FlagUp != 0 {
		return "UP"
	}

	return "DOWN"
}

// parseHardwarePorts 解析 networksetup 输出，仅保留无线端口。
func parseHardwarePorts(raw string) []hardwarePort {
	var ports []hardwarePort
	var current hardwarePort

	flush := func() {
		if current.Device != "" && isWirelessPort(current.Port) {
			ports = append(ports, current)
		}
		current = hardwarePort{}
	}

	for _, line := range strings.Split(raw, "\n") {
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}

		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}

		switch strings.TrimSpace(key) {
		case "Hardware Port":
			current.Port = strings.TrimSpace(value)
		case "Device":
			current.Device = strings.TrimSpace(value)
		case "Ethernet Address":
			current.EthernetAddress = strings.TrimSpace(value)
		}
	}

	flush()

	return ports
}

// isWirelessPort 判断硬件端口是否为无线网卡，兼容 Wi-Fi 与旧版 AirPort 命名。
func isWirelessPort(port string) bool {
	port = strings.ToLower(port)

	return strings.Contains(port, "wi-fi") || strings.Contains(port, "airport")
}

var (
	macProfileOnce sync.Once
	macProfileText string
)

// macOSProfile 读取 system_profiler 的无线信息，整个进程只执行一次。
// 强制 LC_ALL=C 固定英文标签，否则系统语言变化会破坏解析。
func macOSProfile() string {
	macProfileOnce.Do(func() {
		output, err := runCommandWithTimeout(20*time.Second, "env", "LC_ALL=C", "system_profiler", "SPAirPortDataType")
		if err == nil {
			macProfileText = output
		}
	})

	return macProfileText
}

// parseMacOSProfile 从 profiler 文本中取出接口型号与无线网络。
// JSON 输出不含 SSID，只能走文本；解析按相对缩进进行而不写死层级，
// 避免不同 macOS 版本或权限下的排版差异导致漏读。
func parseMacOSProfile(profile string) (map[string]string, []WiFiNetwork) {
	var (
		cardTypes     = make(map[string]string)
		networks      []WiFiNetwork
		iface         string
		current       WiFiNetwork
		sectionIndent = -1
		connected     bool
	)

	flush := func() {
		if current.ESSID != "" {
			networks = append(networks, current)
		}
		current = WiFiNetwork{}
	}

	for _, line := range strings.Split(profile, "\n") {
		text := strings.TrimSpace(line)
		if text == "" {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))

		switch text {
		case "Current Network Information:", "Other Local Wi-Fi Networks:":
			flush()
			sectionIndent, connected = indent, text == "Current Network Information:"
			continue
		}

		// 网络段之外：记录接口名与网卡型号。
		if sectionIndent < 0 {
			if strings.HasPrefix(text, "Card Type:") {
				cardTypes[iface] = cardType(strings.TrimPrefix(text, "Card Type:"))
			} else if strings.HasSuffix(text, ":") {
				iface = strings.TrimSuffix(text, ":")
			}
			continue
		}

		if indent <= sectionIndent { // 段结束
			flush()
			sectionIndent = -1
			continue
		}

		if strings.HasSuffix(text, ":") { // 比段头更深、以冒号结尾的是 SSID
			flush()
			current = WiFiNetwork{ESSID: strings.TrimSuffix(text, ":"), Device: iface, Connected: connected}
			continue
		}

		readMacOSNetworkField(&current, text)
	}

	flush()

	return cardTypes, networks
}

// readMacOSNetworkField 读取一行网络属性，如 “Channel: 157 (5GHz, 80MHz)”。
func readMacOSNetworkField(network *WiFiNetwork, text string) {
	key, value, ok := strings.Cut(text, ":")
	if !ok {
		return
	}

	switch strings.TrimSpace(key) {
	case "PHY Mode":
		network.PHY = strings.TrimSpace(value)
	case "Channel":
		network.Channel, network.Freq, network.ChannelWidth = parseChannel(value)
	case "Security":
		network.Enc, network.Auth = parseSecurity(value)
	case "Signal / Noise":
		network.Signal, network.NoiseFloor = parseSignalNoise(value)
		if network.NoiseFloor != 0 {
			network.SNR = network.Signal - network.NoiseFloor
		}
	case "MCS Index":
		network.MCSIndex = leadingInt(value)
	case "Transmit Rate":
		network.Rate = leadingInt(value)
	}
}

// parseChannel 从 “157 (5GHz, 80MHz)” 拆出信道号、频段与带宽。
func parseChannel(raw string) (channel int, band string, width int) {
	if matches := channelPattern.FindStringSubmatch(raw); matches != nil {
		return atoi(matches[1]), matches[2], atoi(matches[3])
	}

	return leadingInt(raw), "", 0
}

// parseSignalNoise 从 “-56 dBm / -91 dBm” 拆出信号与噪声。
func parseSignalNoise(raw string) (signal int, noise int) {
	values := intPattern.FindAllString(raw, -1)
	if len(values) > 0 {
		signal = atoi(values[0])
	}
	if len(values) > 1 {
		noise = atoi(values[1])
	}

	return signal, noise
}

// parseSecurity 把 “WPA2 Personal” 拆成加密方式与认证方式。
func parseSecurity(raw string) (enc string, auth string) {
	text := strings.TrimSpace(raw)

	switch {
	case strings.Contains(text, "WPA3"):
		enc = "WPA3"
	case strings.Contains(text, "WPA2"):
		enc = "WPA2"
	case strings.Contains(text, "WPA"):
		enc = "WPA"
	case strings.Contains(text, "WEP"):
		enc = "WEP"
	default:
		enc = "OPEN"
	}

	switch {
	case strings.Contains(text, "Enterprise"):
		auth = "802.1X"
	case strings.Contains(text, "Personal"):
		auth = "PSK"
	}

	return enc, auth
}

// atoi 宽松解析整数，失败返回 0。
func atoi(raw string) int {
	value, _ := strconv.Atoi(strings.TrimSpace(raw))

	return value
}

// leadingInt 取字符串中首个整数，如 “-58 dBm / -91 dBm” 得到 -58。
func leadingInt(raw string) int {
	return atoi(matchGroup(intPattern, raw))
}

// cardType 去掉本地化前缀，仅保留括号内的硬件标识。
func cardType(raw string) string {
	if index := strings.Index(raw, "("); index >= 0 {
		return strings.TrimSpace(raw[index:])
	}

	return strings.TrimSpace(raw)
}

// macOSDriver 从 IORegistry 取无线驱动标识。
// 先用 IONetworkRootType=airport 定位无线服务节点，再读同节点的驱动标识，
// 不写死任何厂商或机型，Apple Silicon 与 Intel 机型都适用。
func macOSDriver() string {
	output, err := runCommandWithTimeout(20*time.Second, "ioreg", "-l", "-w0", "-p", "IOService")
	if err != nil {
		return ""
	}

	for _, line := range strings.Split(output, "\n") {
		if airportNodePattern.MatchString(line) {
			if driver := matchGroup(driverIDPattern, line); driver != "" {
				return driver
			}
		}
	}

	return ""
}

// normalizeMAC 统一为小写、冒号分隔。
func normalizeMAC(raw string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(raw)), "-", ":")
}

// sortInterfaces 按接口索引排序，保证输出顺序稳定。
func sortInterfaces(devices []WirelessInterface) {
	sort.Slice(devices, func(i, j int) bool { return devices[i].Index < devices[j].Index })
}

// matchGroup 返回正则首个捕获组，未匹配返回空串。
func matchGroup(pattern *regexp.Regexp, input string) string {
	if matches := pattern.FindStringSubmatch(input); len(matches) > 1 {
		return matches[1]
	}

	return ""
}

// runCommand 以默认超时执行命令并返回标准输出。
func runCommand(name string, args ...string) (string, error) {
	return runCommandWithTimeout(commandTimeout, name, args...)
}

// runCommandWithTimeout 执行外部命令并返回标准输出。
// 以参数列表传参、不经 shell 解释，避免接口名等外部输入造成命令注入。
func runCommandWithTimeout(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("命令 %s 超时", name)
		}
		if detail := strings.TrimSpace(stderr.String()); detail != "" {
			return "", fmt.Errorf("命令 %s 失败：%w：%s", name, err, detail)
		}

		return "", fmt.Errorf("命令 %s 失败：%w", name, err)
	}

	return stdout.String(), nil
}

// stateColor 让运行状态一眼可辨。
func stateColor(state string) string {
	switch state {
	case "UP":
		return constants.ColorGreen
	case "DOWN":
		return constants.ColorRed
	default:
		return ""
	}
}

// terminalWidth 查询终端列数，供表格自适应。
// 非终端输出（管道、日志捕获）或查询失败返回 0 表示不限宽，
// 保证落盘与重定向场景的数据完整性。具体系统调用见平台构建文件。
func terminalWidth() int {
	return terminalColumnWidth()
}

// renderTable 输出带标题的等宽表格；终端过窄时按列优先级自动省略次要列。
func renderTable[T any](title string, columns []tableColumn[T], items []T) {
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		cells := make([]string, len(columns))
		for index, column := range columns {
			value := column.Value(item)
			if value == "" {
				value = placeholder
			}

			cells[index] = value
		}

		rows = append(rows, cells)
	}

	keep := fitColumns(columns, rows, terminalWidth())

	headers := make([]string, len(keep))
	widths := make([]int, len(keep))
	for pos, index := range keep {
		headers[pos] = columns[index].Header
		widths[pos] = cellWidth(columns[index].Header)
	}

	shown := make([][]string, 0, len(rows))
	rowColors := make([][]string, 0, len(rows))
	for _, row := range rows {
		cells := make([]string, len(keep))
		colors := make([]string, len(keep))
		for pos, index := range keep {
			cells[pos] = row[index]
			if width := cellWidth(cells[pos]); width > widths[pos] {
				widths[pos] = width
			}
			if columns[index].Color != nil {
				colors[pos] = columns[index].Color(cells[pos])
			}
		}

		shown = append(shown, cells)
		rowColors = append(rowColors, colors)
	}

	fmt.Printf(
		"\n%s%s%s\n",
		constants.ColorCyan,
		title,
		constants.ColorReset,
	)

	fmt.Printf(
		"%s%s%s\n",
		constants.ColorBlue,
		formatRow(headers, widths, nil),
		constants.ColorReset,
	)

	fmt.Printf(
		"%s%s%s\n",
		constants.ColorGray,
		strings.Repeat("─", tableWidth(widths)),
		constants.ColorReset,
	)

	for index, row := range shown {
		fmt.Println(formatRow(row, widths, rowColors[index]))
	}
}

// renderGrid 把等宽单元格按终端宽度折行输出，适合法规域这类数量多、
// 单格信息少的枚举型数据，相比单列纵表能省下大量纵向空间。
func renderGrid(title string, cells []gridCell) {
	if len(cells) == 0 {
		return
	}

	// 全部单元格等宽：取最大显示宽度，保证列与列对齐。
	width := 0
	for _, cell := range cells {
		if current := cellWidth(cell.Text); current > width {
			width = current
		}
	}

	// 终端宽度未知（0）时按 4 列兜底；过窄时退化为单列。
	columns := 4
	if termWidth := terminalWidth(); termWidth > 0 {
		columns = (termWidth + columnGap) / (width + columnGap)
		if columns < 1 {
			columns = 1
		}
	}
	if columns > len(cells) {
		columns = len(cells)
	}

	fmt.Printf("\n%s%s%s\n", constants.ColorCyan, title, constants.ColorReset)

	lines := make([]string, 0, (len(cells)+columns-1)/columns)
	for start := 0; start < len(cells); start += columns {
		end := start + columns
		if end > len(cells) {
			end = len(cells)
		}

		var line strings.Builder
		for index, cell := range cells[start:end] {
			if index > 0 {
				line.WriteString(strings.Repeat(" ", columnGap))
			}

			// 行尾格不补空格，避免输出行拖着一串无意义的空白。
			padding := ""
			if index < end-start-1 {
				padding = strings.Repeat(" ", width-cellWidth(cell.Text))
			}

			if cell.Color != "" {
				line.WriteString(cell.Color)
			}

			line.WriteString(cell.Text)

			if cell.Color != "" {
				line.WriteString(constants.ColorReset)
			}

			line.WriteString(padding)
		}

		lines = append(lines, line.String())
	}

	fmt.Println(strings.Join(lines, "\n"))
}

// fitColumns 依据终端宽度决定保留哪些列：先省略优先级数值大的列，
// 仍放不下再截断标记为 Shrink 的列（如 ESSID）。width 非正表示不限宽。
// 截断会直接改写 rows 中的单元格，调用方此后只渲染 keep 涉及的列。
func fitColumns[T any](columns []tableColumn[T], rows [][]string, width int) []int {
	keep := make([]int, len(columns))
	for index := range keep {
		keep[index] = index
	}

	if width <= 0 {
		return keep
	}

	widths := make([]int, len(columns))
	for index, column := range columns {
		widths[index] = cellWidth(column.Header)
		for _, row := range rows {
			if current := cellWidth(row[index]); current > widths[index] {
				widths[index] = current
			}
		}
	}

	total := tableWidth(widths)
	for total > width {
		drop := -1
		for _, index := range keep {
			if columns[index].Priority > 0 && (drop == -1 || columns[index].Priority > columns[drop].Priority) {
				drop = index
			}
		}
		if drop == -1 {
			break // 剩余均为必要列，交由可收缩列截断兜底
		}

		total -= widths[drop] + columnGap
		for pos, index := range keep {
			if index == drop {
				keep = append(keep[:pos], keep[pos+1:]...)
				break
			}
		}
	}

	if total <= width {
		return keep
	}

	// 截断预算：扣除必要列宽与列间距后，剩余宽度平分给可收缩列。
	fixed, shrinkCount := 0, 0
	for _, index := range keep {
		if columns[index].Shrink {
			shrinkCount++
			continue
		}

		fixed += widths[index]
	}

	limit := (width - fixed - columnGap*(len(keep)-1)) / max(shrinkCount, 1)
	if shrinkCount == 0 || limit < minShrinkWidth {
		return keep // 空间过窄时放弃截断，避免名称不可读
	}

	for _, index := range keep {
		if !columns[index].Shrink {
			continue
		}

		for _, row := range rows {
			row[index] = truncateCell(row[index], limit)
		}
	}

	return keep
}

// truncateCell 把文本截断到指定显示宽度，超出部分以 … 结尾。
func truncateCell(text string, maxWidth int) string {
	if cellWidth(text) <= maxWidth {
		return text
	}

	width := 0
	for index, current := range text {
		unit := 1
		if isWideRune(current) {
			unit = 2
		}
		if width+unit > maxWidth-1 { // 预留结尾 … 的宽度
			return text[:index] + "…"
		}

		width += unit
	}

	return text
}

// tableWidth 计算整行的显示宽度。
func tableWidth(widths []int) int {
	total := 0
	for _, width := range widths {
		total += width + columnGap
	}

	return total - columnGap
}

// formatRow 按列宽补齐生成一行；颜色只作用于对应单元格，不计入宽度。
func formatRow(cells []string, widths []int, colors []string) string {
	var builder strings.Builder

	for index, cell := range cells {
		if index > 0 {
			builder.WriteString(strings.Repeat(" ", columnGap))
		}

		padding := strings.Repeat(" ", widths[index]-cellWidth(cell))
		color := ""
		if colors != nil {
			color = colors[index]
		}

		if color == "" {
			builder.WriteString(cell)
			builder.WriteString(padding)
			continue
		}

		builder.WriteString(color)
		builder.WriteString(cell)
		builder.WriteString(constants.ColorReset)
		builder.WriteString(padding)
	}

	return strings.TrimRight(builder.String(), " ")
}

// cellWidth 计算终端显示宽度，中日韩文字占两个字符位。
func cellWidth(text string) int {
	width := 0
	for _, current := range text {
		if isWideRune(current) {
			width += 2
			continue
		}

		width++
	}

	return width
}

// isWideRune 判断字符是否占两个字符位。
func isWideRune(current rune) bool {
	switch {
	case current >= 0x1100 && current <= 0x115F, // 韩文字母
		current >= 0x2E80 && current <= 0xA4CF, // 中日韩汉字
		current >= 0xAC00 && current <= 0xD7A3, // 韩文音节
		current >= 0xF900 && current <= 0xFAFF, // 兼容汉字
		current >= 0xFE30 && current <= 0xFE4F, // 兼容符号
		current >= 0xFF00 && current <= 0xFF60, // 全角 ASCII
		current >= 0xFFE0 && current <= 0xFFE6: // 全角符号
		return true
	default:
		return false
	}
}
