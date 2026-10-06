package functions

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"wifisec/internal/constants"
	"wifisec/internal/utilities"
)

const (
	columnGap      = 2                // 列间空格数
	placeholder    = "-"              // 平台取不到的字段占位
	commandTimeout = 10 * time.Second // 外部命令超时
)

// hardwarePort 是 networksetup 输出的一个硬件端口。
type hardwarePort struct {
	Port            string
	Device          string
	EthernetAddress string
}

// tableColumn 描述表格的一列；Color 返回空串表示该列不着色。
type tableColumn[T any] struct {
	Header string
	Value  func(T) string
	Color  func(string) string
}

var (
	iwTypePattern      = regexp.MustCompile(`(?m)^\s*type\s+(\S+)`)
	netshDriverPattern = regexp.MustCompile(`(?m)^\s*(?:Driver|驱动程序)\s*:\s*(.+)$`)
	airportNodePattern = regexp.MustCompile(`"IONetworkRootType"\s*=\s*"airport"`)
	driverIDPattern    = regexp.MustCompile(`"(?:CFBundleIdentifier|IOPersonalityPublisher)"\s*=\s*"([^"]+)"`)
	channelPattern     = regexp.MustCompile(`(\d+)\s*\((\d+GHz)(?:,\s*(\d+)MHz)?`)
	intPattern         = regexp.MustCompile(`(-?\d+)`)

	// 无法读取 /proc/net/wireless 时，按常见无线接口名前缀兜底识别。
	namePrefixes = []string{"wlan", "wlp", "wlx", "wl", "ath", "ra"}
)

var interfaceColumns = []tableColumn[WirelessInterface]{
	{
		Header: "PHY",
		Value: func(d WirelessInterface) string {
			return d.PHY
		},
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
	},
	{
		Header: "类型",
		Value: func(d WirelessInterface) string {
			return d.Mode
		},
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
	},
	{
		Header: "芯片组",
		Value: func(d WirelessInterface) string {
			return d.Chipset
		},
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
	},
	{
		Header: "带宽",
		Value: func(n WiFiNetwork) string {
			if n.ChannelWidth == 0 {
				return ""
			}

			return fmt.Sprintf("%d MHz", n.ChannelWidth)
		},
	},
	{
		Header: "加密",
		Value: func(n WiFiNetwork) string {
			return n.Enc
		},
	},
	{
		Header: "加密套件",
		Value: func(n WiFiNetwork) string {
			return n.Cipher
		},
	},
	{
		Header: "认证",
		Value: func(n WiFiNetwork) string {
			return n.Auth
		},
	},
	{
		Header: "信号",
		Value: func(n WiFiNetwork) string {
			return signalLabel(n.Signal)
		},
	},
	{
		Header: "噪声",
		Value: func(n WiFiNetwork) string {
			return signalLabel(n.NoiseFloor)
		},
	},
	{
		Header: "SNR",
		Value: func(n WiFiNetwork) string {
			if n.SNR == 0 {
				return ""
			}

			return fmt.Sprintf("%d dB", n.SNR)
		},
	},
	{
		Header: "MCS",
		Value: func(n WiFiNetwork) string {
			return number(n.MCSIndex)
		},
	},
	{
		Header: "速率",
		Value: func(n WiFiNetwork) string {
			return rateLabel(n.Rate)
		},
	},
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
		return "已连接"
	}

	return "未连接"
}

// connColor 让已连接的网络突出显示。
func connColor(label string) string {
	if label == "已连接" {
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

// rateLabel 把速率渲染为可读文本。
func rateLabel(mbps int) string {
	if mbps == 0 {
		return ""
	}

	return fmt.Sprintf("%d Mbps", mbps)
}

// WifiList 列出无线接口与周边网络，已连接的网络会一并标出。
func WifiList(arguments []string) error {
	devices, err := FindAllWirelessInterfaces()
	if err != nil {
		return err
	}

	if len(devices) == 0 {
		utilities.Warn("未发现可用无线接口")
		return nil
	}

	renderTable(fmt.Sprintf("无线接口 · 共 %d 个", len(devices)), interfaceColumns, devices)

	networks := scanNetworks()
	if len(networks) == 0 {
		// macOS 在 Wi-Fi 关闭时会省略 SSID，导致扫不到可命名的网络。
		utilities.Warn("未扫描到无线网络，请确认 Wi-Fi 已开启")
		return nil
	}

	sortNetworks(networks)
	renderTable(fmt.Sprintf("无线网络 · 共 %d 个", len(networks)), networkColumns, networks)

	return nil
}

// scanNetworks 扫描周边网络；已连接的网络也在结果中并带标记。
func scanNetworks() []WiFiNetwork {
	switch utilities.GetOS() {
	case utilities.Darwin:
		_, networks := parseMacOSProfile(macOSProfile())
		return dedupeNetworks(networks)
	default:
		return nil
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

// FindAllWirelessInterfaces 按当前平台枚举无线接口。
func FindAllWirelessInterfaces() ([]WirelessInterface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("获取网络接口失败：%w", err)
	}

	switch utilities.GetOS() {
	case utilities.Linux:
		return collectProcInterfaces(interfaces, true), nil
	case utilities.Android:
		return collectProcInterfaces(interfaces, false), nil
	case utilities.Darwin:
		return findMacOSWireless(interfaces)
	case utilities.Windows:
		return findWindowsWireless(interfaces)
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

// collectProcInterfaces 采集 Linux 系（含 Termux）的接口信息。
// useIw 为 false 时不调用 iw，Termux 通常没有该工具。
func collectProcInterfaces(interfaces []net.Interface, useIw bool) []WirelessInterface {
	names, err := procWirelessNames()
	if err != nil || len(names) == 0 {
		names = guessWirelessNames(interfaces)
	}

	devices := make([]WirelessInterface, 0, len(names))
	for _, name := range names {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			continue // 接口可能在枚举与查询之间被移除
		}

		device := WirelessInterface{
			PHY:          sysfsLink("/sys/class/net/" + name + "/phy80211"),
			Name:         iface.Name,
			Index:        iface.Index,
			HardwareAddr: iface.HardwareAddr.String(),
			State:        stateOf(iface.Flags),
			Driver:       sysfsLink("/sys/class/net/" + name + "/device/driver"),
			Chipset:      sysfsChipset(name),
		}
		if useIw {
			device.Mode = iwMode(name)
		}

		devices = append(devices, device)
	}

	sortInterfaces(devices)

	return devices
}

// procWirelessNames 解析 /proc/net/wireless，取冒号前的接口名。
// 前两行内核表头不含冒号，天然被过滤。
func procWirelessNames() ([]string, error) {
	data, err := os.ReadFile(constants.WIRELESS_FILE)
	if err != nil {
		return nil, err
	}

	var names []string
	for _, line := range strings.Split(string(data), "\n") {
		name, _, ok := strings.Cut(line, ":")
		name = strings.TrimSpace(name)
		if ok && name != "" && !strings.Contains(name, "|") {
			names = append(names, name)
		}
	}

	return names, nil
}

// guessWirelessNames 按接口名前缀兜底识别无线网卡。
func guessWirelessNames(interfaces []net.Interface) []string {
	var names []string
	for _, iface := range interfaces {
		for _, prefix := range namePrefixes {
			if strings.HasPrefix(iface.Name, prefix) {
				names = append(names, iface.Name)
				break
			}
		}
	}

	return names
}

// stateOf 把接口标志转换为 UP / DOWN。
func stateOf(flags net.Flags) string {
	if flags&net.FlagUp != 0 {
		return "UP"
	}

	return "DOWN"
}

// sysfsLink 返回 sysfs 符号链接的末段，如 driver -> iwlwifi。
func sysfsLink(path string) string {
	target, err := os.Readlink(path)
	if err != nil {
		return ""
	}

	return filepath.Base(target)
}

// sysfsChipset 尽力读取网卡型号；PCI 网卡通常无法直接获得，返回空串。
func sysfsChipset(name string) string {
	base := "/sys/class/net/" + name + "/device"
	read := func(attr string) string {
		data, err := os.ReadFile(filepath.Join(base, attr))
		if err != nil {
			data, err = os.ReadFile(filepath.Join(base, "..", attr))
		}
		if err != nil {
			return ""
		}

		return strings.TrimSpace(string(data))
	}

	return strings.TrimSpace(strings.Join([]string{read("manufacturer"), read("product")}, " "))
}

// iwMode 通过 iw 查询工作模式；未安装 iw 时返回空串。
func iwMode(name string) string {
	output, err := runCommand("iw", "dev", name, "info")
	if err != nil {
		return ""
	}

	return matchGroup(iwTypePattern, output)
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

// netshWirelessEntry 是 netsh 输出中的一个适配器。
type netshWirelessEntry struct {
	Name        string
	Description string
	MAC         string
	State       string
}

// findWindowsWireless 通过 netsh 枚举无线接口。
// netsh 输出随系统语言变化，因此键名同时兼容中英文。
func findWindowsWireless(interfaces []net.Interface) ([]WirelessInterface, error) {
	output, err := runCommand("netsh", "wlan", "show", "interfaces")
	if err != nil {
		return nil, fmt.Errorf("枚举无线接口失败：%w", err)
	}

	entries := parseNetshInterfaces(output)
	if len(entries) == 0 {
		return nil, errors.New("未发现无线接口")
	}

	driver := windowsDriver()

	devices := make([]WirelessInterface, 0, len(entries))
	for _, entry := range entries {
		device := WirelessInterface{
			Name:         entry.Name,
			HardwareAddr: entry.MAC,
			State:        windowsState(entry.State),
			Driver:       driver,
			Chipset:      entry.Description,
		}

		if iface, err := findInterface(interfaces, entry.Name); err == nil {
			device.Index = iface.Index
		}

		devices = append(devices, device)
	}

	sortInterfaces(devices)

	return devices, nil
}

// parseNetshInterfaces 按空行分块解析 “键 : 值” 行。
func parseNetshInterfaces(raw string) []netshWirelessEntry {
	var entries []netshWirelessEntry
	var current netshWirelessEntry

	flush := func() {
		if current.Name != "" {
			entries = append(entries, current)
		}
		current = netshWirelessEntry{}
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
		case "Name", "名称":
			current.Name = strings.TrimSpace(value)
		case "Description", "描述":
			current.Description = strings.TrimSpace(value)
		case "Physical address", "物理地址":
			current.MAC = normalizeMAC(value)
		case "State", "状态":
			current.State = strings.TrimSpace(value)
		}
	}

	flush()

	return entries
}

// normalizeMAC 统一为小写、冒号分隔。
func normalizeMAC(raw string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(raw)), "-", ":")
}

// windowsState 把 netsh 状态归一化为 UP / DOWN。
func windowsState(raw string) string {
	state := strings.TrimSpace(raw)
	if strings.EqualFold(state, "connected") || strings.Contains(state, "已连接") {
		return "UP"
	}

	return "DOWN"
}

// windowsDriver 取 netsh 报告的驱动名。
func windowsDriver() string {
	output, err := runCommand("netsh", "wlan", "show", "drivers")
	if err != nil {
		return ""
	}

	return strings.TrimSpace(matchGroup(netshDriverPattern, output))
}

// findInterface 按名称查找接口；Windows 接口名大小写不固定。
func findInterface(interfaces []net.Interface, name string) (net.Interface, error) {
	for _, iface := range interfaces {
		if strings.EqualFold(iface.Name, name) {
			return iface, nil
		}
	}

	return net.Interface{}, fmt.Errorf("未找到接口 %s", name)
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

// renderTable 输出带标题的等宽表格。
func renderTable[T any](title string, columns []tableColumn[T], items []T) {
	headers := make([]string, len(columns))
	widths := make([]int, len(columns))
	for index, column := range columns {
		headers[index] = column.Header
		widths[index] = cellWidth(column.Header)
	}

	rows := make([][]string, 0, len(items))
	rowColors := make([][]string, 0, len(items))
	for _, item := range items {
		cells := make([]string, len(columns))
		colors := make([]string, len(columns))
		for index, column := range columns {
			value := column.Value(item)
			if value == "" {
				value = placeholder
			}

			cells[index] = value
			if width := cellWidth(value); width > widths[index] {
				widths[index] = width
			}
			if column.Color != nil {
				colors[index] = column.Color(value)
			}
		}

		rows = append(rows, cells)
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

	for index, row := range rows {
		fmt.Println(formatRow(row, widths, rowColors[index]))
	}
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
