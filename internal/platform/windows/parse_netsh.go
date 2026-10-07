package windows

import (
	"regexp"
	"strconv"
	"strings"
)

// netsh 键名随系统语言变化，正则同时兼容中英文。
var (
	ssidPattern   = regexp.MustCompile(`^SSID \d+\s*:\s*(.*)$`)
	bssidPattern  = regexp.MustCompile(`^BSSID \d+\s*:\s*([0-9a-fA-F:]{17})`)
	macPattern    = regexp.MustCompile(`BSSID\s*:\s*([0-9a-fA-F:]{17})`)
	intPattern    = regexp.MustCompile(`(-?\d+)`)
	driverPattern = regexp.MustCompile(`(?m)^\s*(?:Driver|驱动程序)\s*:\s*(.+)$`)
)

// ParseNetworks 解析 `netsh wlan show networks mode=bssid` 文本。
// SSID 段头位于行首、认证/加密缩进 4 列、BSSID 及其属性缩进更深，
// 利用缩进层级把每个 BSSID 拆成独立一行（同名 2.4G/5G 不会合并）。
//
// netsh 在中文系统输出 GBK，ASCII 字段（BSSID/信道/数值）不受影响，
// SSID 若含非 ASCII 字符可能乱码，属于控制台代码页限制。
func ParseNetworks(output string) []Network {
	networks := make([]Network, 0)

	var ssid, auth, enc string
	var current *Network

	flush := func() {
		if current != nil {
			networks = append(networks, *current)
			current = nil
		}
	}

	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimRight(raw, "\r")
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		trimmed := strings.TrimSpace(line)

		if match := ssidPattern.FindStringSubmatch(trimmed); match != nil && indent == 0 {
			flush()
			ssid, auth, enc = strings.TrimSpace(match[1]), "", ""
			continue
		}

		key, value, found := strings.Cut(trimmed, ":")
		if !found {
			continue
		}

		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		if match := bssidPattern.FindStringSubmatch(trimmed); match != nil {
			flush()
			n := Network{SSID: ssid, BSSID: normalizeMAC(match[1])}
			n.Security, n.Authentication, n.Cipher = mapSecurity(auth, enc)
			current = &n
			continue
		}

		if current != nil && indent >= 5 {
			switch {
			case key == "Signal" || key == "信号":
				// netsh 只给百分比，按通行线性公式换算为 dBm：dBm ≈ pct/2 - 100。
				if m := intPattern.FindStringSubmatch(value); m != nil {
					current.Signal = atoi(m[1])/2 - 100
				}
			case key == "Radio type" || key == "无线电类型":
				current.PHY = value
			case key == "Channel" || key == "频道":
				current.Channel = atoi(value)
			}
			continue
		}

		// SSID 段级字段（缩进 4 列）。
		switch key {
		case "Authentication", "身份验证":
			auth = value
		case "Encryption", "加密":
			enc = value
		}
	}

	flush()

	return networks
}

// ParseConnectedBSSID 从 `netsh wlan show interfaces` 中提取当前关联 BSSID；
// 未连接或没有活动接口时返回空串。
func ParseConnectedBSSID(output string) string {
	if match := macPattern.FindStringSubmatch(output); match != nil {
		return normalizeMAC(match[1])
	}

	return ""
}

// interfaceEntry 是 netsh 接口输出中的一个适配器中间结构。
type interfaceEntry struct {
	Name        string
	Description string
	MAC         string
	State       string
}

// ParseInterfaces 按空行分块解析 `netsh wlan show interfaces` 的“键 : 值”行。
func ParseInterfaces(raw string) []Interface {
	var entries []Interface
	var current interfaceEntry

	flush := func() {
		if current.Name != "" {
			entries = append(entries, Interface{
				Name:        current.Name,
				Description: current.Description,
				MAC:         current.MAC,
				State:       normalizeState(current.State),
			})
		}
		current = interfaceEntry{}
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

// ParseDriver 从 `netsh wlan show drivers` 提取首个驱动程序名。
func ParseDriver(output string) string {
	if match := driverPattern.FindStringSubmatch(output); match != nil {
		return strings.TrimSpace(match[1])
	}

	return ""
}

// mapSecurity 把 netsh 的身份验证/加密两个字段归一化到三列安全标签。
func mapSecurity(auth, enc string) (security, authentication, cipher string) {
	auth, enc = strings.ToUpper(auth), strings.ToUpper(enc)

	switch {
	case strings.Contains(auth, "WPA3"):
		security = "WPA3"
	case strings.Contains(auth, "WPA2"):
		security = "WPA2"
	case strings.Contains(auth, "WPA"):
		security = "WPA"
	case strings.Contains(auth, "WEP"):
		return "WEP", "", "WEP"
	case strings.Contains(auth, "OPEN"), auth == "":
		security = "OPEN"
	}

	switch {
	case strings.Contains(auth, "ENTERPRISE"):
		authentication = "802.1X"
	case security == "WPA3":
		authentication = "SAE"
	case security == "WPA" || security == "WPA2":
		authentication = "PSK"
	}

	if enc != "" && enc != "NONE" {
		cipher = enc
	}

	return security, authentication, cipher
}

// normalizeState 把 netsh 连接状态归一化为 UP / DOWN。
func normalizeState(raw string) string {
	state := strings.TrimSpace(raw)
	if strings.EqualFold(state, "connected") || strings.Contains(state, "【已连接】") {
		return "UP"
	}

	return "DOWN"
}

func normalizeMAC(raw string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(raw)), "-", ":")
}

func atoi(raw string) int {
	value, _ := strconv.Atoi(strings.TrimSpace(raw))

	return value
}
