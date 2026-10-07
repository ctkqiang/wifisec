package linux

import (
	"regexp"
	"strconv"
	"strings"
)

// iw 输出解析所需正则：键名由 iw 固定输出，不存在本地化问题。
var (
	bssPattern     = regexp.MustCompile(`^BSS ([0-9a-fA-F:]{17})\(`)
	freqPattern    = regexp.MustCompile(`\bfreq: (\d+)`)
	signalPattern  = regexp.MustCompile(`signal: (-?\d+)`)
	ssidPattern    = regexp.MustCompile(`SSID:\s?(.*)$`)
	channelPattern = regexp.MustCompile(`DS Parameter set: channel (\d+)`)
	suitePattern   = regexp.MustCompile(`\* (Group cipher|Pairwise ciphers|Authentication suites): (.+)$`)
	widthPattern   = regexp.MustCompile(`\* channel width: (\d+)(?:\s+\(([^)]+)\))?`)
	linkPattern    = regexp.MustCompile(`Connected to ([0-9a-fA-F:]{17})`)
	typePattern    = regexp.MustCompile(`(?m)^\s*type\s+(\S+)`)
)

// ParseScan 解析 `iw dev <iface> scan` 的逐 BSS 文本块。
// 每个 “BSS xx(on …)” 开头的块对应一个真实 AP，因此结果不做去重。
func ParseScan(output, device string) []Network {
	networks := make([]Network, 0)

	var (
		current     *Network
		section     string
		rsnGroup    string
		rsnPairwise string
		rsnAKM      string
		wpaGroup    string
		wpaPairwise string
		wpaAKM      string
		hasRSN      bool
		hasWPA      bool
		hasHT       bool
		hasVHT      bool
		hasHE       bool
		hasEHT      bool
		htSecondary string
		widthCode   int
		widthText   string
	)

	flush := func() {
		if current == nil {
			return
		}

		finalizeSecurity(current, hasRSN, rsnGroup, rsnPairwise, rsnAKM,
			hasWPA, wpaGroup, wpaPairwise, wpaAKM)
		current.PHY = buildPHY(current.Frequency, hasHT, hasVHT, hasHE, hasEHT)
		current.ChannelWidth = resolveWidth(hasHT, htSecondary, widthCode, widthText)
		// 部分信道号信元缺失（隐藏/畸形信标）时，按中心频率兜底换算。
		if current.Channel == 0 {
			current.Channel = freqToChannel(current.Frequency)
		}

		networks = append(networks, *current)
	}

	for _, line := range strings.Split(output, "\n") {
		if match := bssPattern.FindStringSubmatch(line); match != nil {
			flush()
			current = &Network{BSSID: normalizeMAC(match[1]), Device: device}
			section = ""
			hasRSN, hasWPA = false, false
			rsnGroup, rsnPairwise, rsnAKM = "", "", ""
			wpaGroup, wpaPairwise, wpaAKM = "", "", ""
			hasHT, hasVHT, hasHE, hasEHT = false, false, false, false
			htSecondary, widthText = "", ""
			widthCode = 0
			continue
		}

		if current == nil {
			continue
		}

		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "RSN:") {
			section, hasRSN = "rsn", true
		} else if strings.HasPrefix(trimmed, "WPA:") {
			section, hasWPA = "wpa", true
		} else if !strings.Contains(line, "*") {
			section = ""
		}

		if match := suitePattern.FindStringSubmatch(trimmed); match != nil {
			kind, values := match[1], strings.Fields(match[2])
			value := ""
			if len(values) > 0 {
				value = values[0]
			}

			switch kind {
			case "Group cipher":
				switch section {
				case "rsn":
					rsnGroup = value
				case "wpa":
					wpaGroup = value
				}
			case "Pairwise ciphers":
				switch section {
				case "rsn":
					rsnPairwise = value
				case "wpa":
					wpaPairwise = value
				}
			case "Authentication suites":
				switch section {
				case "rsn":
					rsnAKM = strings.Join(values, " ")
				case "wpa":
					wpaAKM = strings.Join(values, " ")
				}
			}
		}

		if strings.HasPrefix(trimmed, "freq:") {
			if m := freqPattern.FindStringSubmatch(line); m != nil {
				current.Frequency = atoi(m[1])
			}
		} else if strings.HasPrefix(trimmed, "signal:") {
			if m := signalPattern.FindStringSubmatch(line); m != nil {
				current.Signal = atoi(m[1])
			}
		} else if strings.HasPrefix(trimmed, "SSID:") {
			if m := ssidPattern.FindStringSubmatch(line); m != nil {
				current.SSID = strings.TrimSpace(m[1])
				// 隐藏网络的 SSID IE 长度为 0，iw 打印为空行。
				if current.SSID == "" {
					current.SSID = "<hidden>"
				}
			}
		} else if strings.HasPrefix(trimmed, "DS Parameter set:") {
			if m := channelPattern.FindStringSubmatch(line); m != nil {
				current.Channel = atoi(m[1])
			}
		} else if strings.HasPrefix(trimmed, "capability:") {
			if !strings.Contains(trimmed, "Privacy") {
				current.Security = "OPEN"
			}
		}

		switch trimmed {
		case "HT capabilities:":
			hasHT = true
		case "VHT capabilities:":
			hasVHT = true
		case "HE:":
			hasHE = true
		case "EHT:":
			hasEHT = true
		}

		if strings.Contains(trimmed, "secondary channel offset:") {
			switch {
			case strings.Contains(trimmed, "above"), strings.Contains(trimmed, "below"):
				htSecondary = "secondary"
			default:
				htSecondary = "none"
			}
		}

		if m := widthPattern.FindStringSubmatch(trimmed); m != nil {
			widthCode = atoi(m[1])
			widthText = m[2]
		}
	}

	flush()

	return networks
}

// finalizeSecurity 根据 RSN/WPA IE 与 capability Privacy 位综合判定安全信息。
// 判定顺序固定：OWE/SAE 属 WPA3；其次 WPA2(RSN)、WPA1(厂商 IE)、WEP、开放。
func finalizeSecurity(network *Network, hasRSN bool, rsnGroup, rsnPairwise, rsnAKM string,
	hasWPA bool, wpaGroup, wpaPairwise, wpaAKM string,
) {
	switch {
	case hasRSN && strings.Contains(rsnAKM, "OWE"):
		network.Security, network.Authentication = "OWE", "OWE"
	case hasRSN && (strings.Contains(rsnAKM, "SAE") || strings.Contains(rsnAKM, "EAP-SHA256")):
		network.Security = "WPA3"
		network.Authentication = mapAKM(rsnAKM)
		network.Cipher = mapCipher(firstNonEmpty(rsnPairwise, rsnGroup))
	case hasRSN:
		network.Security = "WPA2"
		network.Authentication = mapAKM(rsnAKM)
		network.Cipher = mapCipher(firstNonEmpty(rsnPairwise, rsnGroup))
	case hasWPA:
		network.Security = "WPA"
		network.Authentication = mapAKM(wpaAKM)
		network.Cipher = mapCipher(firstNonEmpty(wpaPairwise, wpaGroup))
	default:
		// 无任何安全 IE 但帧带 Privacy 位，是 WEP 网络的典型特征。
		if network.Security != "OPEN" {
			network.Security, network.Cipher = "WEP", "WEP"
		}
	}
}

// mapAKM 把 iw 的 AKM 套件描述归一化为认证标签。
func mapAKM(suites string) string {
	switch {
	case strings.Contains(suites, "SAE"):
		return "SAE"
	case strings.Contains(suites, "802.1X"), strings.Contains(suites, "EAP"):
		return "802.1X"
	case strings.Contains(suites, "PSK"):
		return "PSK"
	default:
		return ""
	}
}

// mapCipher 归一化 iw 的密码套件名称。
func mapCipher(suite string) string {
	switch {
	case strings.Contains(suite, "GCMP"):
		return "GCMP"
	case strings.Contains(suite, "CCMP"):
		return "CCMP"
	case strings.Contains(suite, "TKIP"):
		return "TKIP"
	case strings.Contains(suite, "WEP"):
		return "WEP"
	default:
		return ""
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}

	return ""
}

// buildPHY 按能力 IE 组合 PHY 标签，风格对齐 macOS profiler：
// 5GHz 以 802.11a 起步，2.4GHz 以 802.11b/g 起步，逐级追加 /n /ac /ax /be。
func buildPHY(frequency int, hasHT, hasVHT, hasHE, hasEHT bool) string {
	phy := "802.11b/g"
	if frequency >= 4900 {
		phy = "802.11a"
	}

	if hasHT {
		phy += "/n"
	}
	if hasVHT {
		phy += "/ac"
	}
	if hasHE {
		phy += "/ax"
	}
	if hasEHT {
		phy += "/be"
	}

	return phy
}

// resolveWidth 解析 VHT/HE operation 的带宽。
// iw 在括号内直接给出 MHz（80 MHz / 160 MHz / 80+80 MHz）；
// 无 VHT 时退化为 HT 副信道判断：有偏移即 40MHz，否则 20MHz。
func resolveWidth(hasHT bool, htSecondary string, code int, text string) int {
	if text != "" {
		if width := atoi(text); width > 0 {
			return width
		}
	}

	// 80+80 MHz 不含独立数字时按 160MHz 呈现。
	if strings.Contains(text, "80+80") {
		return 160
	}

	switch code {
	case 1:
		return 80
	case 2, 3:
		return 160
	}

	if hasHT {
		if htSecondary == "secondary" {
			return 40
		}
		return 20
	}

	return 0
}

// ParseConnectedLink 从 `iw dev <iface> link` 输出中提取已关联 BSSID；
// 未连接（Not connected）时返回空串。
func ParseConnectedLink(output string) string {
	if match := linkPattern.FindStringSubmatch(output); match != nil {
		return normalizeMAC(match[1])
	}

	return ""
}

// ParseInterfaceMode 从 `iw dev <iface> info` 输出中提取工作模式。
func ParseInterfaceMode(output string) string {
	if match := typePattern.FindStringSubmatch(output); match != nil {
		return match[1]
	}

	return ""
}

// normalizeMAC 统一为小写、冒号分隔。
func normalizeMAC(raw string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(raw)), "-", ":")
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

func atoi(raw string) int {
	value, _ := strconv.Atoi(strings.TrimSpace(raw))

	return value
}
