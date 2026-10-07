package termux

import "strings"

// ParseCapabilities 解析 wpa_supplicant 风格能力串，如
// [WPA2-PSK-CCMP][RSN-PSK-CCMP][ESS]，只取其中最强的一组标签。
// 判定顺序：WPA3(EAP 变体除外) → WPA2(RSN/WPA2) → WPA → WEP → 开放。
func ParseCapabilities(capabilities string) (security, cipher, authentication string) {
	upper := strings.ToUpper(capabilities)

	switch {
	case strings.Contains(upper, "WPA3"), strings.Contains(upper, "SAE"):
		security = "WPA3"
	case strings.Contains(upper, "RSN"), strings.Contains(upper, "WPA2"):
		security = "WPA2"
	case strings.Contains(upper, "WPA"):
		security = "WPA"
	case strings.Contains(upper, "WEP"):
		return "WEP", "WEP", ""
	default:
		security = "OPEN"
	}

	switch {
	case strings.Contains(upper, "EAP"):
		authentication = "802.1X"
	case security == "WPA3":
		authentication = "SAE"
	case security == "WPA" || security == "WPA2":
		authentication = "PSK"
	}

	switch {
	case strings.Contains(upper, "GCMP"):
		cipher = "GCMP"
	case strings.Contains(upper, "CCMP"):
		cipher = "CCMP"
	case strings.Contains(upper, "TKIP"):
		cipher = "TKIP"
	}

	return security, cipher, authentication
}
