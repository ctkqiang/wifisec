package termux

// Network 是 Termux:API 返回的单个 Wi-Fi 条目。
// 频率保留 MHz 原值，信道与频段由上层统一换算，保证跨平台输出一致。
type Network struct {
	SSID           string
	BSSID          string
	Frequency      int // MHz
	Signal         int // dBm
	Rate           int // Mbps
	Security       string
	Cipher         string
	Authentication string
	Connected      bool
}

// connectionInfo 对应 termux-wifi-connection-info 的 JSON。
type connectionInfo struct {
	State     string `json:"supplicant_state"`
	BSSID     string `json:"bssid"`
	SSID      string `json:"ssid"`
	RSSI      int    `json:"rssi"`
	Frequency int    `json:"frequency"`
	Speed     int    `json:"link_speed_mbps"`
	Error     string `json:"error"`
}

// scanEntry 对应 termux-wifi-scaninfo 的 JSON 数组元素。
type scanEntry struct {
	BSSID        string `json:"bssid"`
	SSID         string `json:"ssid"`
	RSSI         int    `json:"level"`
	Frequency    int    `json:"frequency"`
	Capabilities string `json:"capabilities"`
}
