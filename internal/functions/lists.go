package functions

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
	Freq    string `json:"freq"`    // 频率（例如：2.437 GHz）
}

func WifiList(arguments []string) error {
	return nil
}
