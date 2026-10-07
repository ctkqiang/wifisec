package windows

// Network 是 `netsh wlan show networks mode=bssid` 中的单个 BSS。
// netsh 把同一 SSID 的每个 BSSID 单独列出，同名双频网络天然分行。
type Network struct {
	SSID           string // 网络名称
	BSSID          string // AP 的 MAC（小写、冒号分隔）
	Channel        int    // 信道号
	Signal         int    // 信号强度（dBm，由百分比换算）
	PHY            string // 无线电类型，如 802.11ax
	Security       string // 安全代际：OPEN / WEP / WPA / WPA2 / WPA3
	Cipher         string // 加密方式：CCMP / GCMP / TKIP / WEP
	Authentication string // 认证方式：PSK / SAE / 802.1X
}

// Interface 描述一块 Windows 无线适配器。
type Interface struct {
	Name        string // 适配器名称（连接名），如 Wi-Fi
	Description string // 适配器型号描述
	GUID        string // 适配器 GUID，用于构造 Npcap 设备路径
	MAC         string // 物理地址
	State       string // 归一化后的 UP / DOWN
	Index       int    // 内核接口索引（来自 Go net 包，netsh 不提供）
	Driver      string // netsh 报告的驱动程序名
}
