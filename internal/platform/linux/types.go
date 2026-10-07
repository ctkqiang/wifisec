package linux

// Network 是 Linux 上 `iw dev <iface> scan` 解析出的单个接入点。
// 频率保留原始 MHz 数值，频段标签由上层按同一套规则换算，
// 避免 adapter 承担终端渲染语义。
type Network struct {
	BSSID          string // AP 的 MAC 地址（小写、冒号分隔）
	SSID           string // 网络名称；隐藏网络为 <hidden>
	Device         string // 扫描所用无线接口名
	Frequency      int    // 中心频率（MHz）
	Channel        int    // 802.11 信道号
	Signal         int    // 信号强度（dBm）
	PHY            string // 802.11 能力组合，如 802.11b/g/n
	ChannelWidth   int    // 信道带宽（MHz）
	Security       string // 安全代际：OPEN / WEP / WPA / WPA2 / WPA3 / OWE
	Cipher         string // 组播/单播密码套件：CCMP / GCMP / TKIP / WEP
	Authentication string // 认证套件：PSK / SAE / 802.1X / OWE
}

// Interface 描述一块 Linux 无线网卡，字段对齐 airmon-ng 风格的接口表。
type Interface struct {
	PHY          string // 物理设备编号，如 phy0
	Name         string // 接口名，如 wlan0 / wlp2s0
	Index        int    // 内核接口索引
	HardwareAddr string // 硬件 MAC 地址
	Mode         string // managed / monitor
	State        string // UP / DOWN
	Driver       string // 内核驱动名，如 iwlwifi
	Chipset      string // 网卡型号（sysfs manufacturer/product）
}
