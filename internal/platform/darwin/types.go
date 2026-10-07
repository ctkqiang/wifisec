package darwin

// Network 是 CoreWLAN 主动扫描返回的单个接入点。
// 该类型不依赖 macOS 头文件，非 darwin 平台同样参与编译，
// 供上层在任意平台合并 BSSID 补全结果并编写表驱动测试。
type Network struct {
	SSID    string `json:"ssid"`    // 网络名称（隐藏网络为空串）
	BSSID   string `json:"bssid"`   // 接入点 MAC；未获得定位授权时由系统脱敏为空
	Channel int    `json:"channel"` // 802.11 信道号
	RSSI    int    `json:"rssi"`    // 信号强度（dBm）
}

// AuthorizationStatus 对应 CoreLocation 的 CLAuthorizationStatus 原始值，
// 数值必须与系统枚举保持一致，Go 侧直接按整型接收 Objective-C 返回值。
type AuthorizationStatus int

const (
	AuthNotDetermined AuthorizationStatus = 0 // 用户尚未对本程序作出选择
	AuthRestricted    AuthorizationStatus = 1 // 受系统策略限制（如家长控制、总开关关闭）
	AuthDenied        AuthorizationStatus = 2 // 用户明确拒绝
	AuthAlways        AuthorizationStatus = 3 // 始终允许
	AuthWhenInUse     AuthorizationStatus = 4 // 使用期间允许（macOS 请求 always 时可能只授予此项）
)

// Authorized 表示已经拿到可以读取 BSSID 的任一授权形态。
func (s AuthorizationStatus) Authorized() bool {
	return s == AuthAlways || s == AuthWhenInUse
}
