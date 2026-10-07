package constants

import (
	"log/slog"
	"wifisec/internal/model"
)

const (
	EMBEDDED_MODE = true
)

const (
	PID_FILE        = "/var/run/deauth.pid"
	WIRELESS_FILE   = "/proc/net/wireless"
	DEV_FILE        = "/proc/net/dev"
	DEFAULT_PKT_CNT = 2000
)

const (
	ColorReset   = "\033[0m"
	ColorGray    = "\033[90m"
	ColorBlue    = "\033[34m"
	ColorCyan    = "\033[36m"
	ColorGreen   = "\033[32m"
	ColorYellow  = "\033[33m"
	ColorRed     = "\033[31m"
	ColorMagenta = "\033[35m"
	ColorWhite   = "\033[37m"
	// ColorInverse 反显前景与背景，用于 airodump-ng 式的高亮状态栏。
	ColorInverse = "\033[7m"
)

const (
	LevelVerbose = slog.LevelDebug - 4
	LevelDebug   = slog.LevelDebug
	LevelInfo    = slog.LevelInfo
	LevelWarn    = slog.LevelWarn
	LevelError   = slog.LevelError
)

const (
	// Linux 原始套接字参数：AF_PACKET 直接访问链路层，SOCK_RAW 绕过内核协议栈，
	// ETH_P_ALL 表示不过滤以太类型、捕获全部帧。
	AF_PACKET = 17
	SOCK_RAW  = 3
	ETH_P_ALL = 0x0003

	// 802.11 Frame Control：帧控制字为 2 字节小端，低字节依次排列
	// 2 位协议版本、2 位类型、4 位子类型，故掩码落在低字节内。
	FC_TYPE_MASK          = 0x000C // 类型字段位掩码（bit 2-3）
	FC_SUBTYPE_MASK       = 0x00F0 // 子类型字段位掩码（bit 4-7）
	FC_TYPE_MGMT          = 0x0000 // 类型值 0：管理帧
	FC_SUBTYPE_BEACON     = 0x0080 // 子类型 8：信标帧
	FC_SUBTYPE_PROBE_RESP = 0x0050 // 子类型 5：探测响应帧

	// Radiotap it_present 位图（小端）：某位置 1 表示头部数据区存在对应字段。
	// 字段在数据区中按位序号顺序紧密排列，因此每一位对应固定偏移，
	// 解析时必须逐位判断而不能假设字段一定存在。
	RTAP_FLAG_HAS_FLAGS         = 1 << 1  // it_flags：帧收发属性
	RTAP_FLAG_HAS_RATE          = 1 << 2  // 数据速率
	RTAP_FLAG_HAS_CHANNEL       = 1 << 3  // 信道频率与信道标志
	RTAP_FLAG_HAS_DBM_ANTSIGNAL = 1 << 5  // dBm 天线信号强度
	RTAP_FLAG_HAS_DBM_ANTNOISE  = 1 << 6  // dBm 天线噪声强度
	RTAP_FLAG_NS_BITMAP         = 1 << 31 // 位 31（radiotap 扩展位）：置位表示其后还有一段 it_present

	// Information Element 编号：管理帧中每个 IE 采用 TLV 结构，
	// 首字节即元素编号，据此区分 SSID、信道、安全能力等载荷。
	IE_SSID     = 0   // SSID（网络名称）
	IE_DS_PARAM = 3   // DS Parameter Set（2.4GHz 信道号）
	IE_RSN      = 48  // RSN（WPA2/WPA3 安全能力）
	IE_VENDOR   = 221 // 厂商自定义 IE（WPA1 亦承载于此）

	// 密码套件选择器 = OUI(3 字节) + 类型(1 字节)，取值见 802.11 标准。
	CIPHER_WEP  = 0x000FAC01 // WEP-40
	CIPHER_TKIP = 0x000FAC02 // TKIP
	CIPHER_CCMP = 0x000FAC04 // CCMP-128
	CIPHER_GCMP = 0x000FAC08 // GCMP-128

	// AKM（认证密钥管理）套件选择器，同样由 OUI + 类型组成。
	AUTH_SUITE_8021X = 0x000FAC01 // IEEE 802.1X（企业级认证）
	AUTH_SUITE_PSK   = 0x000FAC02 // PSK（个人级预共享密钥）
)

var DeveloperMetadata = model.Developer{
	Id:           nil,
	Name:         "钟智强",
	Organisation: "哪吒网络安全",
	Email:        "johnmelodymel@qq.com",
	Weixin:       "ctkqiang",
	Version:      "v0.0.1",
	ProjectUrl:   "https://github.com/ctkqiang/wifisec.git",
}

// OUI 用于判定安全 IE 的来源：WPA1 走厂商自定义 IE，WPA2/WPA3 走 RSN IE。
// 切片不满足 Go 对常量的要求（只能是基本类型），因此只能声明为变量。
var (
	WPA_OUI = []byte{0x00, 0x50, 0xF2} // Wi-Fi 联盟 WPA1 的 OUI
	RSN_OUI = []byte{0x00, 0x0F, 0xAC} // IEEE 802.11 标准 OUI
)
