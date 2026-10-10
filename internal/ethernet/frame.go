// Package ethernet 只做“够控制台看一眼”的极简帧解析：
// pcap 文件保留的是完整原始帧，这里不追求协议覆盖度，
// 只把 ARP/IPv4/IPv6 上的 TCP/UDP/ICMP 对话归一成 Src → Dst 摘要，
// 让 get_packet 的实时输出接近 Wireshark 列表视图。
package ethernet

import (
	"encoding/binary"
	"fmt"
	"net"
)

// 常见 EtherType，仅覆盖家用网络里会出现的协议。
const (
	etherTypeIPv4     = 0x0800
	etherTypeARP      = 0x0806
	etherTypeVLAN     = 0x8100
	etherTypeIPv6     = 0x86dd
	etherTypeEAPOL    = 0x888e
	etherTypeLLDP     = 0x88cc
	etherTypeFlowCtrl = 0x8808
)

// 网络层协议号（IPv4 protocol / IPv6 next-header）。
const (
	protoICMP   = 1
	protoTCP    = 6
	protoUDP    = 17
	protoICMPv6 = 58
)

// FrameSummary 是一帧面向终端展示的摘要；pcap 写入不依赖这里的任何字段。
type FrameSummary struct {
	Proto  string // 协议标签：TCP / UDP / ARP / ICMP / EAPOL ...
	Src    string // 源端点（IP:端口，无端口协议退化为 IP，再退化为 MAC）
	Dst    string // 目的端点
	Info   string // Wireshark Info 列风格的补充说明，如 ARP who-has / TCP SYN
	Length int    // 实际捕获长度
}

// Summarize 解析一帧；格式畸形时退化为“裸 MAC + EtherType”摘要而不是报错，
// 抓包场景下任何一帧都不应因为解析器而中断整个会话。
func Summarize(frame []byte) FrameSummary {
	summary := FrameSummary{Length: len(frame)}
	if len(frame) < 14 {
		summary.Proto = "TRUNC"
		summary.Info = fmt.Sprintf("帧长 %d 小于以太网头 14 字节", len(frame))

		return summary
	}

	srcMAC := net.HardwareAddr(frame[6:12]).String()
	dstMAC := net.HardwareAddr(frame[0:6]).String()

	offset, etherType := decodeVLAN(frame)

	switch etherType {
	case etherTypeARP:
		fillARP(&summary, frame)
	case etherTypeIPv4:
		fillIPv4(&summary, frame, offset)
	case etherTypeIPv6:
		fillIPv6(&summary, frame, offset)
	case etherTypeEAPOL:
		summary.Proto = "EAPOL"
		summary.Src, summary.Dst = srcMAC, dstMAC
		summary.Info = "802.1X 认证帧（握手期间出现）"
	case etherTypeLLDP:
		summary.Proto = "LLDP"
		summary.Src, summary.Dst = srcMAC, dstMAC
		summary.Info = "链路层发现协议"
	case etherTypeFlowCtrl:
		summary.Proto = "PAUSE"
		summary.Src, summary.Dst = srcMAC, dstMAC
		summary.Info = "802.3x 流控帧"
	default:
		summary.Proto = fmt.Sprintf("0x%04x", etherType)
		summary.Src, summary.Dst = srcMAC, dstMAC
		summary.Info = "未解析的 EtherType"
	}

	return summary
}

// decodeVLAN 跳过可能存在的单层 802.1Q 标签，返回网络层偏移与真实 EtherType。
func decodeVLAN(frame []byte) (int, uint16) {
	etherType := binary.BigEndian.Uint16(frame[12:14])
	if etherType == etherTypeVLAN && len(frame) >= 18 {
		return 16, binary.BigEndian.Uint16(frame[16:18])
	}

	return 14, etherType
}

// fillARP 解析 28 字节 ARP 报文，输出 nmap/wireshark 风格的 who-has/is-at。
func fillARP(summary *FrameSummary, frame []byte) {
	summary.Proto = "ARP"
	if len(frame) < 42 {
		summary.Info = "ARP 帧不完整"

		return
	}

	opcode := binary.BigEndian.Uint16(frame[20:22])
	senderIP := net.IP(frame[28:32]).String()
	targetIP := net.IP(frame[38:42]).String()

	switch opcode {
	case 1:
		summary.Src, summary.Dst = senderIP, targetIP
		summary.Info = fmt.Sprintf("who-has %s tell %s", targetIP, senderIP)
	case 2:
		summary.Src, summary.Dst = senderIP, targetIP
		summary.Info = fmt.Sprintf("reply %s is-at %s", senderIP, net.HardwareAddr(frame[22:28]).String())
	default:
		summary.Src, summary.Dst = senderIP, targetIP
		summary.Info = fmt.Sprintf("opcode=%d", opcode)
	}
}

// fillIPv4 解析 IPv4 头并按协议号分发到 TCP/UDP/ICMP。
func fillIPv4(summary *FrameSummary, frame []byte, offset int) {
	if len(frame) < offset+20 {
		summary.Proto = "IPv4"
		summary.Info = "IPv4 头不完整"

		return
	}

	headerLen := int(frame[offset]&0x0f) * 4
	if headerLen < 20 || len(frame) < offset+headerLen {
		summary.Proto = "IPv4"
		summary.Info = "IPv4 IHL 字段越界"

		return
	}

	srcIP := net.IP(frame[offset+12 : offset+16]).String()
	dstIP := net.IP(frame[offset+16 : offset+20]).String()
	payload := frame[offset+headerLen:]

	switch frame[offset+9] {
	case protoTCP:
		fillTCP(summary, srcIP, dstIP, payload)
	case protoUDP:
		fillUDP(summary, srcIP, dstIP, payload)
	case protoICMP:
		fillICMP(summary, srcIP, dstIP, payload, "ICMP")
	default:
		summary.Proto = "IPv4"
		summary.Src, summary.Dst = srcIP, dstIP
		summary.Info = fmt.Sprintf("protocol=%d", frame[offset+9])
	}
}

// fillIPv6 只取固定 40 字节头里的 next-header 与地址，扩展头部不做链式遍历。
func fillIPv6(summary *FrameSummary, frame []byte, offset int) {
	if len(frame) < offset+40 {
		summary.Proto = "IPv6"
		summary.Info = "IPv6 头不完整"

		return
	}

	srcIP := net.IP(frame[offset+8 : offset+24]).String()
	dstIP := net.IP(frame[offset+24 : offset+40]).String()
	payload := frame[offset+40:]

	switch frame[offset+6] {
	case protoTCP:
		fillTCP(summary, srcIP, dstIP, payload)
	case protoUDP:
		fillUDP(summary, srcIP, dstIP, payload)
	case protoICMPv6:
		fillICMP(summary, srcIP, dstIP, payload, "ICMP6")
	default:
		summary.Proto = "IPv6"
		summary.Src, summary.Dst = srcIP, dstIP
		summary.Info = fmt.Sprintf("next-header=%d", frame[offset+6])
	}
}

// fillTCP 提取端口与标志位组合（SYN/ACK/FIN/RST/PSH），扫描流量最直观。
func fillTCP(summary *FrameSummary, srcIP, dstIP string, payload []byte) {
	summary.Proto = "TCP"
	if len(payload) < 20 {
		summary.Src, summary.Dst = srcIP, dstIP
		summary.Info = "TCP 头不完整"

		return
	}

	srcPort := binary.BigEndian.Uint16(payload[0:2])
	dstPort := binary.BigEndian.Uint16(payload[2:4])
	flags := payload[13]

	summary.Src = fmt.Sprintf("%s:%d", srcIP, srcPort)
	summary.Dst = fmt.Sprintf("%s:%d", dstIP, dstPort)

	var set []string
	if flags&0x02 != 0 {
		set = append(set, "SYN")
	}
	if flags&0x10 != 0 {
		set = append(set, "ACK")
	}
	if flags&0x01 != 0 {
		set = append(set, "FIN")
	}
	if flags&0x04 != 0 {
		set = append(set, "RST")
	}
	if flags&0x08 != 0 {
		set = append(set, "PSH")
	}
	if flags&0x20 != 0 {
		set = append(set, "URG")
	}

	if len(set) > 0 {
		summary.Info = joinFlags(set)
	}
}

// fillUDP 只提取端口；应用层协议识别交给 Wireshark。
func fillUDP(summary *FrameSummary, srcIP, dstIP string, payload []byte) {
	summary.Proto = "UDP"
	if len(payload) < 8 {
		summary.Src, summary.Dst = srcIP, dstIP
		summary.Info = "UDP 头不完整"

		return
	}

	summary.Src = fmt.Sprintf("%s:%d", srcIP, binary.BigEndian.Uint16(payload[0:2]))
	summary.Dst = fmt.Sprintf("%s:%d", dstIP, binary.BigEndian.Uint16(payload[2:4]))
}

// fillICMP 映射排查时最常用的类型码。
func fillICMP(summary *FrameSummary, srcIP, dstIP string, payload []byte, proto string) {
	summary.Proto = proto
	summary.Src, summary.Dst = srcIP, dstIP

	if len(payload) == 0 {
		return
	}

	typeNames := map[byte]string{
		0:   "echo reply",
		3:   "destination unreachable",
		8:   "echo request",
		11:  "time exceeded",
		128: "echo request",
		129: "echo reply",
		135: "neighbor solicitation",
		136: "neighbor advertisement",
	}

	if name, ok := typeNames[payload[0]]; ok {
		summary.Info = fmt.Sprintf("type %d (%s)", payload[0], name)
	} else {
		summary.Info = fmt.Sprintf("type %d", payload[0])
	}
}

// joinFlags 手工拼接避免为两个元素引入 strings 包的通用 Join 语义混淆。
func joinFlags(flags []string) string {
	result := ""
	for index, flag := range flags {
		if index > 0 {
			result += ","
		}

		result += flag
	}

	return result
}
