// arp.go 构造以太网 ARP 帧（RFC 826）：请求与应答都是 42 字节定长帧。
// 毒化帧的欺骗性只在 ARP 报文内部（sender 协议地址/MAC 任意组合），
// 以太网头的源 MAC 仍取本机真实地址——内核发出的帧本就如此，
// 交换机与对端不会因链路层异常而丢弃。
package ethernet

import (
	"encoding/binary"
	"errors"
	"net"
)

// 以太网帧与 ARP 报文的字段偏移。ARP over Ethernet 固定布局：
// ETH 头 14 字节 + htype/ptype/hlen/plen/oper 8 字节 + 四个地址 20 字节。
const (
	arpFrameLength  = 42
	arpEtherType    = 0x0806
	arpHardwareType = 1      // 以太网
	arpProtocolType = 0x0800 // IPv4
	arpOperRequest  = 1
	arpOperReply    = 2
)

// ARPInfo 只保留「控制台摘要 + 网关识别」要用到的字段；
// 目标 MAC 在请求帧中恒为零，不入结构以免调用方误读。
type ARPInfo struct {
	Opcode    uint16
	SenderIP  net.IP
	SenderMAC net.HardwareAddr
	TargetIP  net.IP
}

// ParseARP 解析一帧 ARP over Ethernet；长度不足或 EtherType 不匹配时返回 false。
// 与 buildArpFrame 共享布局常量，避免两套偏移各走各的而漂移。
func ParseARP(frame []byte) (ARPInfo, bool) {
	if len(frame) < arpFrameLength {
		return ARPInfo{}, false
	}

	if binary.BigEndian.Uint16(frame[12:14]) != arpEtherType {
		return ARPInfo{}, false
	}

	info := ARPInfo{
		Opcode:    binary.BigEndian.Uint16(frame[20:22]),
		SenderMAC: net.HardwareAddr(frame[22:28]),
		SenderIP:  net.IP(frame[28:32]).To4(),
		TargetIP:  net.IP(frame[38:42]).To4(),
	}

	return info, true
}

// BuildArpReply 构造单播 ARP 应答帧：向 targetMAC 声称
// senderIP 由 senderMAC 持有。欺骗帧与恢复帧共用这一个构造器，
// 差异只在调用方传入的 sender 组合是真还是假。
func BuildArpReply(senderIP net.IP, senderMAC net.HardwareAddr, targetIP net.IP, targetMAC net.HardwareAddr) ([]byte, error) {
	return buildArpFrame(arpOperReply, senderIP, senderMAC, targetIP, targetMAC)
}

// BuildArpRequest 构造广播 ARP 请求帧：询问 targetIP 的持有者。
// 收集恢复依据（网关/目标真实 MAC）时用得到，攻击主路径不依赖它。
func BuildArpRequest(senderIP net.IP, senderMAC net.HardwareAddr, targetIP net.IP) ([]byte, error) {
	return buildArpFrame(arpOperRequest, senderIP, senderMAC, targetIP, nil)
}

// buildArpFrame 是请求/应答的公共构造器，oper 决定报文语义；
// 请求帧的目标 MAC 传 nil，按协议约定填全零占位。
func buildArpFrame(oper int, senderIP net.IP, senderMAC net.HardwareAddr, targetIP net.IP, targetMAC net.HardwareAddr) ([]byte, error) {
	senderIP4 := senderIP.To4()
	targetIP4 := targetIP.To4()

	switch {
	case len(senderMAC) != 6:
		return nil, errors.New("发送方 MAC 长度错误，必须为 6 字节")
	case senderIP4 == nil || targetIP4 == nil:
		return nil, errors.New("ARP 仅支持 IPv4 地址")
	case targetMAC != nil && len(targetMAC) != 6:
		return nil, errors.New("目标 MAC 长度错误，必须为 6 字节")
	}

	frame := make([]byte, arpFrameLength)

	// 以太网头：目的 MAC（应答=目标单播，请求=广播）+ 源 MAC + EtherType。
	if targetMAC != nil {
		copy(frame[0:6], targetMAC)
	} else {
		copy(frame[0:6], net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	}
	copy(frame[6:12], senderMAC)
	binary.BigEndian.PutUint16(frame[12:14], arpEtherType)

	// ARP 报文：htype/ptype/hlen/plen/oper 之后依次是四个地址。
	binary.BigEndian.PutUint16(frame[14:16], arpHardwareType)
	binary.BigEndian.PutUint16(frame[16:18], arpProtocolType)
	frame[18] = 6
	frame[19] = 4
	binary.BigEndian.PutUint16(frame[20:22], uint16(oper))
	copy(frame[22:28], senderMAC)
	copy(frame[28:32], senderIP4)

	if targetMAC != nil {
		copy(frame[32:38], targetMAC)
	}
	copy(frame[38:42], targetIP4)

	return frame, nil
}
