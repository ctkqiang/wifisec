// Package eapol 解析 EAPOL-Key 帧、把 4-way 握手的 M1-M4 配成对，
// 并将 PMKID 与握手对归一化为统一的离线破解候选（Candidate），
// 供 extract / get_packet 输出 hashcat 22000 攻击行。
package eapol

import (
	"encoding/binary"
	"fmt"
)

// EAPOL-Key 包体布局（自 EAPOL version 字节起，多字节字段全为大端）：
//
//	[0]     Version（1 = 802.1X-2001, 2 = 802.1X-2004）
//	[1]     Packet Type（3 = EAPOL-Key）
//	[2-3]   Body Length
//	[4]     Key Descriptor Type（2 = RSN, 254 = WPA，不同实现取值不一，不做严格校验）
//	[5-6]   Key Information
//	[7-8]   Key Length
//	[9-16]  Replay Counter
//	[17-48] Key Nonce（M1/M3 = ANonce，M2/M4 = SNonce）
//	[49-64] Key IV
//	[65-72] Key RSC
//	[73-80] Key ID
//	[81-96] Key MIC
//	[97-98] Key Data Length
//	[99..]  Key Data（RSN IE / GTK KDE 等）
const (
	keyNonceOffset   = 17
	keyMICOffset     = 81
	keyDataLenOffset = 97
	keyDataOffset    = 99

	// eapolTypeKey 是 EAPOL Packet Type 中的 EAPOL-Key 取值。
	eapolTypeKey = 3
)

// Key Information 位域（大端 u16）：
const (
	// keyInfoVerMask 是描述符版本位（bits0-2：1=HMAC-MD5, 2=HMAC-SHA1, 3=CMAC）。
	keyInfoVerMask = 0x0007
	// keyInfoPairwiseBit 置位表示成对密钥握手（4-way），清零为组密钥握手。
	keyInfoPairwiseBit = 1 << 3
	// keyInfoACKBit 置位表示要求对方应答——只有 AP 发出的 M1/M3 会置位。
	keyInfoACKBit = 1 << 7
	// keyInfoMICBit 置位表示携带 MIC（M2-M4）。
	keyInfoMICBit = 1 << 8
	// keyInfoSecureBit 置位表示密钥安装完成——只有 M3 置位。
	keyInfoSecureBit = 1 << 9
)

// Message 是 4-way 握手消息的类别判定结果。
type Message int

const (
	MessageNone Message = iota
	MessageM1
	MessageM2
	MessageM3
	MessageM4
)

// KeyFrame 是一条 EAPOL-Key 消息的解析结果。
type KeyFrame struct {
	Version       byte
	Descriptor    byte
	KeyInfo       uint16
	KeyLength     uint16
	ReplayCounter uint64
	Nonce         [32]byte
	MIC           [16]byte
	KeyData       []byte // 已按 Key Data Length 裁剪
	Raw           []byte // 完整 EAPOL 包体（version 起至包尾）
}

// KeyVer 返回描述符版本（1=MD5 / 2=SHA1 / 3=CMAC-AES），
// hashcat 据此选择 MIC 计算路径，存行时无需额外字段。
func (k *KeyFrame) KeyVer() int {
	return int(k.KeyInfo & keyInfoVerMask)
}

// IsPairwise 报告是否成对密钥握手。
func (k *KeyFrame) IsPairwise() bool {
	return k.KeyInfo&keyInfoPairwiseBit != 0
}

// Message 按位域特征判定消息类别。判定次序有讲究：
// M1 的特征是 ACK 置位且无 MIC（唯一例外，先判避免与 M2/M4 混淆）；
// M2 与 M4 共享"MIC 且非 Secure"，用 SNonce 是否全零区分——
// M4 是 STA 的"确认收到 M3"应答，协议规定其 SNonce 重置为零。
func (k *KeyFrame) Message() Message {
	if !k.IsPairwise() {
		// 组密钥握手（GTK update）与 4-way 无关，不参与配对。
		return MessageNone
	}

	hasACK := k.KeyInfo&keyInfoACKBit != 0
	hasMIC := k.KeyInfo&keyInfoMICBit != 0
	secure := k.KeyInfo&keyInfoSecureBit != 0
	nonceZero := nonceIsZero(&k.Nonce)

	switch {
	case hasACK && !hasMIC:
		return MessageM1
	case hasMIC && secure:
		return MessageM3
	case hasMIC && !secure && !nonceZero:
		return MessageM2
	case hasMIC && !secure && nonceZero:
		return MessageM4
	default:
		return MessageNone
	}
}

// ParseKey 解析 EAPOL 包体（自 version 字节起，即 LLC/SNAP 剥离后
// EtherType 0x888E 之后的字节）。
//
// Key Data 长度以字段值为准并容忍两种偏差：驱动附加的尾部 padding
// 按声明长度裁剪；声明超出实际包体（畸形）按实际收下——配对依赖的
// Replay Counter/Nonce/MIC 都在固定偏移，Key Data 缺一截不影响判定。
func ParseKey(payload []byte) (*KeyFrame, error) {
	if len(payload) < keyDataOffset {
		return nil, fmt.Errorf("EAPOL 包体仅 %d 字节，不足 Key 固定字段所需的 %d 字节", len(payload), keyDataOffset)
	}
	if payload[1] != eapolTypeKey {
		return nil, fmt.Errorf("EAPOL Packet Type = %d，非 EAPOL-Key(3)", payload[1])
	}

	frame := &KeyFrame{
		Version:       payload[0],
		Descriptor:    payload[4],
		KeyInfo:       binary.BigEndian.Uint16(payload[5:7]),
		KeyLength:     binary.BigEndian.Uint16(payload[7:9]),
		ReplayCounter: binary.BigEndian.Uint64(payload[9:17]),
		Raw:           append([]byte(nil), payload...),
	}
	copy(frame.Nonce[:], payload[keyNonceOffset:keyNonceOffset+32])
	copy(frame.MIC[:], payload[keyMICOffset:keyMICOffset+16])

	dataLen := int(binary.BigEndian.Uint16(payload[keyDataLenOffset : keyDataLenOffset+2]))
	if available := len(frame.Raw) - keyDataOffset; dataLen > available {
		dataLen = available
	}
	frame.KeyData = frame.Raw[keyDataOffset : keyDataOffset+dataLen]

	return frame, nil
}

// nonceIsZero 报告 32 字节 nonce 是否全零（M4 判定依据）。
func nonceIsZero(nonce *[32]byte) bool {
	for _, b := range nonce {
		if b != 0 {
			return false
		}
	}

	return true
}
