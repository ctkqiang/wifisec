// Package rsnie 解析 802.11 RSN 信息元素（RSN IE，元素编号 0x30）。
//
// RSN IE 承载 WPA2/WPA3 的加密能力声明：成对加密套件、认证密钥管理
// （AKM）套件、PMF 能力与 PMKID 列表。PMKID 攻击的两个数据源——
// 关联响应的信息元素区与 EAPOL M1 的 key data——都以原始 RSN IE
// 载荷字节出现，本包负责把它们安全地解开。
//
// 解析采用游标步进（伪状态机）：每读一个字段前先做剩余长度检查，
// 禁止按固定下标取值——各字段均为变长（cipher/PMKID 数量不定），
// 硬编码偏移在畸形帧下必然越界。任何截断/数量不符都以错误收场，
// 绝不返回半个解析结果。
package rsnie

import (
	"fmt"
)

// 标准 OUI 下的 AKM 类型编号（802.11-2016 表 9-135）。
const (
	// AKMType8021X：企业级 802.1X/EAP，PMK 由 EAP 会话协商派生，
	// 离线拿到 PMKID 也无法用 PSK 字典验证。
	AKMType8021X byte = 1

	// AKMTypePSK：个人级预共享密钥，PMK = PBKDF2(密码, SSID, 4096, 32)。
	// 这是 PMKID 攻击的主目标。
	AKMTypePSK byte = 2

	// AKMTypeFTPSK：802.11r 快速切换 + PSK，PMKID 走 PMKR0Name 派生路径，
	// 与 4-way 的 PMKID 不同源，22000 格式无法使用。
	AKMTypeFTPSK byte = 4

	// AKMTypePSKSHA256：PSK + SHA-256 AKM（PMF 强制场景），PMK 派生
	// 方式与普通 PSK 相同，hashcat 22000 同样支持。
	AKMTypePSKSHA256 byte = 6

	// AKMTypeSAE：WPA3-SAE，PMK 由 SAE 握手的随机数参与派生，
	// 密码不直接决定 PMK，离线字典攻击不可行。
	AKMTypeSAE byte = 8
)

// standardOUI 是 802.11 标准套件 OUI 00-0F-AC。
// 所有标准加密/AKM 套件共享该 OUI，厂商私有套件（如 00-50-F2 微软 WPA）
// 对 PMKID 离线破解一律不适用。
var standardOUI = [3]byte{0x00, 0x0F, 0xAC}

// Cipher 是加密套件选择器：3 字节 OUI + 1 字节类型。
type Cipher struct {
	OUI  [3]byte
	Type byte
}

// AKM 是认证密钥管理套件选择器，决定 PMK 的派生方式——
// 也就决定了离线破解是否可行。
type AKM struct {
	OUI  [3]byte
	Type byte
}

// Capabilities 是 RSN 能力位域（2 字节，LSB 为 bit0）。
type Capabilities struct {
	Raw uint16
}

// PMKIDEntry 是单个 PMKID：HMAC-SHA1(PMK, "PMK Name" ‖ MAC_AP ‖ MAC_STA)
// 的 16 字节截断。对 PSK 网络，PMK 可由密码直接算出，因此拿到
// PMKID + 双方 MAC 即可离线验证候选密码。
type PMKIDEntry [16]byte

// RSNInfo 是 RSN IE 载荷的完整解析结果。
type RSNInfo struct {
	Version         uint16
	GroupCipher     Cipher
	PairwiseCiphers []Cipher
	AKMSuites       []AKM
	Capabilities    Capabilities
	PMKIDs          []PMKIDEntry // 缺省（字段不存在）或数量为 0 时为 nil
}

// parser 是 RSN IE 的游标步进器：pos 永远指向下一个待读字段。
type parser struct {
	buf []byte
	pos int
}

// String 返回 "00-0F-AC:04"（CCMP-128）形式的标准记法。
func (c Cipher) String() string {
	return fmt.Sprintf("%02x-%02x-%02x:%02x", c.OUI[0], c.OUI[1], c.OUI[2], c.Type)
}

// String 返回 "00-0F-AC:02"（PSK）形式的标准记法。
func (a AKM) String() string {
	return fmt.Sprintf("%02x-%02x-%02x:%02x", a.OUI[0], a.OUI[1], a.OUI[2], a.Type)
}

// IsStandard 报告是否 802.11 标准 OUI；厂商私有 AKM 一律不可用。
func (a AKM) IsStandard() bool {
	return a.OUI == standardOUI
}

// IsPSK 报告是否 PSK 家族（PSK / PSK-SHA256）。
// 仅此两类可以由密码直接推出 PMK（PBKDF2），离线字典攻击有效。
func (a AKM) IsPSK() bool {
	return a.IsStandard() && (a.Type == AKMTypePSK || a.Type == AKMTypePSKSHA256)
}

// PreAuth 报告 AP 是否支持预认证（bit0）。
func (c Capabilities) PreAuth() bool { return c.Raw&0x0001 != 0 }

// NoPairwise 报告 AP 是否声明不支持成对密钥（bit1，罕见且多为畸形）。
func (c Capabilities) NoPairwise() bool { return c.Raw&0x0002 != 0 }

// MFPCapable 报告 AP 是否支持受保护管理帧（bit6）。
func (c Capabilities) MFPCapable() bool { return c.Raw&0x0040 != 0 }

// MFPRequired 报告 AP 是否强制受保护管理帧（bit7）。
// 强制 PMF 的网络广播 deauth 无效，deauth → 抓握手的传统链路在此失效，
// 这正是 PMKID 路径的价值所在。
func (c Capabilities) MFPRequired() bool { return c.Raw&0x0080 != 0 }

// HasPMKID 报告 IE 是否携带至少一个 PMKID。
func (r *RSNInfo) HasPMKID() bool {
	return len(r.PMKIDs) > 0
}

// IsPSK 报告任一 AKM 属于 PSK 家族。
// WPA/WPA2 混合模式 AP 常同时声明 802.1X 与 PSK 两个 AKM，
// 客户端可任选路径，PMKID 对 PSK 路径依然有效。
func (r *RSNInfo) IsPSK() bool {
	for _, akm := range r.AKMSuites {
		if akm.IsPSK() {
			return true
		}
	}

	return false
}

// AKMSummary 生成 AKM 类型的人类可读判定，供错误提示统一复用，
// 避免各调用点各自硬编码文案。
func (r *RSNInfo) AKMSummary() string {
	for _, akm := range r.AKMSuites {
		switch {
		case !akm.IsStandard():
			return "厂商私有 AKM"
		case akm.Type == AKMTypeSAE:
			return "WPA3-SAE"
		case akm.Type == AKMType8021X:
			return "802.1X/Enterprise"
		case akm.IsPSK():
			return "WPA2-PSK"
		case akm.Type == AKMTypeFTPSK:
			return "802.11r FT-PSK"
		}
	}

	return "未知 AKM"
}

// ParseRSNIE 解析 RSN IE 载荷（元素编号 0x30 的 TLV 载荷部分，
// 自 Version 字段起，不含 id/length 头）。
//
// 布局（802.11-2016 §9.4.2.25，全部字段小端）：
//
//	[0-1]   Version（必须为 1）
//	[2-5]   Group Cipher Suite（OUI+type，4 字节）
//	[6-7]   Pairwise Cipher Suite Count → N×4 字节
//	[..]    AKM Suite Count → N×4 字节      ← 必须 PSK 才有离线破解价值
//	[..]    RSN Capabilities（2 字节）
//	[..]    PMKID Count（2 字节，字段可整体省略）→ N×16 字节
//	[..]    （802.11r 的 GTK/IGTK 等扩展，与本攻击无关，忽略）
func ParseRSNIE(payload []byte) (*RSNInfo, error) {
	p := &parser{buf: payload}

	info := &RSNInfo{}

	// Version：RSN（WPA2/WPA3）固定为 1。其它值说明这不是 RSN IE
	// 而是被误传入的厂商 IE（如 WPA IE 的 payload 同样以 u16 开头）。
	version, err := p.u16("version")
	if err != nil {
		return nil, err
	}
	if version != 1 {
		return nil, fmt.Errorf("RSN IE version 为 %d 而非 1，疑似非 RSN 信息元素", version)
	}
	info.Version = version

	group, err := p.cipher("组加密套件")
	if err != nil {
		return nil, err
	}
	info.GroupCipher = group

	pairwise, err := p.cipherList("成对加密套件")
	if err != nil {
		return nil, err
	}
	info.PairwiseCiphers = pairwise

	akms, err := p.akmList("AKM 套件")
	if err != nil {
		return nil, err
	}
	info.AKMSuites = akms

	caps, err := p.u16("RSN capabilities")
	if err != nil {
		return nil, err
	}
	info.Capabilities = Capabilities{Raw: caps}

	// PMKID 字段可整体省略（802.11i 允许最小 RSN IE 止于 capabilities），
	// 此处缺字节不是错误，视为无 PMKID。
	if p.remaining() < 2 {
		return info, nil
	}
	pmkidCount := int(p.u16raw())

	// 数量与实际字节数精确核对：count 虚高说明 IE 被截断或伪造，
	// 按总量算出必然越界，直接拒绝而不是读到哪算哪。
	if pmkidCount*16 > p.remaining() {
		return nil, fmt.Errorf("PMKID count %d 与剩余 %d 字节不符（IE 截断或伪造）", pmkidCount, p.remaining())
	}

	info.PMKIDs = make([]PMKIDEntry, pmkidCount)
	for i := 0; i < pmkidCount; i++ {
		copy(info.PMKIDs[i][:], p.buf[p.pos:p.pos+16])
		p.pos += 16
	}

	// 尾部可能还有 802.11r GTK/IGTK 等扩展字段，PMKID 攻击不消费，
	// 静默忽略——完整性已由上面各步的边界检查保证。

	return info, nil
}

// need 检查剩余字节是否足够读出 n 字节，不足时报出字段名，
// 让调用方能区分"死在哪个字段"。
func (p *parser) need(n int, what string) error {
	if p.pos+n > len(p.buf) {
		return fmt.Errorf("RSN IE 在 %s 处截断：需要 %d 字节，仅剩 %d", what, n, len(p.buf)-p.pos)
	}

	return nil
}

// remaining 返回尚未消费的字节数。
func (p *parser) remaining() int {
	return len(p.buf) - p.pos
}

// u16 读取一个小端 u16。
func (p *parser) u16(what string) (uint16, error) {
	if err := p.need(2, what); err != nil {
		return 0, err
	}

	return p.u16raw(), nil
}

// u16raw 在调用方已做长度检查后直接读取。
func (p *parser) u16raw() uint16 {
	value := uint16(p.buf[p.pos]) | uint16(p.buf[p.pos+1])<<8
	p.pos += 2

	return value
}

// cipher 读取 4 字节套件选择器。
func (p *parser) cipher(what string) (Cipher, error) {
	if err := p.need(4, what); err != nil {
		return Cipher{}, err
	}

	c := Cipher{Type: p.buf[p.pos+3]}
	copy(c.OUI[:], p.buf[p.pos:p.pos+3])
	p.pos += 4

	return c, nil
}

// cipherList 读取"u16 数量 + N×加密套件"序列，数量与剩余字节数严格核对。
// count 阶段的核对让畸形大数在分配切片前就被拒绝，无需魔数上限。
func (p *parser) cipherList(what string) ([]Cipher, error) {
	count, err := p.u16(what + "数量")
	if err != nil {
		return nil, err
	}

	if int(count)*4 > p.remaining() {
		return nil, fmt.Errorf("%s数量 %d 与剩余 %d 字节不符（IE 截断或伪造）", what, count, p.remaining())
	}

	list := make([]Cipher, 0, count)
	for i := 0; i < int(count); i++ {
		suite, err := p.cipher(fmt.Sprintf("%s #%d", what, i))
		if err != nil {
			return nil, err
		}

		list = append(list, suite)
	}

	return list, nil
}

// akmList 读取"u16 数量 + N×AKM 套件"序列，与 cipherList 同构但产出
// AKM 类型——AKM 决定 PMK 派生方式，语义上不能与加密套件混用。
func (p *parser) akmList(what string) ([]AKM, error) {
	count, err := p.u16(what + "数量")
	if err != nil {
		return nil, err
	}

	if int(count)*4 > p.remaining() {
		return nil, fmt.Errorf("%s数量 %d 与剩余 %d 字节不符（IE 截断或伪造）", what, count, p.remaining())
	}

	list := make([]AKM, 0, count)
	for i := 0; i < int(count); i++ {
		if err := p.need(4, fmt.Sprintf("%s #%d", what, i)); err != nil {
			return nil, err
		}

		akm := AKM{Type: p.buf[p.pos+3]}
		copy(akm.OUI[:], p.buf[p.pos:p.pos+3])
		p.pos += 4

		list = append(list, akm)
	}

	return list, nil
}
