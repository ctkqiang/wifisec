// analyzer.go 把 EAPOL M1-M4 与 PMKID 归一化为统一的离线破解候选。
//
// 配对策略（hashcat wiki "messagepair" 的四种合法组合）：
//
//	优先级 0  M1M2 —— KCK 直接由 ANonce(M1)+SNonce(M2) 推出，最常见
//	优先级 2  M2M3 —— M2 先于 M1 到达时的后备组合
//	优先级 5  M3M4 —— PMF(WPA3) 网络的常见组合（M2 被加密保护时缺失）
//	优先级 1  M1M4 —— 无 M3 的后备组合
//
// 同一握手可能产出多个候选（如 pair 0 与 pair 5），全部交给调用方：
// hashcat 对多行重复 hash 自行去重，多一条候选就多一分命中概率。
package eapol

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/ctkqiang/wifisec/internal/ieee80211"
	"github.com/ctkqiang/wifisec/internal/rsnie"
)

// pcap DLT 值（与 pcapfile/capture 层一致，包内自带避免依赖平台层）。
const (
	LinkTypeEthernet       = 1
	LinkTypeIEEE80211      = 105
	LinkTypeIEEE80211Radio = 127
)

// pendingLimit 是单类握手消息的待配池上限：正常空中同一 AP/STA 对的
// 未配对消息不会超过几条（重传在内），超出即视为噪声洪泛，淘汰最旧。
const pendingLimit = 256

// Kind 区分候选来源：PMKID（主动关联产出）或 EAPOL 握手对。
type Kind int

const (
	KindEAPOL Kind = iota
	KindPMKID
)

// Candidate 是一条可离线破解的中间结果，同时承载 PMKID 与
// EAPOL 握手对两种形态，22000/16800 格式化器只消费这一个结构。
type Candidate struct {
	Kind        Kind
	MessagePair byte     // hashcat messagepair 位域
	PMKID       [16]byte // KindPMKID 有效
	MIC         [16]byte // KindEAPOL 有效：应答帧的真实 MIC
	MACAP       string   // 小写无冒号 hex（hash 行 MAC 记法）
	MACSTA      string
	ESSID       string
	ESSIDKnown  bool // false = 隐藏/未知，格式化时拒绝产出（空 salt 无意义）
	ANonce      [32]byte
	SNonce      [32]byte
	EAPOLFrame  []byte // 存入 hash 行的应答帧包体（格式化时清零 MIC）
	Channel     int    // 0 = 未知（以太网视角/无 radiotap）
}

// keyPool 是带 FIFO 淘汰的待配消息池：map 保查找、order 保淘汰次序。
type keyPool struct {
	order []string
	items map[string]*KeyFrame
}

func newKeyPool() *keyPool {
	return &keyPool{items: make(map[string]*KeyFrame)}
}

// put 入池；超限时淘汰最旧一条，保证内存有界。
func (p *keyPool) put(key string, frame *KeyFrame) {
	if existing, ok := p.items[key]; ok {
		_ = existing // 同键重传直接覆盖，次序不变
	} else {
		p.order = append(p.order, key)
	}

	p.items[key] = frame

	for len(p.order) > pendingLimit {
		oldest := p.order[0]
		p.order = p.order[1:]
		delete(p.items, oldest)
	}
}

// get 查找；不存在返回 nil。
func (p *keyPool) get(key string) *KeyFrame {
	return p.items[key]
}

// Stats 是 Analyzer 的累计统计，供 extract 摘要与 get_packet 进度打印。
type Stats struct {
	EAPOLFrames     int
	M1Count         int
	M2Count         int
	M3Count         int
	M4Count         int
	Pairs           int
	PMKIDCandidates int
}

// Analyzer 把原始帧流转成离线破解候选。
// 并发安全：抓包 goroutine 调 Feed，主线程调 SetESSID/Stats。
type Analyzer struct {
	mu       sync.Mutex
	linkType int
	essids   map[string]string // 空中学到的 BSSID → ESSID
	explicit map[string]string // 用户显式指定（优先于空中学习）
	m1s      *keyPool
	m2s      *keyPool
	m3s      *keyPool
	reported map[string]bool
	stats    Stats
}

// NewAnalyzer 按捕获链路类型建分析器：DLT 1（连接态以太网）或
// DLT 105/127（802.11 视角），其余链路类型按裸 802.11 处理。
func NewAnalyzer(linkType int) *Analyzer {
	return &Analyzer{
		linkType: linkType,
		essids:   make(map[string]string),
		explicit: make(map[string]string),
		m1s:      newKeyPool(),
		m2s:      newKeyPool(),
		m3s:      newKeyPool(),
		reported: make(map[string]bool),
	}
}

// SetESSID 显式提供 BSSID 对应的 ESSID。连接态以太网抓包看不到信标，
// 用户自己的网络名不属机密，显式给出才能产出可解的 hash 行。
func (a *Analyzer) SetESSID(bssid, ssid string) {
	if bssid = normalizeMAC(bssid); bssid != "" && ssid != "" {
		a.mu.Lock()
		defer a.mu.Unlock()

		a.explicit[bssid] = ssid
	}
}

// Stats 返回累计统计快照。
func (a *Analyzer) Stats() Stats {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.stats
}

// Feed 喂入一帧原始捕获数据（含 radiotap 头，按链路类型分诊），
// 返回本帧新产生的候选（多数帧返回空切片）。
func (a *Analyzer) Feed(frame []byte) []Candidate {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.linkType == LinkTypeEthernet {
		return a.feedEthernet(frame)
	}

	return a.feed80211(frame)
}

// feed80211 处理 802.11 视角帧：先按管理帧分流（信标学 SSID、
// 关联响应产 PMKID），再按数据帧走 EAPOL 配对。
func (a *Analyzer) feed80211(frame []byte) []Candidate {
	body := frame
	if length, ok := ieee80211.RadioTapLen(frame); ok {
		body = frame[length:]
	}

	channel := 0
	if a.linkType == LinkTypeIEEE80211Radio {
		if parsed, ok := ieee80211.ParseRadiotapChannel(frame); ok {
			channel = parsed
		}
	}

	if info, err := ieee80211.ParseManagement(body); err == nil {
		switch info.Subtype {
		case ieee80211.SubtypeBeacon, ieee80211.SubtypeProbeResp:
			// 空 SSID 即隐藏网络，不记录：宁缺毋滥，避免学错映射。
			if info.SSID != "" && len(info.BSSID) == 6 {
				a.essids[normalizeMAC(info.BSSID.String())] = info.SSID
			}
			return nil
		case ieee80211.SubtypeAssocResp:
			return a.assocRespCandidates(body, channel)
		}

		return nil
	}

	dataInfo, err := ieee80211.ParseData(body)
	if err != nil || dataInfo.EtherType != ieee80211.EtherTypeEAPOL {
		return nil
	}

	return a.feedEAPOL(dataInfo, channel)
}

// feedEthernet 处理连接态以太网视角（managed 模式网卡抓的 DLT 1）：
// EAPOL 直接走 EtherType 0x888E，无 radiotap（信道未知）、无信标
// （ESSID 依赖 SetESSID）。dst/src 与 802.11 的 addr1/addr2 同义。
func (a *Analyzer) feedEthernet(frame []byte) []Candidate {
	if len(frame) < 14 {
		return nil
	}

	if etherType := binary.BigEndian.Uint16(frame[12:14]); etherType != ieee80211.EtherTypeEAPOL {
		return nil
	}

	info := ieee80211.DataFrameInfo{
		Receiver:    net.HardwareAddr(append([]byte(nil), frame[0:6]...)),
		Transmitter: net.HardwareAddr(append([]byte(nil), frame[6:12]...)),
		Payload:     frame[14:],
	}

	return a.feedEAPOL(info, 0)
}

// feedEAPOL 是配对引擎主体：判定消息类别 → 确定角色 → 池化/配对。
func (a *Analyzer) feedEAPOL(info ieee80211.DataFrameInfo, channel int) []Candidate {
	keyFrame, err := ParseKey(info.Payload)
	if err != nil {
		return nil
	}

	message := keyFrame.Message()
	if message == MessageNone {
		return nil
	}

	a.stats.EAPOLFrames++
	switch message {
	case MessageM1:
		a.stats.M1Count++
	case MessageM2:
		a.stats.M2Count++
	case MessageM3:
		a.stats.M3Count++
	case MessageM4:
		a.stats.M4Count++
	}

	// 802.11 恒定 addr2 = 发送方（TA）。M1/M3 只由 AP 发出、
	// M2/M4 只由 STA 发出，据此确定角色而不依赖帧方向位。
	var ap, sta string
	if message == MessageM1 || message == MessageM3 {
		ap, sta = macOf(info.Transmitter), macOf(info.Receiver)
	} else {
		ap, sta = macOf(info.Receiver), macOf(info.Transmitter)
	}

	pair := ap + "|" + sta
	var candidates []Candidate

	// M1 的 Key Data 携带 AP 的 RSN IE：PMF 网络的 PMKID 多从这里出现，
	// 与关联响应路径互补。
	if message == MessageM1 && len(keyFrame.KeyData) > 0 {
		if payload, ok := ieee80211.FindElementInIEs(keyFrame.KeyData, ieee80211.ElementRSN); ok {
			if rsn, parseErr := rsnie.ParseRSNIE(payload); parseErr == nil && rsn.HasPMKID() {
				candidates = append(candidates, a.pmkidCandidates(ap, sta, rsn, channel)...)
			}
		}
	}

	// 应答帧（STA 帧）的 Replay Counter 不得小于请求帧（AP 帧）——
	// 乱序重传/跨握手的错配在此拦截。
	build := func(messagePair byte, apFrame, staFrame *KeyFrame) {
		candidate, ok := buildEAPOLCandidate(messagePair, apFrame, staFrame, ap, sta, channel, a.essidFor(ap))
		if !ok {
			return
		}
		if a.markReported("eapol", ap, sta, hex.EncodeToString(candidate.MIC[:])) {
			candidates = append(candidates, candidate)
			a.stats.Pairs++
		}
	}

	switch message {
	case MessageM1:
		a.m1s.put(pair, keyFrame)
	case MessageM2:
		// M1M2 优先；无 M1 时池化等 M3 到来组 M2M3。
		if m1 := a.m1s.get(pair); m1 != nil {
			build(MessagePairM1M2, m1, keyFrame)
		} else {
			a.m2s.put(pair, keyFrame)
		}
	case MessageM3:
		// M2 先到（M1 缺失）时由 M3 补配：ANonce 取 M3（与 M1 相同）。
		if m2 := a.m2s.get(pair); m2 != nil {
			build(MessagePairM2M3, keyFrame, m2)
		} else {
			a.m3s.put(pair, keyFrame)
		}
	case MessageM4:
		// M4 优先配 M3（KCK 已就绪的常规后备），退化配 M1。
		if m3 := a.m3s.get(pair); m3 != nil {
			build(MessagePairM3M4, m3, keyFrame)
		} else if m1 := a.m1s.get(pair); m1 != nil {
			build(MessagePairM1M4, m1, keyFrame)
		}
	}

	return candidates
}

// assocRespCandidates 从关联响应的 RSN IE 提取 PMKID。
// 多数 AP 把 PMKID 推迟到 EAPOL M1 才返回，但部分实现在关联响应
// 阶段即给出，两条路径互补、命中任一即可。
func (a *Analyzer) assocRespCandidates(frame []byte, channel int) []Candidate {
	if len(frame) < 16 {
		return nil
	}

	payload, ok := ieee80211.FindElement(frame, ieee80211.ElementRSN)
	if !ok {
		return nil
	}

	rsn, err := rsnie.ParseRSNIE(payload)
	if err != nil || !rsn.HasPMKID() {
		return nil
	}

	// 关联响应由 AP 发出：addr2 = AP（发送方），addr1 = 假客户端。
	return a.pmkidCandidates(macOf(frame[10:16]), macOf(frame[4:10]), rsn, channel)
}

// pmkidCandidates 把 RSN IE 的 PMKID 列表转成候选（逐条去重）。
func (a *Analyzer) pmkidCandidates(ap, sta string, rsn *rsnie.RSNInfo, channel int) []Candidate {
	var candidates []Candidate

	for _, pmkid := range rsn.PMKIDs {
		if !a.markReported("pmkid", ap, sta, hex.EncodeToString(pmkid[:])) {
			continue
		}

		essid := a.essidFor(ap)
		candidates = append(candidates, Candidate{
			Kind:        KindPMKID,
			MessagePair: pmkidMessagePair(rsn),
			PMKID:       pmkid,
			MACAP:       ap,
			MACSTA:      sta,
			ESSID:       essid,
			ESSIDKnown:  essid != "",
			Channel:     channel,
		})
		a.stats.PMKIDCandidates++
	}

	return candidates
}

// buildEAPOLCandidate 由一对（AP 帧 + STA 帧）组装握手候选。
// EAPOLFrame 取 STA 应答帧——hashcat wiki 规定：M1M2/M2M3 存 M2、
// M1M4/M3M4 存 M4；ANONCE 取 AP 帧（M1 与 M3 的 ANonce 恒相同）。
func buildEAPOLCandidate(messagePair byte, apFrame, staFrame *KeyFrame, ap, sta string, channel int, essid string) (Candidate, bool) {
	// Replay Counter 单调性：STA 应答的 counter 不应小于 AP 请求，
	// 违反即乱序/跨握手错配，宁可放弃也不产出解不开的 hash。
	if staFrame.ReplayCounter < apFrame.ReplayCounter {
		return Candidate{}, false
	}

	return Candidate{
		Kind:        KindEAPOL,
		MessagePair: messagePair,
		MIC:         staFrame.MIC,
		MACAP:       ap,
		MACSTA:      sta,
		ESSID:       essid,
		ESSIDKnown:  essid != "",
		ANonce:      apFrame.Nonce,
		SNonce:      staFrame.Nonce,
		EAPOLFrame:  staFrame.Raw,
		Channel:     channel,
	}, true
}

// markReported 去重登记：同源（kind+双方 MAC+指纹）只产出一次，
// 返回 true 表示首次出现。
func (a *Analyzer) markReported(kind, ap, sta, fingerprint string) bool {
	key := strings.Join([]string{kind, ap, sta, fingerprint}, "|")
	if a.reported[key] {
		return false
	}

	a.reported[key] = true

	// reported 只增不减是刻意取舍：一次会话的握手帧有限（千级），
	// 换全量去重的实现简单性；未来若支持长驻监测再引入 TTL。
	return true
}

// essidFor 返回 BSSID 的 ESSID：显式指定优先于空中学习。
func (a *Analyzer) essidFor(bssid string) string {
	if ssid, ok := a.explicit[bssid]; ok {
		return ssid
	}

	return a.essids[bssid]
}

// pmkidMessagePair 按 hashcat messagepair 位域标记 PMKID 来源：
// bit0 = 来自 AP（关联响应 / M1），bit1 = AKM 为 SHA-256 变体
// （00-0F-AC:6，hashcat 走 SHA256 路径）。
func pmkidMessagePair(rsn *rsnie.RSNInfo) byte {
	messagePair := byte(MessagePairPMKIDFromAP)

	for _, akm := range rsn.AKMSuites {
		if akm.IsStandard() && akm.Type == rsnie.AKMTypePSKSHA256 {
			messagePair |= MessagePairPMKIDSHA256
			break
		}
	}

	return messagePair
}

// macOf 归一化 MAC 为小写无冒号 hex（hash 行的 MAC 记法）。
func macOf(addr net.HardwareAddr) string {
	return normalizeMAC(addr.String())
}

// normalizeMAC 归一化字符串形式 MAC。
func normalizeMAC(value string) string {
	return strings.ToLower(strings.ReplaceAll(value, ":", ""))
}

// String 便于日志与 --json 之外的调试输出。
func (c Candidate) String() string {
	switch c.Kind {
	case KindPMKID:
		return fmt.Sprintf("PMKID ap=%s sta=%s ch=%d mp=%02x", c.MACAP, c.MACSTA, c.Channel, c.MessagePair)
	default:
		return fmt.Sprintf("EAPOL ap=%s sta=%s ch=%d mp=%02x", c.MACAP, c.MACSTA, c.Channel, c.MessagePair)
	}
}
