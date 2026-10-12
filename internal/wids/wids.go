// Package wids 是无线入侵检测的纯逻辑引擎，不触碰任何系统资源：
// 输入是扫描快照（Observation）与空中管理帧的摘要（FrameKind + MAC），
// 输出是告警（Alert），时钟由调用方注入，因此全部规则可表驱动单测。
//
// 检测面分两层：
//  1. 扫描差分（免 root，全平台）：对比相邻快照，识别伪造 AP、KARMA、
//     加密降级，并盘点弱加密与开放网络；
//  2. 帧级监测（需 monitor/BPF 特权，尽力而为）：滑动窗口计数
//     deauth/disassoc 风暴与信标泛洪，可识别针对本机的定向攻击。
//
// 阈值全部集中在本文件常量区： IDS 的可信度来自"误报可解释、漏报有边界"，
// 调参时必须同步更新 docs/feature/wireless_ids.md 的判读说明。
package wids

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// 检测阈值。单位与出处：
//   - scanFloodThreshold：一次快照里全新 BSSID 数；beacon flood 工具
//     （如 mdk4）每秒伪造数百个，正常商圈扫描很难单轮出现 30 个新 BSS。
//   - karmaSSIDThreshold：同一 BSSID 宣称的 SSID 数；合法 AP 终生只用
//     一两个 SSID，KARMA 工具会应答任意探测请求，轻松超过 6 个。
//   - stormWindow / stormThreshold：10 秒滑窗内同一发送方的 deauth ≥ 12 帧。
//     正常漫游/信号差时客户端也会偶发 deauth，12 帧且集中在单窗口是攻击特征。
//   - beaconFloodThreshold：10 秒滑窗内出现信标的去重发送方 ≥ 40 个。
//   - repeatCooldown：同一 (类别, 主体) 的告警冷却期，防止刷屏淹没终端。
const (
	scanFloodThreshold    = 30
	karmaSSIDThreshold    = 6
	stormWindow           = 10 * time.Second
	stormThreshold        = 12
	beaconFloodThreshold  = 40
	beaconFloodWindow     = 10 * time.Second
	repeatCooldown        = 5 * time.Minute
	stormAlertCooldown    = time.Minute
	maxTrackedTransmitter = 512
)

const (
	KindRogueAP     Kind = "伪造AP"
	KindKarma       Kind = "KARMA"
	KindDowngrade   Kind = "加密降级"
	KindWeakCrypto  Kind = "弱加密"
	KindOpenNetwork Kind = "开放网络"
	KindDeauth      Kind = "去认证风暴"
	KindDisassoc    Kind = "解除关联风暴"
	KindBeaconFlood Kind = "信标泛洪"
)

const (
	SevCritical Severity = iota
	SevWarning
	SevInfo
)

const (
	FrameDeauth FrameKind = iota
	FrameDisassoc
	FrameBeacon
)

// Kind 是告警类别名，直接使用中文以便终端渲染与文档一致。
type Kind string

// Severity 是告警等级。Critical 表示正在发生的攻击特征，
// Warning 表示高危配置，Info 表示盘点信息。
type Severity int

// FrameKind 是帧级监测关心的管理帧类型。
type FrameKind int

// Observation 是一次扫描快照中的一个 BSS。字段刻意收窄到检测所需，
// 与 functions.WiFiNetwork 解耦，避免引擎依赖展示层结构。
type Observation struct {
	SSID    string
	BSSID   string // 归一化（大写冒号分隔）后的 MAC，调用方负责
	Channel int
	Enc     string // 原样透传的加密描述（WPA2/WPA3/WEP/OPEN 等）
	Cipher  string // CCMP/TKIP/WEP 等
	Auth    string // PSK/OPEN/802.1X 等
}

// Alert 是一条检测告警。Subject 是可归因主体（SSID 或 MAC），
// Detail 是一句话证据，渲染层原样输出不做二次加工。
type Alert struct {
	Kind     Kind
	Severity Severity
	Time     time.Time
	Subject  string
	Detail   string
}

// Offender 是帧级监测的归因条目，用于总结的重点来源列表。
type Offender struct {
	MAC      string
	Deauth   int
	Disassoc int
}

// Report 是会话结束时的统计快照。
type Report struct {
	TrackedAPs    int
	AlertTotals   map[Kind]int
	FrameDeauth   int
	FrameDisassoc int
	Offenders     []Offender
}

// trackedAP 记录一个 BSSID 的基线状态，差分检测全部基于它。
type trackedAP struct {
	SSID      string
	Channel   int
	Level     int // securityLevel 的基线值
	FirstSeen time.Time
	LastSeen  time.Time
}

// Engine 是可跨 goroutine 复用的检测引擎；扫描循环与帧读取
// goroutine 各自调用 Observe/ObserveFrame，内部互斥保护状态。
type Engine struct {
	mutex sync.Mutex

	primed     bool
	ourMAC     string
	watchSSID  string                     // 非空时只评估该 SSID（或其已知 BSSID）的观察
	watchMACs  map[string]bool            // SetWatch 解析出的目标 BSSID 集（大写）
	baseline   map[string]*trackedAP      // BSSID → 基线
	ssidBSSIDs map[string]map[string]bool // SSID → 请求过它的 BSSID 集
	karmaSeen  map[string]map[string]bool // BSSID → 宣称过的 SSID 集
	reported   map[string]time.Time       // kind|subject → 上次告警时刻

	frames      map[string]*transmitterStats // 发送方 → 帧统计（环 + 累计）
	beacons     map[string][]time.Time       // 发送方 → beacon 时间戳环
	frameTotals map[FrameKind]int            // 帧累计计数（总结用）
}

// transmitterStats 是单个发送方的帧统计：滑窗时间戳用于阈值判定，
// 累计计数用于总结的重点来源排序（滑窗会清零，累计不会）。
type transmitterStats struct {
	deauth        []time.Time
	disassoc      []time.Time
	deauthTotal   int
	disassocTotal int
}

// String 返回等级的中文名，渲染层据此选色。
func (severity Severity) String() string {
	switch severity {
	case SevCritical:
		return "严重"
	case SevWarning:
		return "警告"
	default:
		return "提示"
	}
}

// NewEngine 创建引擎。
func NewEngine() *Engine {
	return &Engine{
		baseline:    make(map[string]*trackedAP),
		ssidBSSIDs:  make(map[string]map[string]bool),
		karmaSeen:   make(map[string]map[string]bool),
		reported:    make(map[string]time.Time),
		frames:      make(map[string]*transmitterStats),
		beacons:     make(map[string][]time.Time),
		frameTotals: make(map[FrameKind]int),
	}
}

// SetOurMAC 标记本机 MAC：帧级监测发现 receiver 命中时，
// 告警升级为"针对本机"，这是被 deauth 掉线时的第一手证据。
func (engine *Engine) SetOurMAC(mac string) {
	engine.mutex.Lock()
	defer engine.mutex.Unlock()

	engine.ourMAC = strings.ToUpper(mac)
}

// SetWatch 锁定监测目标：非空后，扫描差分只评估 SSID 匹配或
// BSSID 命中 macs 的观察；帧级风暴检测只统计收发双方命中 macs 的帧。
// 泛洪类检测保持全局——泛洪波及整个空域，不因选定目标而豁免。
func (engine *Engine) SetWatch(ssid string, macs map[string]bool) {
	engine.mutex.Lock()
	defer engine.mutex.Unlock()

	engine.watchSSID = ssid
	engine.watchMACs = macs
}

// watched 判定一条扫描观察是否属于锁定的监测目标。
// 未锁定（watchSSID 为空）时全部放行。
func (engine *Engine) watched(ssid, bssid string) bool {
	if engine.watchSSID == "" {
		return true
	}

	return ssid == engine.watchSSID || engine.watchMACs[bssid]
}

// Observe 消化一轮扫描快照，返回本轮触发的告警。
// 首轮只建立基线与安全盘点，不做差分——没有参照物的差分全是误报。
func (engine *Engine) Observe(observations []Observation, at time.Time) []Alert {
	engine.mutex.Lock()
	defer engine.mutex.Unlock()

	var alerts []Alert
	newBSSIDs := 0

	for _, observation := range observations {
		bssid := strings.ToUpper(observation.BSSID)
		if bssid == "" || bssid == "FF:FF:FF:FF:FF:FF" {
			continue
		}

		if !engine.watched(observation.SSID, bssid) {
			continue
		}

		level := securityLevel(observation)

		if tracked, seen := engine.baseline[bssid]; seen {
			alerts = append(alerts, engine.diffTracked(tracked, observation, level, at)...)
			tracked.LastSeen = at
			continue
		}

		newBSSIDs++
		alerts = append(alerts, engine.learn(bssid, observation, level, at)...)
		alerts = append(alerts, engine.inventory(bssid, observation, level, at)...)
	}

	// 首轮之后才启用泛洪判据；单轮全新 BSSID 超阈值即告警。
	if engine.primed && newBSSIDs >= scanFloodThreshold {
		alerts = append(alerts, engine.emit(
			KindBeaconFlood, SevCritical, "扫描快照",
			fmt.Sprintf("单轮快照出现 %d 个全新 BSSID（阈值 %d），疑似信标泛洪", newBSSIDs, scanFloodThreshold),
			at, repeatCooldown,
		)...)
	}

	engine.primed = true
	engine.pruneFrameState(at)

	return alerts
}

// diffTracked 把已知 BSSID 与基线对比：加密降级是硬证据，
// 同 SSID 多 BSSID 需结合信道/加密差异区分 Evil Twin 与合法 Mesh。
func (engine *Engine) diffTracked(tracked *trackedAP, observation Observation, level int, at time.Time) []Alert {
	var alerts []Alert

	bssid := strings.ToUpper(observation.BSSID)

	if level < tracked.Level {
		alerts = append(alerts, engine.emit(
			KindDowngrade, SevCritical, label(observation),
			fmt.Sprintf("%s 从安全等级 %d 降为 %d（现 %s），疑似降级攻击",
				bssid, tracked.Level, level, securityText(observation)),
			at, repeatCooldown,
		)...)
		tracked.Level = level
	}

	// 同一 BSSID 换 SSID 宣称是 KARMA 的核心行为；SSID 为空的
	// 隐藏网络不参与 KARMA 统计，避免把 beacon 轮换误判进来。
	if ssid := observation.SSID; ssid != "" && ssid != tracked.SSID {
		seen := engine.karmaSeen[bssid]
		if seen == nil {
			seen = make(map[string]bool)
			engine.karmaSeen[bssid] = seen
		}

		seen[ssid] = true

		if len(seen) >= karmaSSIDThreshold {
			alerts = append(alerts, engine.emit(
				KindKarma, SevCritical, bssid,
				fmt.Sprintf("同一 BSSID 宣称了 %d 个不同 SSID（阈值 %d），KARMA 特征", len(seen), karmaSSIDThreshold),
				at, repeatCooldown,
			)...)
		}
	}

	return alerts
}

// learn 把新 BSSID 写入基线，并做伪造 AP 判定。
// 判定的关键前提是同频段对比：同一 SSID 在 2.4GHz 与 5GHz 各起一个
// BSSID 是双频路由器的默认拓扑，跨频段出现不算异常、不产生任何告警。
// 只有同频段内出现信道或安全等级不一致的第二个 BSSID 才升级为警告；
// 同频段且配置完全一致，更像 Mesh/漫游组，只留提示。
func (engine *Engine) learn(bssid string, observation Observation, level int, at time.Time) []Alert {
	engine.baseline[bssid] = &trackedAP{
		SSID:      observation.SSID,
		Channel:   observation.Channel,
		Level:     level,
		FirstSeen: at,
		LastSeen:  at,
	}

	ssid := observation.SSID
	if ssid == "" {
		return nil
	}

	peers := engine.ssidBSSIDs[ssid]
	if peers == nil {
		peers = make(map[string]bool)
		engine.ssidBSSIDs[ssid] = peers
	}

	var alerts []Alert

	if len(peers) > 0 {
		band := bandOf(observation.Channel)
		conflict := false
		sameBandSeen := false

		for peer := range peers {
			baseline, ok := engine.baseline[peer]
			if !ok || bandOf(baseline.Channel) != band {
				continue
			}

			sameBandSeen = true

			if baseline.Channel != observation.Channel || baseline.Level != level {
				conflict = true
				break
			}
		}

		switch {
		case !sameBandSeen:
			// 全是跨频段成员：双频/三频路由器的正常形态，静默记录。
		case conflict:
			alerts = append(alerts, engine.emit(
				KindRogueAP, SevWarning, ssid,
				fmt.Sprintf("SSID 在同频段出现第二个 BSSID %s（信道 %d · %s），与基线配置不一致，疑似 Evil Twin",
					bssid, observation.Channel, securityText(observation)),
				at, repeatCooldown,
			)...)
		default:
			alerts = append(alerts, engine.emit(
				KindRogueAP, SevInfo, ssid,
				fmt.Sprintf("SSID 在同频段出现第二个 BSSID %s，配置与基线一致，可能是合法 Mesh/漫游", bssid),
				at, repeatCooldown,
			)...)
		}
	}

	peers[bssid] = true

	return alerts
}

// bandOf 把信道号折算成频段：1-14 为 2.4GHz，其余为 5/6GHz。
// 同频段对比是伪造 AP 判定的前提——双频合一路由器的两个 BSSID
// 天然落在不同频段，跨频段比较只会制造误报。
func bandOf(channel int) int {
	if channel >= 1 && channel <= 14 {
		return 24
	}

	return 5
}

// inventory 对新见到的 BSSID 做一次性的安全盘点：
// 开放网络与 WPA/TKIP 是提示级，WEP 直接升级为警告（可离线破解）。
func (engine *Engine) inventory(bssid string, observation Observation, level int, at time.Time) []Alert {
	switch level {
	case 0:
		return engine.emit(
			KindOpenNetwork, SevInfo, label(observation),
			fmt.Sprintf("开放网络（%s 信道 %d），流量明文可嗅探", bssid, observation.Channel),
			at, repeatCooldown,
		)
	case 1:
		return engine.emit(
			KindWeakCrypto, SevWarning, label(observation),
			fmt.Sprintf("WEP 加密（%s 信道 %d），可离线破解，属高危配置", bssid, observation.Channel),
			at, repeatCooldown,
		)
	case 2:
		return engine.emit(
			KindWeakCrypto, SevInfo, label(observation),
			fmt.Sprintf("弱加密 WPA/TKIP（%s 信道 %d），建议升级 WPA2-CCMP 及以上", bssid, observation.Channel),
			at, repeatCooldown,
		)
	default:
		return nil
	}
}

// ObserveFrame 消化一条空中管理帧摘要，返回触发的告警。
// transmitter/receiver 为大写冒号分隔 MAC；receiver 为广播或本机。
func (engine *Engine) ObserveFrame(kind FrameKind, transmitter, receiver string, at time.Time) []Alert {
	engine.mutex.Lock()
	defer engine.mutex.Unlock()

	transmitter = strings.ToUpper(transmitter)
	receiver = strings.ToUpper(receiver)
	if transmitter == "" {
		return nil
	}

	engine.frameTotals[kind]++

	switch kind {
	case FrameDeauth, FrameDisassoc:
		// 锁定目标时只统计与目标 BSS 有收发关系的风暴帧；
		// 信标泛洪保持全局（攻击者用随机 MAC，收发侧都不可归因）。
		if engine.watchSSID != "" && !engine.watchMACs[transmitter] && !engine.watchMACs[receiver] {
			return nil
		}

		return engine.countStorm(kind, transmitter, receiver, at)
	case FrameBeacon:
		return engine.countBeacon(transmitter, at)
	default:
		return nil
	}
}

// countStorm 滑动窗口计数 deauth/disassoc：同一发送方在
// stormWindow 内超过 stormThreshold 即告警，冷却期内不重复报。
func (engine *Engine) countStorm(kind FrameKind, transmitter, receiver string, at time.Time) []Alert {
	stats, ok := engine.frames[transmitter]
	if !ok {
		// 状态上限防内存膨胀：攻击者可用随机伪造 MAC 灌爆计数表，
		// 超限时整体重建——泛洪本身已由泛洪检测覆盖，不在计数面硬扛。
		if len(engine.frames) > maxTrackedTransmitter {
			engine.frames = make(map[string]*transmitterStats)
		}

		stats = &transmitterStats{}
		engine.frames[transmitter] = stats
	}

	stamps := &stats.deauth
	if kind == FrameDisassoc {
		stamps = &stats.disassoc
	}

	*stamps = append(*stamps, at)

	cutoff := at.Add(-stormWindow)
	head := 0
	for head < len(*stamps) && (*stamps)[head].Before(cutoff) {
		head++
	}
	*stamps = (*stamps)[head:]

	if kind == FrameDisassoc {
		stats.disassocTotal++
	} else {
		stats.deauthTotal++
	}

	if len(*stamps) < stormThreshold {
		return nil
	}

	kindName := KindDeauth
	if kind == FrameDisassoc {
		kindName = KindDisassoc
	}

	detail := fmt.Sprintf("10 秒内 %d 帧（阈值 %d）", len(*stamps), stormThreshold)
	switch {
	case engine.ourMAC != "" && receiver == engine.ourMAC:
		detail += "，目标为本机——你的连接正在被强制断开"
	case receiver == "FF:FF:FF:FF:FF:FF":
		detail += "，广播帧（波及该 BSS 全部客户端）"
	default:
		detail += "，目标 " + receiver
	}

	return engine.emit(
		kindName, SevCritical, transmitter, detail, at, stormAlertCooldown,
	)
}

// countBeacon 按去重发送方计数信标：短窗口内大量互不相识的
// 发射方同时打信标，是 beacon flood 工具的指纹。
func (engine *Engine) countBeacon(transmitter string, at time.Time) []Alert {
	engine.beacons[transmitter] = append(engine.beacons[transmitter], at)

	cutoff := at.Add(-beaconFloodWindow)
	active := 0

	for mac, stamps := range engine.beacons {
		head := 0
		for head < len(stamps) && stamps[head].Before(cutoff) {
			head++
		}

		stamps = stamps[head:]
		if len(stamps) == 0 {
			delete(engine.beacons, mac)
			continue
		}

		engine.beacons[mac] = stamps
		active++
	}

	if active < beaconFloodThreshold {
		return nil
	}

	return engine.emit(
		KindBeaconFlood, SevCritical, "空中帧",
		fmt.Sprintf("10 秒内 %d 个不同发送方在打信标（阈值 %d），疑似信标泛洪", active, beaconFloodThreshold),
		at, repeatCooldown,
	)
}

// emit 生成告警并做冷却判定：同一 (类别, 主体) 在冷却期内只报一次，
// 返回空切片表示已被抑制。全量告警与计数仍在报告中保留。
func (engine *Engine) emit(kind Kind, severity Severity, subject, detail string, at time.Time, cooldown time.Duration) []Alert {
	key := string(kind) + "|" + subject
	if last, seen := engine.reported[key]; seen && at.Sub(last) < cooldown {
		return nil
	}

	engine.reported[key] = at

	return []Alert{{
		Kind:     kind,
		Severity: severity,
		Time:     at,
		Subject:  subject,
		Detail:   detail,
	}}
}

// Summary 汇总会话统计。帧计数表的剪枝在 Observe 里统一做。
func (engine *Engine) Summary() Report {
	engine.mutex.Lock()
	defer engine.mutex.Unlock()

	totals := make(map[Kind]int)
	for key := range engine.reported {
		parts := strings.SplitN(key, "|", 2)
		totals[Kind(parts[0])]++
	}

	offenders := make([]Offender, 0, len(engine.frames))
	for mac, stats := range engine.frames {
		if stats.deauthTotal == 0 && stats.disassocTotal == 0 {
			continue
		}

		offenders = append(offenders, Offender{
			MAC:      mac,
			Deauth:   stats.deauthTotal,
			Disassoc: stats.disassocTotal,
		})
	}

	sort.Slice(offenders, func(i, j int) bool {
		return offenders[i].Deauth+offenders[i].Disassoc > offenders[j].Deauth+offenders[j].Disassoc
	})

	if len(offenders) > 5 {
		offenders = offenders[:5]
	}

	return Report{
		TrackedAPs:    len(engine.baseline),
		AlertTotals:   totals,
		FrameDeauth:   engine.frameTotals[FrameDeauth],
		FrameDisassoc: engine.frameTotals[FrameDisassoc],
		Offenders:     offenders,
	}
}

// pruneFrameState 清理长期未活跃的帧计数表，长时间会话不膨胀。
func (engine *Engine) pruneFrameState(at time.Time) {
	if len(engine.frames) <= maxTrackedTransmitter && len(engine.beacons) <= maxTrackedTransmitter {
		return
	}

	cutoff := at.Add(-stormWindow)
	for mac, stats := range engine.frames {
		lastDeauth := len(stats.deauth) > 0 && stats.deauth[len(stats.deauth)-1].After(cutoff)
		lastDisassoc := len(stats.disassoc) > 0 && stats.disassoc[len(stats.disassoc)-1].After(cutoff)
		if lastDeauth || lastDisassoc {
			continue
		}

		delete(engine.frames, mac)
	}

	beaconCutoff := at.Add(-beaconFloodWindow)
	for mac, stamps := range engine.beacons {
		if len(stamps) > 0 && stamps[len(stamps)-1].After(beaconCutoff) {
			continue
		}
		delete(engine.beacons, mac)
	}
}

// SecurityLevel 导出安全等级评估（0 开放…4 WPA3），
// 供热力图等可视化层给 AP 列表打风险徽章时复用同一口径。
func SecurityLevel(enc, cipher string) int {
	return securityLevel(Observation{Enc: enc, Cipher: cipher})
}

// securityLevel 把加密描述折算成 0-4 的单调等级：
// 0=开放、1=WEP、2=WPA/TKIP、3=WPA2-CCMP、4=WPA3。
// 各平台扫描器的取值口径不同（iw 是 WPA2-PSK-CCMP，macOS 是 WPA3），
// 因此用包含匹配而不是等值比较；识别不了时保守给 3，不制造降级误报。
func securityLevel(observation Observation) int {
	enc := strings.ToUpper(observation.Enc)
	cipher := strings.ToUpper(observation.Cipher)

	level := 0
	switch {
	case strings.Contains(enc, "WPA3"):
		level = 4
	case strings.Contains(enc, "WPA2"):
		level = 3
	case strings.Contains(enc, "WPA"), strings.Contains(cipher, "TKIP"):
		level = 2
	case strings.Contains(enc, "WEP"), strings.Contains(cipher, "WEP"):
		level = 1
	default:
		level = 0
	}

	// 加密声明存在但等级仍为 0：把 WPA1 的厂商 IE 描述也算上，
	// 宁可高估也不把加密网络误判成开放网络。
	if level == 0 && (enc != "" && enc != "OPEN" && enc != "NONE" && enc != "NONE/OPEN" && enc != "OPN") {
		if strings.Contains(enc, "RSN") || strings.Contains(enc, "WPA") {
			level = 3
		}
	}

	if level > 2 && strings.Contains(cipher, "TKIP") {
		level = 2
	}

	return level
}

// securityText 输出人类可读的安全描述，用于告警证据行。
func securityText(observation Observation) string {
	if text := strings.TrimSpace(observation.Enc); text != "" {
		return strings.ToUpper(text)
	}

	return "OPEN"
}

// label 优先用 SSID 指认目标，隐藏网络退回 BSSID。
func label(observation Observation) string {
	if ssid := strings.TrimSpace(observation.SSID); ssid != "" {
		return ssid
	}

	return strings.ToUpper(observation.BSSID)
}
