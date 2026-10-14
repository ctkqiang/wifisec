// sniff_event.go 提供 bettercap 风格的事件流：把零散的帧收敛成
// 语义化事件（DNS 查询、HTTP 请求、TLS SNI、ARP who-has、凭据告警、
// 新主机上线），每帧最多产出两条事件（新主机 + 协议事件），按令牌桶限速打印。
// 与 sniff.go 的 Wireshark 风格 printSniffLine 互不干扰——get_packet 仍走旧路径。
package functions

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ctkqiang/wifisec/internal/constants"
	"github.com/ctkqiang/wifisec/internal/ethernet"
	"github.com/ctkqiang/wifisec/internal/utilities"
)

// 事件速率上限：与 get_packet 的实时行限速一致，避免 DNS 泛洪把终端刷屏。
const sniffEventsPerSecond = 40

// tagColumnWidth 是事件标签列的固定可见宽度（含方括号，如 [http]）。
// 描述列紧跟其后，不设独立 source 列——source 内联到描述里用 → 连接。
const tagColumnWidth = 6

// 事件标签：与 ethernet.L7* 同值但语义独立——arp/host 没有 L7 对应。
const (
	tagDNS  = "dns"
	tagHTTP = "http"
	tagSNI  = "sni"
	tagARP  = "arp"
	tagHost = "host"
	tagCred = "cred"
)

// tagColor 给事件标签着色，让终端事件流一眼可辨：
// DNS 青、HTTP 绿、SNI 黄、ARP 紫、主机 蓝、凭据 红（最醒目，告警级别）。
var tagColor = map[string]string{
	tagDNS:  constants.ColorCyan,
	tagHTTP: constants.ColorGreen,
	tagSNI:  constants.ColorYellow,
	tagARP:  constants.ColorMagenta,
	tagHost: constants.ColorBlue,
	tagCred: constants.ColorRed,
}

// colorTag 把事件标签包成带颜色的 [tag]；查不到颜色映射时原样输出。
func colorTag(tag string) string {
	if color, ok := tagColor[tag]; ok {
		return color + "[" + tag + "]" + constants.ColorReset
	}

	return "[" + tag + "]"
}

// colorSource 给事件 Source 上色：{本机}/{网关} 用绿色与 devices 表的角色色对齐，
// 普通 IP 保持默认色。让角色端点在密集事件流中跳出来。
func colorSource(source string) string {
	switch source {
	case "{本机}", "{网关}":
		return constants.ColorGreen + source + constants.ColorReset
	}

	return source
}

// hostColumns 是退出主机表的列定义，遵循 deviceColumns 的多行展开约定。
var hostColumns = []tableColumn[ethernet.Host]{
	{
		Header:   "IP 地址",
		Value:    func(h ethernet.Host) string { return h.IP.String() },
		Priority: 0,
	},
	{
		Header:   "MAC 地址",
		Value:    func(h ethernet.Host) string { return h.MAC.String() },
		Priority: 0,
	},
	{
		Header:   "厂商",
		Value:    func(h ethernet.Host) string { return h.Vendor },
		Priority: 1,
		Shrink:   true,
	},
	{
		Header:   "事件数",
		Value:    func(h ethernet.Host) string { return fmt.Sprintf("%d", h.Events) },
		Priority: 0,
	},
	{
		Header:   "角色",
		Value:    func(h ethernet.Host) string { return roleLabel(h.Role) },
		Color:    roleColor,
		Priority: 0,
	},
}

// SniffEvent 是一条面向终端的事件：Tag 是类别标签，Line 是完整描述。
// 发起方内联到 Line 里，不拆独立列——bettercap 风格是 [tag] 完整描述。
type SniffEvent struct {
	Tag  string
	Line string
}

// EventFilter 把原始帧分派成事件；持有 HostTracker 用于即时更新主机表，
// 新主机出现时产出一个 [host] 事件。selfIP/gatewayIP 用于 Source 标注——
// 本机流量显示 {本机}，网关流量显示 {网关}，取代裸 IP 提升可读性。
// tracker 为 nil 时跳过主机跟踪。
type EventFilter struct {
	tracker   *ethernet.HostTracker
	selfIP    net.IP
	gatewayIP net.IP
}

// NewEventFilter 构造过滤器；selfIP/gatewayIP 用于 Source 角色标注，
// 两者均可为 nil（不标注角色）。tracker 为 nil 时跳过主机跟踪与 [host] 事件。
func NewEventFilter(tracker *ethernet.HostTracker, selfIP, gatewayIP net.IP) *EventFilter {
	return &EventFilter{
		tracker:   tracker,
		selfIP:    selfIP.To4(),
		gatewayIP: gatewayIP.To4(),
	}
}

// Filter 解析一帧并产出 0-2 条事件；先更新主机表（可能产出 [host]），
// 再按协议产出一条语义事件。ARP 帧走 ParseARP，其余帧走 ParseL7。
func (f *EventFilter) Filter(frame []byte, summary ethernet.FrameSummary) []SniffEvent {
	var events []SniffEvent

	// 主机表更新：只跟踪 RFC1918 私有 IP。公网 IP 的源 MAC 实际上是网关 MAC
	// （流量经路由器转发），跟踪它们会把网关 MAC 错误关联到一堆公网 IP 上。
	// EAPOL/LLDP 的 Src 是 MAC 字符串，extractIP 返回 nil，自然不进表。
	if f.tracker != nil && len(summary.SrcMAC) == 6 {
		if ip := extractIP(summary.Src); ip != nil && isPrivateIPv4(ip) {
			if host, isNew := f.tracker.Observe(ip, summary.SrcMAC); isNew {
				events = append(events, f.makeHostEvent(host))
			}
		}
	}

	// ARP 帧：EtherType 0x0806，ParseARP 会校验长度与类型；命中后不再跑 L7。
	if info, ok := ethernet.ParseARP(frame); ok {
		// RFC 826 opcode：1 = request，2 = reply；只对 request 产事件，
		// reply 含毒化/恢复帧，刷屏无信息量但会更新主机表（已在上面处理）。
		if info.Opcode == 1 {
			events = append(events, SniffEvent{
				Tag:  tagARP,
				Line: fmt.Sprintf("%s → who-has %s", colorSource(f.sourceLabel(info.SenderIP.String())), info.TargetIP),
			})
		}

		return events
	}

	// L7 事件：ParseL7 复走网络层/传输层头，拿到结构化的 DNS/HTTP/SNI/Credential。
	event, ok := ethernet.ParseL7(frame)
	if !ok {
		return events
	}

	// source 内联到描述里，用 → 表示方向，不拆独立列——bettercap 风格。
	source := colorSource(f.sourceLabel(summary.Src))

	switch event.Kind {
	case ethernet.L7DNS:
		qtype := event.DNSQType
		if qtype == "" {
			qtype = "未知"
		}

		events = append(events, SniffEvent{
			Tag:  tagDNS,
			Line: fmt.Sprintf("%s → %s (%s)", source, event.DNSName, qtype),
		})
	case ethernet.L7HTTP:
		line := fmt.Sprintf("%s %s", event.HTTPMethod, event.HTTPPath)
		if event.HTTPHost != "" {
			line += " Host: " + event.HTTPHost
		}

		events = append(events, SniffEvent{
			Tag:  tagHTTP,
			Line: fmt.Sprintf("%s → %s", source, line),
		})
	case ethernet.L7SNI:
		events = append(events, SniffEvent{
			Tag:  tagSNI,
			Line: fmt.Sprintf("%s → %s", source, event.SNI),
		})
	case ethernet.L7CRED:
		// 凭据事件不输出 User/Pass 值，只标注方法与凭据来源类型，
		// 与 formatL7Event 的安全策略一致——终端/日志不落明文口令。
		events = append(events, SniffEvent{
			Tag:  tagCred,
			Line: fmt.Sprintf("%s → %s 命中 %s 凭据", source, event.HTTPMethod, event.Credential.Type),
		})
	}

	return events
}

// makeHostEvent 构造一条 [host] 事件；描述自包含角色、IP、MAC、厂商，
// 不依赖 source 列——bettercap 风格是 `[tag] 完整描述`，不拆列。
func (f *EventFilter) makeHostEvent(host ethernet.Host) SniffEvent {
	vendor := vendorOrUnknown(host.Vendor)

	switch host.Role {
	case "self":
		return SniffEvent{
			Tag:  tagHost,
			Line: fmt.Sprintf("本机 %s (%s · %s)", host.IP, host.MAC, vendor),
		}
	case "gateway":
		return SniffEvent{
			Tag:  tagHost,
			Line: fmt.Sprintf("网关 %s (%s · %s)", host.IP, host.MAC, vendor),
		}
	}

	return SniffEvent{
		Tag:  tagHost,
		Line: fmt.Sprintf("新主机 %s (%s · %s)", host.IP, host.MAC, vendor),
	}
}

// sourceLabel 把端点 IP 转成角色标签：本机显示 {本机}，网关显示 {网关}，
// 其余原样返回。提升事件流可读性——一眼看出哪条流量是本机发出的。
func (f *EventFilter) sourceLabel(endpoint string) string {
	if ip := extractIP(endpoint); ip != nil {
		ip4 := ip.To4()
		if f.selfIP != nil && ip4.Equal(f.selfIP) {
			return "{本机}"
		}

		if f.gatewayIP != nil && ip4.Equal(f.gatewayIP) {
			return "{网关}"
		}
	}

	return endpoint
}

// isPrivateIPv4 判定 IP 是否在 RFC1918 私有网段或 link-local 范围内。
// 只有私有 IP 才进入主机表——公网 IP 的二层 MAC 是网关 MAC，跟踪它们
// 会把网关 MAC 错误关联到一堆公网 IP 上，产生无意义的主机条目。
func isPrivateIPv4(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}

	switch {
	case ip4[0] == 10:
		return true
	case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
		return true
	case ip4[0] == 192 && ip4[1] == 168:
		return true
	case ip4[0] == 169 && ip4[1] == 254:
		return true
	}

	return false
}

// vendorOrUnknown 把空厂商字符串显示为 "未知"，避免终端出现裸空串。
func vendorOrUnknown(vendor string) string {
	if vendor == "" {
		return "未知"
	}

	return vendor
}

// formatSniffEventLine 把一条事件格式化成 bettercap 风格的单行：
//
//	[HH:MM:SS] [tag]  description
//
// 时间戳灰色弱化、标签按类型着色并对齐到固定宽度，描述自包含来源与语义，
// 密集事件流在终端里呈左对齐表格状，扫一眼就能定位协议与内容。
func formatSniffEventLine(event SniffEvent) string {
	timestamp := time.Now().Format("15:04:05")
	tag := padRightVisible(colorTag(event.Tag), tagColumnWidth)

	return fmt.Sprintf("%s[%s]%s %s  %s",
		constants.ColorGray, timestamp, constants.ColorReset,
		tag, event.Line,
	)
}

// printSniffEvent 按令牌桶限速打印一条事件；被折叠的事件在每秒第一次
// 恢复打印时补一条说明，与 printSniffLine 的限速策略同构。
func printSniffEvent(event SniffEvent, budget int, refillAt *time.Time, suppressed int) (int, int) {
	now := time.Now()
	if now.After(*refillAt) {
		if suppressed > 0 {
			fmt.Printf("  %s… %d 条事件已折叠%s\n", constants.ColorGray, suppressed, constants.ColorReset)
		}

		*refillAt = now.Add(time.Second)
		budget = sniffEventsPerSecond
		suppressed = 0
	}

	if budget <= 0 {
		return budget, suppressed + 1
	}

	budget--
	fmt.Println(formatSniffEventLine(event))

	return budget, suppressed
}

// visibleWidth 返回字符串在终端的可见宽度，跳过 ANSI 转义序列并把 CJK
// 双宽字符按 2 计。复用 lists.go 的 isWideRune 判断双宽字符。
// 事件标签和角色标签都带颜色码，按 rune 计数会把转义符算进去导致列错位；
// 角色标签含中文，按单宽算会少算宽度导致描述列右移。
func visibleWidth(s string) int {
	inEscape := false
	count := 0

	for _, r := range s {
		if r == '\x1b' {
			inEscape = true
			continue
		}

		if inEscape {
			if r == 'm' {
				inEscape = false
			}

			continue
		}

		if isWideRune(r) {
			count += 2
		} else {
			count++
		}
	}

	return count
}

// padRightVisible 按可见宽度把 s 右侧补空格到 width；已超过则原样返回。
func padRightVisible(s string, width int) string {
	vl := visibleWidth(s)
	if vl >= width {
		return s
	}

	return s + strings.Repeat(" ", width-vl)
}

// printSniffHostSummary 在会话结束时输出主机表与统计摘要。
// 主机表仅在 tracker 非空且有数据时渲染，避免空表占屏。
func printSniffHostSummary(tracker *ethernet.HostTracker, stats captureStats) {
	if tracker != nil {
		hosts := tracker.Snapshot()
		if len(hosts) > 0 {
			renderTable("嗅探期间观测到的主机", hostColumns, hosts)
		}
	}

	utilities.Info("嗅探结束：%d 帧 · %s · 时长 %s\n协议分布：%s",
		stats.packets, humanizeBytes(stats.bytes),
		time.Since(stats.started).Round(10*time.Millisecond),
		formatProtocolDistribution(stats.protocol, 5))
}

// roleLabel 把 ethernet.Host 的英文角色转成中文显示，与 devices.go 的 lanDevice.Role 对齐。
func roleLabel(role string) string {
	switch role {
	case "gateway":
		return "网关"
	case "self":
		return "本机"
	}

	return ""
}

// extractIP 从 "IP:port" 或纯 IP 字符串中提取 IPv4；MAC 或非法值返回 nil。
// SplitHostPort 失败（无端口分隔）时退回直接 ParseIP，覆盖 ARP 的纯 IP 形态。
func extractIP(endpoint string) net.IP {
	if host, _, err := net.SplitHostPort(endpoint); err == nil {
		return net.ParseIP(host).To4()
	}

	return net.ParseIP(endpoint).To4()
}
