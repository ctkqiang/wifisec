// ids.go 实现 `wifisec ids` 无线入侵检测会话：
// 扫描差分引擎（免 root，全平台）周期对比快照识别伪造 AP/KARMA/加密降级，
// 帧级监测引擎在拿到 802.11 原始帧时（Linux monitor VIF / macOS BPF /
// Windows Npcap 原生 802.11）叠加 deauth 风暴与信标泛洪检测。
//
// 检测逻辑全部在 internal/wids 纯引擎中，本文件只做编排：
// 解析参数、启动/清理帧源、驱动扫描节拍、渲染告警与总结。
// 输出沿用 utilities 日志与彩色告警行，Ctrl-C/到点后打印统计正常收尾。
package functions

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ctkqiang/wifisec/internal/constants"
	"github.com/ctkqiang/wifisec/internal/ieee80211"
	platformcapture "github.com/ctkqiang/wifisec/internal/platform/capture"
	"github.com/ctkqiang/wifisec/internal/platform/linux"
	"github.com/ctkqiang/wifisec/internal/utilities"
	"github.com/ctkqiang/wifisec/internal/wids"
)

// 扫描节拍与信道跳频间隔。15 秒一轮兼顾检测时延与
// macOS system_profiler/Linux iw 的扫描成本；跳频 2 秒一轮
// 让 monitor 接口在 30 秒内覆盖 2.4GHz 全部信道与 5GHz 常用信道。
const (
	idsScanInterval = 15 * time.Second
	idsHopInterval  = 2 * time.Second
)

// idsHopChannels 是跳频序列：2.4GHz 全部信道在前，5GHz 非 DFS
// 常用信道在后；SetChannel 对 DFS/禁用信道报错时直接跳过下一轮。
var idsHopChannels = []int{
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
	36, 40, 44, 48, 149, 153, 157, 161, 165,
}

// IDSOptions 是 ids 子命令的参数集。
type IDSOptions struct {
	SSID      string        // 锁定监测的 SSID（空 = 全空域）
	Interface string        // 帧级监测绑定的网卡（空=自动选择无线网卡）
	Seconds   int           // 监测秒数；0 = 持续到 Ctrl-C
	Duration  time.Duration // Seconds 的 time.Duration 形式
}

// ParseIDSArgs 按位置语义解析：纯整数是秒数；其余 token 先按网卡名
// 试探（net.InterfaceByName 命中即网卡），否则视为要锁定的 SSID。
// 与 ParseSniffArgs 同一套约定，`-` 开头的 token 直接报错。
func ParseIDSArgs(arguments []string) (IDSOptions, error) {
	options := IDSOptions{}

	for _, raw := range arguments {
		token := strings.TrimSpace(raw)
		if token == "" {
			continue
		}

		switch {
		case isSniffDuration(token):
			seconds, err := strconv.Atoi(token)
			if err != nil || seconds < 0 {
				return options, fmt.Errorf("非法监测秒数 %q：请给出非负整数（0=监测到 Ctrl-C）", token)
			}

			options.Seconds = seconds
			options.Duration = time.Duration(seconds) * time.Second
		case strings.HasPrefix(token, "-"):
			return options, fmt.Errorf("无法识别的参数 %q（秒数必须是非负整数）", token)
		default:
			if iface, err := net.InterfaceByName(token); err == nil && iface != nil {
				if options.Interface != "" {
					return options, fmt.Errorf("无法识别的多余参数 %q", token)
				}

				options.Interface = token
				continue
			}

			if options.SSID != "" {
				return options, fmt.Errorf("无法识别的多余参数 %q", token)
			}

			options.SSID = token
		}
	}

	return options, nil
}

// RunWirelessIDS 是 `wifisec ids` 的入口。
func RunWirelessIDS(arguments []string) error {
	options, err := ParseIDSArgs(arguments)
	if err != nil {
		return err
	}

	utilities.Warn("监测仅限自有网络或已获书面授权的环境；检测记录涉及周边网络的元数据，请依法留存")

	ctx, cancel := setupSignalHandler()
	defer cancel()

	if options.Seconds > 0 {
		var cancelTimeout context.CancelFunc
		ctx, cancelTimeout = context.WithTimeout(ctx, options.Duration)
		defer cancelTimeout()
	}

	engine := wids.NewEngine()
	alertsCh := make(chan []wids.Alert, 16)

	var watchChannels []int

	if options.SSID != "" {
		resolved, channels, err := resolveWatchTarget(options.SSID)
		if err != nil {
			return err
		}

		engine.SetWatch(options.SSID, resolved)
		watchChannels = channels
	}

	source, stopFeed := startIDSFrameFeed(ctx, options.Interface, watchChannels, engine, alertsCh)
	defer stopFeed()

	runIDSScanLoop(ctx, engine, alertsCh, options.SSID, source != nil)
	printIDSSummary(engine)

	return nil
}

// resolveWatchTarget 用一轮即时扫描把目标 SSID 解析成 BSSID 集与信道集：
// BSSID 集供引擎过滤与帧级归因，信道集用于把 monitor 跳频钉在目标所在信道。
// SSID 本身不可见（不在覆盖范围/拼写错误）直接报错退出，不空转；
// BSSID 被系统隐藏（macOS 未授权定位）时降级为纯 SSID 匹配并明说。
func resolveWatchTarget(ssid string) (map[string]bool, []int, error) {
	networks, err := scanNetworks()
	if err != nil {
		return nil, nil, fmt.Errorf("解析目标 %q 前无线扫描失败：%w", ssid, err)
	}

	seen := false
	macs := make(map[string]bool)
	channelSet := make(map[int]bool)

	for _, network := range networks {
		if network.ESSID != ssid {
			continue
		}

		seen = true

		if mac := normalizeMAC(network.BSSID); mac != "" {
			macs[mac] = true
		}

		if network.Channel > 0 {
			channelSet[network.Channel] = true
		}
	}

	if !seen {
		return nil, nil, fmt.Errorf("目标 SSID %q 当前不可见：请确认在信号覆盖范围内并检查拼写", ssid)
	}

	channels := make([]int, 0, len(channelSet))
	for channel := range channelSet {
		channels = append(channels, channel)
	}

	sort.Ints(channels)

	if len(macs) == 0 {
		utilities.Warn("系统隐藏了目标 BSSID（macOS 需授权定位）：锁定退化为 SSID 匹配，帧级归因不可用")
		utilities.Info("已锁定目标 %q（SSID 匹配模式）· 信道 %v", ssid, channels)
	} else {
		utilities.Info("已锁定目标 %q：%d 个 BSSID · 信道 %v", ssid, len(macs), channels)
	}

	return macs, channels, nil
}

// startIDSFrameFeed 尽力而为地启动帧级监测：
// 返回 nil 表示帧源不可用（无特权/平台限制），IDS 自动降级为纯扫描差分。
// watchChannels 非空时 monitor 跳频钉在目标信道，不做全频段轮转。
func startIDSFrameFeed(
	ctx context.Context,
	ifaceName string,
	watchChannels []int,
	engine *wids.Engine,
	alertsCh chan<- []wids.Alert,
) (platformcapture.Source, func()) {
	noop := func() {}

	switch {
	case utilities.GetOS() == utilities.Linux && !isTermux():
		return startLinuxIDSFrameFeed(ctx, watchChannels, engine, alertsCh)
	case utilities.GetOS() == utilities.Darwin || utilities.GetOS() == utilities.Windows:
		return start80211IDSFrameFeed(ctx, ifaceName, engine, alertsCh, false)
	default:
		utilities.Info("当前平台无帧级监测能力，启用扫描差分引擎（免 root）")
		return nil, noop
	}
}

// startLinuxIDSFrameFeed 在无线 PHY 上建 monitor VIF 后读原始 802.11 帧：
// 需要 root（CAP_NET_ADMIN）；失败时尝试直连读——managed 模式下 DLT
// 是以太网，classify 阶段会静默丢弃，最终给出降级说明。
func startLinuxIDSFrameFeed(
	ctx context.Context,
	watchChannels []int,
	engine *wids.Engine,
	alertsCh chan<- []wids.Alert,
) (platformcapture.Source, func()) {
	noop := func() {}

	wireless, err := FindWirelessInterface()
	if err != nil {
		utilities.Info("未找到无线接口，帧级监测不可用：%v", err)
		return nil, noop
	}

	monitorName, own, err := prepareMonitor(wireless)
	if err != nil {
		utilities.Info("帧级监测需要 root（sudo）创建 monitor 接口：%v；已降级为仅扫描差分", err)
		return start80211IDSFrameFeed(ctx, wireless.Name, engine, alertsCh, true)
	}

	source, err := platformcapture.Open(monitorName)
	if err != nil {
		if own {
			_ = linux.DeleteInterface(monitorName)
		}
		utilities.Info("monitor 接口 %s 打开失败：%v；已降级为仅扫描差分", monitorName, err)
		return nil, noop
	}

	go hopIDSChannels(ctx, monitorName, watchChannels)
	go feedIDSFrames(ctx, source, engine, alertsCh)

	engine.SetOurMAC(wireless.HardwareAddr)

	if len(watchChannels) > 0 {
		utilities.Info("帧级监测已启用：monitor 接口 %s（钉在目标信道 %v，含 deauth 风暴与信标泛洪检测）", monitorName, watchChannels)
	} else {
		utilities.Info("帧级监测已启用：monitor 接口 %s（跳频覆盖 2.4/5GHz，含 deauth 风暴与信标泛洪检测）", monitorName)
	}

	stop := func() {
		_ = source.Close()
		if own {
			_ = linux.DeleteInterface(monitorName)
		}
	}

	return source, stop
}

// start80211IDSFrameFeed 直接在指定网卡上打开帧源并按 DLT 分诊：
// DLT 127（radiotap）/105（裸 802.11）才有管理帧；以太网视角说明
// 网卡处于连接态，管理帧不可见，如实降级而不是假装在检测。
// silent 参数用于 Linux 降级路径：失败原因已由上游打印，不再重复。
func start80211IDSFrameFeed(
	ctx context.Context,
	ifaceName string,
	engine *wids.Engine,
	alertsCh chan<- []wids.Alert,
	silent bool,
) (platformcapture.Source, func()) {
	noop := func() {}

	if ifaceName == "" {
		wireless, err := FindWirelessInterface()
		if err != nil {
			if !silent {
				utilities.Info("未找到无线接口，帧级监测不可用：%v", err)
			}
			return nil, noop
		}

		ifaceName = wireless.Name
		engine.SetOurMAC(wireless.HardwareAddr)
	}

	source, err := platformcapture.Open(ifaceName)
	if err != nil {
		if !silent {
			utilities.Info("帧级监测不可用（%s）：%v；已降级为仅扫描差分", ifaceName, err)
		}
		return nil, noop
	}

	linkType := source.LinkType()
	if linkType != platformcapture.LinkTypeIEEE80211Radio && linkType != 105 {
		_ = source.Close()
		if !silent {
			utilities.Info(
				"接口 %s 链路为以太网视角（DLT %d），空中管理帧不可见；已降级为仅扫描差分",
				ifaceName, linkType,
			)
		}
		return nil, noop
	}

	go feedIDSFrames(ctx, source, engine, alertsCh)

	if !silent {
		utilities.Info(
			"帧级监测已启用：接口 %s（连接态客户端视角：可检测针对本机的 deauth 与当前信道信标）",
			ifaceName,
		)
	}

	return source, func() { _ = source.Close() }
}

// hopIDSChannels 让 monitor 接口在信道序列上轮转：
// 单信道只能看到本信道的管理帧，跳频是单网卡 IDS 覆盖面的下限手段。
// channels 非空（锁定 SSID 时）只轮转目标信道，其余时间留在目标上。
// DFS/不支持信道由 SetChannel 报错，静默跳过即可。
func hopIDSChannels(ctx context.Context, monitorName string, channels []int) {
	if len(channels) == 0 {
		channels = idsHopChannels
	}

	for index := 0; ; index = (index + 1) % len(channels) {
		_ = linux.SetChannel(monitorName, channels[index])

		select {
		case <-ctx.Done():
			return
		case <-time.After(idsHopInterval):
		}
	}
}

// feedIDSFrames 从帧源持续读取并喂给引擎；告警经 alertsCh 送主循环渲染，
// 保证所有终端输出都从单一线程发生，彩色日志不会交错。
func feedIDSFrames(ctx context.Context, source platformcapture.Source, engine *wids.Engine, alertsCh chan<- []wids.Alert) {
	for ctx.Err() == nil {
		frame, err := source.Read()
		if err != nil {
			if errors.Is(err, platformcapture.ErrReadTimeout) {
				continue
			}

			utilities.Warn("帧级监测读取终止：%v", err)
			return
		}

		alerts := classifyIDSFrame(source.LinkType(), frame, engine, time.Now())
		if len(alerts) == 0 {
			continue
		}

		select {
		case alertsCh <- alerts:
		case <-ctx.Done():
			return
		}
	}
}

// classifyIDSFrame 把一条原始帧折算成引擎事件：
// DLT 127 先剥 radiotap（it_len 自描述），DLT 105 直接解析，
// 其余（以太网视角）静默丢弃——连接态链路上没有 802.11 管理帧。
func classifyIDSFrame(linkType uint32, frame []byte, engine *wids.Engine, at time.Time) []wids.Alert {
	payload := frame

	switch linkType {
	case platformcapture.LinkTypeIEEE80211Radio:
		length, ok := ieee80211.RadioTapLen(frame)
		if !ok {
			return nil
		}
		payload = frame[length:]
	case 105:
	default:
		return nil
	}

	info, err := ieee80211.ParseManagement(payload)
	if err != nil {
		return nil
	}

	var kind wids.FrameKind

	switch info.Subtype {
	case ieee80211.SubtypeDeauth:
		kind = wids.FrameDeauth
	case ieee80211.SubtypeDisassoc:
		kind = wids.FrameDisassoc
	case ieee80211.SubtypeBeacon, ieee80211.SubtypeProbeResp:
		kind = wids.FrameBeacon
	default:
		return nil
	}

	return engine.ObserveFrame(kind, info.Transmitter.String(), info.Receiver.String(), at)
}

// runIDSScanLoop 驱动扫描节拍：首轮建立基线，之后每轮差分渲染告警；
// 帧源告警经 alertsCh 并入同一渲染路径。targetSSID 非空表示锁定模式。
func runIDSScanLoop(ctx context.Context, engine *wids.Engine, alertsCh <-chan []wids.Alert, targetSSID string, frameEngine bool) {
	mode := "扫描差分"
	if frameEngine {
		mode = "扫描差分 + 帧级监测"
	}

	if targetSSID != "" {
		utilities.Info("无线入侵检测启动（%s）· 目标 %q · 扫描间隔 %s · Ctrl-C 结束", mode, targetSSID, idsScanInterval)
	} else {
		utilities.Info("无线入侵检测启动（%s）· 全空域 · 扫描间隔 %s · Ctrl-C 结束", mode, idsScanInterval)
	}

	ticker := time.NewTicker(idsScanInterval)
	defer ticker.Stop()

	rounds := 0

	for {
		for _, alert := range engine.Observe(idsSnapshot(), time.Now()) {
			printIDSAlert(alert)
		}

		rounds++
		if rounds == 1 {
			utilities.Info("基线已建立（首轮扫描不做差分），进入持续监测")
		} else {
			utilities.Info("快照 #%d 完成 · 继续监测", rounds)
		}

		select {
		case <-ctx.Done():
			return
		case incoming := <-alertsCh:
			for _, alert := range incoming {
				printIDSAlert(alert)
			}
		case <-ticker.C:
		}
	}
}

// idsSnapshot 把 scanNetworks 的结果折算成引擎观察集。
// 扫描失败不致命：返回空集，基线保持不变，下一轮重试。
func idsSnapshot() []wids.Observation {
	networks, err := scanNetworks()
	if err != nil {
		utilities.Warn("无线扫描失败（保留既有基线）：%v", err)
		return nil
	}

	observations := make([]wids.Observation, 0, len(networks))

	for _, network := range networks {
		observations = append(observations, wids.Observation{
			SSID:    strings.TrimSpace(network.ESSID),
			BSSID:   normalizeMAC(network.BSSID),
			Channel: network.Channel,
			Enc:     strings.ToUpper(network.Enc),
			Cipher:  strings.ToUpper(network.Cipher),
			Auth:    strings.ToUpper(network.Auth),
		})
	}

	return observations
}

// printIDSAlert 按等级着色渲染一条告警行：
// 严重=红、警告=黄、提示=灰；时间取本地时钟便于与系统日志对账。
func printIDSAlert(alert wids.Alert) {
	color := constants.ColorRed

	switch alert.Severity {
	case wids.SevWarning:
		color = constants.ColorYellow
	case wids.SevInfo:
		color = constants.ColorGray
	}

	fmt.Printf(
		"%s[%s]%s %s %s · %s — %s\n",
		color,
		alert.Severity,
		constants.ColorReset,
		alert.Time.Format("15:04:05"),
		alert.Kind,
		alert.Subject,
		alert.Detail,
	)
}

// printIDSSummary 输出会话总结：追踪规模、告警分布与重点帧来源。
func printIDSSummary(engine *wids.Engine) {
	report := engine.Summary()

	total := 0
	parts := make([]string, 0, len(report.AlertTotals))

	kinds := make([]wids.Kind, 0, len(report.AlertTotals))
	for kind := range report.AlertTotals {
		kinds = append(kinds, kind)
	}

	sort.Slice(kinds, func(i, j int) bool {
		return report.AlertTotals[kinds[i]] > report.AlertTotals[kinds[j]]
	})

	for _, kind := range kinds {
		parts = append(parts, fmt.Sprintf("%s %d", kind, report.AlertTotals[kind]))
		total += report.AlertTotals[kind]
	}

	utilities.Info(
		"检测结束：追踪 %d 个 BSSID · deauth %d 帧 · disassoc %d 帧 · 告警 %d 条",
		report.TrackedAPs, report.FrameDeauth, report.FrameDisassoc, total,
	)

	if total == 0 {
		utilities.Info("整个会话零告警，当前空域基线稳定")
		return
	}

	utilities.Info("告警分布：%s", strings.Join(parts, " · "))

	for _, offender := range report.Offenders {
		if offender.Deauth+offender.Disassoc == 0 {
			continue
		}

		utilities.Warn(
			"重点来源 %s：deauth×%d · disassoc×%d",
			offender.MAC, offender.Deauth, offender.Disassoc,
		)
	}
}
