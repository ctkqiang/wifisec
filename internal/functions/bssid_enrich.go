package functions

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
	"wifisec/internal/constants"
	platformdarwin "wifisec/internal/platform/darwin"
)

// authorizationWaitTimeout 是终端实例等待自举授权完成的最长时间，
// 与自举实例弹窗等待时长保持一致，留出系统动画余量。
const authorizationWaitTimeout = 120 * time.Second

// enrichMacOSBSSID 通过 CoreWLAN 补全所有接入点（含未连接网络）的真实 BSSID。
// macOS 隐私模型把 BSSID 归类为精确位置信息：首次使用经 .app 自举触发系统
// 授权弹窗，已授权后静默补全；拒绝、受限或超时时不打断扫描主流程。
func enrichMacOSBSSID(networks []WiFiNetwork) {
	// sudo（root）进程位于当前登录用户的 GUI 会话之外，系统不会呈现 TCC 弹窗，
	// LaunchServices 自举同样无法交互。root 下只在“已经授权过”时直接读取。
	if os.Geteuid() == 0 {
		if platformdarwin.LocationStatus().Authorized() {
			fillBSSIDFromCoreWLAN(networks)
		} else {
			fmt.Printf("%s提示：扫描不需要 sudo，改用普通权限运行并允许定位后可显示全部 BSSID%s\n",
				constants.ColorGray, constants.ColorReset)
		}
		return
	}

	status := platformdarwin.LocationStatus()
	if status == platformdarwin.AuthNotDetermined {
		fmt.Println("macOS 将 Wi-Fi BSSID 视为精确位置信息，系统即将弹出定位授权，请选择「允许」。")
		status = platformdarwin.EnsureAuthorization(authorizationWaitTimeout)
	}

	if !status.Authorized() {
		if hasMissingBSSID(networks) {
			fmt.Printf("%s未获得定位权限，BSSID 暂显示为 - 。可在 系统设置 → 隐私与安全性 → 定位服务 → wifisec 中开启。%s\n",
				constants.ColorGray, constants.ColorReset)
		}
		return
	}

	fillBSSIDFromCoreWLAN(networks)
}

// fillBSSIDFromCoreWLAN 执行 CoreWLAN 扫描并把结果合并进 system_profiler 主数据；
// 扫描失败属于可降级路径（主表格的其他字段仍然完整），静默返回。
func fillBSSIDFromCoreWLAN(networks []WiFiNetwork) {
	cwNetworks, err := platformdarwin.ScanNetworks()
	if err != nil || len(cwNetworks) == 0 {
		return
	}

	MergeCoreWLANBSSID(networks, cwNetworks)
}

// MergeCoreWLANBSSID 按 SSID+信道把 CoreWLAN 扫到的 BSSID 合并进主结果。
// 同名双频网络以信道区分（如 HOME 与 HOME_5G 各有独立信道与 BSSID）；
// 主结果已有真实 BSSID（如 wdutil 提供的已连接网络）时不覆盖。
func MergeCoreWLANBSSID(networks []WiFiNetwork, cwNetworks []platformdarwin.Network) {
	byKey := make(map[string]string, len(cwNetworks))

	for _, cw := range cwNetworks {
		if mac := normalizeMAC(cw.BSSID); mac != "" && mac != ":" {
			byKey[bssidMergeKey(cw.SSID, cw.Channel)] = mac
		}
	}

	for i := range networks {
		if bssidPresent(networks[i].BSSID) {
			continue
		}

		if mac := byKey[bssidMergeKey(networks[i].ESSID, networks[i].Channel)]; mac != "" {
			networks[i].BSSID = mac
		}
	}
}

// bssidMergeKey 构造 BSSID 合并键：同 SSID 在同一信道上视为同一接入点。
func bssidMergeKey(ssid string, channel int) string {
	return ssid + "|" + strconv.Itoa(channel)
}

// bssidPresent 区分真实 MAC 与占位符：解析层对缺失字段统一填 "-"，
// 而 normalizeMAC("-") 会得到 ":"，两种形态都必须视为缺失。
func bssidPresent(bssid string) bool {
	bssid = strings.TrimSpace(bssid)
	return bssid != "" && bssid != "-" && bssid != ":"
}

// hasMissingBSSID 判断是否存在需要定位权限才能补全的行，
// 避免在结果本就完整时还向用户打印权限提示。
func hasMissingBSSID(networks []WiFiNetwork) bool {
	for _, network := range networks {
		if !bssidPresent(network.BSSID) {
			return true
		}
	}

	return false
}
