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

// helperWaitTimeout 是终端实例等待 helper（系统弹窗 + CoreWLAN 扫描）
// 回传结果的最长时间，必须覆盖用户阅读弹窗文案并做出选择的时间。
const helperWaitTimeout = 120 * time.Second

// enrichMacOSBSSID 通过 helper 架构补全所有接入点（含未连接网络）的真实 BSSID。
//
// macOS TCC 模型下，终端内进程的「责任进程」归属终端宿主（系统终端 / IDE），
// 该链路永远无法直接获得定位授权或未脱敏 BSSID；真正持有授权的是经
// LaunchServices 激活的 wifisec.app。因此主流程先做一次零成本直接扫描
// （兼容未来系统行为变化与已声明定位用途的终端），未获 BSSID 时唤起
// .app helper：由它弹系统授权窗、执行扫描，结果经文件回传，终端负责渲染。
func enrichMacOSBSSID(networks []WiFiNetwork) {
	// 快速路径：当前进程直接能拿到（已授权的终端宿主、或系统策略放宽）。
	if mergeCoreWLANScan(networks) {
		return
	}

	// root 进程位于当前登录用户的 GUI 会话之外，无法呈现 TCC 弹窗，
	// 也不能替当前用户唤起可交互的 LaunchServices helper。
	if os.Geteuid() == 0 {
		fmt.Printf("%s提示：扫描不需要 sudo，改用普通权限运行并允许定位后可显示全部 BSSID%s\n",
			constants.ColorGray, constants.ColorReset)
		return
	}

	// 正式路径：唤起 .app helper。首次使用系统会弹定位窗，点「允许」即可；
	// 已授权后 helper 静默完成，不再打扰。
	fmt.Println("正在通过 macOS 定位服务获取 BSSID… 首次使用请在系统弹窗中点「允许」。")

	cwNetworks, status, err := platformdarwin.ScanViaHelper(helperWaitTimeout)
	if err == nil && status.Authorized() {
		if mergeNetworks(networks, cwNetworks) {
			return
		}
	}

	if hasMissingBSSID(networks) {
		fmt.Printf("%s未获得定位权限，BSSID 暂显示为 - 。可在 系统设置 → 隐私与安全性 → 定位服务 → wifisec 中开启。%s\n",
			constants.ColorGray, constants.ColorReset)
	}
}

// mergeCoreWLANScan 在当前进程内直接执行 CoreWLAN 扫描并合并。
// 返回 true 表示本次扫描实际带回了至少一个真实 BSSID。
func mergeCoreWLANScan(networks []WiFiNetwork) bool {
	cwNetworks, err := platformdarwin.ScanNetworks()
	if err != nil || len(cwNetworks) == 0 {
		return false
	}

	return mergeNetworks(networks, cwNetworks)
}

// mergeNetworks 把一批 CoreWLAN 扫描结果合并进主表，
// 返回这批数据中是否存在真实 BSSID。
func mergeNetworks(networks []WiFiNetwork, cwNetworks []platformdarwin.Network) bool {
	hadBSSID := false

	for _, cw := range cwNetworks {
		if bssidPresent(cw.BSSID) {
			hadBSSID = true
			break
		}
	}

	if !hadBSSID {
		return false
	}

	MergeCoreWLANBSSID(networks, cwNetworks)
	return true
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
