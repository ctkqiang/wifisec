package termux

import (
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
	"time"
)

const (
	connectionInfoTimeout = 15 * time.Second
	scanInfoTimeout       = 20 * time.Second
)

// ErrTermuxAPIMissing 表示未安装 termux-api CLI / Termux:API 应用。
var ErrTermuxAPIMissing = errors.New(
	"Android 无 root 无法直接扫描：请安装 Termux:API 应用，并在 Termux 内执行 pkg install termux-api",
)

// ErrScanUnavailable 表示 Termux:API 已安装但拿不到任何 Wi-Fi 数据。
// Android 9+ 普遍对周边扫描限流或直接封禁，属于系统策略限制。
var ErrScanUnavailable = errors.New(
	"未能从 Termux:API 获取 Wi-Fi 信息：请确认已授予位置权限且 Wi-Fi 已开启；Android 9+ 周边扫描默认被系统限流或禁用")

// Available 判断 Termux:API CLI 是否可用；纯 Go 实现，任意开发机均可编译，
// 是否调用由上层按运行环境（GOOS/PREFIX/TERMUX_VERSION）决定。
func Available() bool {
	_, err := exec.LookPath("termux-wifi-connection-info")
	return err == nil
}

// Scan 优先返回周边扫描结果；新版 Android 普遍封禁该接口，
// 失败时退回只含当前连接网络的 connection-info，两者都不可用才报错。
func Scan() ([]Network, error) {
	if !Available() {
		return nil, ErrTermuxAPIMissing
	}

	connected := queryConnectionInfo()

	// scaninfo 是唯一可能给出周边列表的途径；Android 9+ 多数设备直接返回错误。
	if entries, ok := queryScanInfo(); ok && len(entries) > 0 {
		networks := make([]Network, 0, len(entries))
		for _, entry := range entries {
			network := Network{
				SSID:      entry.SSID,
				BSSID:     normalizeMAC(entry.BSSID),
				Signal:    entry.RSSI,
				Frequency: entry.Frequency,
			}
			network.Security, network.Cipher, network.Authentication = ParseCapabilities(entry.Capabilities)

			if connected != nil && network.BSSID == normalizeMAC(connected.BSSID) {
				network.Connected = true
			}

			networks = append(networks, network)
		}

		return networks, nil
	}

	// 周边扫描不可用时，至少呈现当前连接的网络（真实 BSSID 由系统 API 提供）。
	if connected != nil {
		return []Network{{
			SSID:      connected.SSID,
			BSSID:     normalizeMAC(connected.BSSID),
			Signal:    connected.RSSI,
			Rate:      connected.Speed,
			Frequency: connected.Frequency,
			Connected: true,
		}}, nil
	}

	return nil, ErrScanUnavailable
}

// queryConnectionInfo 读取当前连接信息；任何异常都返回 nil，
// 因为未连接 Wi-Fi 本身不是错误，周边扫描仍可独立成功。
func queryConnectionInfo() *connectionInfo {
	var info connectionInfo

	output, err := run(connectionInfoTimeout, "termux-wifi-connection-info")
	if err != nil {
		return nil
	}

	if json.Unmarshal([]byte(output), &info) != nil || info.Error != "" || info.State != "COMPLETED" {
		return nil
	}

	return &info
}

// queryScanInfo 读取周边扫描；第二返回值为 false 表示接口不可用，
// 调用方据此回退到连接信息。
func queryScanInfo() ([]scanEntry, bool) {
	output, err := run(scanInfoTimeout, "termux-wifi-scaninfo")
	if err != nil {
		return nil, false
	}

	var entries []scanEntry
	if json.Unmarshal([]byte(output), &entries) != nil || len(entries) == 0 {
		return nil, false
	}

	return entries, true
}

func normalizeMAC(raw string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(raw)), "-", ":")
}
