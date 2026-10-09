package assoc

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Native 是 macOS 本机网卡关联器，经 networksetup 发起系统级关联。
// 纯 exec 实现，不动 CoreWLAN：CGO 路径需要 .m 编译链，
// 而 networksetup 是系统自带命令，退出码即可判定密码对错。
type Native struct {
	iface, lastBSSID string
}

// NewNative 定位 Wi-Fi 接口（通常 en0）。
func NewNative() (*Native, error) {
	out, err := exec.Command("networksetup", "-listallhardwareports").Output()
	if err != nil {
		return nil, fmt.Errorf("枚举网络硬件端口失败：%w", err)
	}
	iface := parseWiFiDevice(out)
	if iface == "" {
		return nil, errors.New("未找到 Wi-Fi 接口")
	}
	return &Native{iface: iface}, nil
}

// Associate 经 networksetup -setairportnetwork 尝试关联。
// 密码错误时命令非零退出且输出含「Failed to join」，属正常爆破路径；
// 其余非零退出（接口被占用、参数非法）按错误上抛。
//
// 注意：networksetup 返回 0 只代表 join 请求被系统受理，不代表关联
// 完成——直接当真会产生「受理了但没连上」的假命中。必须轮询
// -getairportnetwork 确认接口真实接入目标 SSID 才算密码正确。
func (n *Native) Associate(ssid, password string) (bool, error) {
	out, err := exec.Command("networksetup", "-setairportnetwork", n.iface, ssid, password).CombinedOutput()
	if err != nil {
		if bytes.Contains(out, []byte("Failed to join")) {
			return false, nil
		}
		return false, fmt.Errorf("关联尝试执行失败：%s", bytes.TrimSpace(out))
	}

	// 轮询确认真实关联：最长 10 秒，接口当前网络名与目标精确一致才算命中。
	for range 10 {
		time.Sleep(time.Second)
		if n.currentSSID() == ssid {
			// 关联当下立刻缓存 BSSID：事后查询时连接可能已被系统重置。
			n.lastBSSID = queryBSSID()
			return true, nil
		}
	}
	return false, nil
}

// ConnectedBSSID 返回最近一次成功关联时记录的 BSSID；查不到为空串。
func (n *Native) ConnectedBSSID(string) string {
	return n.lastBSSID
}

// currentSSID 查询接口当前接入的 SSID；未关联时 networksetup 输出
// 「You are not associated with an AirPort network.」，返回空串。
func (n *Native) currentSSID() string {
	out, err := exec.Command("networksetup", "-getairportnetwork", n.iface).Output()
	if err != nil {
		return ""
	}
	rest, ok := strings.CutPrefix(strings.TrimSpace(string(out)), "Current Wi-Fi Network:")
	if !ok {
		return ""
	}
	return strings.TrimSpace(rest)
}

// queryBSSID 经 wdutil 查询当前连接的 BSSID。wdutil 为 macOS 14+ 自带；
// 未获定位授权时系统把 BSSID 脱敏为 <redacted>，未关联时输出 None，
// 两者都返回空串由调用方标注。
func queryBSSID() string {
	out, err := exec.Command("wdutil", "info").Output()
	if err != nil {
		return ""
	}
	for line := range strings.SplitSeq(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "BSSID") {
			continue
		}
		rest := strings.TrimLeft(strings.TrimPrefix(trimmed, "BSSID"), " \t:")
		if rest == "" || rest == "None" || strings.Contains(rest, "<redacted>") {
			return ""
		}
		return rest
	}
	return ""
}

// parseWiFiDevice 从 networksetup -listallhardwareports 输出取 Wi-Fi 设备名。
// 输出按「Hardware Port: 名称」+「Device: enX」成对出现，取第一对 Wi-Fi。
func parseWiFiDevice(out []byte) string {
	lines := bytes.Split(out, []byte("\n"))
	for i, line := range lines {
		if bytes.Contains(line, []byte("Hardware Port: Wi-Fi")) && i+1 < len(lines) {
			return string(bytes.TrimSpace(bytes.TrimPrefix(lines[i+1], []byte("Device:"))))
		}
	}
	return ""
}
