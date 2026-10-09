package assoc

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Native 是 Windows 本机网卡关联器，经 netsh 临时无线配置尝试关联。
type Native struct {
	profilePath, lastBSSID string
}

// profileName 是爆破用的临时配置名。固定名字而非 SSID，避免误删用户已有配置。
const profileName = "wifisec-brute"

// NewNative 准备临时配置文件的落盘位置。
func NewNative() (*Native, error) {
	return &Native{profilePath: filepath.Join(os.TempDir(), "wifisec-brute-profile.xml")}, nil
}

// Associate 写入临时 WLAN 配置并发起连接。
// netsh connect 的返回只表示「请求已受理」，不代表关联成功——
// 成败必须轮询 netsh wlan show interfaces 的接口状态判定。
// 无论成败都删除临时配置，不留错误密码的持久化配置。
func (n *Native) Associate(ssid, password string) (bool, error) {
	if err := os.WriteFile(n.profilePath, []byte(profileXML(ssid, password)), 0o600); err != nil {
		return false, fmt.Errorf("写入临时无线配置失败：%w", err)
	}
	defer os.Remove(n.profilePath)

	if out, err := exec.Command("netsh", "wlan", "add", "profile", "filename="+n.profilePath).CombinedOutput(); err != nil {
		return false, fmt.Errorf("导入临时无线配置失败：%s", bytes.TrimSpace(out))
	}
	defer exec.Command("netsh", "wlan", "delete", "profile", "name="+profileName).Run()

	exec.Command("netsh", "wlan", "connect", "name="+profileName).Run()

	// 关联是异步的：轮询 12 秒，接口进入 connected 且 SSID 匹配才算命中。
	for range 12 {
		time.Sleep(time.Second)
		out, _ := exec.Command("netsh", "wlan", "show", "interfaces").Output()
		if associatedWith(string(out), ssid) {
			// 在 defer 删除配置断连之前，从同一份输出里缓存 BSSID。
			n.lastBSSID = parseBSSID(string(out))
			return true, nil
		}
	}
	return false, nil
}

// ConnectedBSSID 返回最近一次成功关联时记录的 BSSID；查不到为空串。
func (n *Native) ConnectedBSSID(string) string {
	return n.lastBSSID
}

// parseBSSID 从 netsh wlan show interfaces 输出取 BSSID 字段值。
func parseBSSID(out string) string {
	for line := range strings.Lines(out) {
		trimmed := strings.TrimSpace(line)
		rest, ok := strings.CutPrefix(trimmed, "BSSID")
		if ok {
			return strings.TrimLeft(rest, " \t:")
		}
	}
	return ""
}

// associatedWith 判定接口状态输出中目标 SSID 已连接。
// netsh 输出随系统语言本地化，State 同时匹配中英文。
func associatedWith(out, ssid string) bool {
	seenSSID, connected := false, false
	for line := range strings.Lines(out) {
		trimmed := strings.TrimSpace(line)
		// 排除 BSSID 行：只认行首的 SSID 字段
		if strings.HasPrefix(trimmed, "SSID") && strings.Contains(trimmed, ssid) {
			seenSSID = true
		}
		if (strings.HasPrefix(trimmed, "State") || strings.HasPrefix(trimmed, "状态")) &&
			(strings.Contains(trimmed, "connected") || strings.Contains(trimmed, "已连接")) {
			connected = true
		}
	}
	return seenSSID && connected
}

// profileXML 生成 WPA2-PSK 临时配置。SSID 与密码经 XML 转义。
func profileXML(ssid, password string) string {
	return `<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
	<name>` + profileName + `</name>
	<SSIDConfig><SSID><name>` + xmlEscape(ssid) + `</name></SSID></SSIDConfig>
	<connectionType>ESS</connectionType>
	<connectionMode>manual</connectionMode>
	<MSM><security>
		<authEncryption><authentication>WPA2PSK</authentication><encryption>AES</encryption><useOneX>false</useOneX></authEncryption>
		<sharedKey><keyType>passPhrase</keyType><protected>false</protected><keyMaterial>` + xmlEscape(password) + `</keyMaterial></sharedKey>
	</security></MSM>
</WLANProfile>`
}

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}
