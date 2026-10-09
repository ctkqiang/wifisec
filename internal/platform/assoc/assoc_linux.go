//go:build linux && !android

package assoc

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// Native 是 Linux 本机网卡关联器，经 NetworkManager（nmcli）尝试关联。
type Native struct {
	iface, lastBSSID string
}

// profileName 是爆破用的临时连接配置名。固定名字而非 SSID：
// 用户系统里可能已有同名 SSID 的自己的配置，按 SSID 删除会误伤。
const profileName = "wifisec-brute"

// NewNative 检查 nmcli 可用并定位受管 WiFi 接口。
func NewNative() (*Native, error) {
	if _, err := exec.LookPath("nmcli"); err != nil {
		return nil, errors.New("未找到 nmcli：Linux 本机爆破依赖 NetworkManager；无 NetworkManager 的环境（如容器/精简发行版）请使用 ESP 协处理器")
	}
	out, err := exec.Command("nmcli", "-t", "-f", "DEVICE,TYPE", "dev").Output()
	if err != nil {
		return nil, fmt.Errorf("枚举网络接口失败：%w", err)
	}
	for line := range strings.SplitSeq(string(out), "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 && parts[1] == "wifi" {
			return &Native{iface: parts[0]}, nil
		}
	}
	return nil, errors.New("未找到受 NetworkManager 管理的 WiFi 接口")
}

// Associate 用一次性连接配置尝试关联。
// 流程：add（固定 con-name）→ up（--wait 15 限定等待上限）→ delete。
// 密码错误时 NetworkManager 默认等满 90 秒才放弃，远超 AP 真实拒绝窗口，
// 必须压缩；无论成败都删除配置，不留带错误密码的持久化配置污染系统。
func (n *Native) Associate(ssid, password string) (bool, error) {
	// 清掉上一次可能残留的配置（进程被 kill 时会留下）
	exec.Command("nmcli", "con", "delete", profileName).Run()

	add := exec.Command("nmcli", "con", "add", "type", "wifi",
		"con-name", profileName, "ifname", n.iface, "ssid", ssid,
		"wifi-sec.key-mgmt", "wpa-psk", "wifi-sec.psk", password)
	if out, err := add.CombinedOutput(); err != nil {
		return false, fmt.Errorf("创建临时连接配置失败：%s", bytes.TrimSpace(out))
	}
	defer exec.Command("nmcli", "con", "delete", profileName).Run()

	up := exec.Command("nmcli", "--wait", "15", "con", "up", profileName)
	out, err := up.CombinedOutput()
	if err != nil {
		return false, nil
	}
	if !bytes.Contains(out, []byte("successfully activated")) {
		return false, nil
	}
	// 必须在 defer 删除配置断连之前缓存 BSSID。
	n.lastBSSID = n.queryActiveBSSID()
	return true, nil
}

// ConnectedBSSID 返回最近一次成功关联时记录的 BSSID；查不到为空串。
func (n *Native) ConnectedBSSID(string) string {
	return n.lastBSSID
}

// queryActiveBSSID 取当前激活连接的 BSSID。nmcli -t 模式把 BSSID 内的
// 冒号转义为 \:（防与字段分隔符混淆），解析后需还原。
func (n *Native) queryActiveBSSID() string {
	out, err := exec.Command("nmcli", "-t", "-f", "ACTIVE,BSSID", "dev", "wifi", "list").Output()
	if err != nil {
		return ""
	}
	for line := range strings.SplitSeq(string(out), "\n") {
		rest, ok := strings.CutPrefix(line, "yes:")
		if !ok {
			continue
		}
		return strings.ReplaceAll(rest, `\:`, ":")
	}
	return ""
}
