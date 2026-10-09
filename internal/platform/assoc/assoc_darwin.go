package assoc

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
)

// Native 是 macOS 本机网卡关联器，经 networksetup 发起系统级关联。
// 纯 exec 实现，不动 CoreWLAN：CGO 路径需要 .m 编译链，
// 而 networksetup 是系统自带命令，退出码即可判定密码对错。
type Native struct {
	iface string
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
func (n *Native) Associate(ssid, password string) (bool, error) {
	out, err := exec.Command("networksetup", "-setairportnetwork", n.iface, ssid, password).CombinedOutput()
	if err != nil {
		if bytes.Contains(out, []byte("Failed to join")) {
			return false, nil
		}
		return false, fmt.Errorf("关联尝试执行失败：%s", bytes.TrimSpace(out))
	}
	return true, nil
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
