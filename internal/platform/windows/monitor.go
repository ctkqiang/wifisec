//go:build windows

package windows

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// wlanHelperTimeout 与 netsh 同量级，WlanHelper 切换模式可能阻塞数秒。
	wlanHelperTimeout = 10 * time.Second
)

// SetMonitorMode 通过 Npcap 自带的 WlanHelper.exe 切换适配器 monitor 模式。
// 返回值为切换前是否已是 monitor 模式：true 表示复用现有状态，退出时不回滚；
// false 表示由本进程切换，退出时应调用 SetMonitorMode(..., false) 恢复 managed。
//
// WlanHelper 的 interface 参数接受 Npcap 设备路径（\Device\NPF_{GUID}）或友好名。
func SetMonitorMode(devicePath string, enable bool) (wasActive bool, err error) {
	if !CheckNpcapAvailable() {
		return false, ErrNpcapMissing
	}

	targetMode := "managed"
	if enable {
		targetMode = "monitor"
	}

	output, err := run(wlanHelperTimeout, npcapDir+`\WlanHelper.exe`, devicePath, "mode", targetMode)
	if err != nil {
		detail := err.Error()
		switch {
		case strings.Contains(detail, "you do not have permission"),
			strings.Contains(detail, "Access is denied"):
			return false, errors.New("切换 monitor 模式需要管理员权限，请以管理员身份运行终端")
		case strings.Contains(detail, "does not support monitor"),
			strings.Contains(detail, "not supported"):
			return false, errors.New("网卡驱动不支持 monitor 模式，无法在该适配器上执行 deauth")
		default:
			return false, fmt.Errorf("WlanHelper 切换模式失败：%s", detail)
		}
	}

	// WlanHelper 输出包含 "Current mode: monitor" 或 "Current mode: managed"。
	return strings.Contains(strings.ToLower(output), "current mode: monitor"), nil
}

// SetChannel 通过 WlanHelper 切换适配器信道。
// 仅 monitor 模式下有效；DFS 信道或驱动限制可能导致失败，错误透传给上层。
func SetChannel(devicePath string, channel int) error {
	if !CheckNpcapAvailable() {
		return ErrNpcapMissing
	}

	_, err := run(wlanHelperTimeout, npcapDir+`\WlanHelper.exe`, devicePath, "channel", fmt.Sprintf("%d", channel))
	if err != nil {
		detail := err.Error()
		if strings.Contains(detail, "does not support") || strings.Contains(detail, "invalid") {
			return fmt.Errorf("信道 %d 不被当前适配器/法规域支持", channel)
		}
		return fmt.Errorf("切换信道 %d 失败：%s", channel, detail)
	}

	return nil
}

// CheckNpcapAvailable 是 CheckNpcap 的布尔封装，供 monitor 函数快速探测。
func CheckNpcapAvailable() bool {
	return CheckNpcap() == nil
}
