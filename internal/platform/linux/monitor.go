package linux

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

const (
	// monitorTimeout 与 scan 同量级，iw 建口/信道切换可能阻塞数秒。
	monitorTimeout = 10 * time.Second
)

// CreateMonitor 在指定 phy 上创建 monitor 模式接口，返回接口名。
// 命名从 wifimon0 开始递增，直到找到未被占用的名字。
// 若 iw 命令缺失或权限不足，返回带明确指导的错误。
func CreateMonitor(phy string) (string, error) {
	if _, err := exec.LookPath("iw"); err != nil {
		return "", errors.New("未找到 iw 命令，请先安装发行版的 iw 包（如 apt install iw）")
	}

	for i := 0; i < 10; i++ {
		name := fmt.Sprintf("wifimon%d", i)
		if _, err := net.InterfaceByName(name); err == nil {
			continue // 名字已被占用，尝试下一个
		}

		_, err := run(monitorTimeout, "iw", "phy", phy, "interface", "add", name, "type", "monitor")
		if err != nil {
			detail := err.Error()
			if strings.Contains(detail, "Operation not permitted") || strings.Contains(detail, "permission denied") {
				return "", errors.New("创建 monitor 接口需要 root 权限（CAP_NET_ADMIN），请使用 sudo 运行")
			}
			return "", fmt.Errorf("iw 创建 monitor 接口失败：%s", detail)
		}

		return name, nil
	}

	return "", errors.New("wifimon0..9 均被占用，请先清理多余的 monitor 接口")
}

// DeleteInterface 删除由本进程创建的 monitor 接口（或任何指定接口）。
// 只应在清理路径调用；不存在的接口由内核返回错误，这里静默忽略。
func DeleteInterface(name string) error {
	if _, err := exec.LookPath("iw"); err != nil {
		return errors.New("未找到 iw 命令，无法删除接口")
	}

	_, err := run(monitorTimeout, "iw", "dev", name, "del")
	if err != nil {
		detail := err.Error()
		// 接口已不存在，视为清理成功。
		if strings.Contains(detail, "No such device") || strings.Contains(detail, "does not exist") {
			return nil
		}
		return fmt.Errorf("删除接口 %s 失败：%s", name, detail)
	}

	return nil
}

// SetInterfaceUp 把接口置为 UP；monitor 接口必须 UP 后才能注入帧。
func SetInterfaceUp(name string) error {
	if _, err := exec.LookPath("ip"); err != nil {
		return errors.New("未找到 ip 命令，请先安装 iproute2")
	}

	_, err := run(monitorTimeout, "ip", "link", "set", name, "up")
	if err != nil {
		detail := err.Error()
		if strings.Contains(detail, "Operation not permitted") || strings.Contains(detail, "permission denied") {
			return errors.New("启用接口需要 root 权限（CAP_NET_ADMIN），请使用 sudo 运行")
		}
		return fmt.Errorf("启用接口 %s 失败：%s", name, detail)
	}

	return nil
}

// SetChannel 切换接口到指定信道；monitor 模式下注入帧前必须对准目标信道。
// 某些信道（如 DFS 52-140）在部分驱动/法规域下可能不允许主动注入，
// 失败时错误透传给上层，由调用方决定是否跳过该目标。
func SetChannel(name string, channel int) error {
	if _, err := exec.LookPath("iw"); err != nil {
		return errors.New("未找到 iw 命令，无法设置信道")
	}

	_, err := run(monitorTimeout, "iw", "dev", name, "set", "channel", fmt.Sprintf("%d", channel))
	if err != nil {
		detail := err.Error()
		if strings.Contains(detail, "Operation not permitted") || strings.Contains(detail, "permission denied") {
			return errors.New("设置信道需要 root 权限（CAP_NET_ADMIN），请使用 sudo 运行")
		}
		return fmt.Errorf("接口 %s 切换信道 %d 失败：%s", name, channel, detail)
	}

	return nil
}
