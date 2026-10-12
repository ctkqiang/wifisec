//go:build darwin

package fwd

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// darwinState 持有被改写的 sysctl 键与其旧值。
// macOS 没有独立的 send_redirects 开关，icmp_rlim（重定向速率上限）
// 置 0 即等效压制；转发开关是 net.inet.ip.forwarding。
type darwinState struct {
	saved map[string]string
}

// enableTargets 是欺骗期间需要改写的 sysctl 键与目标值。
var enableTargets = []struct {
	key string
	on  string
}{
	{key: "net.inet.ip.forwarding", on: "1"},
	{key: "net.inet.icmp.icmp_rlim", on: "0"},
}

// enable 经 sysctl 命令读旧值再写新值；exec 只允许出现在 adapter 层，
// 本文件正是 fwd 包的平台 adapter。
func enable(ifaceName string) (*darwinState, error) {
	_ = ifaceName // macOS 的两个键都是全局的，无按接口版本

	state := &darwinState{saved: make(map[string]string)}

	for _, target := range enableTargets {
		old, err := sysctlRead(target.key)
		if err != nil {
			return nil, err
		}

		if err := sysctlWrite(target.key, target.on); err != nil {
			restoreSaved(state)
			return nil, err
		}

		state.saved[target.key] = old
	}

	return state, nil
}

// disable 按旧值恢复全部键。
func disable(inner any) error {
	state, ok := inner.(*darwinState)
	if !ok {
		return errors.New("fwd Token 类型异常，无法恢复")
	}

	var firstErr error
	for key, old := range state.saved {
		if err := sysctlWrite(key, old); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	return firstErr
}

// restoreSaved 把已改写的键写回旧值；仅在 enable 半途失败时使用。
func restoreSaved(state *darwinState) {
	for key, old := range state.saved {
		_ = sysctlWrite(key, old)
	}
}

// sysctlRead 读取一个 sysctl 键的当前值。
func sysctlRead(key string) (string, error) {
	output, err := exec.Command("sysctl", "-n", key).Output()
	if err != nil {
		return "", fmt.Errorf("读取 sysctl %s 失败（需要 root）：%w", key, err)
	}

	return strings.TrimSpace(string(output)), nil
}

// sysctlWrite 写入一个 sysctl 键的新值。
func sysctlWrite(key, value string) error {
	if output, err := exec.Command("sysctl", "-w", key+"="+value).CombinedOutput(); err != nil {
		return fmt.Errorf("写入 sysctl %s=%s 失败（需要 root）：%s（%w）", key, value, strings.TrimSpace(string(output)), err)
	}

	return nil
}
