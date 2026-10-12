//go:build linux

package fwd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Linux 的转发与重定向开关都暴露在 procfs，纯 Go 读写即可，
// 不需要 exec sysctl。all 与具体网卡的 conf 节点都要压：
// 只压 all 时部分内核按「all 与接口值取 max」生效，redirect 仍会发出。
const (
	procIPForward     = "/proc/sys/net/ipv4/ip_forward"
	procRedirectAll   = "/proc/sys/net/ipv4/conf/all/send_redirects"
	procRedirectIface = "/proc/sys/net/ipv4/conf/%s/send_redirects"
)

// linuxState 持有欺骗期间被改写的全部 procfs 节点旧值。
type linuxState struct {
	saved []savedValue
}

// savedValue 是一个已改写节点的旧值备份。
type savedValue struct {
	path string
	old  string
}

// enableTarget 描述一个 procfs 开关：路径与欺骗期间应取的值。
type enableTarget struct {
	path string
	on   string
}

// enable 读旧值→写新值；任何一步失败都把已改过的节点写回，
// 不留下「转发开了、重定向没压」的半吊子状态。
func enable(ifaceName string) (*linuxState, error) {
	targets := []enableTarget{
		{path: procIPForward, on: "1"},
		{path: procRedirectAll, on: "0"},
		{path: fmt.Sprintf(procRedirectIface, filepath.Base(ifaceName)), on: "0"},
	}

	state := &linuxState{}

	for _, target := range targets {
		old, err := readSysctl(target.path)
		if err != nil {
			restoreSaved(state)
			return nil, err
		}

		if err := writeSysctl(target.path, target.on); err != nil {
			restoreSaved(state)
			return nil, err
		}

		state.saved = append(state.saved, savedValue{path: target.path, old: old})
	}

	return state, nil
}

// disable 按旧值恢复；某个节点恢复失败记录首个错误但不中断其余节点。
func disable(inner any) error {
	state, ok := inner.(*linuxState)
	if !ok {
		return errors.New("fwd Token 类型异常，无法恢复")
	}

	var firstErr error
	for _, item := range state.saved {
		if err := writeSysctl(item.path, item.old); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	return firstErr
}

// restoreSaved 把已写入的节点写回旧值；仅在 enable 半途失败时使用。
func restoreSaved(state *linuxState) {
	for _, item := range state.saved {
		_ = writeSysctl(item.path, item.old)
	}
}

// readSysctl 读取 procfs 开关当前值并去掉换行。
func readSysctl(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("读取 %s 失败（需要 root）：%w", path, err)
	}

	return trimNewline(string(raw)), nil
}

// writeSysctl 向 procfs 开关写入新值。
func writeSysctl(path, value string) error {
	if err := os.WriteFile(path, []byte(value), 0); err != nil {
		return fmt.Errorf("写入 %s 失败（需要 root）：%w", path, err)
	}

	return nil
}

// trimNewline 去掉尾部换行与空白。
func trimNewline(text string) string {
	for len(text) > 0 {
		last := text[len(text)-1]
		if last != '\n' && last != '\r' && last != ' ' {
			break
		}

		text = text[:len(text)-1]
	}

	return text
}
