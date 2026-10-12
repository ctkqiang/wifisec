// Package gui 提供跨平台 GUI 权限提示弹窗能力。
// Linux 上探测 zenity → 回退 kdialog → 都不可用则静默回退到终端文本。

//go:build linux

package gui

import (
	"os/exec"
	"time"
)

// dialogTimeout 是 GUI 弹窗的最大存活时间，防止 GUI 卡死阻塞命令行。
const dialogTimeout = 10 * time.Second

// ShowPermissionDialog 在 Linux 上弹出 GUI 权限提示弹窗。
// 优先探测 zenity（GTK 风格），回退到 kdialog（KDE 风格），
// 两者都不可用时静默回退，调用方照常输出终端错误。
func ShowPermissionDialog(title, message string) error {
	if path, err := exec.LookPath("zenity"); err == nil {
		return runDialog(path, "--info", "--title="+title, "--text="+message, "--width=400")
	}

	if path, err := exec.LookPath("kdialog"); err == nil {
		return runDialog(path, "--msgbox", message, "--title", title)
	}

	// 两个 GUI 前端都不存在，静默回退到终端文本。
	return nil
}

// runDialog 执行 GUI 命令，带超时保护。
// GUI 卡死或用户长时间不关弹窗时不会阻塞命令行流程。
func runDialog(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	timer := time.AfterFunc(dialogTimeout, func() {
		_ = cmd.Process.Kill()
	})
	defer timer.Stop()

	return cmd.Run()
}
