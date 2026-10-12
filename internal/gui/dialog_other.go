// Package gui 提供跨平台 GUI 权限提示弹窗能力。
// 此文件是 !linux && !windows 的空实现。

//go:build !linux && !windows

package gui

// ShowPermissionDialog 在权限不足时弹出 GUI 提示窗。
// 不可用平台静默返回 nil，调用方照常输出终端错误。
func ShowPermissionDialog(title, message string) error {
	return nil
}
