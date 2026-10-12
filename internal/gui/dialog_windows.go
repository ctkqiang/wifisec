// Package gui 提供跨平台 GUI 权限提示弹窗能力。
// Windows 上调用 user32.dll 的 MessageBoxW。

//go:build windows

package gui

import (
	"syscall"
	"unsafe"
)

const (
	mbOK              = 0x00000000
	mbIconInformation = 0x00000040
)

// ShowPermissionDialog 在 Windows 上弹出 MessageBoxW 权限提示弹窗。
// 调用 user32.dll 的 MessageBoxW，标题栏显示 "wifisec"，
// 消息体使用中文说明，图标为信息（i）样式。
func ShowPermissionDialog(title, message string) error {
	user32 := syscall.NewLazyDLL("user32.dll")
	procMessageBoxW := user32.NewProc("MessageBoxW")

	titlePtr, _ := syscall.UTF16PtrFromString(title)
	messagePtr, _ := syscall.UTF16PtrFromString(message)

	_, _, _ = procMessageBoxW.Call(
		0,
		uintptr(unsafe.Pointer(messagePtr)),
		uintptr(unsafe.Pointer(titlePtr)),
		mbOK|mbIconInformation,
	)

	return nil
}
