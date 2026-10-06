//go:build windows

package functions

import (
	"syscall"
	"unsafe"
)

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleInfo = kernel32.NewProc("GetConsoleScreenBufferInfo")
)

type windowsCoord struct {
	x, y int16
}

type windowsSmallRect struct {
	left, top, right, bottom int16
}

// consoleScreenBufferInfo 对应 Windows API 的 CONSOLE_SCREEN_BUFFER_INFO。
type consoleScreenBufferInfo struct {
	size              windowsCoord
	cursorPosition    windowsCoord
	attributes        uint16
	window            windowsSmallRect
	maximumWindowSize windowsCoord
}

// terminalColumnWidth 通过 GetConsoleScreenBufferInfo 读取控制台窗口列数。
// 管道或重定向场景下句柄不是控制台，调用失败即返回 0（不限宽），
// 与 Unix 分支的兜底语义保持一致。
func terminalColumnWidth() int {
	var info consoleScreenBufferInfo
	ret, _, _ := procGetConsoleInfo.Call(
		uintptr(syscall.Stdout),
		uintptr(unsafe.Pointer(&info)),
	)
	if ret == 0 {
		return 0
	}

	width := int(info.window.right-info.window.left) + 1
	if width <= 0 {
		return 0
	}

	return width
}
