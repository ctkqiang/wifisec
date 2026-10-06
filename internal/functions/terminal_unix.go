//go:build darwin || linux || android

package functions

import (
	"runtime"
	"syscall"
	"unsafe"
)

const (
	// sysIoctl 为 ioctl 系统调用号，Linux amd64/arm64（Termux 主流环境）与 macOS 均为 54。
	sysIoctl = 54

	// TIOCGWINSZ 请求码：Linux/Android 为 0x5413，macOS 为 0x40087468。
	tiocGWinszLinux  = 0x5413
	tiocGWinszDarwin = 0x40087468
)

// winsize 对应 TIOCGWINSZ 的返回结构。
type winsize struct {
	rows, cols, xpixel, ypixel uint16
}

// terminalColumnWidth 通过 TIOCGWINSZ 查询终端列数。
// 管道或重定向场景下 fd 不是终端，ioctl 失败即返回 0（不限宽），
// 保证落盘输出的数据完整性。
func terminalColumnWidth() int {
	// 同一 Unix 分支内 macOS 与 Linux 请求码不同，按运行时平台取值。
	request := uintptr(tiocGWinszLinux)
	if runtime.GOOS == "darwin" {
		request = tiocGWinszDarwin
	}

	var size winsize
	_, _, errno := syscall.Syscall(
		sysIoctl,
		uintptr(syscall.Stdout),
		request,
		uintptr(unsafe.Pointer(&size)),
	)
	if errno != 0 || size.cols == 0 {
		return 0
	}

	return int(size.cols)
}
