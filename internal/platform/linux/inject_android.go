//go:build android

package linux

import (
	"errors"
	"fmt"
	"net"
	"syscall"
)

// htons 把主机字节序的 uint16 转成网络字节序（大端）。
func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}

// FrameInjector 封装 Android 内核的 AF_PACKET 原始套接字。
// Android 与 Linux 共享同一套内核 ABI，因此实现与 inject_linux.go 完全一致；
// 独立文件是因为 Go 的 _linux.go 文件名后缀不会覆盖 android 构建标签。
type FrameInjector struct {
	fd int
}

// OpenInjector 在指定接口上打开 AF_PACKET/SOCK_RAW 套接字。
// 进程必须具有 root 权限（tsu/su），否则打开套接字会被拒绝。
func OpenInjector(ifaceName string) (*FrameInjector, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("获取接口 %s 索引失败：%w", ifaceName, err)
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			return nil, errors.New("打开原始套接字需要 root 权限（请使用 tsu 或 su 运行）")
		}
		return nil, fmt.Errorf("创建 AF_PACKET 套接字失败：%w", err)
	}

	addr := syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL),
		Ifindex:  iface.Index,
	}

	if err := syscall.Bind(fd, &addr); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("绑定套接字到接口 %s 失败：%w", ifaceName, err)
	}

	return &FrameInjector{fd: fd}, nil
}

// Write 把一帧 802.11 数据注入空中。
func (fi *FrameInjector) Write(frame []byte) error {
	if fi.fd < 0 {
		return errors.New("注入器已关闭")
	}

	_, err := syscall.Write(fi.fd, frame)
	return err
}

// Close 关闭底层套接字。
func (fi *FrameInjector) Close() error {
	if fi.fd < 0 {
		return nil
	}

	err := syscall.Close(fi.fd)
	fi.fd = -1
	return err
}
