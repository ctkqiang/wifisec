//go:build android

package capture

import (
	"errors"
	"fmt"
	"net"
	"syscall"
)

// 单次读取可容纳的最大帧；常规以太网 1500 MTU 加头绰绰有余。
const readBufferSize = 65535

// rawSource 封装 AF_PACKET/SOCK_RAW 套接字。Android 与 Linux 共享同一套
// 内核 ABI，实现与 capture_linux.go 完全一致；独立文件是因为 Go 的
// _linux.go 文件名后缀不会覆盖 android 构建标签（与注入器同样的处理）。
type rawSource struct {
	fd       int
	buffer   []byte
	linkType uint32
}

// htons 把主机字节序转网络字节序，仅用于 sockaddr_ll 的 protocol 字段。
func htons(value uint16) uint16 {
	return (value << 8) | (value >> 8)
}

// Open 在 ifaceName 上打开原始读取套接字，进程必须具有 root（tsu/su）。
func Open(ifaceName string) (Source, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("获取接口 %s 索引失败：%w", ifaceName, err)
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			return nil, errors.New("抓包需要 root 权限（请使用 tsu 或 su 运行）")
		}

		return nil, fmt.Errorf("创建 AF_PACKET 套接字失败：%w", err)
	}

	bindAddr := syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL),
		Ifindex:  iface.Index,
	}

	if err := syscall.Bind(fd, &bindAddr); err != nil {
		_ = syscall.Close(fd)

		return nil, fmt.Errorf("绑定套接字到接口 %s 失败：%w", ifaceName, err)
	}

	timeout := syscall.Timeval{Usec: 500000}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &timeout); err != nil {
		_ = syscall.Close(fd)

		return nil, fmt.Errorf("设置套接字读超时失败：%w", err)
	}

	return &rawSource{
		fd:       fd,
		buffer:   make([]byte, readBufferSize),
		linkType: LinkTypeEthernet,
	}, nil
}

// Read 返回一帧含以太网头的完整报文。
func (source *rawSource) Read() ([]byte, error) {
	for {
		n, err := syscall.Read(source.fd, source.buffer)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
				return nil, ErrReadTimeout
			}

			return nil, fmt.Errorf("读取 AF_PACKET 套接字失败：%w", err)
		}

		if n == 0 {
			continue
		}

		return source.buffer[:n], nil
	}
}

// LinkType managed 模式固定为 DLT_EN13MB。
func (source *rawSource) LinkType() uint32 {
	return source.linkType
}

// Close 关闭底层套接字。
func (source *rawSource) Close() error {
	if source.fd < 0 {
		return nil
	}

	err := syscall.Close(source.fd)
	source.fd = -1

	return err
}
