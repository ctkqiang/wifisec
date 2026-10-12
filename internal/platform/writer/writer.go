// Package writer 是「向指定网卡发送原始二层帧」的跨平台端口：
// Linux/Android 走 AF_PACKET，macOS 走 /dev/bpf*（O_RDWR 直写），
// Windows 走 Npcap 的 pcap_sendpacket。与 capture 包同构——
// 应用层只见 Port，平台细节全部收在 adapter 层。
//
// 读写使用独立句柄：抓包走 capture.Open，发送走本包 Open，
// 互不干扰；ARP 欺骗的毒化/恢复帧经 Port.Write 注入。
package writer

import (
	"errors"
)

// errUnsupportedPlatform 在未适配的操作系统上调用 Open 时返回。
var errUnsupportedPlatform = errors.New(
	"发送原始帧需要 AF_PACKET（Linux）、BPF（macOS）或 Npcap（Windows），当前平台暂不支持",
)

// Port 是一个已打开的原始帧发送句柄。
type Port interface {
	// Write 把一个完整二层帧（含以太网头）注入网卡。
	Write(frame []byte) error
	Close() error
}

// Open 打开 ifaceName 对应网卡的发送通道；需要 root/管理员特权。
// 每个平台的实现文件负责把「网卡名」翻译成自己的底层句柄。
func Open(ifaceName string) (Port, error) {
	return open(ifaceName)
}
