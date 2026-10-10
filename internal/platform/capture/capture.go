// Package capture 是“打开一块网卡读取原始二层帧”的跨平台端口：
// Linux/Android 走 AF_PACKET，macOS 走 /dev/bpf*，Windows 走 Npcap。
// 三个实现都以约 500ms 的粒度阻塞，空闲周期返回 ErrReadTimeout，
// 让上层抓包循环可以定期检查 Ctrl-C/超时上下文而不被永久阻塞。
package capture

import "errors"

// 链路层类型取自 libpcap 注册表，与 internal/pcapfile 的常量保持同义。
const (
	LinkTypeEthernet       uint32 = 1   // 普通网卡 managed 模式（全部平台默认）
	LinkTypeIEEE80211Radio uint32 = 127 // monitor 模式 radiotap 头
)

// ErrReadTimeout 表示一个空闲读取周期结束但没有收到帧，不是错误，
// 上层应检查取消信号后继续 Read。
var ErrReadTimeout = errors.New("抓包空闲周期超时")

// errCaptureUnsupported 在未适配的平台调用 Open 时返回。
var errCaptureUnsupported = errors.New(
	"抓包需要 AF_PACKET（Linux）、BPF（macOS）或 Npcap（Windows），当前平台暂不支持",
)

// Source 是一个已打开的抓包会话。Read 返回的切片只在下次 Read 前有效，
// 调用方需要持久化时（如写 pcap）必须同步完成复制。
type Source interface {
	Read() ([]byte, error)
	LinkType() uint32
	Close() error
}
