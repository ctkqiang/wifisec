//go:build windows

package windows

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

// Npcap 安装路径：64 位进程固定加载 System32\Npcap 下的 DLL。
// 先显式加载 packet.dll，再加载 wpcap.dll，可确保依赖解析到同一目录。
const (
	npcapDir      = `C:\Windows\System32\Npcap`
	packetDLLPath = npcapDir + `\packet.dll`
	wpcapDLLPath  = npcapDir + `\wpcap.dll`
)

var (
	// 延迟加载，避免程序启动时就因缺少 Npcap 而失败。
	packetDLL = syscall.NewLazyDLL(packetDLLPath)
	wpcapDLL  = syscall.NewLazyDLL(wpcapDLLPath)

	procPacketOpenAdapter  = packetDLL.NewProc("PacketOpenAdapter")
	procPacketCloseAdapter = packetDLL.NewProc("PacketCloseAdapter")
	procPcapOpen           = wpcapDLL.NewProc("pcap_open")
	procPcapClose          = wpcapDLL.NewProc("pcap_close")
	procPcapSendPacket     = wpcapDLL.NewProc("pcap_sendpacket")
)

// ErrNpcapMissing 表示未检测到 Npcap 驱动。
var ErrNpcapMissing = errors.New(
	"未检测到 Npcap：请先安装 Npcap（https://npcap.com），" +
		"安装时必须勾选 \"Support raw 802.11 traffic (and monitor mode) for wireless adapters\"")

// CheckNpcap 验证 Npcap 驱动是否可用。
// 只加载 DLL 不打开适配器，副作用为零，可在 deauth 流程前置执行。
func CheckNpcap() error {
	if err := packetDLL.Load(); err != nil {
		return ErrNpcapMissing
	}
	if err := wpcapDLL.Load(); err != nil {
		return ErrNpcapMissing
	}
	return nil
}

// NPFDevicePath 把适配器 GUID 转成 Npcap 设备路径。
// Npcap 的命名规则固定为 \Device\NPF_{GUID}（大写花括号形式）。
func NPFDevicePath(guid string) string {
	// 统一为大写花括号格式，Npcap 内部字符串匹配是大小写敏感的。
	upper := strings.ToUpper(strings.TrimSpace(guid))
	if !strings.HasPrefix(upper, "{") {
		upper = "{" + upper
	}
	if !strings.HasSuffix(upper, "}") {
		upper = upper + "}"
	}
	return `\Device\NPF_` + upper
}

// FrameInjector 封装 Npcap wpcap.dll 的 pcap_t 句柄，用于注入 802.11 帧。
type FrameInjector struct {
	handle uintptr // pcap_t*
}

// OpenInjector 在指定适配器上打开 Npcap 注入句柄。
// devicePath 必须是 \Device\NPF_{GUID} 形式；适配器必须处于 monitor 模式。
func OpenInjector(devicePath string) (*FrameInjector, error) {
	if err := CheckNpcap(); err != nil {
		return nil, err
	}

	// pcap_open 参数：source, snaplen, flags, read_timeout, auth, errbuf
	// flags=0（非混杂），timeout=1000ms（仅注入用不到），auth=NULL。
	source, err := syscall.BytePtrFromString(devicePath)
	if err != nil {
		return nil, fmt.Errorf("设备路径含非法字符：%w", err)
	}

	var errbuf [256]byte
	handle, _, callErr := procPcapOpen.Call(
		uintptr(unsafe.Pointer(source)),
		uintptr(65535),
		uintptr(0),
		uintptr(1000),
		uintptr(0),
		uintptr(unsafe.Pointer(&errbuf[0])),
	)
	if handle == 0 {
		detail := strings.TrimRight(string(errbuf[:]), "\x00")
		if callErr != syscall.Errno(0) {
			return nil, fmt.Errorf("打开 Npcap 适配器失败：%s（%v）", detail, callErr)
		}
		return nil, fmt.Errorf("打开 Npcap 适配器失败：%s", detail)
	}

	return &FrameInjector{handle: handle}, nil
}

// Write 把一帧 802.11 数据注入空中。
// Npcap 要求帧以 radiotap 头开头，驱动会剥离 radiotap 后发送原始 802.11。
func (fi *FrameInjector) Write(frame []byte) error {
	if fi.handle == 0 {
		return errors.New("注入器已关闭")
	}

	ret, _, callErr := procPcapSendPacket.Call(
		fi.handle,
		uintptr(unsafe.Pointer(&frame[0])),
		uintptr(len(frame)),
	)
	if ret != 0 {
		return fmt.Errorf("pcap_sendpacket 返回 %d：%v", ret, callErr)
	}
	return nil
}

// Close 释放 Npcap 句柄。
func (fi *FrameInjector) Close() error {
	if fi.handle == 0 {
		return nil
	}

	procPcapClose.Call(fi.handle)
	fi.handle = 0
	return nil
}
