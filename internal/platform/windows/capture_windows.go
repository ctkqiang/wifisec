//go:build windows

package windows

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

var (
	// pcap_next_ex 按下一个包；pcap_datalink 返回当前链路类型。
	procPcapNextEx   = wpcapDLL.NewProc("pcap_next_ex")
	procPcapDatalink = wpcapDLL.NewProc("pcap_datalink")
)

// ErrCaptureReadTimeout 对应 pcap_next_ex 返回 0：读超时周期内没有包，
// 不是致命错误；platform/capture 包会把它归一为自己的空闲周期哨兵。
var ErrCaptureReadTimeout = errors.New("Npcap 读超时周期内没有数据包")

// CaptureSource 封装用于收包的 pcap_t 句柄。Npcap 返回的数据指针只在
// 下次调用前有效，因此 Read 总是把帧拷贝到自有缓冲，调用方可安全持有。
type CaptureSource struct {
	handle   uintptr // pcap_t*
	buffer   []byte
	linkType uint32
}

// OpenCapture 在 \Device\NPF_{GUID} 上以混杂模式打开抓包句柄，
// read_timeout=500ms 让 pcap_next_ex 周期性返回 0，便于上层响应 Ctrl-C。
func OpenCapture(devicePath string) (*CaptureSource, error) {
	if err := CheckNpcap(); err != nil {
		return nil, err
	}

	source, err := syscall.BytePtrFromString(devicePath)
	if err != nil {
		return nil, fmt.Errorf("设备路径含非法字符：%w", err)
	}

	var errbuf [256]byte
	handle, _, callErr := procPcapOpen.Call(
		uintptr(unsafe.Pointer(source)),
		uintptr(65535), // snaplen
		uintptr(1),     // PCAP_OPENFLAG_PROMISCUOUS
		uintptr(500),   // 读超时（毫秒）
		uintptr(0),     // 远程抓包认证，本机固定 NULL
		uintptr(unsafe.Pointer(&errbuf[0])),
	)
	if handle == 0 {
		detail := strings.TrimRight(string(errbuf[:]), "\x00")

		return nil, fmt.Errorf("打开 Npcap 抓包适配器失败：%s（%v），请以管理员身份运行", detail, callErr)
	}

	linkType, _, _ := procPcapDatalink.Call(handle)
	if linkType == 0 {
		linkType = 1 // DLT_EN13MB，普通 NDIS 网卡的兜底值
	}

	return &CaptureSource{
		handle:   handle,
		buffer:   make([]byte, 0, 65535),
		linkType: uint32(linkType),
	}, nil
}

// pcapPacketHeader 与 wpcap.dll 的 struct pcap_pkthdr 对齐：
// Windows 的 long 是 32 位，时间戳两个字段各 4 字节，caplen 固定在偏移 8。
type pcapPacketHeader struct {
	tvSec    uint32
	tvUsec   uint32
	captured uint32
	original uint32
}

// Read 读取一帧。pcap_next_ex 返回值：1 成功，0 超时，-1 错误，-2 离线文件 EOF。
func (capture *CaptureSource) Read() ([]byte, error) {
	if capture.handle == 0 {
		return nil, errors.New("抓包句柄已关闭")
	}

	// 二级指针由 Npcap 填充：hdr 指向其内部头，data 指向帧数据。
	var (
		header *pcapPacketHeader
		data   *byte
	)

	result, _, callErr := procPcapNextEx.Call(
		capture.handle,
		uintptr(unsafe.Pointer(&header)),
		uintptr(unsafe.Pointer(&data)),
	)

	switch int32(result) {
	case 1:
		if header == nil || data == nil || header.captured == 0 {
			return nil, errors.New("Npcap 返回了空帧")
		}

		capture.buffer = append(
			capture.buffer[:0],
			unsafe.Slice(data, int(header.captured))...,
		)

		return capture.buffer, nil
	case 0:
		return nil, ErrCaptureReadTimeout
	case -2:
		return nil, errors.New("Npcap 句柄意外到达 EOF")
	default:
		return nil, fmt.Errorf("pcap_next_ex 返回 %d：%v", result, callErr)
	}
}

// LinkType 返回打开时查询到的 DLT 链路类型。
func (capture *CaptureSource) LinkType() uint32 {
	return capture.linkType
}

// Close 释放 pcap_t 句柄。
func (capture *CaptureSource) Close() error {
	if capture.handle == 0 {
		return nil
	}

	procPcapClose.Call(capture.handle)
	capture.handle = 0

	return nil
}
