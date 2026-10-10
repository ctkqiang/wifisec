// Package pcapfile 用标准库手写 Wireshark 原生 .pcap 二进制格式，
// 不引入 libpcap 绑定，因此在 Linux/macOS/Windows/Android 上产物完全一致。
//
// 文件布局（libpcap v2.4，小端、微秒时间戳）：
//
//	全局头 24B：magic a1b2c3d4 | 版本 2.4 | snaplen | linktype
//	每包记录：  时间戳秒/微秒 | 捕获长度 | 原始长度 | 帧数据
//
// 抓包循环可能并发统计，所有写入经互斥锁串行化。
package pcapfile

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"
)

const (
	// magicMicroseconds 是经典 pcap 的魔数；Wireshark 据此识别格式与字节序。
	magicMicroseconds uint32 = 0xa1b2c3d4

	// versionMajor/minor 固定为 2.4，所有现代分析工具都支持。
	versionMajor uint16 = 2
	versionMinor uint16 = 4

	// globalHeaderSize 固定 24 字节；recordHeaderSize 固定 16 字节。
	globalHeaderSize = 24
	recordHeaderSize = 16

	// defaultSnaplen 65535 足以容纳完整以太网帧（含 VLAN/巨型帧常规流量）。
	defaultSnaplen uint32 = 65535
)

// 链路层类型取自 libpcap 注册表（Wireshark 按此选择解析器）。
const (
	LinkTypeEthernet       uint32 = 1   // DLT_EN13MB：普通网卡 managed 模式
	LinkTypeIEEE80211Radio uint32 = 127 // DLT_IEEE802_11_RADIO：monitor 模式 radiotap
)

// Writer 把帧以 pcap 格式写入底层 io.Writer（通常是 *os.File）。
type Writer struct {
	writer io.Writer
	mu     sync.Mutex
}

// NewWriter 写入 24 字节全局头并返回 Writer。
// linkType 必须在首包写入前确定（Ethernet=1，radiotap=127）。
func NewWriter(writer io.Writer, linkType uint32) (*Writer, error) {
	header := make([]byte, globalHeaderSize)
	binary.LittleEndian.PutUint32(header[0:4], magicMicroseconds)
	binary.LittleEndian.PutUint16(header[4:6], versionMajor)
	binary.LittleEndian.PutUint16(header[6:8], versionMinor)
	// thiszone(8:12) 与 sigfigs(12:16) 保持零值。
	binary.LittleEndian.PutUint32(header[16:20], defaultSnaplen)
	binary.LittleEndian.PutUint32(header[20:24], linkType)

	if _, err := writer.Write(header); err != nil {
		return nil, err
	}

	return &Writer{writer: writer}, nil
}

// WritePacket 追加一条记录。captured 超过 snaplen 时按 libpcap 语义截断，
// 但 origlen 仍记录帧的真实长度，Wireshark 会明确标注该包被截断。
func (w *Writer) WritePacket(frame []byte, capturedAt time.Time) error {
	if len(frame) == 0 {
		return errors.New("空帧不能写入 pcap")
	}

	data := frame
	if len(data) > int(defaultSnaplen) {
		data = data[:defaultSnaplen]
	}

	header := make([]byte, recordHeaderSize)
	binary.LittleEndian.PutUint32(header[0:4], uint32(capturedAt.Unix()))
	binary.LittleEndian.PutUint32(header[4:8], uint32(capturedAt.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(header[8:12], uint32(len(data)))
	binary.LittleEndian.PutUint32(header[12:16], uint32(len(frame)))

	w.mu.Lock()
	defer w.mu.Unlock()

	if _, err := w.writer.Write(header); err != nil {
		return err
	}

	_, err := w.writer.Write(data)

	return err
}
