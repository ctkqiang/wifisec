// reader.go 提供 pcap 读侧：extract 需要把 get_packet 或外部工具
// （tcpdump / Wireshark）产出的 .pcap 回放成帧流，交给 eapol.Analyzer
// 提取握手对与 PMKID。
//
// 与 Writer（固定小端、微秒）对称，Reader 按魔数自适应四种布局：
// 字节序（小端/大端）× 时间精度（微秒/纳秒），与 libpcap 生态互通。
package pcapfile

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

// 除 Writer 已定义的小端微秒魔数外，Reader 还需识别的三种组合；
// 值即文件头前 4 字节按大端解读的结果（libpcap 惯例记法）。
const (
	magicBigMicroseconds   uint32 = 0xd4c3b2a1
	magicLittleNanoseconds uint32 = 0xa1b23c4d
	magicBigNanoseconds    uint32 = 0x4d3cb2a1
)

// maxFrameSize 是单条记录捕获长度的硬上限：畸形/伪造文件的 incl_len
// 最大可达 4GiB，按声明长度直接分配会瞬间耗尽内存，必须先校验再分配。
const maxFrameSize = 256 * 1024

// Reader 按记录逐条回放 pcap 文件。
type Reader struct {
	reader     io.Reader
	byteOrder  binary.ByteOrder
	nanosecond bool

	// LinkType 与 Snaplen 来自全局头：LinkType 决定帧解析路径
	//（1 = Ethernet，127 = radiotap），Snaplen 仅供展示。
	LinkType uint32
	Snaplen  uint32

	offset int // 已消费字节数，错误信息据此定位坏记录
}

// NewReader 读取并校验 24 字节全局头，按魔数确定字节序与时间精度。
func NewReader(reader io.Reader) (*Reader, error) {
	header := make([]byte, globalHeaderSize)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, fmt.Errorf("读取 pcap 全局头失败（文件为空或已截断）：%w", err)
	}

	r := &Reader{reader: reader, offset: globalHeaderSize}

	switch magic := binary.LittleEndian.Uint32(header[0:4]); magic {
	case magicMicroseconds:
		r.byteOrder = binary.LittleEndian
	case magicBigMicroseconds:
		r.byteOrder = binary.BigEndian
	case magicLittleNanoseconds:
		r.byteOrder, r.nanosecond = binary.LittleEndian, true
	case magicBigNanoseconds:
		r.byteOrder, r.nanosecond = binary.BigEndian, true
	default:
		return nil, fmt.Errorf("魔数 %#08x 不是 pcap 文件（可能为 pcapng 或已损坏）", magic)
	}

	r.Snaplen = r.byteOrder.Uint32(header[16:20])
	r.LinkType = r.byteOrder.Uint32(header[20:24])

	return r, nil
}

// ReadPacket 回放下一条记录：返回帧数据与捕获时刻。
// 文件干净结束返回 io.EOF；记录头不完整或长度校验失败返回定位到
// 字节偏移的错误，extract 据此提示文件在何处损坏。
func (r *Reader) ReadPacket() ([]byte, time.Time, error) {
	header := make([]byte, recordHeaderSize)
	n, err := io.ReadFull(r.reader, header)
	if err != nil {
		if errors.Is(err, io.EOF) && n == 0 {
			return nil, time.Time{}, io.EOF
		}

		return nil, time.Time{}, fmt.Errorf("第 %d 字节处记录头不完整（文件被截断）：%w", r.offset, err)
	}

	tsSec := r.byteOrder.Uint32(header[0:4])
	tsFrac := r.byteOrder.Uint32(header[4:8])
	included := r.byteOrder.Uint32(header[8:12])
	original := r.byteOrder.Uint32(header[12:16])

	switch {
	case included == 0:
		return nil, time.Time{}, fmt.Errorf("第 %d 字节的记录捕获长度为 0，文件已损坏", r.offset)
	case included > maxFrameSize:
		return nil, time.Time{}, fmt.Errorf("第 %d 字节的记录声称捕获 %d 字节，超出 %d 上限，文件已损坏", r.offset, included, maxFrameSize)
	case included > original:
		return nil, time.Time{}, fmt.Errorf("第 %d 字节的记录捕获长度 %d 大于原始长度 %d，文件已损坏", r.offset, included, original)
	}

	frame := make([]byte, included)
	if _, err := io.ReadFull(r.reader, frame); err != nil {
		return nil, time.Time{}, fmt.Errorf("第 %d 字节的记录数据不完整（文件被截断）：%w", r.offset, err)
	}
	r.offset += recordHeaderSize + int(included)

	// 精度按全局头魔数区分：微秒文件的小数部分要放大 1000 倍成纳秒。
	var capturedAt time.Time
	if r.nanosecond {
		capturedAt = time.Unix(int64(tsSec), int64(tsFrac))
	} else {
		capturedAt = time.Unix(int64(tsSec), int64(tsFrac)*1000)
	}

	return frame, capturedAt, nil
}
