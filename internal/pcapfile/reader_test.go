package pcapfile

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
	"time"
)

// craftPcap 按指定魔数与字节序手工组装 pcap 文件。Writer 只产小端微秒
// 文件，其余三种布局（大端/纳秒）必须手工构造才能检验 Reader 的自适应。
func craftPcap(magic uint32, order binary.ByteOrder, records [][]byte) []byte {
	buf := &bytes.Buffer{}

	header := make([]byte, globalHeaderSize)
	order.PutUint32(header[0:4], magic)
	order.PutUint16(header[4:6], versionMajor)
	order.PutUint16(header[6:8], versionMinor)
	order.PutUint32(header[16:20], defaultSnaplen)
	order.PutUint32(header[20:24], LinkTypeIEEE80211Radio)
	buf.Write(header)

	for _, rec := range records {
		recHeader := make([]byte, recordHeaderSize)
		order.PutUint32(recHeader[0:4], 1700000000)
		order.PutUint32(recHeader[4:8], 123456)
		order.PutUint32(recHeader[8:12], uint32(len(rec)))
		order.PutUint32(recHeader[12:16], uint32(len(rec)))
		buf.Write(recHeader)
		buf.Write(rec)
	}

	return buf.Bytes()
}

func TestReaderRoundTrip(t *testing.T) {
	// Writer → Reader 往返：帧字节与微秒级时间戳必须精确还原。
	buf := &bytes.Buffer{}
	writer, err := NewWriter(buf, LinkTypeIEEE80211Radio)
	if err != nil {
		t.Fatalf("建 Writer 失败：%v", err)
	}

	frames := [][]byte{bytes.Repeat([]byte{0xAA}, 36), bytes.Repeat([]byte{0xBB}, 120), {0x01}}
	base := time.Unix(1700000000, 500000000)
	timestamps := []time.Time{base, base.Add(1500 * time.Millisecond), base.Add(2 * time.Second)}

	for i, frame := range frames {
		if err := writer.WritePacket(frame, timestamps[i]); err != nil {
			t.Fatalf("写入记录 %d 失败：%v", i, err)
		}
	}

	reader, rerr := NewReader(bytes.NewReader(buf.Bytes()))
	if rerr != nil {
		t.Fatalf("建 Reader 失败：%v", rerr)
	}

	if reader.LinkType != LinkTypeIEEE80211Radio {
		t.Errorf("LinkType = %d，期望 %d", reader.LinkType, LinkTypeIEEE80211Radio)
	}

	for i := range frames {
		frame, ts, err := reader.ReadPacket()
		if err != nil {
			t.Fatalf("读取记录 %d 失败：%v", i, err)
		}

		if !bytes.Equal(frame, frames[i]) {
			t.Errorf("记录 %d 帧字节不符：%x", i, frame)
		}
		if ts.Unix() != timestamps[i].Unix() || ts.Nanosecond()/1000 != timestamps[i].Nanosecond()/1000 {
			t.Errorf("记录 %d 时间戳 = %v，期望 %v（微秒精度）", i, ts, timestamps[i])
		}
	}

	if _, _, err := reader.ReadPacket(); err != io.EOF {
		t.Fatalf("末尾应返回 io.EOF，实际：%v", err)
	}
}

func TestReaderByteOrderAndPrecision(t *testing.T) {
	// 四种魔数布局逐一回放：字节序与精度自适应是 extract 兼容
	// tcpdump/Wireshark 产物的前提。craftPcap 收"文件自身字节序下的
	// 规范魔数"（µs=0xa1b2c3d4 / ns=0xa1b23c4d），按 order 写出后
	// Reader 端的小端解读正好命中各自的分支。
	cases := []struct {
		name        string
		magic       uint32
		order       binary.ByteOrder
		nanoseconds bool
	}{
		{"小端微秒（本工具 Writer 产物）", magicMicroseconds, binary.LittleEndian, false},
		{"大端微秒（老 tcpdump）", magicMicroseconds, binary.BigEndian, false},
		{"小端纳秒", magicLittleNanoseconds, binary.LittleEndian, true},
		{"大端纳秒", magicLittleNanoseconds, binary.BigEndian, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			frame := bytes.Repeat([]byte{0x5A}, 64)
			data := craftPcap(c.magic, c.order, [][]byte{frame})

			reader, err := NewReader(bytes.NewReader(data))
			if err != nil {
				t.Fatalf("建 Reader 失败：%v", err)
			}

			got, _, err := reader.ReadPacket()
			if err != nil {
				t.Fatalf("读取失败：%v", err)
			}

			if !bytes.Equal(got, frame) {
				t.Errorf("帧字节不符：%x", got)
			}
		})
	}
}

func TestReaderNanosecondTimestamp(t *testing.T) {
	frame := bytes.Repeat([]byte{0x11}, 16)
	data := craftPcap(magicLittleNanoseconds, binary.LittleEndian, [][]byte{frame})

	// 改写时间戳小数部分为纳秒值：123456 纳秒（微秒文件里会是 123456µs）。
	binary.LittleEndian.PutUint32(data[24+4:24+8], 123456)

	reader, err := NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("建 Reader 失败：%v", err)
	}

	_, ts, err := reader.ReadPacket()
	if err != nil {
		t.Fatalf("读取失败：%v", err)
	}

	if ts.Nanosecond() != 123456 {
		t.Errorf("纳秒小数部分 = %d，期望 123456", ts.Nanosecond())
	}
}

func TestReaderRejectsCorruptFiles(t *testing.T) {
	frame := bytes.Repeat([]byte{0x33}, 40)

	cases := []struct {
		name string
		data []byte
	}{
		{"空文件", nil},
		{"魔数不符（pcapng）", append([]byte{0x0a, 0x0d, 0x0d, 0x0a}, make([]byte, 20)...)},
		{"记录头截断", craftPcap(magicMicroseconds, binary.LittleEndian, [][]byte{frame})[:24+8]},
		{"帧数据截断", craftPcap(magicMicroseconds, binary.LittleEndian, [][]byte{frame})[:24+16+10]},
		{"捕获长度为 0", func() []byte {
			data := craftPcap(magicMicroseconds, binary.LittleEndian, nil)
			rec := make([]byte, recordHeaderSize)
			binary.LittleEndian.PutUint32(rec[8:12], 0)
			binary.LittleEndian.PutUint32(rec[12:16], 0)

			return append(data, rec...)
		}()},
		{"incl_len 超上限", func() []byte {
			data := craftPcap(magicMicroseconds, binary.LittleEndian, nil)
			rec := make([]byte, recordHeaderSize)
			binary.LittleEndian.PutUint32(rec[8:12], 0xFFFFFFFF)
			binary.LittleEndian.PutUint32(rec[12:16], 0xFFFFFFFF)

			return append(data, rec...)
		}()},
		{"incl_len 大于 orig_len", func() []byte {
			data := craftPcap(magicMicroseconds, binary.LittleEndian, nil)
			rec := make([]byte, recordHeaderSize)
			binary.LittleEndian.PutUint32(rec[8:12], 64)
			binary.LittleEndian.PutUint32(rec[12:16], 32)

			return append(data, rec...)
		}()},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reader, err := NewReader(bytes.NewReader(c.data))
			if err != nil {
				return // 全局头阶段已拒绝，同样算通过
			}

			if _, _, err := reader.ReadPacket(); err == nil {
				t.Fatalf("%s未被拒绝", c.name)
			}
		})
	}
}
