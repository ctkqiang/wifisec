package tests

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/ctkqiang/wifisec/internal/ethernet"
	"github.com/ctkqiang/wifisec/internal/functions"
	"github.com/ctkqiang/wifisec/internal/pcapfile"
)

// 邻居表解析器带平台构建标签，对应测试拆分在：
// lan_neigh_linux_test.go / lan_neigh_darwin_test.go / lan_neigh_windows_test.go。

// TestParsePortSpec 覆盖端口规格的五种输入与两类非法格式。
func TestParsePortSpec(t *testing.T) {
	tests := []struct {
		name      string
		spec      string
		wantFirst int
		wantLast  int
		wantCount int
		wantErr   bool
	}{
		{name: "空串等于 top", spec: "", wantFirst: 7, wantLast: 27017, wantCount: 47},
		{name: "top 关键字", spec: "top", wantFirst: 7, wantLast: 27017, wantCount: 47},
		{name: "all 为 1-1000", spec: "all", wantFirst: 1, wantLast: 1000, wantCount: 1000},
		{name: "枚举加区间混合去重", spec: "443,80,80-82", wantFirst: 80, wantLast: 443, wantCount: 4},
		{name: "端口越界", spec: "0-80", wantErr: true},
		{name: "区间倒置", spec: "100-50", wantErr: true},
		{name: "无法识别", spec: "ssh", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ports, err := functions.ParsePortSpec(tt.spec)
			if (err != nil) != tt.wantErr {
				t.Fatalf("错误状态不符：err=%v, wantErr=%v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if len(ports) != tt.wantCount {
				t.Fatalf("端口数不符：got %d, want %d", len(ports), tt.wantCount)
			}
			if ports[0] != tt.wantFirst || ports[len(ports)-1] != tt.wantLast {
				t.Fatalf("排序/范围不符：first=%d last=%d", ports[0], ports[len(ports)-1])
			}
		})
	}
}

// TestParseSniffArgs 验证位置参数语义：网卡、秒数、pcap 文件任意顺序混排。
func TestParseSniffArgs(t *testing.T) {
	tests := []struct {
		name      string
		arguments []string
		wantIface string
		wantSecs  int
		wantFile  string
		wantErr   bool
	}{
		{
			name:      "完整参数",
			arguments: []string{"en0", "30", "capture.pcap"},
			wantIface: "en0",
			wantSecs:  30,
			wantFile:  "capture.pcap",
		},
		{
			name:      "只有秒数和路径风格文件",
			arguments: []string{"15", "/tmp/a.pcap"},
			wantSecs:  15,
			wantFile:  "/tmp/a.pcap",
		},
		{
			name:      "零表示抓到 Ctrl-C",
			arguments: []string{"wlan0", "0"},
			wantIface: "wlan0",
			wantSecs:  0,
		},
		{
			name:      "两个网卡名报错",
			arguments: []string{"en0", "en1"},
			wantErr:   true,
		},
		{
			name:      "负数秒数报错",
			arguments: []string{"-3"},
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options, err := functions.ParseSniffArgs(tt.arguments)
			if (err != nil) != tt.wantErr {
				t.Fatalf("错误状态不符：err=%v, wantErr=%v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if options.Interface != tt.wantIface || options.Seconds != tt.wantSecs || options.OutputPath != tt.wantFile {
				t.Fatalf("解析结果不符：%+v", options)
			}
		})
	}
}

// TestPcapWriter 验证全局头与记录头的字节级布局，确保 Wireshark 能直接识别。
func TestPcapWriter(t *testing.T) {
	var buffer bytes.Buffer

	writer, err := pcapfile.NewWriter(&buffer, pcapfile.LinkTypeEthernet)
	if err != nil {
		t.Fatalf("创建写入器失败：%v", err)
	}

	capturedAt := time.Unix(1700000000, 123000000) // 微秒部分应为 123000
	frame := []byte{0xde, 0xad, 0xbe, 0xef}
	if err := writer.WritePacket(frame, capturedAt); err != nil {
		t.Fatalf("写入记录失败：%v", err)
	}

	data := buffer.Bytes()
	if len(data) != 24+16+4 {
		t.Fatalf("文件长度应为 全局头24+记录头16+帧4=44，实际 %d", len(data))
	}

	if binary.LittleEndian.Uint32(data[0:4]) != 0xa1b2c3d4 {
		t.Fatalf("魔数错误：% x", data[0:4])
	}
	if binary.LittleEndian.Uint16(data[4:6]) != 2 || binary.LittleEndian.Uint16(data[6:8]) != 4 {
		t.Fatalf("pcap 版本应为 2.4")
	}
	if binary.LittleEndian.Uint32(data[20:24]) != pcapfile.LinkTypeEthernet {
		t.Fatalf("链路类型字段错误")
	}
	if binary.LittleEndian.Uint32(data[24:28]) != 1700000000 ||
		binary.LittleEndian.Uint32(data[28:32]) != 123000 {
		t.Fatalf("记录时间戳错误")
	}
	if binary.LittleEndian.Uint32(data[32:36]) != 4 ||
		binary.LittleEndian.Uint32(data[36:40]) != 4 {
		t.Fatalf("caplen/origlen 应为 4/4")
	}
	if !bytes.Equal(data[40:44], frame) {
		t.Fatalf("帧数据未原样写入")
	}
}

// TestSummarizeARP 验证 ARP 请求被解析成 who-has 风格摘要。
func TestSummarizeARP(t *testing.T) {
	frame := buildTestARPFrame()

	summary := ethernet.Summarize(frame)
	if summary.Proto != "ARP" {
		t.Fatalf("协议应为 ARP，实际 %s", summary.Proto)
	}
	if summary.Src != "192.168.1.5" || summary.Dst != "192.168.1.1" {
		t.Fatalf("ARP 端点不符：%s → %s", summary.Src, summary.Dst)
	}
	if !strings.Contains(summary.Info, "who-has 192.168.1.1") {
		t.Fatalf("Info 应含 who-has，实际 %s", summary.Info)
	}
}

// TestSummarizeTCPSYN 验证 IPv4/TCP 端口与 SYN 标志解析。
func TestSummarizeTCPSYN(t *testing.T) {
	frame := buildTestTCPSYNFrame()

	summary := ethernet.Summarize(frame)
	if summary.Proto != "TCP" || summary.Info != "SYN" {
		t.Fatalf("应为 TCP SYN，实际 %s %q", summary.Proto, summary.Info)
	}
	if summary.Src != "192.168.1.5:51000" || summary.Dst != "142.250.1.2:443" {
		t.Fatalf("TCP 端点不符：%s → %s", summary.Src, summary.Dst)
	}
}

// TestSummarizeTruncated 验证超短帧不 panic 且返回 TRUNC 标签。
func TestSummarizeTruncated(t *testing.T) {
	summary := ethernet.Summarize(make([]byte, 10))
	if summary.Proto != "TRUNC" {
		t.Fatalf("超短帧应标 TRUNC，实际 %s", summary.Proto)
	}
}

// buildTestARPFrame 构造一帧广播 ARP 请求：
// 192.168.1.5 (11:22:33:44:55:66) 询问 192.168.1.1 的 MAC。
func buildTestARPFrame() []byte {
	frame := make([]byte, 42)

	copy(frame[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(frame[6:12], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66})
	frame[12], frame[13] = 0x08, 0x06

	frame[14], frame[15] = 0x00, 0x01 // 硬件类型 Ethernet
	frame[16], frame[17] = 0x08, 0x00 // 协议类型 IPv4
	frame[18], frame[19] = 6, 4       // 地址长度
	frame[20], frame[21] = 0x00, 0x01 // ARP 请求
	copy(frame[22:28], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66})
	copy(frame[28:32], []byte{192, 168, 1, 5})
	// frame[32:38] 目标 MAC 全零
	copy(frame[38:42], []byte{192, 168, 1, 1})

	return frame
}

// buildTestTCPSYNFrame 构造一帧 54 字节 IPv4 SYN：
// 192.168.1.5:51000 → 142.250.1.2:443。
func buildTestTCPSYNFrame() []byte {
	frame := make([]byte, 54)

	copy(frame[6:12], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66})
	copy(frame[0:6], []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	frame[12], frame[13] = 0x08, 0x00

	ip := frame[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 40)
	ip[8] = 64
	ip[9] = 6 // TCP
	copy(ip[12:16], []byte{192, 168, 1, 5})
	copy(ip[16:20], []byte{142, 250, 1, 2})

	tcp := frame[34:54]
	binary.BigEndian.PutUint16(tcp[0:2], 51000)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	tcp[12] = 0x50 // 数据偏移 5 个 32 位字
	tcp[13] = 0x02 // SYN

	return frame
}
