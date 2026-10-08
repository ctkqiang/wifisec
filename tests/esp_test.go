package tests

import (
	platformesp "github.com/ctkqiang/wifisec/internal/platform/esp"
	"testing"
)

// TestEncodeCommand 验证主机→固件帧布局：魔数、命令字、小端长度与 payload。
func TestEncodeCommand(t *testing.T) {
	tests := []struct {
		name    string
		cmd     byte
		payload []byte
		want    []byte
	}{
		{
			name:    "无载荷扫描命令",
			cmd:     0x01,
			payload: nil,
			want:    []byte{0xA5, 0x01, 0x00, 0x00},
		},
		{
			name:    "注入命令含信道与帧",
			cmd:     0x02,
			payload: []byte{0x06, 0xC0, 0x00},
			want:    []byte{0xA5, 0x02, 0x03, 0x00, 0x06, 0xC0, 0x00},
		},
		{
			name:    "长度小端编码",
			cmd:     0x02,
			payload: make([]byte, 258),
			want:    nil, // 只校验长度字段，见下方断言
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := platformesp.EncodeCommand(tt.cmd, tt.payload)

			if tt.want != nil {
				if len(got) != len(tt.want) {
					t.Fatalf("长度不符：got %d, want %d", len(got), len(tt.want))
				}
				for i := range tt.want {
					if got[i] != tt.want[i] {
						t.Fatalf("字节 %d 不符：got 0x%02X, want 0x%02X", i, got[i], tt.want[i])
					}
				}
				return
			}

			// 长度字段小端：258 = 0x0102 → lo=0x02 hi=0x01
			if got[2] != 0x02 || got[3] != 0x01 {
				t.Fatalf("长度字段小端编码错误：lo=0x%02X hi=0x%02X", got[2], got[3])
			}
			if len(got) != 4+258 {
				t.Fatalf("总帧长不符：got %d", len(got))
			}
		})
	}
}

// TestDecodeReply 验证回复帧解析：噪声重同步、帧分片、不完整帧保留。
// ESP 芯片上电以非工作波特率输出启动日志（ESP8266 为 74880），
// 在 115200 下呈现为随机噪声，解析器必须跳过噪声找到帧头，
// 否则后续数据全部被堵死。
func TestDecodeReply(t *testing.T) {
	tests := []struct {
		name        string
		stream      []byte
		wantOK      bool
		wantCmd     byte
		wantPayload []byte
		wantRestLen int
	}{
		{
			name:        "完整 PONG 帧",
			stream:      []byte{0x5A, 0x00, 0x01, 0x00, 0x01},
			wantOK:      true,
			wantCmd:     0x00,
			wantPayload: []byte{0x01},
			wantRestLen: 0,
		},
		{
			name:        "帧头前带 boot 噪声",
			stream:      []byte{0x7F, 0x8C, 0xFF, 0x5A, 0x00, 0x01, 0x00, 0x01},
			wantOK:      true,
			wantCmd:     0x00,
			wantPayload: []byte{0x01},
			wantRestLen: 0,
		},
		{
			name:        "帧跨两次读取",
			stream:      []byte{0x5A, 0x01, 0x03, 0x00, 0xAA},
			wantOK:      false,
			wantRestLen: 5, // 残缺帧必须原样保留等下一段
		},
		{
			name:        "纯噪声没有帧头",
			stream:      []byte{0x11, 0x22, 0x33},
			wantOK:      false,
			wantRestLen: 0,
		},
		{
			name:        "帧尾紧随第二帧",
			stream:      []byte{0x5A, 0x02, 0x00, 0x00, 0x5A, 0x00, 0x01, 0x00, 0x01},
			wantOK:      true,
			wantCmd:     0x02,
			wantPayload: []byte{},
			wantRestLen: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, payload, rest, ok := platformesp.DecodeReply(tt.stream)

			if ok != tt.wantOK {
				t.Fatalf("ok 不符：got %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				if len(rest) != tt.wantRestLen {
					t.Fatalf("残留长度不符：got %d, want %d", len(rest), tt.wantRestLen)
				}
				return
			}
			if cmd != tt.wantCmd {
				t.Errorf("cmd 不符：got 0x%02X, want 0x%02X", cmd, tt.wantCmd)
			}
			if len(payload) != len(tt.wantPayload) {
				t.Fatalf("payload 长度不符：got %d, want %d", len(payload), len(tt.wantPayload))
			}
			for i := range tt.wantPayload {
				if payload[i] != tt.wantPayload[i] {
					t.Fatalf("payload[%d] 不符：got 0x%02X, want 0x%02X", i, payload[i], tt.wantPayload[i])
				}
			}
			if len(rest) != tt.wantRestLen {
				t.Errorf("rest 长度不符：got %d, want %d", len(rest), tt.wantRestLen)
			}
		})
	}
}

// TestParsePong 验证握手应答解析：完整两字节载荷、旧固件单字节、空载荷。
// 能力位图是协议 v1 的尾部扩展，旧固件不带该字节时必须按无扩展能力处理，
// 否则旧固件会被误判为损坏而遭到拒绝。
func TestParsePong(t *testing.T) {
	tests := []struct {
		name        string
		payload     []byte
		wantVersion byte
		wantCaps    byte
		wantErr     bool
	}{
		{
			name:        "完整载荷含能力位图",
			payload:     []byte{0x01, platformesp.CapBand5GHz},
			wantVersion: 1,
			wantCaps:    platformesp.CapBand5GHz,
		},
		{
			name:        "旧固件只回版本号",
			payload:     []byte{0x01},
			wantVersion: 1,
			wantCaps:    0x00,
		},
		{
			name:    "空载荷",
			payload: []byte{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, caps, err := platformesp.ParsePong(tt.payload)

			if tt.wantErr {
				if err == nil {
					t.Fatal("期望报错但解析成功")
				}
				return
			}

			if err != nil {
				t.Fatalf("解析失败：%v", err)
			}
			if version != tt.wantVersion {
				t.Errorf("版本不符：got %d, want %d", version, tt.wantVersion)
			}
			if caps != tt.wantCaps {
				t.Errorf("能力位图不符：got 0x%02X, want 0x%02X", caps, tt.wantCaps)
			}
		})
	}
}

// TestParseScanEntry 覆盖合法条目、截断载荷、SSID 越界、隐藏网络（空 SSID）。
func TestParseScanEntry(t *testing.T) {
	tests := []struct {
		name        string
		payload     []byte
		wantSSID    string
		wantBSSID   string
		wantChannel int
		wantRSSI    int
		wantErr     bool
	}{
		{
			name: "完整条目",
			payload: []byte{
				0xB4, 0xB0, 0x24, 0xB6, 0x12, 0x4B, // bssid
				0x06, // channel 6
				0xC4, // rssi -60（有符号）
				0x06, // ssid 长度 6
				'g', 'u', 'n', 'n', 'e', 'r',
			},
			wantSSID:    "gunner",
			wantBSSID:   "b4:b0:24:b6:12:4b",
			wantChannel: 6,
			wantRSSI:    -60,
		},
		{
			name: "隐藏网络空 SSID",
			payload: []byte{
				0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
				0x01,
				0xD0, // rssi -48
				0x00, // ssid 长度 0
			},
			wantSSID:    "",
			wantBSSID:   "00:11:22:33:44:55",
			wantChannel: 1,
			wantRSSI:    -48,
		},
		{
			name:    "载荷不足 9 字节",
			payload: []byte{0x01, 0x02, 0x03},
			wantErr: true,
		},
		{
			name: "SSID 长度越界",
			payload: []byte{
				0xB4, 0xB0, 0x24, 0xB6, 0x12, 0x4B,
				0x06,
				0xC4,
				0x20, // 声明 32 字节但后续无数据
				'x',
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := platformesp.ParseScanEntry(tt.payload)

			if tt.wantErr {
				if err == nil {
					t.Fatal("期望报错但解析成功")
				}
				return
			}

			if err != nil {
				t.Fatalf("解析失败：%v", err)
			}
			if got.SSID != tt.wantSSID {
				t.Errorf("SSID 不符：got %q, want %q", got.SSID, tt.wantSSID)
			}
			if got.BSSID != tt.wantBSSID {
				t.Errorf("BSSID 不符：got %q, want %q", got.BSSID, tt.wantBSSID)
			}
			if got.Channel != tt.wantChannel {
				t.Errorf("信道不符：got %d, want %d", got.Channel, tt.wantChannel)
			}
			if got.RSSI != tt.wantRSSI {
				t.Errorf("RSSI 不符：got %d, want %d", got.RSSI, tt.wantRSSI)
			}
		})
	}
}
