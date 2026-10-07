package tests

import (
	"testing"
	platformesp "wifisec/internal/platform/esp8266"
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
