package tests

import (
	platformesp "github.com/ctkqiang/wifisec/internal/platform/esp"
	"testing"
)

// TestParseCloneResult 验证克隆结果载荷解析：result(1) + apMAC(6)。
// 覆盖 up 成功、down 的全零 MAC、失败结果与长度不足四类输入。
func TestParseCloneResult(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		wantOK  bool
		wantMAC string
		wantErr bool
	}{
		{
			name:    "up 成功回传克隆 AP MAC",
			payload: []byte{0x01, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F},
			wantOK:  true,
			wantMAC: "1a:2b:3c:4d:5e:6f",
		},
		{
			name:    "down 回复 MAC 全零",
			payload: []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			wantOK:  true,
			wantMAC: "00:00:00:00:00:00",
		},
		{
			name:    "固件开启 SoftAP 失败",
			payload: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			wantOK:  false,
			wantMAC: "00:00:00:00:00:00",
		},
		{
			name:    "载荷不足 7 字节",
			payload: []byte{0x01, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, apMAC, err := platformesp.ParseCloneResult(tt.payload)

			if (err != nil) != tt.wantErr {
				t.Fatalf("错误状态不符：err=%v, wantErr=%v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if ok != tt.wantOK {
				t.Fatalf("结果位不符：got %v, want %v", ok, tt.wantOK)
			}
			if apMAC != tt.wantMAC {
				t.Fatalf("MAC 不符：got %s, want %s", apMAC, tt.wantMAC)
			}
		})
	}
}

// TestParseCloneStatus 验证克隆状态载荷解析：count(1) + count×MAC(6)。
// 覆盖零设备、单设备、多设备与长度越界四类输入。
func TestParseCloneStatus(t *testing.T) {
	tests := []struct {
		name      string
		payload   []byte
		wantCount int
		wantFirst string
		wantErr   bool
	}{
		{
			name:      "无设备接入",
			payload:   []byte{0x00},
			wantCount: 0,
		},
		{
			name:      "单设备",
			payload:   []byte{0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
			wantCount: 1,
			wantFirst: "aa:bb:cc:dd:ee:ff",
		},
		{
			name: "多设备按 6 字节步进切分",
			payload: []byte{
				0x02,
				0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
				0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
			},
			wantCount: 2,
			wantFirst: "aa:bb:cc:dd:ee:ff",
		},
		{
			name:      "count 声明两台但载荷只有一台",
			payload:   []byte{0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
			wantErr:   true,
			wantCount: -1,
		},
		{
			name:      "空载荷",
			payload:   []byte{},
			wantErr:   true,
			wantCount: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			macs, err := platformesp.ParseCloneStatus(tt.payload)

			if (err != nil) != tt.wantErr {
				t.Fatalf("错误状态不符：err=%v, wantErr=%v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if len(macs) != tt.wantCount {
				t.Fatalf("设备数不符：got %d, want %d", len(macs), tt.wantCount)
			}
			if tt.wantCount > 0 && macs[0] != tt.wantFirst {
				t.Fatalf("首台 MAC 不符：got %s, want %s", macs[0], tt.wantFirst)
			}
		})
	}
}
