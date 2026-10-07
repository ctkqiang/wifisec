package tests

import (
	"net"
	"testing"
	"wifisec/internal/ieee80211"
)

// TestBuildDeauthFrame 逐字节断言 34 字节 deauth 帧布局。
func TestBuildDeauthFrame(t *testing.T) {
	bssid, err := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	if err != nil {
		t.Fatalf("解析测试 BSSID 失败：%v", err)
	}

	frame, err := ieee80211.BuildDeauthFrame(bssid)
	if err != nil {
		t.Fatalf("构造帧失败：%v", err)
	}

	if len(frame) != 34 {
		t.Fatalf("帧长度应为 34，实际 %d", len(frame))
	}

	// Radiotap 头：version 0 + pad 0 + length 8 + present 0
	wantRadiotap := []byte{0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00}
	for i := range wantRadiotap {
		if frame[i] != wantRadiotap[i] {
			t.Errorf("radiotap[%d] 应为 0x%02x，实际 0x%02x", i, wantRadiotap[i], frame[i])
		}
	}

	// Frame Control：c0 00（deauthentication 管理帧）
	if frame[8] != 0xc0 || frame[9] != 0x00 {
		t.Errorf("Frame Control 应为 c0 00，实际 %02x %02x", frame[8], frame[9])
	}

	// addr1：广播地址 ff:ff:ff:ff:ff:ff
	for i := 12; i < 18; i++ {
		if frame[i] != 0xff {
			t.Errorf("addr1[%d] 应为 0xff，实际 0x%02x", i-12, frame[i])
		}
	}

	// addr2 = BSSID
	for i := 0; i < 6; i++ {
		if frame[18+i] != bssid[i] {
			t.Errorf("addr2[%d] 应为 0x%02x，实际 0x%02x", i, bssid[i], frame[18+i])
		}
	}

	// addr3 = BSSID
	for i := 0; i < 6; i++ {
		if frame[24+i] != bssid[i] {
			t.Errorf("addr3[%d] 应为 0x%02x，实际 0x%02x", i, bssid[i], frame[24+i])
		}
	}

	// Reason Code：7（class 3 frame received from nonassociated STA）
	if frame[32] != 0x07 || frame[33] != 0x00 {
		t.Errorf("Reason Code 应为 07 00，实际 %02x %02x", frame[32], frame[33])
	}
}

// TestBuildDeauthFrameBadLength 对非 6 字节 MAC 返回错误。
func TestBuildDeauthFrameBadLength(t *testing.T) {
	tests := []struct {
		name  string
		bssid net.HardwareAddr
	}{
		{"空切片", net.HardwareAddr{}},
		{"太短", net.HardwareAddr{0x01, 0x02, 0x03}},
		{"太长", net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ieee80211.BuildDeauthFrame(tt.bssid); err == nil {
				t.Errorf("长度 %d 的 BSSID 应返回错误", len(tt.bssid))
			}
		})
	}
}
