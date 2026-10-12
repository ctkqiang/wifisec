package tests

import (
	"net"
	"testing"

	"github.com/ctkqiang/wifisec/internal/functions"
	"github.com/ctkqiang/wifisec/internal/ieee80211"
)

// TestBuildDisassocFrameStructure 覆盖 disassoc 帧结构：与 deauth 完全一致，
// 仅 Frame Control 子类型为 0xA0（subtype 10）。
func TestBuildDisassocFrameStructure(t *testing.T) {
	bssid := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

	frame, err := ieee80211.BuildDisassocFrame(bssid)
	if err != nil {
		t.Fatalf("BuildDisassocFrame 失败：%v", err)
	}

	if len(frame) != ieee80211.DeauthFrameLen {
		t.Errorf("帧长度 %d，期望 %d", len(frame), ieee80211.DeauthFrameLen)
	}

	// disassoc 子类型 10 → 0xA0
	if frame[8] != 0xA0 {
		t.Errorf("Frame Control 低字节 0x%02x，期望 0xA0", frame[8])
	}

	// addr1 广播
	for i := 12; i < 18; i++ {
		if frame[i] != 0xff {
			t.Errorf("addr1[%d] = 0x%02x，期望 0xff", i, frame[i])
		}
	}

	// addr2 = BSSID
	for i := 0; i < 6; i++ {
		if frame[18+i] != bssid[i] {
			t.Errorf("addr2[%d] = 0x%02x，期望 0x%02x", i, frame[18+i], bssid[i])
		}
	}

	// addr3 = BSSID
	for i := 0; i < 6; i++ {
		if frame[24+i] != bssid[i] {
			t.Errorf("addr3[%d] = 0x%02x，期望 0x%02x", i, frame[24+i], bssid[i])
		}
	}
}

// TestBuildManagementFrameInvalidBSSID 确保非法 BSSID 长度返回错误。
func TestBuildManagementFrameInvalidBSSID(t *testing.T) {
	short := net.HardwareAddr{0xaa, 0xbb, 0xcc}

	if _, err := ieee80211.BuildDeauthFrame(short); err == nil {
		t.Error("短 BSSID 应返回错误")
	}

	if _, err := ieee80211.BuildDisassocFrame(short); err == nil {
		t.Error("短 BSSID 应返回错误")
	}
}

// TestDeauthDisassocFrameDifference 确保两种帧只有子类型字节不同。
func TestDeauthDisassocFrameDifference(t *testing.T) {
	bssid := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

	deauth, _ := ieee80211.BuildDeauthFrame(bssid)
	disassoc, _ := ieee80211.BuildDisassocFrame(bssid)

	// 唯一差异应该是 frame[8]（子类型字节）
	diffCount := 0
	for i := range deauth {
		if deauth[i] != disassoc[i] {
			diffCount++
		}
	}

	if diffCount != 1 {
		t.Errorf("两帧应有 1 字节差异，实际 %d", diffCount)
	}

	if deauth[8] == disassoc[8] {
		t.Error("子类型字节应不同")
	}
}

// TestParseJamArgs 覆盖 jam 的参数解析：all 模式、SSID、BSSID、缺参数、多余参数。
func TestParseJamArgs(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantTarget string
		wantAll    bool
		wantIface  string
		wantErr    bool
	}{
		{
			name:       "all 模式",
			args:       []string{"all"},
			wantTarget: "",
			wantAll:    true,
		},
		{
			name:       "ALL 大写也生效",
			args:       []string{"ALL"},
			wantTarget: "",
			wantAll:    true,
		},
		{
			name:       "SSID 模式",
			args:       []string{"MyWiFi"},
			wantTarget: "MyWiFi",
			wantAll:    false,
		},
		{
			name:       "SSID 加网卡",
			args:       []string{"MyWiFi", "wlan0"},
			wantTarget: "MyWiFi",
			wantIface:  "wlan0",
		},
		{
			name:       "BSSID 模式",
			args:       []string{"aa:bb:cc:dd:ee:ff"},
			wantTarget: "aa:bb:cc:dd:ee:ff",
			wantAll:    false,
		},
		{
			name:    "缺参数",
			args:    []string{},
			wantErr: true,
		},
		{
			name:    "空串",
			args:    []string{"  "},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, jamAll, _, ifaceName, err := functions.ParseJamArgs(tt.args)

			if tt.wantErr {
				if err == nil {
					t.Error("期望错误，实际 nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("意外错误：%v", err)
			}

			if target != tt.wantTarget {
				t.Errorf("target = %q, 期望 %q", target, tt.wantTarget)
			}

			if jamAll != tt.wantAll {
				t.Errorf("jamAll = %v, 期望 %v", jamAll, tt.wantAll)
			}

			if ifaceName != tt.wantIface {
				t.Errorf("iface = %q, 期望 %q", ifaceName, tt.wantIface)
			}
		})
	}
}
