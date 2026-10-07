package tests

import (
	"net"
	"testing"
	"wifisec/internal/functions"
	platformlinux "wifisec/internal/platform/linux"
)

// TestSelectDeauthTargets 覆盖 SSID 精确匹配、BSSID 归一化匹配、同名多 AP 入选、无命中四类场景。
func TestSelectDeauthTargets(t *testing.T) {
	scanned := []platformlinux.Network{
		{BSSID: "aa:bb:cc:dd:ee:01", SSID: "HomeWiFi", Channel: 6},
		{BSSID: "aa:bb:cc:dd:ee:02", SSID: "HomeWiFi", Channel: 36},
		{BSSID: "aa:bb:cc:dd:ee:03", SSID: "CoffeeShop", Channel: 1},
		{BSSID: "aa:bb:cc:dd:ee:04", SSID: "homewifi", Channel: 11}, // 小写，不应匹配
	}

	tests := []struct {
		name      string
		target    string
		targetMAC net.HardwareAddr
		wantCount int
		wantBSSID []string
	}{
		{
			name:      "SSID 精确匹配：同名双频全部入选",
			target:    "HomeWiFi",
			targetMAC: nil,
			wantCount: 2,
			wantBSSID: []string{"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"},
		},
		{
			name:      "SSID 大小写敏感",
			target:    "homewifi",
			targetMAC: nil,
			wantCount: 1,
			wantBSSID: []string{"aa:bb:cc:dd:ee:04"},
		},
		{
			name:      "BSSID 精确匹配",
			target:    "aa:bb:cc:dd:ee:03",
			targetMAC: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x03},
			wantCount: 1,
			wantBSSID: []string{"aa:bb:cc:dd:ee:03"},
		},
		{
			name:      "BSSID 大小写归一化匹配",
			target:    "AA:BB:CC:DD:EE:01",
			targetMAC: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01},
			wantCount: 1,
			wantBSSID: []string{"aa:bb:cc:dd:ee:01"},
		},
		{
			name:      "无命中",
			target:    "NoSuchNetwork",
			targetMAC: nil,
			wantCount: 0,
			wantBSSID: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := functions.SelectDeauthTargets(scanned, tt.target, tt.targetMAC)
			if len(got) != tt.wantCount {
				t.Fatalf("应命中 %d 个目标，实际 %d 个", tt.wantCount, len(got))
			}

			for i, want := range tt.wantBSSID {
				if got[i].BSSID != want {
					t.Errorf("第 %d 个目标 BSSID 应为 %s，实际 %s", i, want, got[i].BSSID)
				}
			}
		})
	}
}
