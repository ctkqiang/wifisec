package tests

import (
	"testing"
	"wifisec/internal/functions"
	platformdarwin "wifisec/internal/platform/darwin"
)

func TestMergeCoreWLANBSSID(t *testing.T) {
	tests := []struct {
		name      string
		existing  functions.WiFiNetwork
		cw        []platformdarwin.Network
		wantBSSID string
	}{
		{
			name:      "占位符横线由 CoreWLAN 补齐",
			existing:  functions.WiFiNetwork{ESSID: "CafeGuest", BSSID: "-", Channel: 6},
			cw:        []platformdarwin.Network{{SSID: "CafeGuest", BSSID: "AA:BB:CC:DD:EE:FF", Channel: 6}},
			wantBSSID: "aa:bb:cc:dd:ee:ff",
		},
		{
			name:      "空 BSSID 由 CoreWLAN 补齐",
			existing:  functions.WiFiNetwork{ESSID: "CafeGuest", BSSID: "", Channel: 6},
			cw:        []platformdarwin.Network{{SSID: "CafeGuest", BSSID: "AA:BB:CC:DD:EE:FF", Channel: 6}},
			wantBSSID: "aa:bb:cc:dd:ee:ff",
		},
		{
			name:      "已有真实 BSSID 不被覆盖",
			existing:  functions.WiFiNetwork{ESSID: "Home", BSSID: "11:22:33:44:55:66", Channel: 3},
			cw:        []platformdarwin.Network{{SSID: "Home", BSSID: "AA:BB:CC:DD:EE:FF", Channel: 3}},
			wantBSSID: "11:22:33:44:55:66",
		},
		{
			name:      "同名双频按信道区分 2.4G",
			existing:  functions.WiFiNetwork{ESSID: "Home", BSSID: "-", Channel: 3},
			cw:        []platformdarwin.Network{{SSID: "Home", BSSID: "B4:B0:24:B6:12:4C", Channel: 3}, {SSID: "Home", BSSID: "B4:B0:24:B6:12:4B", Channel: 157}},
			wantBSSID: "b4:b0:24:b6:12:4c",
		},
		{
			name:      "同名双频按信道区分 5G",
			existing:  functions.WiFiNetwork{ESSID: "Home", BSSID: "-", Channel: 157},
			cw:        []platformdarwin.Network{{SSID: "Home", BSSID: "B4:B0:24:B6:12:4C", Channel: 3}, {SSID: "Home", BSSID: "B4:B0:24:B6:12:4B", Channel: 157}},
			wantBSSID: "b4:b0:24:b6:12:4b",
		},
		{
			name:      "未授权脱敏时 CoreWLAN BSSID 为空则保持占位",
			existing:  functions.WiFiNetwork{ESSID: "Mystery", BSSID: "-", Channel: 11},
			cw:        []platformdarwin.Network{{SSID: "Mystery", BSSID: "", Channel: 11}},
			wantBSSID: "-",
		},
		{
			name:      "信道不匹配不合并且保持占位",
			existing:  functions.WiFiNetwork{ESSID: "Cafe", BSSID: "-", Channel: 1},
			cw:        []platformdarwin.Network{{SSID: "Cafe", BSSID: "AA:BB:CC:DD:EE:FF", Channel: 11}},
			wantBSSID: "-",
		},
		{
			name:      "SSID 不匹配不合并且保持占位",
			existing:  functions.WiFiNetwork{ESSID: "Cafe", BSSID: "-", Channel: 1},
			cw:        []platformdarwin.Network{{SSID: "Other", BSSID: "AA:BB:CC:DD:EE:FF", Channel: 1}},
			wantBSSID: "-",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			networks := []functions.WiFiNetwork{tt.existing}
			functions.MergeCoreWLANBSSID(networks, tt.cw)

			if networks[0].BSSID != tt.wantBSSID {
				t.Errorf("BSSID = %q，期望 %q", networks[0].BSSID, tt.wantBSSID)
			}
		})
	}
}
