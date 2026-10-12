package functions

import (
	"net"
	"testing"
)

// TestPMKIDResolveTarget 锁定目标解析的三条硬规则：
// 同名多 AP 必须拒绝（hash 与 BSSID 绑定）、隐藏 SSID 必须显式给名、
// 信道未知必须拒绝（monitor 无法锁定）。
func TestPMKIDResolveTarget(t *testing.T) {
	aps := []pmkidAP{
		{bssid: "aa:bb:cc:dd:ee:01", ssid: "HomeWiFi", channel: 6, rssi: -40},
		{bssid: "aa:bb:cc:dd:ee:02", ssid: "HomeWiFi", channel: 36, rssi: -55},
		{bssid: "aa:bb:cc:dd:ee:03", ssid: "CoffeeShop", channel: 1, rssi: -60},
		{bssid: "aa:bb:cc:dd:ee:04", ssid: "", channel: 11, rssi: -45},
		{bssid: "aa:bb:cc:dd:ee:05", ssid: "NoChannel"},
	}

	hiddenMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:04")
	uniqueMAC, _ := net.ParseMAC("AA:BB:CC:DD:EE:03")

	cases := []struct {
		name          string
		target        string
		targetMAC     net.HardwareAddr
		essidOverride string
		wantBSSID     string
		wantSSID      string
		wantChannel   int
		wantErr       bool
	}{
		{
			name:        "BSSID 精确命中且大小写归一",
			target:      "AA:BB:CC:DD:EE:03",
			targetMAC:   uniqueMAC,
			wantBSSID:   "aa:bb:cc:dd:ee:03",
			wantSSID:    "CoffeeShop",
			wantChannel: 1,
		},
		{
			name:        "SSID 唯一命中",
			target:      "CoffeeShop",
			wantBSSID:   "aa:bb:cc:dd:ee:03",
			wantSSID:    "CoffeeShop",
			wantChannel: 1,
		},
		{
			name:    "同名多 AP 拒绝执行",
			target:  "HomeWiFi",
			wantErr: true,
		},
		{
			name:    "SSID 大小写敏感",
			target:  "homewifi",
			wantErr: true,
		},
		{
			name:    "无命中",
			target:  "NoSuchNetwork",
			wantErr: true,
		},
		{
			name:      "隐藏 SSID 无覆盖拒绝",
			target:    "aa:bb:cc:dd:ee:04",
			targetMAC: hiddenMAC,
			wantErr:   true,
		},
		{
			name:          "隐藏 SSID 有 --ssid 通过",
			target:        "aa:bb:cc:dd:ee:04",
			targetMAC:     hiddenMAC,
			essidOverride: "HiddenNet",
			wantBSSID:     "aa:bb:cc:dd:ee:04",
			wantSSID:      "HiddenNet",
			wantChannel:   11,
		},
		{
			name:    "信道未知拒绝",
			target:  "NoChannel",
			wantErr: true,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pmkidResolveTarget(aps, tt.target, tt.targetMAC, tt.essidOverride)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("期望拒绝，实际解析成功：%+v", got)
				}

				return
			}

			if err != nil {
				t.Fatalf("期望解析成功，实际报错：%v", err)
			}

			if got.bssid != tt.wantBSSID || got.ssid != tt.wantSSID || got.channel != tt.wantChannel {
				t.Errorf("目标绑定不符：got {%s %s %d %d}，want {%s %s %d}",
					got.bssid, got.ssid, got.channel, got.rssi, tt.wantBSSID, tt.wantSSID, tt.wantChannel)
			}
		})
	}
}

func TestNormalizeHiddenSSID(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"iw 隐藏表示归空", "<hidden>", ""},
		{"空串保持为空", "", ""},
		{"首尾空白剥离", "  Spa  ", "Spa"},
		{"普通 SSID 原样", "HomeWiFi", "HomeWiFi"},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeHiddenSSID(tt.input); got != tt.want {
				t.Errorf("normalizeHiddenSSID(%q) = %q，期望 %q", tt.input, got, tt.want)
			}
		})
	}
}
