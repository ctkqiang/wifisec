package tests

import (
	"testing"
	"time"

	"github.com/ctkqiang/wifisec/internal/functions"
)

func TestParsePMKIDArgs(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		want    functions.PMKIDOptions
		wantErr bool
	}{
		{
			name: "仅目标 SSID",
			args: []string{"MyWiFi"},
			want: functions.PMKIDOptions{Target: "MyWiFi"},
		},
		{
			name: "目标加网卡",
			args: []string{"MyWiFi", "wlan0mon"},
			want: functions.PMKIDOptions{Target: "MyWiFi", Interface: "wlan0mon"},
		},
		{
			name: "flag 穿插在位置参数之间",
			args: []string{"--json", "aa:bb:cc:dd:ee:ff", "-o", "out.22000", "wlan0"},
			want: functions.PMKIDOptions{
				Target:    "aa:bb:cc:dd:ee:ff",
				Interface: "wlan0",
				Output:    "out.22000",
				JSON:      true,
			},
		},
		{
			name: "全量参数组合",
			args: []string{"aa:bb:cc:dd:ee:ff", "wlan0", "-o", "out.22000", "--ssid", "HiddenNet", "--attempts", "5", "--json"},
			want: functions.PMKIDOptions{
				Target:    "aa:bb:cc:dd:ee:ff",
				Interface: "wlan0",
				Output:    "out.22000",
				SSID:      "HiddenNet",
				Attempts:  5,
				JSON:      true,
			},
		},
		{name: "缺目标", args: []string{}, wantErr: true},
		{name: "-o 缺值", args: []string{"MyWiFi", "-o"}, wantErr: true},
		{name: "--ssid 缺值", args: []string{"MyWiFi", "--ssid"}, wantErr: true},
		{name: "--attempts 非数字", args: []string{"MyWiFi", "--attempts", "abc"}, wantErr: true},
		{name: "--attempts 为零", args: []string{"MyWiFi", "--attempts", "0"}, wantErr: true},
		{name: "--attempts 负数", args: []string{"MyWiFi", "--attempts", "-3"}, wantErr: true},
		{name: "未知 flag", args: []string{"MyWiFi", "--bogus"}, wantErr: true},
		{name: "多余位置参数", args: []string{"a", "b", "c"}, wantErr: true},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := functions.ParsePMKIDArgs(tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("期望报错，实际解析成功：%+v", got)
				}

				return
			}

			if err != nil {
				t.Fatalf("期望解析成功，实际报错：%v", err)
			}

			if got != tt.want {
				t.Errorf("解析结果不符：got %+v，want %+v", got, tt.want)
			}
		})
	}
}

func TestParseExtractArgs(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		want    functions.ExtractOptions
		wantErr bool
	}{
		{
			name: "仅输入文件",
			args: []string{"capture.pcap"},
			want: functions.ExtractOptions{Input: "capture.pcap"},
		},
		{
			name: "全量参数组合",
			args: []string{"capture.pcap", "--hashcat", "out.22000", "--pmkid", "out.16800", "--bssid", "AA:BB:CC:DD:EE:FF", "--ssid", "HomeNet", "--json"},
			want: functions.ExtractOptions{
				Input:      "capture.pcap",
				HashcatOut: "out.22000",
				PMKIDOut:   "out.16800",
				BSSID:      "aa:bb:cc:dd:ee:ff",
				SSID:       "HomeNet",
				JSON:       true,
			},
		},
		{name: "缺输入", args: []string{}, wantErr: true},
		{name: "--hashcat 缺值", args: []string{"capture.pcap", "--hashcat"}, wantErr: true},
		{name: "--pmkid 缺值", args: []string{"capture.pcap", "--pmkid"}, wantErr: true},
		{name: "--bssid 缺值", args: []string{"capture.pcap", "--bssid"}, wantErr: true},
		{name: "非法 BSSID", args: []string{"capture.pcap", "--bssid", "zz"}, wantErr: true},
		{name: "--ssid 缺值", args: []string{"capture.pcap", "--ssid"}, wantErr: true},
		{name: "未知 flag", args: []string{"capture.pcap", "--bogus"}, wantErr: true},
		{name: "多余位置参数", args: []string{"a.pcap", "b.pcap"}, wantErr: true},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := functions.ParseExtractArgs(tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("期望报错，实际解析成功：%+v", got)
				}

				return
			}

			if err != nil {
				t.Fatalf("期望解析成功，实际报错：%v", err)
			}

			if got != tt.want {
				t.Errorf("解析结果不符：got %+v，want %+v", got, tt.want)
			}
		})
	}
}

// TestParseSniffArgsFlags 覆盖 --eapol/--pmkid/--bssid/--ssid/--json 的
// flag 语义；位置参数（网卡/秒数/文件）的解析在 lan_tools_test.go。
func TestParseSniffArgsFlags(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		want    functions.SniffOptions
		wantErr bool
	}{
		{
			name: "新 flag 全开且与位置参数共存",
			args: []string{"--eapol", "--pmkid", "--json", "--bssid", "AA:BB:CC:DD:EE:FF", "--ssid", "HomeNet", "wlan0", "60", "eapol.pcap"},
			want: functions.SniffOptions{
				Interface:  "wlan0",
				Seconds:    60,
				Duration:   60 * time.Second,
				OutputPath: "eapol.pcap",
				EAPOL:      true,
				PMKID:      true,
				BSSID:      "aa:bb:cc:dd:ee:ff",
				SSID:       "HomeNet",
				JSON:       true,
			},
		},
		{
			name: "仅 --eapol 不影响其他字段",
			args: []string{"--eapol", "en0"},
			want: functions.SniffOptions{Interface: "en0", EAPOL: true},
		},
		{name: "--bssid 缺值", args: []string{"--bssid"}, wantErr: true},
		{name: "非法 BSSID", args: []string{"--bssid", "zz"}, wantErr: true},
		{name: "--ssid 缺值", args: []string{"--ssid"}, wantErr: true},
		{name: "未知 flag", args: []string{"--bogus"}, wantErr: true},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := functions.ParseSniffArgs(tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("期望报错，实际解析成功：%+v", got)
				}

				return
			}

			if err != nil {
				t.Fatalf("期望解析成功，实际报错：%v", err)
			}

			if got != tt.want {
				t.Errorf("解析结果不符：got %+v，want %+v", got, tt.want)
			}
		})
	}
}
