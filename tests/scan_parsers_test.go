package tests

import (
	"strings"
	"testing"
	"wifisec/internal/functions"
)

func TestParseIWScanOutput(t *testing.T) {
	const sample = "BSS 24:7f:20:11:22:33(on wlan0)\n" +
		"\tTSF: 123456 us (0d)\n" +
		"\tfreq: 2412\n" +
		"\tbeacon interval: 100 TUs\n" +
		"\tcapability: ESS Privacy ShortPreamble (0x00000411)\n" +
		"\tsignal: -58.00 dBm\n" +
		"\tlast seen: 0 ms ago\n" +
		"\tSSID: SkyFiber\n" +
		"\tSupported rates: 1.0* 2.0* 5.5* 11.0*\n" +
		"\tDS Parameter set: channel 1\n" +
		"\tRSN:\t * Version: 1\n" +
		"\t\t * Group cipher: CCMP\n" +
		"\t\t * Pairwise ciphers: CCMP\n" +
		"\t\t * Authentication suites: PSK\n" +
		"\t\t * Capabilities: (0x00000000)\n" +
		"\tHT capabilities:\n" +
		"\tHT operation:\n" +
		"\t\t * primary channel: 1\n" +
		"\t\t * secondary channel offset: below\n" +
		"\nBSS 24:7f:20:aa:bb:cc(on wlan0)\n" +
		"\tfreq: 5180\n" +
		"\tcapability: ESS (0x00000001)\n" +
		"\tsignal: -70.00 dBm\n" +
		"\tSSID: \n" +
		"\tDS Parameter set: channel 36\n" +
		"\tVHT capabilities:\n" +
		"\tVHT operation:\n" +
		"\t\t * channel width: 1 (80 MHz)\n" +
		"\t\t * channel center freq segment 0: 42\n" +
		"\t\t * 0: 72\n" +
		"\tHE:\n"

	networks := functions.ParseIWScanOutput(sample, "wlan0")

	if len(networks) != 2 {
		t.Fatalf("应解析出 2 个 BSS，实际 %d 个", len(networks))
	}

	first := networks[0]
	if first.BSSID != "24:7f:20:11:22:33" {
		t.Errorf("BSSID 归一化错误：got %s", first.BSSID)
	}
	if first.ESSID != "SkyFiber" || first.Signal != -58 || first.Channel != 1 {
		t.Errorf("基础字段错误：%+v", first)
	}
	if first.Freq != "2GHz" {
		t.Errorf("频段应为 2GHz，got %s", first.Freq)
	}
	if first.Enc != "WPA2" || first.Cipher != "CCMP" || first.Auth != "PSK" {
		t.Errorf("安全套件错误：enc=%s cipher=%s auth=%s", first.Enc, first.Cipher, first.Auth)
	}
	if first.ChannelWidth != 40 {
		t.Errorf("HT 副信道在 below 时应为 40MHz，got %d", first.ChannelWidth)
	}
	if !strings.Contains(first.PHY, "/n") || strings.Contains(first.PHY, "/ac") {
		t.Errorf("仅 HT 能力时 PHY 应包含 /n 且不含 /ac，got %s", first.PHY)
	}
	if first.Device != "wlan0" {
		t.Errorf("设备名应为 wlan0，got %s", first.Device)
	}

	second := networks[1]
	if second.ESSID != "<hidden>" {
		t.Errorf("空 SSID IE 应渲染为 <hidden>，got %q", second.ESSID)
	}
	if second.Channel != 36 || second.Freq != "5GHz" {
		t.Errorf("5GHz 信道/频段错误：ch=%d band=%s", second.Channel, second.Freq)
	}
	if second.Enc != "OPEN" {
		t.Errorf("无 Privacy 位且无安全 IE 应为 OPEN，got %s", second.Enc)
	}
	if second.ChannelWidth != 80 {
		t.Errorf("VHT code 1 应为 80MHz，got %d", second.ChannelWidth)
	}
}

func TestParseIWScanWPA3AndWEP(t *testing.T) {
	tests := []struct {
		name        string
		output      string
		wantEnc     string
		wantCipher  string
		wantAuth    string
		wantChannel int
	}{
		{
			name: "wpa3 sae gcmp 无 DS 参数走频率换算",
			output: "BSS 11:22:33:44:55:66(on wlan0)\n" +
				"\tfreq: 5500\n" +
				"\tsignal: -60.00 dBm\n" +
				"\tSSID: SecureNet\n" +
				"\tcapability: ESS Privacy (0x00000011)\n" +
				"\tRSN:\t * Version: 1\n" +
				"\t\t * Group cipher: GCMP-128\n" +
				"\t\t * Pairwise ciphers: GCMP-128\n" +
				"\t\t * Authentication suites: SAE FT/SAE\n",
			wantEnc:     "WPA3",
			wantCipher:  "GCMP",
			wantAuth:    "SAE",
			wantChannel: 100,
		},
		{
			name: "仅有 Privacy 位无安全 IE 判定为 WEP",
			output: "BSS aa:bb:cc:dd:ee:ff(on wlan0)\n" +
				"\tfreq: 2437\n" +
				"\tsignal: -80.00 dBm\n" +
				"\tSSID: OldNet\n" +
				"\tcapability: ESS Privacy ShortSlot (0x00000011)\n",
			wantEnc:     "WEP",
			wantCipher:  "WEP",
			wantAuth:    "",
			wantChannel: 6,
		},
		{
			name: "企业级 802.1X 认证套件",
			output: "BSS 66:77:88:99:aa:bb(on wlan0)\n" +
				"\tfreq: 5180\n" +
				"\tsignal: -65.00 dBm\n" +
				"\tSSID: CorpNet\n" +
				"\tcapability: ESS Privacy (0x00000011)\n" +
				"\tRSN:\t * Version: 1\n" +
				"\t\t * Group cipher: CCMP\n" +
				"\t\t * Pairwise ciphers: CCMP\n" +
				"\t\t * Authentication suites: 802.1X\n",
			wantEnc:     "WPA2",
			wantCipher:  "CCMP",
			wantAuth:    "802.1X",
			wantChannel: 36,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			networks := functions.ParseIWScanOutput(tt.output, "wlan0")
			if len(networks) != 1 {
				t.Fatalf("应解析 1 个 BSS，实际 %d", len(networks))
			}

			n := networks[0]
			if n.Enc != tt.wantEnc || n.Cipher != tt.wantCipher || n.Auth != tt.wantAuth {
				t.Errorf("安全字段错误：enc=%s cipher=%s auth=%s", n.Enc, n.Cipher, n.Auth)
			}
			if n.Channel != tt.wantChannel {
				t.Errorf("信道应为 %d，got %d", tt.wantChannel, n.Channel)
			}
		})
	}
}

func TestParseNetshBSSIDOutput(t *testing.T) {
	tests := []struct {
		name      string
		output    string
		wantCount int
		check     func(t *testing.T, networks []functions.WiFiNetwork)
	}{
		{
			name: "英文系统 同名 2.4G/5G 双 BSSID + 开放网络",
			output: "Interface name : Wi-Fi\r\n" +
				"There are 2 networks currently visible.\r\n\r\n" +
				"SSID 1 : SkyFiber\r\n" +
				"    Network type            : Infrastructure\r\n" +
				"    Authentication          : WPA2-Personal\r\n" +
				"    Encryption              : CCMP\r\n" +
				"    BSSID 1                 : 24:7f:20:11:22:33\r\n" +
				"         Signal             : 84%\r\n" +
				"         Radio type         : 802.11ax\r\n" +
				"         Channel            : 1\r\n" +
				"    BSSID 2                 : 24:7f:20:aa:bb:cc\r\n" +
				"         Signal             : 60%\r\n" +
				"         Radio type         : 802.11ac\r\n" +
				"         Channel            : 36\r\n\r\n" +
				"SSID 2 : OpenNet\r\n" +
				"    Network type            : Infrastructure\r\n" +
				"    Authentication          : Open\r\n" +
				"    Encryption              : None\r\n" +
				"    BSSID 1                 : 00:11:22:33:44:55\r\n" +
				"         Signal             : 30%\r\n" +
				"         Radio type         : 802.11n\r\n" +
				"         Channel            : 6\r\n",
			wantCount: 3,
			check: func(t *testing.T, networks []functions.WiFiNetwork) {
				if networks[0].ESSID != "SkyFiber" || networks[1].ESSID != "SkyFiber" {
					t.Errorf("同名 SSID 应各成一行：%+v / %+v", networks[0], networks[1])
				}
				if networks[0].BSSID != "24:7f:20:11:22:33" || networks[1].BSSID != "24:7f:20:aa:bb:cc" {
					t.Errorf("BSSID 拆分错误：%s / %s", networks[0].BSSID, networks[1].BSSID)
				}
				if networks[0].Signal != -58 || networks[1].Signal != -70 {
					t.Errorf("信号百分比换算错误：%d / %d", networks[0].Signal, networks[1].Signal)
				}
				if networks[0].Channel != 1 || networks[0].Freq != "2GHz" {
					t.Errorf("2.4G 信道/频段错误：%d %s", networks[0].Channel, networks[0].Freq)
				}
				if networks[1].Channel != 36 || networks[1].Freq != "5GHz" {
					t.Errorf("5G 信道/频段错误：%d %s", networks[1].Channel, networks[1].Freq)
				}
				if networks[0].Enc != "WPA2" || networks[0].Auth != "PSK" || networks[0].Cipher != "CCMP" {
					t.Errorf("WPA2 套件错误：%+v", networks[0])
				}
				if networks[2].Enc != "OPEN" || networks[2].Auth != "" || networks[2].Cipher != "" {
					t.Errorf("开放网络套件错误：%+v", networks[2])
				}
			},
		},
		{
			name: "中文系统 WPA3 键名兼容",
			output: "接口名称 : Wi-Fi\r\n" +
				"当前有 1 个网络可见。\r\n\r\n" +
				"SSID 1 : 测试网络\r\n" +
				"    网络类型          : 基础结构\r\n" +
				"    身份验证          : WPA3-Personal\r\n" +
				"    加密              : GCMP\r\n" +
				"    BSSID 1           : 66:77:88:99:aa:bb\r\n" +
				"         信号         : 50%\r\n" +
				"         无线电类型   : 802.11ax\r\n" +
				"         频道         : 149\r\n",
			wantCount: 1,
			check: func(t *testing.T, networks []functions.WiFiNetwork) {
				n := networks[0]
				if n.Enc != "WPA3" || n.Auth != "SAE" || n.Cipher != "GCMP" {
					t.Errorf("WPA3 中文键名解析错误：%+v", n)
				}
				if n.Signal != -75 {
					t.Errorf("信号换算错误：%d", n.Signal)
				}
				if n.Channel != 149 || n.Freq != "5GHz" {
					t.Errorf("信道/频段错误：%d %s", n.Channel, n.Freq)
				}
				if n.PHY != "802.11ax" {
					t.Errorf("无线电类型错误：%s", n.PHY)
				}
			},
		},
		{
			name: "英文系统 WPA2 企业级映射 802.1X",
			output: "Interface name : Wi-Fi\r\n" +
				"There are 1 networks currently visible.\r\n\r\n" +
				"SSID 1 : CorpNet\r\n" +
				"    Network type            : Infrastructure\r\n" +
				"    Authentication          : WPA2-Enterprise\r\n" +
				"    Encryption              : CCMP\r\n" +
				"    BSSID 1                 : 66:77:88:99:aa:bb\r\n" +
				"         Signal             : 70%\r\n" +
				"         Radio type         : 802.11ax\r\n" +
				"         Channel            : 36\r\n",
			wantCount: 1,
			check: func(t *testing.T, networks []functions.WiFiNetwork) {
				n := networks[0]
				if n.Enc != "WPA2" || n.Auth != "802.1X" || n.Cipher != "CCMP" {
					t.Errorf("企业级套件映射错误：%+v", n)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			networks := functions.ParseNetshBSSIDOutput(tt.output)
			if len(networks) != tt.wantCount {
				t.Fatalf("应解析 %d 个网络，实际 %d", tt.wantCount, len(networks))
			}
			tt.check(t, networks)
		})
	}
}
