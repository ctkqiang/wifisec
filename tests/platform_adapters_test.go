package tests

import (
	platformlinux "github.com/ctkqiang/wifisec/internal/platform/linux"
	platformtermux "github.com/ctkqiang/wifisec/internal/platform/termux"
	platformwindows "github.com/ctkqiang/wifisec/internal/platform/windows"
	"testing"
)

func TestParseTermuxCapabilities(t *testing.T) {
	tests := []struct {
		name         string
		capabilities string
		wantEnc      string
		wantCipher   string
		wantAuth     string
	}{
		{name: "wpa2 psk ccmp", capabilities: "[WPA2-PSK-CCMP][RSN-PSK-CCMP][ESS]", wantEnc: "WPA2", wantCipher: "CCMP", wantAuth: "PSK"},
		{name: "wpa3 sae", capabilities: "[RSN-SAE+GCMP-256][ESS]", wantEnc: "WPA3", wantCipher: "GCMP", wantAuth: "SAE"},
		{name: "企业 eap", capabilities: "[WPA2-EAP-CCMP][ESS]", wantEnc: "WPA2", wantCipher: "CCMP", wantAuth: "802.1X"},
		{name: "wpa1 tkip", capabilities: "[WPA-PSK-TKIP][ESS]", wantEnc: "WPA", wantCipher: "TKIP", wantAuth: "PSK"},
		{name: "wep", capabilities: "[WEP][ESS]", wantEnc: "WEP", wantCipher: "WEP", wantAuth: ""},
		{name: "开放", capabilities: "[ESS]", wantEnc: "OPEN", wantCipher: "", wantAuth: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc, cipher, auth := platformtermux.ParseCapabilities(tt.capabilities)
			if enc != tt.wantEnc || cipher != tt.wantCipher || auth != tt.wantAuth {
				t.Errorf("ParseCapabilities() = (%q, %q, %q)，期望 (%q, %q, %q)",
					enc, cipher, auth, tt.wantEnc, tt.wantCipher, tt.wantAuth)
			}
		})
	}
}

func TestParseConnectedLink(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{
			name:   "已连接",
			output: "Connected to b4:b0:24:b6:12:4b (on wlan0)\nSSID: HOME\nfreq: 5785",
			want:   "b4:b0:24:b6:12:4b",
		},
		{
			name:   "未连接",
			output: "Not connected.",
			want:   "",
		},
		{
			name:   "大写 BSSID 归一化",
			output: "Connected to AA:BB:CC:DD:EE:FF (on wlan0)",
			want:   "aa:bb:cc:dd:ee:ff",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := platformlinux.ParseConnectedLink(tt.output); got != tt.want {
				t.Errorf("ParseConnectedLink() = %q，期望 %q", got, tt.want)
			}
		})
	}
}

func TestParseInterfaceMode(t *testing.T) {
	output := "Interface wlan0\n\tifindex 4\n\ttype managed\n\tchannel 11 (2462 MHz)"
	if got := platformlinux.ParseInterfaceMode(output); got != "managed" {
		t.Errorf("ParseInterfaceMode() = %q，期望 managed", got)
	}
}

func TestParseNetshInterfaces(t *testing.T) {
	raw := "名称    : Wi-Fi\r\n" +
		"描述    : Intel(R) Wi-Fi 6E AX211\r\n" +
		"物理地址: 9C:3E:53:83:CC:87\r\n" +
		"状态    : connected\r\n"

	interfaces := platformwindows.ParseInterfaces(raw)
	if len(interfaces) != 1 {
		t.Fatalf("应解析 1 个适配器，实际 %d 个", len(interfaces))
	}

	got := interfaces[0]
	if got.Name != "Wi-Fi" || got.MAC != "9c:3e:53:83:cc:87" || got.State != "UP" {
		t.Errorf("接口字段错误：%+v", got)
	}
}

func TestParseNetshDriver(t *testing.T) {
	output := "接口名称: Wi-Fi\n    驱动程序                  : Intel(R) Wi-Fi 6E AX211\n    供应商: Intel"
	if got := platformwindows.ParseDriver(output); got != "Intel(R) Wi-Fi 6E AX211" {
		t.Errorf("ParseDriver() = %q", got)
	}
}
