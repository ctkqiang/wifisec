package tests

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
	"wifisec/internal/functions"
)

// captureStdout 捕获 fn 执行期间写入标准输出的全部内容，用于行为级断言。
// 输出仅几 KB，远低于管道缓冲区，fn 返回后统一读取不会阻塞。
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	original := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("创建管道失败：%v", err)
	}

	os.Stdout = writer
	defer func() { os.Stdout = original }()

	fn()

	if err := writer.Close(); err != nil {
		t.Fatalf("关闭管道写端失败：%v", err)
	}

	var buffer bytes.Buffer
	if _, err := io.Copy(&buffer, reader); err != nil {
		t.Fatalf("读取管道失败：%v", err)
	}

	return buffer.String()
}

// TestExplainRegulatoryGrid 验证法规合规区块以网格呈现：
// 单元格含国码、名称与判定，且一行容纳多格（网格化的意义所在）。
func TestExplainRegulatoryGrid(t *testing.T) {
	network := functions.WiFiNetwork{
		ESSID: "grid-check", BSSID: "aa:bb:cc:dd:ee:ff",
		Enc: "WPA2", Cipher: "CCMP", Auth: "PSK",
		Channel: 157, Freq: "5GHz", Signal: -55,
	}

	output := captureStdout(t, func() {
		functions.ExplainNetworks([]functions.WiFiNetwork{network}, "")
	})

	for _, marker := range []string{"信道 157 各法规域对照", "AU 澳大利亚 · 合法", "EU 欧盟 · 禁用"} {
		if !strings.Contains(output, marker) {
			t.Errorf("网格输出应包含 %q，实际输出：\n%s", marker, output)
		}
	}

	// 网格特征：至少一行装了两个以上单元格（即含两个判定标记）。
	// 用「· 合法 / · 禁用 / · DFS」计数，避开安全态势行里的「· 套件 · 认证」。
	gridLike := false
	for _, line := range strings.Split(output, "\n") {
		verdicts := strings.Count(line, "· 合法") + strings.Count(line, "· 禁用") + strings.Count(line, "· DFS")
		if verdicts >= 2 {
			gridLike = true
			break
		}
	}

	if !gridLike {
		t.Errorf("法规域应以网格（一行多格）呈现，实际输出：\n%s", output)
	}
}

// TestExplainSecurityRouting 验证安全态势按认证方式分流：
// 企业级（802.1X）输出 EAP 态势对照表，个人级输出 PSK/SAE 话术，互不串场。
func TestExplainSecurityRouting(t *testing.T) {
	tests := []struct {
		name           string
		network        functions.WiFiNetwork
		mustContain    []string
		mustNotContain []string
	}{
		{
			name: "WPA2 企业级输出 EAP 态势对照",
			network: functions.WiFiNetwork{
				ESSID: "corp-wifi", BSSID: "aa:bb:cc:dd:ee:ff",
				Enc: "WPA2", Cipher: "CCMP", Auth: "802.1X",
				Channel: 36, Freq: "5GHz", Signal: -60,
			},
			mustContain: []string{
				"802.1X", "EAP-TLS", "EAP-TTLS", "PEAP", "EAP-MD5", "LEAP",
				"流氓 AP", "域账号", "不随信标广播",
			},
			mustNotContain: []string{"PSK 模式"},
		},
		{
			name: "WPA3 企业级补充 192 位 CNSA 说明",
			network: functions.WiFiNetwork{
				ESSID: "corp-ax", BSSID: "11:22:33:44:55:66",
				Enc: "WPA3", Cipher: "GCMP", Auth: "802.1X",
				Channel: 100, Freq: "5GHz", Signal: -55,
			},
			mustContain:    []string{"802.1X", "192 位", "EAP-TLS"},
			mustNotContain: []string{"SAE（Dragonfly）", "PSK 模式"},
		},
		{
			name: "WPA2 个人级保持 PSK 话术",
			network: functions.WiFiNetwork{
				ESSID: "home-wifi", BSSID: "24:7f:20:11:22:33",
				Enc: "WPA2", Cipher: "CCMP", Auth: "PSK",
				Channel: 6, Freq: "2GHz", Signal: -58,
			},
			mustContain:    []string{"PSK 模式", "KRACK"},
			mustNotContain: []string{"EAP-MD5", "802.1X/RADIUS"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := captureStdout(t, func() {
				functions.ExplainNetworks([]functions.WiFiNetwork{tt.network}, "")
			})

			for _, marker := range tt.mustContain {
				if !strings.Contains(output, marker) {
					t.Errorf("输出应包含 %q，实际输出：\n%s", marker, output)
				}
			}

			for _, marker := range tt.mustNotContain {
				if strings.Contains(output, marker) {
					t.Errorf("输出不应包含 %q，实际输出：\n%s", marker, output)
				}
			}
		})
	}
}
