//go:build linux || android

package tests

import (
	"strings"
	"testing"

	"github.com/ctkqiang/wifisec/internal/platform/lan"
)

// TestParseProcARP 验证 /proc/net/arp 解析：
// 正常条目保留，incomplete 全零 MAC 与表头丢弃。
func TestParseProcARP(t *testing.T) {
	raw := []byte(strings.Join([]string{
		"IP address       HW type     Flags       HW address            Mask     Device",
		"192.168.1.1      0x1         0x2         f4:ec:be:aa:bb:cc     *        wlan0",
		"192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        wlan0",
		"192.168.1.22     0x1         0x2         1:2:3:4:5:6           *        eth0",
	}, "\n"))

	neighbors := lan.ParseProcARP(raw)
	if len(neighbors) != 2 {
		t.Fatalf("应解析出 2 条有效邻居，实际 %d 条", len(neighbors))
	}

	if neighbors[0].IP.String() != "192.168.1.1" || neighbors[0].Device != "wlan0" {
		t.Fatalf("首条字段不符：%+v", neighbors[0])
	}

	if neighbors[1].HWAddr.String() != "01:02:03:04:05:06" {
		t.Fatalf("短十六进制 MAC 应归一化，实际 %s", neighbors[1].HWAddr)
	}
}
