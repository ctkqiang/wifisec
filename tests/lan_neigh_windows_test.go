//go:build windows

package tests

import (
	"strings"
	"testing"

	"github.com/ctkqiang/wifisec/internal/platform/lan"
)

// TestParseWindowsARP 验证中英文 Windows arp -a 行解析：
// 横杠 MAC 归一化，IPv6/表头行不混入。
func TestParseWindowsARP(t *testing.T) {
	output := strings.Join([]string{
		"接口: 192.168.1.50 --- 0xa",
		"  Internet 地址         物理地址              类型",
		"  192.168.1.1           aa-bb-cc-dd-ee-ff     动态",
		"  2001:db8::1                                  已访问",
		"  192.168.1.22          11-22-33-44-55-66     静态",
	}, "\n")

	neighbors := lan.ParseWindowsARP(output)
	if len(neighbors) != 2 {
		t.Fatalf("应解析出 2 条 IPv4 邻居，实际 %d 条", len(neighbors))
	}

	if neighbors[0].HWAddr.String() != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("横杠 MAC 应归一化为冒号形式，实际 %s", neighbors[0].HWAddr)
	}
}
