//go:build darwin

package tests

import (
	"strings"
	"testing"

	"github.com/ctkqiang/wifisec/internal/platform/lan"
)

// TestParseBSDARP 验证 macOS arp -an 输出解析，incomplete 条目必须被过滤。
func TestParseBSDARP(t *testing.T) {
	output := strings.Join([]string{
		"? (192.168.1.1) at f4:ec:be:aa:bb:cc on en0 ifscope [ethernet]",
		"? (192.168.1.9) at (incomplete) on en0 ifscope [ethernet]",
		"router (10.0.0.1) at aa:bb:cc:dd:ee:ff on en1 permanent [ethernet]",
	}, "\n")

	neighbors := lan.ParseBSDARP(output)
	if len(neighbors) != 2 {
		t.Fatalf("应解析出 2 条有效邻居（incomplete 丢弃），实际 %d 条", len(neighbors))
	}

	if neighbors[1].IP.String() != "10.0.0.1" || neighbors[1].Device != "en1" {
		t.Fatalf("第二条字段不符：%+v", neighbors[1])
	}
}
