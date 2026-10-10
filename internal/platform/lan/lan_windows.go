//go:build windows

package lan

import (
	"context"
	"net"
	"os/exec"
	"strings"
	"time"
)

// 命令挂死会让整个发现流程卡住，统一给 3 秒上限。
const commandTimeout = 3 * time.Second

// Neighbors 调用 arp -a 读取全部接口的邻居表。
// 中英文 Windows 的表头文案不同，但数据行始终是 ASCII：
//
//	192.168.1.1           aa-bb-cc-dd-ee-ff     动态/dynamic
func Neighbors() ([]Neighbor, error) {
	output, err := runCommand("arp", "-a")
	if err != nil {
		return nil, err
	}

	return ParseWindowsARP(output), nil
}

// ParseWindowsARP 按字段位置解析 arp -a：
// 只有“IPv4 + 六段 MAC”同时成立的行才是有效单播邻居，
// IPv6 行、表头行、incomplete 行由此自然排除。
func ParseWindowsARP(output string) []Neighbor {
	var neighbors []Neighbor

	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		ip := net.ParseIP(fields[0]).To4()
		mac := ParseMAC(fields[1])
		if ip == nil || mac == nil {
			continue
		}

		neighbors = append(neighbors, Neighbor{IP: ip, HWAddr: mac})
	}

	return neighbors
}

// DefaultGateway 从 route print -4 的活动路由表取第一条 0.0.0.0/0 的下一跳。
// 数据行固定为五列：目标 / 掩码 / 网关 / 接口 / 跃点数，不随语言变化。
func DefaultGateway() (net.IP, error) {
	output, err := runCommand("route", "print", "-4")
	if err != nil {
		return nil, err
	}

	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] != "0.0.0.0" || fields[1] != "0.0.0.0" {
			continue
		}

		if gateway := net.ParseIP(fields[2]).To4(); gateway != nil {
			return gateway, nil
		}
	}

	return nil, errGatewayNotFound
}

// runCommand 带超时执行系统命令并返回 stdout；适配器层允许 exec。
func runCommand(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	output, err := exec.CommandContext(ctx, name, args...).Output()

	return strings.TrimSpace(string(output)), err
}
