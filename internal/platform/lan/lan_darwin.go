//go:build darwin

package lan

import (
	"context"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// BSD 系 arp 输出形如：
//
//	? (192.168.1.1) at f4:ec:be:aa:bb:cc on en0 ifscope [ethernet]
//	? (192.168.1.9) at (incomplete) on en0 ifscope [ethernet]
//
// -n 让 arp 不做反向解析（秒级卡顿的主要来源），主机名由应用层并发查询。
var bsdARPEntryPattern = regexp.MustCompile(
	`\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+(\S+)(?:\s+on\s+(\S+))?`,
)

// 命令挂死会让整个发现流程卡住，统一给 3 秒上限。
const commandTimeout = 3 * time.Second

// Neighbors 调用 arp -an 读取当前邻居表。
func Neighbors() ([]Neighbor, error) {
	output, err := runCommand("arp", "-an")
	if err != nil {
		return nil, err
	}

	return ParseBSDARP(output), nil
}

// ParseBSDARP 解析 arp -an 文本；incomplete 条目的 MAC 段是 "(incomplete)"，
// ParseMAC 会返回 nil 并被自然过滤。
func ParseBSDARP(output string) []Neighbor {
	var neighbors []Neighbor

	for _, match := range bsdARPEntryPattern.FindAllStringSubmatch(output, -1) {
		ip := net.ParseIP(match[1]).To4()
		mac := ParseMAC(strings.Trim(match[2], "()"))
		if ip == nil || mac == nil {
			continue
		}

		neighbors = append(neighbors, Neighbor{
			IP:     ip,
			HWAddr: mac,
			Device: match[3],
		})
	}

	return neighbors
}

// DefaultGateway 解析 route -n get default 的 "gateway: x.x.x.x" 行。
func DefaultGateway() (net.IP, error) {
	output, err := runCommand("route", "-n", "get", "default")
	if err != nil {
		return nil, err
	}

	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "gateway:" {
			if ip := net.ParseIP(fields[1]).To4(); ip != nil {
				return ip, nil
			}
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
