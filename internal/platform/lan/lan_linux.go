//go:build linux || android

package lan

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"net"
	"os"
	"strconv"
	"strings"
)

// 邻居表与路由表是 procfs 上的普通文本文件，Termux 未 root 也可读，
// 比 fork arp/ip 命令更稳：不同发行版 iproute2 的输出列并不一致。
const (
	procARPTable   = "/proc/net/arp"
	procRouteTable = "/proc/net/route"
)

// Neighbors 读取 /proc/net/arp 中的完整邻居条目。
func Neighbors() ([]Neighbor, error) {
	data, err := os.ReadFile(procARPTable)
	if err != nil {
		return nil, err
	}

	return ParseProcARP(data), nil
}

// ParseProcARP 解析 /proc/net/arp 的固定列布局：
//
//	IP address       HW type     Flags       HW address            Mask     Device
//	192.168.1.1      0x1         0x2         f4:ec:be:aa:bb:cc     *        wlan0
//
// MAC 全零表示尚未解析（incomplete），由 ParseMAC 过滤。
func ParseProcARP(data []byte) []Neighbor {
	var neighbors []Neighbor

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 || fields[0] == "IP" {
			continue
		}

		ip := net.ParseIP(fields[0]).To4()
		mac := ParseMAC(fields[3])
		if ip == nil || mac == nil {
			continue
		}

		neighbors = append(neighbors, Neighbor{
			IP:     ip,
			HWAddr: mac,
			Device: fields[5],
		})
	}

	return neighbors
}

// DefaultGateway 读取默认路由（Destination 为 00000000）的下一跳。
// 内核用十六进制小端序记录网关，多默认路由时取 Metric 最小者。
func DefaultGateway() (net.IP, error) {
	file, err := os.Open(procRouteTable)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var (
		bestMetric uint64 = ^uint64(0)
		gateway    net.IP
		scanner    = bufio.NewScanner(file)
	)

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 7 || fields[1] != "00000000" || fields[2] == "00000000" {
			continue
		}

		metric, parseErr := strconv.ParseUint(fields[6], 10, 64)
		if parseErr != nil || metric >= bestMetric {
			continue
		}

		raw, decodeErr := hex.DecodeString(fields[2])
		if decodeErr != nil || len(raw) != net.IPv4len {
			continue
		}

		// proc 按小端序存储，"0101A8C0" 的实际地址是 192.168.1.1。
		bestMetric = metric
		gateway = net.IPv4(raw[3], raw[2], raw[1], raw[0])
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if gateway == nil {
		return nil, errGatewayNotFound
	}

	return gateway, nil
}
