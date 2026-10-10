// Package lan 提供局域网邻居表（ARP 缓存）与默认网关的跨平台只读访问。
// 三个主流平台的实现都不使用原始套接字，也不要求特权：
// Linux/Android 直接解析 /proc，macOS 与 Windows 调用系统自带的
// arp/route 命令；exec.Command 只允许出现在这个 adapter 层。
package lan

import (
	"errors"
	"net"
)

// errGatewayNotFound 在系统路由表中找不到 0.0.0.0/0 默认路由时返回。
var errGatewayNotFound = errors.New("路由表中没有默认网关")

// errUnsupportedPlatform 在未适配的操作系统上调用邻居表读取时返回。
var errUnsupportedPlatform = errors.New("当前平台不支持读取 ARP 邻居表")

// Neighbor 描述邻居表中的一台设备：它的 IPv4 地址、解析到的 MAC
// 以及内核记录该条目所经过的网卡名（Windows 下可能为空）。
type Neighbor struct {
	IP     net.IP
	HWAddr net.HardwareAddr
	Device string
}

// ParseMAC 把各平台输出的 MAC 文本统一为 net.HardwareAddr，
// 无法解析或全零（incomplete 占位）时返回 nil，调用方直接判空即可。
func ParseMAC(token string) net.HardwareAddr {
	hw, err := net.ParseMAC(token)
	if err != nil {
		return nil
	}

	for _, octet := range hw {
		if octet != 0 {
			return hw
		}
	}

	return nil
}
