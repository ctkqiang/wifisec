//go:build !linux && !android && !darwin && !windows

package lan

import "net"

// 其他平台暂不提供邻居表读取；设备发现目前覆盖 Linux/Android/macOS/Windows。

// Neighbors 在不支持的平台上始终返回错误。
func Neighbors() ([]Neighbor, error) {
	return nil, errUnsupportedPlatform
}

// DefaultGateway 在不支持的平台上始终返回错误。
func DefaultGateway() (net.IP, error) {
	return nil, errUnsupportedPlatform
}
