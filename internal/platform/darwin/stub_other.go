//go:build !darwin

package darwin

import "time"

// 非 macOS 平台不存在 CoreWLAN / CoreLocation，全部以受限状态与空结果占位，
// 保证上层（internal/functions）在 Linux、Windows 上无需 build tag 即可编译，
// 且纯 Go 工具链（CGO_ENABLED=0）不受 Objective-C 源文件影响。

// BootstrapFlag 在非 macOS 上不会出现，保留常量仅为消除引用处的条件编译。
const BootstrapFlag = "--wifisec-location-bootstrap"

// HandleBootstrap 在非 macOS 上永远不是自举实例。
func HandleBootstrap() bool {
	return false
}

// ScanViaHelper 在非 macOS 上无 CoreWLAN 数据源。
func ScanViaHelper(wait time.Duration) ([]Network, AuthorizationStatus, error) {
	return nil, AuthRestricted, nil
}

// LocationStatus 在非 macOS 上恒为受限。
func LocationStatus() AuthorizationStatus {
	return AuthRestricted
}

// RequestLocationAuthorization 在非 macOS 上无定位授权概念，直接返回受限。
func RequestLocationAuthorization(timeout time.Duration) AuthorizationStatus {
	return AuthRestricted
}

// ScanNetworks 在非 macOS 上无 CoreWLAN 数据源。
func ScanNetworks() ([]Network, error) {
	return nil, nil
}
