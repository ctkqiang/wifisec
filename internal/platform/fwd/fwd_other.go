//go:build !linux && !darwin && !windows

package fwd

import "errors"

// errUnsupported 在未适配的操作系统上调用 Enable 时返回。
var errUnsupported = errors.New(
	"当前平台不支持修改 IP 转发设置（支持：Linux/Android、macOS）",
)

// enable 直接拒绝。
func enable(string) (any, error) {
	return nil, errUnsupported
}

// disable 无 Token 可恢复。
func disable(any) error {
	return nil
}
