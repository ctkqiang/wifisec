//go:build !linux && !android

package linux

import (
	"errors"
)

// ErrUnsupported 表示当前平台不支持 802.11 帧注入。
// 上层平台守卫正常不会走到此文件，stub 仅为保证非 Linux 构建可通过。
var ErrUnsupported = errors.New("802.11 帧注入仅支持 Linux")

// FrameInjector 在非 Linux 平台无实际实现。
type FrameInjector struct{}

// OpenInjector 在非 Linux 平台直接返回不支持错误。
func OpenInjector(string) (*FrameInjector, error) {
	return nil, ErrUnsupported
}

// Write 在非 Linux 平台直接返回不支持错误。
func (fi *FrameInjector) Write([]byte) error {
	return ErrUnsupported
}

// Close 在非 Linux 平台无任何操作。
func (fi *FrameInjector) Close() error {
	return nil
}
