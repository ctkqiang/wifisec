//go:build !windows

package windows

import (
	"errors"
)

// ErrUnsupported 表示当前平台不支持 802.11 帧注入。
// 上层平台守卫正常不会走到此文件，stub 仅为保证非 Windows 构建可通过。
var ErrUnsupported = errors.New("802.11 帧注入仅支持 Windows（Npcap）")

// FrameInjector 在非 Windows 平台无实际实现。
type FrameInjector struct{}

// CheckNpcap 在非 Windows 平台直接返回不支持错误。
func CheckNpcap() error {
	return ErrUnsupported
}

// NPFDevicePath 在非 Windows 平台无意义，返回空串。
func NPFDevicePath(string) string {
	return ""
}

// OpenInjector 在非 Windows 平台直接返回不支持错误。
func OpenInjector(string) (*FrameInjector, error) {
	return nil, ErrUnsupported
}

// SetMonitorMode 在非 Windows 平台直接返回不支持错误。
func SetMonitorMode(string, bool) (bool, error) {
	return false, ErrUnsupported
}

// SetChannel 在非 Windows 平台直接返回不支持错误。
func SetChannel(string, int) error {
	return ErrUnsupported
}

// Write 在非 Windows 平台直接返回不支持错误。
func (fi *FrameInjector) Write([]byte) error {
	return ErrUnsupported
}

// Close 在非 Windows 平台无任何操作。
func (fi *FrameInjector) Close() error {
	return nil
}
