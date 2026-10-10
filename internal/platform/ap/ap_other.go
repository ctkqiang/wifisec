//go:build !linux || android

package ap

import "errors"

// errUnsupportedPlatform 说明宿主机承载克隆 AP 在当前平台不可行的
// 根本原因，并指引可用的替代路径。逐平台陈述具体技术限制，
// 而非笼统的「不支持」，让用户能自行判断下一步。
var errUnsupportedPlatform = errors.New(
	"本机热点克隆仅支持 Linux（hostapd）：" +
		"macOS 无公开的 AP hosting API（CoreWLAN 的 IBSS 仅支持 WEP/开放网络），" +
		"Windows 的 hostednetwork 已被 Microsoft 废弃，" +
		"Android 应用层禁止第三方进程承载 AP；" +
		"请插入 ESP 协处理器，克隆 AP 将由板载射频承载",
)

// Host 是非 Linux 平台的占位实现：构造必然失败，
// 方法仅为满足 cloneAP 接口而存在，不会被调用到。
type Host struct{}

// New 恒定返回平台不可行的精确说明。
func New() (*Host, error) {
	return nil, errUnsupportedPlatform
}

func (h *Host) Interface() string { return "" }

func (h *Host) Up(string, string, int) (string, error) {
	return "", errUnsupportedPlatform
}

func (h *Host) Down() error { return nil }

func (h *Host) StationEvents() <-chan StationEvent { return nil }

func (h *Host) KickWriter() (KickInjector, error) {
	return nil, errUnsupportedPlatform
}
