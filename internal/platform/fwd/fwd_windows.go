//go:build windows

package fwd

// enable 返回平台不可用错误：透明转发做不到「随时开、退出即恢复」。
// ARP 欺骗在 Windows 被入口层直接拒绝，不会走到这里，防御性兜底。
func enable(string) (any, error) {
	return nil, ErrSpoofUnsupported
}

// disable 对应 enable 恒错，正常流程不会拿到 Token，直接返回 nil。
func disable(any) error {
	return nil
}
