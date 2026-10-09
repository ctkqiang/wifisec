//go:build android

package assoc

import "errors"

// Native 在 Android 上不可用：Android 10 起应用无权编程发起 WiFi 关联
// （WifiNetworkSuggestion 也只能建议、不能指定密码强制连接），
// Termux 未 root 更是完全没有入口。
type Native struct{}

// NewNative 返回精确的技术说明，引导用户使用 ESP 协处理器路径。
func NewNative() (*Native, error) {
	return nil, errors.New("Android 未 root 无法编程关联 WiFi（Android 10+ 系统限制）；请插入 ESP 协处理器后重试，或在已 root 设备上操作")
}

// Associate 不会到达（NewNative 已拒绝），存在仅为满足接口编译。
func (n *Native) Associate(ssid, password string) (bool, error) {
	return false, errors.New("Android 未 root 无法编程关联 WiFi，请使用 ESP 协处理器")
}
