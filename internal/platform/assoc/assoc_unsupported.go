//go:build !darwin && !linux && !windows && !android

package assoc

import (
	"fmt"
	"runtime"
)

type Native struct{}

// NewNative 覆盖项目支持范围之外的平台，编译不中断、运行时给出明确说明。
func NewNative() (*Native, error) {
	return nil, fmt.Errorf("平台 %s 暂不支持本机网卡爆破，请使用 ESP 协处理器路径", runtime.GOOS)
}

// Associate 不会到达（NewNative 已拒绝），存在仅为满足接口编译。
func (n *Native) Associate(ssid, password string) (bool, error) {
	return false, fmt.Errorf("平台 %s 暂不支持本机网卡爆破，请使用 ESP 协处理器路径", runtime.GOOS)
}
