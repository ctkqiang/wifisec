//go:build !linux && !android && !darwin && !windows

package writer

// open 在未适配的平台上直接返回不支持错误。
// ARP 欺骗依赖原始帧注入，没有第三方依赖可兜底。
func open(string) (Port, error) {
	return nil, errUnsupportedPlatform
}
