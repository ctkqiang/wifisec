//go:build !linux && !android && !darwin && !windows

package capture

// 当前抓包只适配了 Linux/Android（AF_PACKET）、macOS（BPF）与
// Windows（Npcap），其他平台没有可用的免驱动抓包通道。

// Open 在不支持的平台上始终返回错误。
func Open(_ string) (Source, error) {
	return nil, errCaptureUnsupported
}
