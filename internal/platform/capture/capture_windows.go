//go:build windows

package capture

import (
	"errors"
	"fmt"
	"strings"

	winadapter "github.com/ctkqiang/wifisec/internal/platform/windows"
)

// npcapSource 把 platform/windows 的 Npcap 句柄适配为统一 Source，
// 仅负责把平台侧超时哨兵翻译成 capture 包自己的 ErrReadTimeout。
type npcapSource struct {
	inner *winadapter.CaptureSource
}

// Open 在 ifaceName 指定的无线适配器上抓包。ifaceName 可以是
// netsh 显示的适配器连接名（如 Wi-Fi）、{GUID} 或完整 \Device\NPF_{GUID} 路径。
func Open(ifaceName string) (Source, error) {
	devicePath, err := resolveNPFDevice(ifaceName)
	if err != nil {
		return nil, err
	}

	inner, err := winadapter.OpenCapture(devicePath)
	if err != nil {
		return nil, err
	}

	return &npcapSource{inner: inner}, nil
}

// resolveNPFDevice 把用户输入归一为 Npcap 设备路径；
// 友好名需要通过一次 netsh 枚举换取 GUID。
func resolveNPFDevice(name string) (string, error) {
	trimmed := strings.TrimSpace(name)

	switch {
	case strings.HasPrefix(trimmed, `\Device\NPF_`):
		return trimmed, nil
	case strings.HasPrefix(strings.ToUpper(trimmed), "{"):
		return winadapter.NPFDevicePath(trimmed), nil
	}

	interfaces, err := winadapter.DiscoverInterfaces()
	if err != nil {
		return "", fmt.Errorf("枚举无线适配器失败：%w", err)
	}

	for _, iface := range interfaces {
		if strings.EqualFold(iface.Name, trimmed) {
			return winadapter.NPFDevicePath(iface.GUID), nil
		}
	}

	return "", fmt.Errorf("未找到名为 %s 的无线适配器（也可直接传入 {GUID}）", name)
}

// Read 透传一帧，空闲周期统一映射为 ErrReadTimeout。
func (source *npcapSource) Read() ([]byte, error) {
	frame, err := source.inner.Read()
	if errors.Is(err, winadapter.ErrCaptureReadTimeout) {
		return nil, ErrReadTimeout
	}

	return frame, err
}

// LinkType 透传 DLT 链路类型。
func (source *npcapSource) LinkType() uint32 {
	return source.inner.LinkType()
}

// Close 释放底层 Npcap 句柄。
func (source *npcapSource) Close() error {
	return source.inner.Close()
}
