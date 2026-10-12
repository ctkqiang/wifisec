//go:build windows

package writer

import (
	"fmt"
	"strings"

	winadapter "github.com/ctkqiang/wifisec/internal/platform/windows"
)

// open 在指定网卡上打开 Npcap 发送通道。npcap 的 pcap_t 句柄读写一体，
// OpenInjector 打开的句柄可直接 pcap_sendpacket 注入以太网帧，
// 对 managed 模式的适配器（非 monitor）同样有效。
func open(ifaceName string) (Port, error) {
	devicePath, err := resolveNPFDevice(ifaceName)
	if err != nil {
		return nil, err
	}

	return winadapter.OpenInjector(devicePath)
}

// resolveNPFDevice 把用户输入归一为 Npcap 设备路径；
// 与 capture 包的解析规则一致：完整路径、{GUID}、友好名三选一。
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
		return "", fmt.Errorf("枚举网络适配器失败：%w", err)
	}

	for _, iface := range interfaces {
		if strings.EqualFold(iface.Name, trimmed) {
			return winadapter.NPFDevicePath(iface.GUID), nil
		}
	}

	return "", fmt.Errorf("未找到名为 %s 的适配器（也可直接传入 {GUID}）", name)
}
