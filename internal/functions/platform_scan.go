package functions

import (
	"errors"
	platformlinux "wifisec/internal/platform/linux"
	platformtermux "wifisec/internal/platform/termux"
	platformwindows "wifisec/internal/platform/windows"
)

// 本文件是应用层与三个外部平台适配器（Linux iw / Windows netsh / Termux API）
// 之间的组装层：调用 adapter、把结构化结果映射为终端表格模型 WiFiNetwork，
// 并保留对 tests/ 暴露的纯文本解析入口（底层实际走各平台 parser）。
// scanLinuxNetworks 调用 iw adapter 扫描，并用不需要 root 的 iw link
// 标记当前关联；adapter 对权限不足有明确错误语义，这里转成用户可执行的建议。
func scanLinuxNetworks() ([]WiFiNetwork, error) {
	iface, err := FindWirelessInterface()
	if err != nil {
		return nil, err
	}

	scanned, err := platformlinux.Scan(iface.Name)
	if err != nil {
		if errors.Is(err, platformlinux.ErrPermissionDenied) {
			return nil, errors.New("扫描需要 root 权限：请使用 sudo 运行，例如 sudo make list")
		}

		return nil, err
	}

	networks := mapLinuxNetworks(scanned)
	markConnectedBSSID(networks, platformlinux.ConnectedBSSID(iface.Name))

	return networks, nil
}

// ParseIWScanOutput 保留给 tests/ 的契约入口：喂一段真实 iw scan 文本，
// 得到终端模型。实现已下沉至 platform/linux adapter。
func ParseIWScanOutput(output, device string) []WiFiNetwork {
	return mapLinuxNetworks(platformlinux.ParseScan(output, device))
}

// mapLinuxNetworks 把 iw adapter 的结构化结果映射为表格模型；
// 信道缺失时按中心频率兜底，频段统一在此换算。
func mapLinuxNetworks(scanned []platformlinux.Network) []WiFiNetwork {
	networks := make([]WiFiNetwork, 0, len(scanned))

	for _, n := range scanned {
		channel := n.Channel
		if channel == 0 {
			channel = freqToChannel(n.Frequency)
		}

		networks = append(networks, WiFiNetwork{
			BSSID:        n.BSSID,
			Channel:      channel,
			Signal:       n.Signal,
			Enc:          n.Security,
			Cipher:       n.Cipher,
			Auth:         n.Authentication,
			ESSID:        n.SSID,
			Device:       n.Device,
			Freq:         bandLabel(n.Frequency),
			PHY:          n.PHY,
			ChannelWidth: n.ChannelWidth,
		})
	}

	return networks
}

// mapLinuxInterfaces 把接口发现结果映射为表格模型。
func mapLinuxInterfaces(scanned []platformlinux.Interface) []WirelessInterface {
	devices := make([]WirelessInterface, 0, len(scanned))

	for _, d := range scanned {
		devices = append(devices, WirelessInterface{
			PHY:          d.PHY,
			Name:         d.Name,
			Index:        d.Index,
			HardwareAddr: d.HardwareAddr,
			Mode:         d.Mode,
			State:        d.State,
			Driver:       d.Driver,
			Chipset:      d.Chipset,
		})
	}

	return devices
}

// scanWindowsNetworks 通过 netsh adapter 扫描，并标记当前关联 BSSID。
func scanWindowsNetworks() ([]WiFiNetwork, error) {
	scanned, err := platformwindows.Scan()
	if err != nil {
		return nil, err
	}

	networks := mapWindowsNetworks(scanned)
	markConnectedBSSID(networks, platformwindows.ConnectedBSSID())

	return networks, nil
}

// ParseNetshBSSIDOutput 保留给 tests/ 的契约入口，底层走 windows adapter。
func ParseNetshBSSIDOutput(output string) []WiFiNetwork {
	return mapWindowsNetworks(platformwindows.ParseNetworks(output))
}

func mapWindowsNetworks(scanned []platformwindows.Network) []WiFiNetwork {
	networks := make([]WiFiNetwork, 0, len(scanned))

	for _, n := range scanned {
		networks = append(networks, WiFiNetwork{
			BSSID:   n.BSSID,
			Channel: n.Channel,
			Signal:  n.Signal,
			Enc:     n.Security,
			Cipher:  n.Cipher,
			Auth:    n.Authentication,
			ESSID:   n.SSID,
			Freq:    channelBand(n.Channel),
			PHY:     n.PHY,
		})
	}

	return networks
}

// channelBand 按信道号推断频段：1-14 为 2.4GHz，其余按 5GHz 呈现。
func channelBand(channel int) string {
	switch {
	case channel >= 1 && channel <= 14:
		return "2GHz"
	case channel > 14:
		return "5GHz"
	default:
		return ""
	}
}

func mapWindowsInterfaces(scanned []platformwindows.Interface) []WirelessInterface {
	devices := make([]WirelessInterface, 0, len(scanned))

	for _, d := range scanned {
		devices = append(devices, WirelessInterface{
			Name:         d.Name,
			Index:        d.Index,
			HardwareAddr: d.MAC,
			State:        d.State,
			Driver:       d.Driver,
			Chipset:      d.Description,
		})
	}

	return devices
}

// scanTermuxNetworks 通过 Termux:API adapter 取数；环境缺失与系统限流
// 两类失败的可执行建议由 adapter 以固定错误给出，这里原样上抛。
func scanTermuxNetworks() ([]WiFiNetwork, error) {
	scanned, err := platformtermux.Scan()
	if err != nil {
		return nil, err
	}

	return mapTermuxNetworks(scanned), nil
}

func mapTermuxNetworks(scanned []platformtermux.Network) []WiFiNetwork {
	networks := make([]WiFiNetwork, 0, len(scanned))

	for _, n := range scanned {
		networks = append(networks, WiFiNetwork{
			BSSID:     n.BSSID,
			Channel:   freqToChannel(n.Frequency),
			Signal:    n.Signal,
			Rate:      n.Rate,
			Enc:       n.Security,
			Cipher:    n.Cipher,
			Auth:      n.Authentication,
			ESSID:     n.SSID,
			Freq:      bandLabel(n.Frequency),
			Connected: n.Connected,
		})
	}

	return networks
}
