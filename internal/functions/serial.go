package functions

import (
	"fmt"
	"sort"

	"wifisec/internal/constants"
	"wifisec/internal/utilities"

	"go.bug.st/serial/enumerator"
)

// serialColumns 呈现串口清单；USB 设备额外给出 VID:PID、产品名与序列号，
// 帮助用户在多个同类设备中分辨目标开发板。
var serialColumns = []tableColumn[serialPortInfo]{
	{
		Header: "端口",
		Value: func(p serialPortInfo) string {
			return p.Name
		},
	},
	{
		Header: "类型",
		Value: func(p serialPortInfo) string {
			return p.Kind
		},
		Color: func(kind string) string {
			if kind == "USB" {
				return constants.ColorGreen
			}

			return constants.ColorGray
		},
	},
	{
		Header: "VID:PID",
		Value: func(p serialPortInfo) string {
			return p.VIDPID
		},
		Priority: 2,
	},
	{
		Header: "产品",
		Value: func(p serialPortInfo) string {
			return p.Product
		},
		Priority: 1,
	},
	{
		Header: "序列号",
		Value: func(p serialPortInfo) string {
			return p.SerialNumber
		},
		Priority: 3,
	},
}

// serialPortInfo 是串口列表的表格模型。
type serialPortInfo struct {
	Name         string
	Kind         string // USB / 系统
	VIDPID       string
	Product      string
	SerialNumber string
}

// Serial 枚举系统全部串口（类似 Arduino IDE 的端口列表），
// 供用户确认开发板是否被识别、以及在多设备时取端口名传给 deauth。
// USB 设备排前面并给出 VID:PID，蓝牙等系统虚拟串口列在后。
func Serial(arguments []string) error {
	ports, err := enumerator.GetDetailedPortsList()
	if err != nil {
		return fmt.Errorf("枚举串口失败：%w", err)
	}

	if len(ports) == 0 {
		utilities.Warn("未发现任何串口设备；若已插入开发板，请检查数据线（须为数据线非充电线）与驱动（CH340/CP2102）")
		return nil
	}

	devices := make([]serialPortInfo, 0, len(ports))
	for _, p := range ports {
		info := serialPortInfo{
			Name:    p.Name,
			Kind:    "系统",
			Product: placeholder,
		}

		if p.IsUSB {
			info.Kind = "USB"
			info.VIDPID = fmt.Sprintf("%s:%s", p.VID, p.PID)

			if p.Product != "" {
				info.Product = p.Product
			}

			if p.SerialNumber != "" {
				info.SerialNumber = p.SerialNumber
			} else {
				info.SerialNumber = placeholder
			}
		} else {
			info.VIDPID = placeholder
			info.SerialNumber = placeholder
		}

		devices = append(devices, info)
	}

	// USB 设备在前（目标板几乎都是 USB 串口），同类内按端口名排序。
	sort.Slice(devices, func(i, j int) bool {
		if (devices[i].Kind == "USB") != (devices[j].Kind == "USB") {
			return devices[i].Kind == "USB"
		}

		return devices[i].Name < devices[j].Name
	})

	renderTable(fmt.Sprintf("串口设备 · 共 %d 个", len(devices)), serialColumns, devices)

	return nil
}
