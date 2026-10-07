package windows

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

const netshTimeout = 15 * time.Second

// Scan 通过 netsh 枚举周边 BSS。netsh 无需管理员权限即可列出网络，
// 这是 Windows 上不依赖第三方驱动的唯一稳定数据源。
func Scan() ([]Network, error) {
	output, err := run(netshTimeout, "netsh", "wlan", "show", "networks", "mode=bssid")
	if err != nil {
		return nil, fmt.Errorf("netsh 扫描失败：%w", err)
	}

	return ParseNetworks(output), nil
}

// ConnectedBSSID 查询当前关联的 AP BSSID；无活动接口时返回空串。
func ConnectedBSSID() string {
	output, err := run(netshTimeout, "netsh", "wlan", "show", "interfaces")
	if err != nil {
		return ""
	}

	return ParseConnectedBSSID(output)
}

// DiscoverInterfaces 枚举无线适配器：netsh 提供名称/型号/MAC/状态与驱动，
// 接口索引通过 Go net 包按名称（Windows 下大小写不固定）补全。
func DiscoverInterfaces() ([]Interface, error) {
	output, err := run(netshTimeout, "netsh", "wlan", "show", "interfaces")
	if err != nil {
		return nil, fmt.Errorf("枚举无线接口失败：%w", err)
	}

	entries := ParseInterfaces(output)
	if len(entries) == 0 {
		return nil, fmt.Errorf("未发现无线接口")
	}

	driver := queryDriver()

	devices := make([]Interface, 0, len(entries))
	for _, entry := range entries {
		entry.Driver = driver
		entry.Index = lookupIndex(entry.Name)
		devices = append(devices, entry)
	}

	sort.Slice(devices, func(i, j int) bool { return devices[i].Index < devices[j].Index })

	return devices, nil
}

// queryDriver 取 netsh 报告的驱动名；查询失败不影响接口枚举。
func queryDriver() string {
	output, err := run(netshTimeout, "netsh", "wlan", "show", "drivers")
	if err != nil {
		return ""
	}

	return ParseDriver(output)
}

// lookupIndex 按名称在 Go net 包中查找接口索引；找不到返回 0。
func lookupIndex(name string) int {
	interfaces, err := net.Interfaces()
	if err != nil {
		return 0
	}

	for _, iface := range interfaces {
		// Windows 适配器名大小写不固定，按不敏感方式匹配。
		if strings.EqualFold(iface.Name, name) {
			return iface.Index
		}
	}

	return 0
}
