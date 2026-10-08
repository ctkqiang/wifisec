package linux

import (
	"github.com/ctkqiang/wifisec/internal/constants"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// fallbackNamePrefixes 是 /proc/net/wireless 不可读时的兜底识别规则，
// 覆盖主流驱动的常见命名（wlan0 / wlp2s0 / wlx<MAC> / ath / ra）。
var fallbackNamePrefixes = []string{"wlan", "wlp", "wlx", "wl", "ath", "ra"}

// DiscoverInterfaces 枚举本机无线网卡。
//
// 数据全部来自内核稳定接口：/proc/net/wireless 判定哪些网卡是无线设备，
// net 包取索引与 MAC，sysfs 符号链接给出 phy 编号与驱动，iw（可选）给模式。
// useIW 为 false 时跳过 iw 调用——Termux 环境通常没有该工具，
// 也没有读取 sysfs 的权限，属于平台限制而非错误。
func DiscoverInterfaces(useIW bool) []Interface {
	names, err := procWirelessNames()
	if err != nil || len(names) == 0 {
		names = guessWirelessNames()
	}

	devices := make([]Interface, 0, len(names))
	for _, name := range names {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			continue // 接口可能在枚举与查询之间被移除
		}

		device := Interface{
			PHY:          sysfsLink("/sys/class/net/" + name + "/phy80211"),
			Name:         iface.Name,
			Index:        iface.Index,
			HardwareAddr: iface.HardwareAddr.String(),
			State:        stateLabel(iface.Flags),
			Driver:       sysfsLink("/sys/class/net/" + name + "/device/driver"),
			Chipset:      sysfsChipset(name),
		}
		if useIW {
			device.Mode = InterfaceMode(name)
		}

		devices = append(devices, device)
	}

	// 按内核索引排序，保证多网卡时输出顺序稳定。
	sort.Slice(devices, func(i, j int) bool { return devices[i].Index < devices[j].Index })

	return devices
}

// procWirelessNames 解析 /proc/net/wireless，取冒号前的接口名。
// 前两行内核表头不含冒号，天然被过滤。
func procWirelessNames() ([]string, error) {
	data, err := os.ReadFile(constants.WIRELESS_FILE)
	if err != nil {
		return nil, err
	}

	var names []string
	for _, line := range strings.Split(string(data), "\n") {
		name, _, ok := strings.Cut(line, ":")
		name = strings.TrimSpace(name)
		// 含竖线的行是状态标志列，一并排除。
		if ok && name != "" && !strings.Contains(name, "|") {
			names = append(names, name)
		}
	}

	return names, nil
}

// guessWirelessNames 按接口名前缀兜底识别无线网卡。
func guessWirelessNames() []string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var names []string
	for _, iface := range interfaces {
		for _, prefix := range fallbackNamePrefixes {
			if strings.HasPrefix(iface.Name, prefix) {
				names = append(names, iface.Name)
				break
			}
		}
	}

	return names
}

// stateLabel 把接口标志转换为 UP / DOWN。
func stateLabel(flags net.Flags) string {
	if flags&net.FlagUp != 0 {
		return "UP"
	}

	return "DOWN"
}

// sysfsLink 返回 sysfs 符号链接的末段，如 driver -> iwlwifi。
func sysfsLink(path string) string {
	target, err := os.Readlink(path)
	if err != nil {
		return ""
	}

	return filepath.Base(target)
}

// sysfsChipset 尽力读取网卡型号；多数 PCI 网卡不暴露该属性，返回空串。
func sysfsChipset(name string) string {
	base := "/sys/class/net/" + name + "/device"
	read := func(attr string) string {
		data, err := os.ReadFile(filepath.Join(base, attr))
		if err != nil {
			data, err = os.ReadFile(filepath.Join(base, "..", attr))
		}
		if err != nil {
			return ""
		}

		return strings.TrimSpace(string(data))
	}

	return strings.TrimSpace(read("manufacturer") + " " + read("product"))
}
