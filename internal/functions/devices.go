// devices.go 实现 `wifisec devices`：列出当前所连局域网里的在线设备。
//
// 免特权的发现思路（与 arp-scan 的原始套接字路线不同）：
//  1. 用 UDP connect 技巧找到承担默认路由的网卡与网段；
//  2. 向网段内每个地址的常用端口发起短超时 TCP 探测，
//     无论握手成功还是被 RST 拒绝，内核都会先完成 ARP 解析；
//  3. 读取系统 ARP 邻居表，与本机/网关标记、反向 DNS 组装成表格。
//
// 该方案在 Linux/Android/macOS/Windows 上均可非 root 运行，
// 代价是只能发现“近期与本机有二层通信”的设备，休眠中的手机可能缺席。

package functions

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ctkqiang/wifisec/internal/constants"
	"github.com/ctkqiang/wifisec/internal/platform/lan"
	"github.com/ctkqiang/wifisec/internal/utilities"
)

const (
	// 每个地址探测的常用端口：Web/SSH/SMB，覆盖路由器与绝大多数在线主机。
	deviceProbePorts = "80,443,22,445"

	// 单次 TCP 握手超时；家用网络 ARP 与 SYN 通常 100ms 内有结论。
	deviceProbeTimeout = 700 * time.Millisecond

	// 同时进行的握手数；253 主机 × 4 端口在 128 并发下约 5~6 秒跑完。
	deviceProbeWorkers = 128

	// /16 等超大网段不全量探测，只扫本机所在 /24，避免长时间空等。
	maxDiscoveryHosts = 1024

	// 反向解析给路由器 DNS 很短的预算，查不到不阻塞设备清单。
	reverseDNSTimeout = 500 * time.Millisecond
)

// routeProbeTarget 是 RFC5737 文档地址，UDP connect 只会做路由查询不会发包。
const routeProbeTarget = "203.0.113.1:80"

// lanDevice 是设备清单表格的一行。
type lanDevice struct {
	IP       string
	MAC      string
	Hostname string
	Role     string
}

// deviceColumns 必须多行展开、字段对齐并显式给 Priority，
// 这是项目里所有 renderTable 调用的统一约定。
var deviceColumns = []tableColumn[lanDevice]{
	{
		Header:   "IP 地址",
		Value:    func(device lanDevice) string { return device.IP },
		Priority: 0,
	},
	{
		Header:   "MAC 地址",
		Value:    func(device lanDevice) string { return device.MAC },
		Priority: 0,
	},
	{
		Header:   "主机名",
		Value:    func(device lanDevice) string { return device.Hostname },
		Priority: 1,
		Shrink:   true,
	},
	{
		Header:   "角色",
		Value:    func(device lanDevice) string { return device.Role },
		Color:    roleColor,
		Priority: 0,
	},
}

// GetAllDeviceInThisWifi 列出当前 Wi-Fi（或指定网卡）局域网内的设备。
// 用法：wifisec devices [网卡名]
func GetAllDeviceInThisWifi(arguments []string) error {
	started := time.Now()

	utilities.Warn("仅可在已授权的网络中使用；探测行为可能被对端安全设备记录")

	iface, ipnet, selfIP, err := selectInterface(arguments)
	if err != nil {
		return err
	}

	utilities.Info("接口 %s · 本机 %s · 网段 %s", iface.Name, selfIP, ipnet.String())

	gateway := lookupGateway()
	if gateway != "" {
		utilities.Info("默认网关 %s", gateway)
	}

	hosts := planDiscoveryTargets(ipnet, selfIP, gateway)
	utilities.Info("正在并发探测 %d 个地址的 %s 端口以刷新 ARP 表…", len(hosts), deviceProbePorts)
	probeHosts(hosts)

	neighbors, err := lan.Neighbors()
	if err != nil {
		return fmt.Errorf("读取 ARP 邻居表失败：%w", err)
	}

	devices := assembleDevices(neighbors, ipnet, iface, selfIP, gateway)
	resolveHostnames(devices)

	if len(devices) == 0 {
		utilities.Warn("ARP 表中没有本网段的设备，所有终端可能都在休眠，可稍后再试")
	}

	renderTable("局域网在线设备（数据来源：系统 ARP 邻居表）", deviceColumns, devices)

	lines := []string{
		fmt.Sprintf("共 %d 台设备 · 探测地址 %d 个 · 耗时 %s",
			len(devices), len(hosts), time.Since(started).Round(10*time.Millisecond)),
		"休眠终端不会回应二层解析，未出现不代表设备离线；精确审计请结合 get_packet",
	}
	utilities.Info("%s", strings.Join(lines, "\n"))

	return nil
}

// selectInterface 选定要发现的网卡与 IPv4 网段：
// 显式传名时按名查找，否则用 UDP connect 技巧取默认路由出口。
func selectInterface(arguments []string) (*net.Interface, *net.IPNet, net.IP, error) {
	if len(arguments) > 0 && strings.TrimSpace(arguments[0]) != "" {
		return interfaceByName(strings.TrimSpace(arguments[0]))
	}

	conn, err := net.Dial("udp4", routeProbeTarget)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("确定默认路由出口失败（当前未联网？）：%w", err)
	}
	defer conn.Close()

	selfIP := conn.LocalAddr().(*net.UDPAddr).IP.To4()

	return interfaceByIP(selfIP)
}

// interfaceByName 按用户指定的网卡名找到它与第一个 IPv4 地址。
func interfaceByName(name string) (*net.Interface, *net.IPNet, net.IP, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("找不到网卡 %s：%w", name, err)
	}

	return firstIPv4OfInterface(iface)
}

// interfaceByIP 在系统网卡列表里反查持有某 IPv4 的网卡。
func interfaceByIP(target net.IP) (*net.Interface, *net.IPNet, net.IP, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("枚举本机网卡失败：%w", err)
	}

	for index := range interfaces {
		iface := &interfaces[index]
		if iface.Flags&net.FlagUp == 0 || len(iface.HardwareAddr) == 0 {
			continue
		}

		if ipnet, ip, ok := findIPv4(iface, target); ok {
			return iface, ipnet, ip, nil
		}
	}

	return nil, nil, nil, fmt.Errorf("没有找到承载 %s 的已启用网卡", target)
}

// firstIPv4OfInterface 返回网卡的第一个 IPv4 地址与网段。
func firstIPv4OfInterface(iface *net.Interface) (*net.Interface, *net.IPNet, net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("读取网卡 %s 地址失败：%w", iface.Name, err)
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ip4 := ipnet.IP.To4(); ip4 != nil {
				return iface, ipnetMaskIPv4(ipnet), ip4, nil
			}
		}
	}

	return nil, nil, nil, fmt.Errorf("网卡 %s 没有 IPv4 地址", iface.Name)
}

// ipnetMaskIPv4 把 IPNet 的 IP 归一为 4 字节形式，后续 Contains 才稳定。
func ipnetMaskIPv4(ipnet *net.IPNet) *net.IPNet {
	return &net.IPNet{IP: ipnet.IP.To4(), Mask: ipnet.Mask}
}

// findIPv4 判断网卡是否持有 target，并返回归一化后的网段与地址。
func findIPv4(iface *net.Interface, target net.IP) (*net.IPNet, net.IP, bool) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, nil, false
	}

	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}

		if ip4 := ipnet.IP.To4(); ip4 != nil && ip4.Equal(target) {
			return ipnetMaskIPv4(ipnet), ip4, true
		}
	}

	return nil, nil, false
}

// planDiscoveryTargets 枚举网段内可用主机地址；网段过大时退化为
// 以本机为中心的 /24 邻域，并确保网关始终在探测集合中。
func planDiscoveryTargets(ipnet *net.IPNet, selfIP net.IP, gateway string) []net.IP {
	hosts := enumerateHosts(ipnet)
	if len(hosts) <= maxDiscoveryHosts {
		return hosts
	}

	utilities.Warn("网段 %s 含 %d 个地址，仅探测本机所在 /24 邻域以避免长时间等待",
		ipnet.String(), len(hosts))

	// 不能对 selfIP 的底层数组做三字节切片 append，那会改写本机地址末字节。
	local24 := &net.IPNet{
		IP:   net.IPv4(selfIP[0], selfIP[1], selfIP[2], 0),
		Mask: net.CIDRMask(24, 32),
	}
	hosts = enumerateHosts(local24)

	if gatewayIP := net.ParseIP(gateway).To4(); gatewayIP != nil && !local24.Contains(gatewayIP) {
		hosts = append(hosts, gatewayIP)
	}

	return hosts
}

// enumerateHosts 列出网段内除网络地址、广播地址和本机之外的所有地址。
func enumerateHosts(ipnet *net.IPNet) []net.IP {
	mask := ipnet.Mask
	if len(mask) != 4 {
		return nil
	}

	base := binary.BigEndian.Uint32(ipnet.IP.To4())
	maskValue := binary.BigEndian.Uint32(mask)
	network := base & maskValue
	broadcast := network | ^maskValue

	var hosts []net.IP

	for value := network + 1; value < broadcast; value++ {
		if value == binary.BigEndian.Uint32(ipnet.IP.To4()) {
			continue
		}

		ip := make(net.IP, net.IPv4len)
		binary.BigEndian.PutUint32(ip, value)
		hosts = append(hosts, ip)
	}

	return hosts
}

// probeHosts 用带缓冲信号量控制并发，向每个地址的常用端口发起
// 短超时 TCP 握手；只负责制造二层通信，成功/失败结果都不关心。
func probeHosts(hosts []net.IP) {
	var (
		semaphore = make(chan struct{}, deviceProbeWorkers)
		wg        sync.WaitGroup
	)

	for _, host := range hosts {
		for _, port := range strings.Split(deviceProbePorts, ",") {
			portNumber, err := strconv.Atoi(strings.TrimSpace(port))
			if err != nil {
				continue
			}

			wg.Add(1)

			go func(ip net.IP, targetPort int) {
				defer wg.Done()

				semaphore <- struct{}{}
				defer func() { <-semaphore }()

				conn, dialErr := net.DialTimeout(
					"tcp4",
					net.JoinHostPort(ip.String(), strconv.Itoa(targetPort)),
					deviceProbeTimeout,
				)
				if dialErr == nil {
					_ = conn.Close()
				}
			}(host, portNumber)
		}
	}

	wg.Wait()
}

// lookupGateway 读取系统默认网关；失败不致命，只是清单里少一个角色标记。
func lookupGateway() string {
	gateway, err := lan.DefaultGateway()
	if err != nil {
		utilities.Debug("读取默认网关失败：%v", err)

		return ""
	}

	return gateway.String()
}

// assembleDevices 把 ARP 表条目过滤到目标网段、补上本机，按 IP 排序。
func assembleDevices(
	neighbors []lan.Neighbor,
	ipnet *net.IPNet,
	iface *net.Interface,
	selfIP net.IP,
	gateway string,
) []lanDevice {
	seen := make(map[string]lanDevice)

	networkAddress := binary.BigEndian.Uint32(ipnet.IP.To4())
	maskValue := binary.BigEndian.Uint32(ipnet.Mask)
	broadcast := net.IP(make([]byte, 4))
	binary.BigEndian.PutUint32(broadcast, (networkAddress&maskValue)|^maskValue)

	for _, neighbor := range neighbors {
		ip := neighbor.IP.To4()
		if ip == nil || !ipnet.Contains(ip) || ip.Equal(selfIP) {
			continue
		}

		// 网络地址、广播地址和广播/组播 MAC 不是设备，必须排除。
		if ip.Equal(broadcast) || !isUnicastMAC(neighbor.HWAddr) {
			continue
		}

		device := lanDevice{
			IP:   ip.String(),
			MAC:  strings.ToUpper(neighbor.HWAddr.String()),
			Role: roleOf(ip.String(), selfIP.String(), gateway),
		}
		seen[device.IP] = device
	}

	// ARP 表里通常没有本机自己，显式补一行。
	seen[selfIP.String()] = lanDevice{
		IP:       selfIP.String(),
		MAC:      strings.ToUpper(iface.HardwareAddr.String()),
		Hostname: hostnameOrSelf(),
		Role:     "本机",
	}

	devices := make([]lanDevice, 0, len(seen))
	for _, device := range seen {
		devices = append(devices, device)
	}

	sort.Slice(devices, func(i, j int) bool {
		return ipToUint32(devices[i].IP) < ipToUint32(devices[j].IP)
	})

	return devices
}

// isUnicastMAC 排除广播与组播 MAC：首字节最低位（I/G 位）为 1 即非单播。
func isUnicastMAC(mac net.HardwareAddr) bool {
	return len(mac) == 6 && mac[0]&1 == 0
}

// roleOf 标记网关/本机，其余留空由表格占位符显示。
func roleOf(ip, self, gateway string) string {
	switch ip {
	case gateway:
		return "网关"
	case self:
		return "本机"
	default:
		return ""
	}
}

// hostnameOrSelf 返回本机主机名，失败时给一个固定中文占位。
func hostnameOrSelf() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "本机"
	}

	return hostname
}

// resolveHostnames 并发做反向 DNS；总预算很短，查不到的格子留空。
func resolveHostnames(devices []lanDevice) {
	var wg sync.WaitGroup

	for index := range devices {
		if devices[index].Role == "本机" {
			continue
		}

		wg.Add(1)

		go func(pos int) {
			defer wg.Done()

			ctx, cancel := context.WithTimeout(context.Background(), reverseDNSTimeout)
			defer cancel()

			var resolver net.Resolver

			names, err := resolver.LookupAddr(ctx, devices[pos].IP)
			if err == nil && len(names) > 0 {
				devices[pos].Hostname = strings.TrimSuffix(names[0], ".")
			}
		}(index)
	}

	wg.Wait()
}

// ipToUint32 把 IPv4 文本转成可比较整数；非法输入排到最后。
func ipToUint32(text string) uint32 {
	ip := net.ParseIP(text).To4()
	if ip == nil {
		return ^uint32(0)
	}

	return binary.BigEndian.Uint32(ip)
}

// roleColor 让本机/网关行在终端里一眼可辨。
func roleColor(role string) string {
	if role == "" {
		return ""
	}

	if role == "本机" || role == "网关" {
		return constants.ColorGreen
	}

	return constants.ColorYellow
}
