// portscan.go 实现 `wifisec scan_ports`：nmap -sT 风格的 TCP connect 扫描。
//
// 选择 connect() 而不是原始套接字 SYN 扫描（nmap -sS）的原因：
// 三次元握手由内核完成，Linux/macOS/Windows/Android 全平台免 root，
// 语义同样可以区分三种状态——握上=open，回 RST=closed，超时/不可达=filtered。
// open 的端口再做一次被动 banner 抓取（HTTP 端口补一发 HEAD）。

package functions

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ctkqiang/wifisec/internal/constants"
	"github.com/ctkqiang/wifisec/internal/utilities"
)

const (
	// 单次握手超时：家用/内网排查 1.5s 足够，公网高延迟目标可显式缩小端口集。
	portDialTimeout = 1500 * time.Millisecond

	// 并发握手数；connect 扫描只占一个 fd，200 并发对内核毫无压力。
	portScanWorkers = 200

	// banner 读取总预算，被动问候与 HTTP 主动探测共享。
	bannerTotalBudget = 1100 * time.Millisecond
	bannerReadBudget  = 600 * time.Millisecond
	bannerMaxLength   = 60

	// all 关键字扫描 1-1000，与 nmap 默认只扫最常见 1000 端口的直觉一致。
	allPortsLower = 1
	allPortsUpper = 1000
)

// 端口状态三态，文案直接采用 nmap 术语。
type portState string

const (
	portOpen     portState = "open"
	portClosed   portState = "closed"
	portFiltered portState = "filtered"
)

// portResult 是单个端口的扫描结论。
type portResult struct {
	Port    int
	State   portState
	Service string
	Banner  string
}

// topTCPPorts 是默认端口集：运维排障最常确认的四十余个服务，
// 空参或显式 top 时使用；想扫更多请给区间，如 1-1000。
var topTCPPorts = []int{
	7, 20, 21, 22, 23, 25, 53, 80, 81, 110, 111, 113, 135, 139, 143,
	161, 389, 443, 445, 465, 587, 993, 995, 1080, 1433, 1521, 1723,
	1883, 2049, 2375, 3000, 3306, 3389, 5432, 5900, 5985, 6379, 6443,
	8000, 8080, 8443, 8888, 9000, 9090, 9200, 11211, 27017,
}

// serviceNames 覆盖 topTCPPorts 的服务标注，未命中时留空，
// 不臆造（nmap 的服务识别是主动探测数百个探针，这里不模仿）。
var serviceNames = map[int]string{
	7: "echo", 20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet",
	25: "smtp", 53: "domain", 80: "http", 81: "http-alt", 110: "pop3",
	111: "rpcbind", 113: "ident", 135: "msrpc", 139: "netbios-ssn",
	143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "microsoft-ds",
	465: "smtps", 587: "submission", 993: "imaps", 995: "pop3s",
	1080: "socks", 1433: "ms-sql-s", 1521: "oracle", 1723: "pptp",
	1883: "mqtt", 2049: "nfs", 2375: "docker", 3000: "http-alt",
	3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql", 5900: "vnc",
	5985: "wsman", 6379: "redis", 6443: "kubernetes", 8000: "http-alt",
	8080: "http-proxy", 8443: "https-alt", 8888: "http-alt", 9000: "http-alt",
	9090: "websm", 9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}

// httpProbePorts 上的服务在被动读不到问候语时补发一个 HEAD 请求。
var httpProbePorts = map[int]bool{
	80: true, 81: true, 3000: true, 8000: true, 8080: true, 8888: true, 9000: true, 9090: true,
}

// portColumns 多行展开、显式 Priority，与其他表格保持同一约定。
var portColumns = []tableColumn[portResult]{
	{
		Header:   "端口",
		Value:    func(result portResult) string { return strconv.Itoa(result.Port) },
		Priority: 0,
	},
	{
		Header:   "状态",
		Value:    func(result portResult) string { return string(result.State) },
		Color:    portStateColor,
		Priority: 0,
	},
	{
		Header:   "服务",
		Value:    func(result portResult) string { return result.Service },
		Priority: 0,
	},
	{
		Header:   "Banner",
		Value:    func(result portResult) string { return result.Banner },
		Priority: 1,
		Shrink:   true,
	},
}

// CheckPort 对目标执行 TCP connect 扫描。
// 用法：wifisec scan_ports <IP|主机名> [top|all|端口规格]
// 端口规格形如 "80,443"、"1-1000"、"22,8000-8100"；缺省为 top。
func CheckPort(arguments []string) error {
	if len(arguments) == 0 || strings.TrimSpace(arguments[0]) == "" {
		return errors.New("用法：wifisec scan_ports <IP|主机名> [top|all|80,443|1-1000]")
	}

	target := strings.TrimSpace(arguments[0])
	spec := "top"
	if len(arguments) > 1 {
		spec = strings.TrimSpace(arguments[1])
	}

	ports, err := ParsePortSpec(spec)
	if err != nil {
		return err
	}

	resolved, err := resolveIPv4(target)
	if err != nil {
		return err
	}

	utilities.Warn("仅可对已授权目标扫描；握手行为会被防火墙与安全设备记录")
	utilities.Info("目标 %s（%s）· 待扫端口 %d 个 · 并发 %d · 单端口超时 %s",
		target, resolved, len(ports), portScanWorkers, portDialTimeout)

	started := time.Now()
	results := scanPorts(resolved, ports)

	open, filtered, closed := splitResults(results)

	if len(open)+len(filtered) == 0 {
		utilities.Info("没有 open 或 filtered 的端口（closed %d 个），目标可能静默丢弃了全部探测", closed)
	} else {
		renderTable(
			fmt.Sprintf("端口扫描结果 · %s（%s）", target, resolved),
			portColumns,
			append(open, filtered...),
		)
	}

	lines := []string{
		fmt.Sprintf("open %d · filtered %d · closed %d · 共 %d 端口 · 耗时 %s",
			len(open), len(filtered), closed, len(ports), time.Since(started).Round(10*time.Millisecond)),
		"closed=内核收到 RST；filtered=超时/不可达，可能是防火墙丢弃，也可能主机不在线",
	}
	utilities.Info("%s", strings.Join(lines, "\n"))

	return nil
}

// ParsePortSpec 解析端口规格并返回去重排序后的端口列表。
// 空串与 top 等价；all 表示 1-1000；其余按逗号切分，每项为数字或闭区间。
func ParsePortSpec(spec string) ([]int, error) {
	spec = strings.ToLower(strings.TrimSpace(spec))

	switch spec {
	case "", "top":
		return append([]int(nil), topTCPPorts...), nil
	case "all":
		ports := make([]int, 0, allPortsUpper-allPortsLower+1)
		for port := allPortsLower; port <= allPortsUpper; port++ {
			ports = append(ports, port)
		}

		return ports, nil
	}

	seen := make(map[int]struct{})

	for _, token := range strings.Split(spec, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}

		if strings.Contains(token, "-") {
			bounds := strings.SplitN(token, "-", 2)
			lower, errLower := strconv.Atoi(strings.TrimSpace(bounds[0]))
			upper, errUpper := strconv.Atoi(strings.TrimSpace(bounds[1]))

			if errLower != nil || errUpper != nil || lower > upper {
				return nil, fmt.Errorf("非法端口区间 %q，正确示例：1-1000", token)
			}

			if err := validatePortRange(lower, upper); err != nil {
				return nil, err
			}

			for port := lower; port <= upper; port++ {
				seen[port] = struct{}{}
			}

			continue
		}

		port, err := strconv.Atoi(token)
		if err != nil {
			return nil, fmt.Errorf("无法解析端口规格 %q（支持 top、all、80,443、1-1000）", token)
		}

		if err := validatePortRange(port, port); err != nil {
			return nil, err
		}

		seen[port] = struct{}{}
	}

	if len(seen) == 0 {
		return nil, errors.New("端口规格为空，请给出至少一个端口")
	}

	ports := make([]int, 0, len(seen))
	for port := range seen {
		ports = append(ports, port)
	}

	sort.Ints(ports)

	return ports, nil
}

// validatePortRange 校验区间完全落在 1-65535 内。
func validatePortRange(lower, upper int) error {
	if lower < 1 || upper > 65535 {
		return fmt.Errorf("端口 %d-%d 越界，合法范围为 1-65535", lower, upper)
	}

	return nil
}

// resolveIPv4 在 3 秒预算内把主机名或 IP 文本解析为一个 IPv4 地址。
func resolveIPv4(target string) (string, error) {
	if ip := net.ParseIP(target); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String(), nil
		}

		return "", errors.New("本扫描器当前只支持 IPv4 目标")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, target)
	if err != nil {
		return "", fmt.Errorf("解析目标 %s 失败：%w", target, err)
	}

	for _, address := range addresses {
		if ip4 := address.IP.To4(); ip4 != nil {
			return ip4.String(), nil
		}
	}

	return "", fmt.Errorf("目标 %s 没有可用的 IPv4 地址", target)
}

// scanPorts 以信号量限流并发扫描全部端口，结果经 channel 汇聚，
// 避免在 worker 之间共享切片与互斥锁。
func scanPorts(target string, ports []int) []portResult {
	var (
		semaphore = make(chan struct{}, portScanWorkers)
		wg        sync.WaitGroup
		results   = make(chan portResult, len(ports))
	)

	for _, port := range ports {
		wg.Add(1)

		go func(targetPort int) {
			defer wg.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			results <- scanOnePort(target, targetPort)
		}(port)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	collected := make([]portResult, 0, len(ports))
	for result := range results {
		collected = append(collected, result)
	}

	sort.Slice(collected, func(i, j int) bool {
		return collected[i].Port < collected[j].Port
	})

	return collected
}

// scanOnePort 执行一次握手并归类三态；open 时顺带抓 banner。
func scanOnePort(target string, port int) portResult {
	address := net.JoinHostPort(target, strconv.Itoa(port))

	conn, err := net.DialTimeout("tcp4", address, portDialTimeout)
	if err != nil {
		return portResult{
			Port:    port,
			State:   classifyDialError(err),
			Service: serviceNames[port],
		}
	}

	return portResult{
		Port:    port,
		State:   portOpen,
		Service: serviceNames[port],
		Banner:  grabBanner(conn, port),
	}
}

// classifyDialError 把内核错误翻译成 nmap 三态：
// RST 类拒绝=closed；超时与不可达=filtered（防火墙丢弃与主机关机无法区分）。
func classifyDialError(err error) portState {
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) {
		return portClosed
	}

	var timeout interface{ Timeout() bool }
	if errors.As(err, &timeout) && timeout.Timeout() {
		return portFiltered
	}

	if errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.EHOSTDOWN) {
		return portFiltered
	}

	return portFiltered
}

// grabBanner 先被动等待服务端问候（SSH/FTP/SMTP/Redis 都会先说话），
// 读不到内容且是常见 HTTP 端口时补发 HEAD；TLS 端口不主动发握手随机数。
func grabBanner(conn net.Conn, port int) string {
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(bannerReadBudget))

	buffer := make([]byte, 256)

	n, _ := conn.Read(buffer)
	if n == 0 && httpProbePorts[port] {
		_ = conn.SetDeadline(time.Now().Add(bannerTotalBudget))
		_, _ = conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))

		n, _ = conn.Read(buffer)
	}

	return sanitizeBanner(buffer[:n])
}

// sanitizeBanner 取首行、折叠空白并截断显示长度，避免表格被撑坏。
func sanitizeBanner(raw []byte) string {
	firstLine := strings.SplitN(string(raw), "\n", 2)[0]
	firstLine = strings.Trim(firstLine, "\r\t ")
	firstLine = strings.Join(strings.Fields(firstLine), " ")

	runes := []rune(firstLine)
	if len(runes) > bannerMaxLength {
		return string(runes[:bannerMaxLength]) + "…"
	}

	return firstLine
}

// splitResults 按状态拆成三组，open/filtered 组内保持入参已排好的端口序。
func splitResults(results []portResult) (open, filtered []portResult, closed int) {
	for _, result := range results {
		switch result.State {
		case portOpen:
			open = append(open, result)
		case portFiltered:
			filtered = append(filtered, result)
		default:
			closed++
		}
	}

	return open, filtered, closed
}

// portStateColor 给 open 绿色、filtered 黄色，closed 不参与展示。
func portStateColor(state string) string {
	switch portState(state) {
	case portOpen:
		return constants.ColorGreen
	case portFiltered:
		return constants.ColorYellow
	default:
		return constants.ColorGray
	}
}
