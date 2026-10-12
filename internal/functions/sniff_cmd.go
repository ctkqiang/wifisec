// sniff_cmd.go 实现bettercap 风格的实时嗅探与 ARP 欺骗 MITM：
// 被动模式直读网卡帧并做应用层标注；--spoof 开启双向 ARP 毒化，
// 把目标与网关之间的流量引到本机转发，退出时自动还原全部系统改动。
package functions

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"time"

	"github.com/ctkqiang/wifisec/internal/ethernet"
	"github.com/ctkqiang/wifisec/internal/mitm"
	"github.com/ctkqiang/wifisec/internal/platform/capture"
	"github.com/ctkqiang/wifisec/internal/platform/fwd"
	"github.com/ctkqiang/wifisec/internal/platform/lan"
	"github.com/ctkqiang/wifisec/internal/platform/writer"
	"github.com/ctkqiang/wifisec/internal/utilities"
)

// maxSpoofTargets 是单次会话毒化的主机数上限：每台目标每个毒化
// 周期产生两帧、恢复期产生十帧，无上限的全网段毒化会无谓放大总线
// 噪声；家庭/办公网段的在线主机通常远低于此值。
const maxSpoofTargets = 32

// SniffCommandOptions 是 sniff 命令解析后的参数，导出供 tests/ 表驱动测试。
type SniffCommandOptions struct {
	Interface string   // 网卡名；空表示自动选择（优先无线网卡）
	Spoof     bool     // --spoof：ARP 欺骗 MITM
	Targets   []string // --targets：逗号分隔的目标 IPv4；空表示毒化全部在线主机
}

// RunSniff 是 sniff 命令入口：被动嗅探当前连接网络的流量并实时标注
// DNS/HTTP/SNI，--spoof 时叠加 ARP 欺骗把目标流量引到本机。
// 用法：
//
//	wifisec sniff [--iface 网卡名]
//	wifisec sniff --spoof [--targets ip1,ip2] [--iface 网卡名]
func RunSniff(arguments []string) error {
	options, err := ParseSniffCommandArgs(arguments)
	if err != nil {
		return err
	}

	// Windows 的 IPEnableRouter 改动需要注册表写入与服务重启，
	// 做不到「退出即还原」；欺骗入口直接拒绝，被动嗅探不受影响。
	if options.Spoof && runtime.GOOS == "windows" {
		return fwd.ErrSpoofUnsupported
	}

	// 三个平台的原始抓包句柄都要求特权：BPF/AF_PACKET/Npcap 打开即需要；
	// GUI 预提示先行，避免用户在终端里闷头撞上 sudo 失败。
	if runtime.GOOS == "windows" {
		if err = checkAdminWithGUI(); err != nil {
			return err
		}
	} else if err = checkRootWithGUI(); err != nil {
		return err
	}

	if options.Interface == "" {
		if options.Interface = defaultCaptureInterface(); options.Interface == "" {
			return errors.New("无法自动确定嗅探网卡，请显式传入网卡名（可用 wifisec list 查看）")
		}
	}

	iface, ipnet, selfIP, err := selectInterface([]string{options.Interface})
	if err != nil {
		return err
	}

	var (
		stats     = captureStats{started: time.Now(), protocol: make(map[string]int)}
		spoofer   *mitm.Spoofer
		framePort writer.Port
		fwdToken  *fwd.Token

		gatewayIP  net.IP
		gatewayMAC net.HardwareAddr
		targets    []mitm.Target
	)

	// 统一清理：先停毒化（恢复帧还要走端口），再关端口，最后还原
	// 转发开关。Ctrl-C 与中途出错共用这一出口，毒化条目绝不残留。
	defer func() {
		if spoofer != nil {
			spoofer.Stop()
			utilities.Info("ARP 毒化已停止：共注入 %d 帧（含 5 轮恢复帧），网关与目标的缓存条目已还原", spoofer.FramesSent())
		}

		if framePort != nil {
			_ = framePort.Close()
		}

		if fwdToken != nil {
			if disableErr := fwd.Disable(fwdToken); disableErr != nil {
				utilities.Error("还原 IP 转发配置失败，请手动检查系统设置：%v", disableErr)
			}
		}

		utilities.Info("嗅探结束：%d 帧 · %s · 时长 %s\n协议分布：%s",
			stats.packets, humanizeBytes(stats.bytes),
			time.Since(stats.started).Round(10*time.Millisecond),
			formatProtocolDistribution(stats.protocol, 5))
	}()

	if options.Spoof {
		if gatewayIP, err = lan.DefaultGateway(); err != nil {
			return fmt.Errorf("读取默认网关失败，ARP 欺骗需要网关参与：%w", err)
		}

		if targets, gatewayMAC, err = resolveSpoofMaterials(options.Targets, ipnet, selfIP, gatewayIP); err != nil {
			return err
		}
	}

	ctx, cancel := setupSignalHandler()
	defer cancel()

	// 转发开关先于毒化就绪：流量涌入本机却转不出去，目标会立刻断网。
	if options.Spoof {
		if fwdToken, err = fwd.Enable(iface.Name); err != nil {
			return err
		}

		if framePort, err = writer.Open(iface.Name); err != nil {
			return err
		}

		if spoofer, err = mitm.NewSpoofer(framePort, iface.HardwareAddr, gatewayIP, gatewayMAC, targets); err != nil {
			return err
		}
	}

	source, err := capture.Open(iface.Name)
	if err != nil {
		return err
	}
	defer source.Close()

	printSniffBanner(iface.Name, options, targets, gatewayIP)

	if spoofer != nil {
		spoofer.Start()
	}

	sniffReadLoop(ctx, source, spoofer, iface.HardwareAddr, &stats)

	return nil
}

// ParseSniffCommandArgs 解析 sniff 命令参数：--spoof 为布尔开关，
// --targets/--iface 带值；裸位置参数与 --iface 等价，两者同时出现
// 视为冲突。导出供 tests/ 表驱动测试。
func ParseSniffCommandArgs(arguments []string) (SniffCommandOptions, error) {
	options := SniffCommandOptions{}

	for index := 0; index < len(arguments); index++ {
		token := strings.TrimSpace(arguments[index])
		if token == "" {
			continue
		}

		switch {
		case token == "--spoof":
			options.Spoof = true
		case token == "--targets":
			if index+1 >= len(arguments) {
				return options, errors.New("--targets 需要逗号分隔的 IPv4 列表，例如 --targets 192.168.1.66,192.168.1.107")
			}

			index++

			var listErr error
			if options.Targets, listErr = parseSpoofTargetList(arguments[index]); listErr != nil {
				return options, listErr
			}
		case token == "--iface":
			if index+1 >= len(arguments) {
				return options, errors.New("--iface 需要网卡名，例如 --iface en0")
			}

			index++
			options.Interface = strings.TrimSpace(arguments[index])
		case strings.HasPrefix(token, "-"):
			return options, fmt.Errorf("无法识别的参数 %q（支持 --spoof/--targets/--iface）", token)
		default:
			if options.Interface != "" {
				return options, fmt.Errorf("无法识别的多余参数 %q（网卡名已指定为 %s）", token, options.Interface)
			}

			options.Interface = token
		}
	}

	return options, nil
}

// parseSpoofTargetList 拆分并校验逗号分隔的 IPv4 列表：逐项
// ParseIP 校验、归一为规范文本并去重，空段静默跳过。
func parseSpoofTargetList(token string) ([]string, error) {
	var (
		targets []string
		seen    = make(map[string]bool)
	)

	for part := range strings.SplitSeq(token, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		ip := net.ParseIP(part).To4()
		if ip == nil {
			return nil, fmt.Errorf("--targets 中的 %q 不是有效的 IPv4 地址", part)
		}

		if seen[ip.String()] {
			continue
		}

		seen[ip.String()] = true
		targets = append(targets, ip.String())
	}

	if len(targets) == 0 {
		return nil, errors.New("--targets 需要至少一个 IPv4 地址，例如 --targets 192.168.1.66")
	}

	return targets, nil
}

// resolveSpoofMaterials 把「--targets 显式列表 / 全网段发现」统一为
// 可毒化目标并顺带取回网关 MAC：先经 TCP 探测触发内核 ARP 解析，
// 再查系统邻居表取真实 MAC。MAC 未知的主机跳过并告警——没有真实
// MAC 就没有恢复依据，毒化它等于断网，违背「可完全还原」的承诺。
func resolveSpoofMaterials(explicit []string, ipnet *net.IPNet, selfIP, gatewayIP net.IP) ([]mitm.Target, net.HardwareAddr, error) {
	var candidates []net.IP

	if len(explicit) > 0 {
		for _, token := range explicit {
			ip := net.ParseIP(token).To4()
			switch {
			case ip == nil:
				return nil, nil, fmt.Errorf("目标 %s 不是有效的 IPv4 地址", token)
			case !ipnet.Contains(ip):
				return nil, nil, fmt.Errorf("目标 %s 不在网段 %s 内，ARP 欺骗只对同网段主机有效", token, ipnet.String())
			case ip.Equal(selfIP):
				return nil, nil, errors.New("目标不能是本机自身")
			}

			candidates = append(candidates, ip)
		}
	} else {
		candidates = planDiscoveryTargets(ipnet, selfIP, gatewayIP.String())
	}

	probeHosts(candidates)

	neighbors, err := lan.Neighbors()
	if err != nil {
		return nil, nil, fmt.Errorf("读取 ARP 邻居表失败：%w", err)
	}

	// 以 4 字节 IP 的文本形式为键建立索引：Neighbors 返回的 IP
	// 字节表示不一（16 字节形式的 v4 映射很常见），归一后再比对。
	table := make(map[string]net.HardwareAddr, len(neighbors))
	for _, neighbor := range neighbors {
		if ip4 := neighbor.IP.To4(); ip4 != nil && neighbor.HWAddr != nil {
			table[string(ip4)] = neighbor.HWAddr
		}
	}

	gatewayMAC, known := table[string(gatewayIP.To4())]
	if !known {
		return nil, nil, fmt.Errorf("网关 %s 不在 ARP 邻居表中（未解析过 MAC），先 ping 一下网关再重试", gatewayIP)
	}

	var targets []mitm.Target

	for _, ip := range candidates {
		if ip.Equal(selfIP) || ip.Equal(gatewayIP) {
			continue
		}

		mac, online := table[string(ip.To4())]
		if !online {
			utilities.Warn("主机 %s 不在邻居表中（不在线或被防火墙屏蔽），已跳过", ip)

			continue
		}

		targets = append(targets, mitm.Target{IP: ip, MAC: mac})
	}

	switch {
	case len(targets) == 0:
		return nil, nil, errors.New("没有可毒化的目标：邻居表中找不到任何有效主机")
	case len(targets) > maxSpoofTargets:
		utilities.Warn("在线主机 %d 台超过单会话毒化上限 %d，仅毒化前 %d 台", len(targets), maxSpoofTargets, maxSpoofTargets)
		targets = targets[:maxSpoofTargets]
	}

	return targets, gatewayMAC, nil
}

// sniffReadLoop 是主读取循环：仅在空闲超时点检查取消信号，收到帧时
// 过滤本机自发帧、更新统计并限速打印。毒化会话把每帧喂给 Spoofer，
// 「目标 who-has 网关」时即时应答，不等下一个秒级毒化周期。
func sniffReadLoop(ctx context.Context, source capture.Source, spoofer *mitm.Spoofer, selfMAC net.HardwareAddr, stats *captureStats) {
	ticker := time.NewTicker(sniffStatInterval)
	defer ticker.Stop()

	var (
		budget     = sniffLinesPerSecond
		refillAt   = time.Now().Add(time.Second)
		suppressed int
		sequence   int
	)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		frame, readErr := source.Read()
		if readErr != nil {
			if errors.Is(readErr, capture.ErrReadTimeout) {
				if ticked(ticker) {
					utilities.Info("进行中：%d 帧 · %s · 运行 %s（Ctrl-C 结束）",
						stats.packets, humanizeBytes(stats.bytes), time.Since(stats.started).Round(time.Second))
				}

				continue
			}

			utilities.Error("读取网卡帧失败，嗅探中止：%v", readErr)

			return
		}

		// 读写句柄独立，但内核回环会把发出的毒化/恢复帧送回读句柄；
		// 按源 MAC 过滤，ARP 事件行全部来自网络真实活动。
		if len(frame) >= 12 && bytes.Equal(frame[6:12], selfMAC) {
			continue
		}

		summary := ethernet.SummarizeWithL7(frame)
		stats.packets++
		stats.bytes += len(frame)
		stats.protocol[summary.Proto]++

		if spoofer != nil {
			spoofer.Observe(frame)
		}

		sequence++
		budget, suppressed = printSniffLine(sequence, summary, len(frame), budget, &refillAt, suppressed)
	}
}

// printSniffBanner 输出会话说明。被动可见性的诚实说明放在首位：
// WPA2 加密下被动嗅探看不到他人单播流量，用户需要先知道这一点
// 再决定是否启用欺骗。
func printSniffBanner(ifaceName string, options SniffCommandOptions, targets []mitm.Target, gatewayIP net.IP) {
	lines := []string{
		fmt.Sprintf("实时嗅探接口 %s · Ctrl-C 结束", ifaceName),
	}

	if options.Spoof {
		labels := make([]string, 0, len(targets))
		for _, target := range targets {
			labels = append(labels, target.IP.String())
		}

		lines = append(lines,
			fmt.Sprintf("ARP 欺骗 MITM：网关 %s ↔ 目标 %d 台（%s）", gatewayIP, len(targets), strings.Join(labels, ", ")),
			"目标流量将途经本机，DNS 查询 / HTTP 请求 / TLS SNI 会实时标注",
			"警告：kill -9 会跳过恢复帧，目标将断网直至其 ARP 缓存老化（通常 1-5 分钟）",
		)
	} else {
		lines = append(lines,
			"WPA2 下被动模式只能看到本机流量与广播帧（ARP/DHCP/mDNS）",
			"要观测他人单播流量请加 --spoof 启用 ARP 欺骗（仅限已授权网络）",
		)
	}

	utilities.Info("%s", strings.Join(lines, "\n"))
}
