// sniff.go 实现 `wifisec get_packet`：在连接态网卡上抓包并导出 pcap。
//
// 与 deauth 的 802.11 监听模式不同，这里抓的是本机内核视角的以太网帧
// （DLT_EN13MB）：不需要切 monitor、不会断开当前 Wi-Fi，Windows 走 Npcap、
// macOS 走 BPF、Linux/Android 走 AF_PACKET。实时流在终端按 Wireshark
// 列表风格限速打印，每一帧都完整写入 pcap，供 Wireshark 离线分析。

package functions

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ctkqiang/wifisec/internal/ethernet"
	"github.com/ctkqiang/wifisec/internal/pcapfile"
	"github.com/ctkqiang/wifisec/internal/platform/capture"
	"github.com/ctkqiang/wifisec/internal/utilities"
)

const (
	// 终端实时行限速：手机备份、视频流会瞬间打出几千帧，
	// 折叠多余行但帧数据一个不落地进 pcap。
	sniffLinesPerSecond = 40

	// 每 5 秒输出一行运行中统计，长时间抓包也知道会话还活着。
	sniffStatInterval = 5 * time.Second

	// 缺省文件名前缀与时间格式。
	sniffFilePrefix = "wifisec"
	sniffTimeLayout = "20060102-150405"
)

// SniffOptions 是 get_packet 解析后的参数，导出供 tests/ 表驱动测试。
type SniffOptions struct {
	Interface  string
	Seconds    int           // 0 表示抓到 Ctrl-C 为止
	Duration   time.Duration // Seconds 的换算结果，0 同样表示无限
	OutputPath string
}

// GetPacket 打开网卡抓包并把全部帧写入 pcap 文件。
// 用法：wifisec get_packet [网卡名] [秒数] [输出文件.pcap]
func GetPacket(arguments []string) error {
	options, err := ParseSniffArgs(arguments)
	if err != nil {
		return err
	}

	if options.Interface == "" {
		options.Interface = defaultCaptureInterface()
		if options.Interface == "" {
			return errors.New("无法自动确定抓包网卡，请显式传入网卡名（可用 wifisec list 查看）")
		}
	}

	if options.OutputPath == "" {
		options.OutputPath = fmt.Sprintf("%s-%s.pcap", sniffFilePrefix, time.Now().Format(sniffTimeLayout))
	}

	utilities.Warn("抓包内容可能包含同一网络他人的通信，仅限已授权网络与设备使用")

	ctx, cancel := setupSignalHandler()
	defer cancel()

	if options.Seconds > 0 {
		var cancelTimeout context.CancelFunc
		ctx, cancelTimeout = context.WithTimeout(ctx, options.Duration)
		defer cancelTimeout()
	}

	return runCaptureSession(ctx, options)
}

// ParseSniffArgs 按位置语义解析参数：纯整数是秒数，带路径分隔符或
// .pcap/.cap 后缀的是输出文件，其余视为网卡名；三者都可省略。
func ParseSniffArgs(arguments []string) (SniffOptions, error) {
	options := SniffOptions{}

	for _, raw := range arguments {
		token := strings.TrimSpace(raw)
		if token == "" {
			continue
		}

		switch {
		case isSniffDuration(token):
			seconds, err := strconv.Atoi(token)
			if err != nil || seconds < 0 {
				return options, fmt.Errorf("非法抓包秒数 %q：请给出非负整数（0=抓到 Ctrl-C）", token)
			}

			options.Seconds = seconds
			options.Duration = time.Duration(seconds) * time.Second
		case isSniffOutputFile(token):
			options.OutputPath = token
		case strings.HasPrefix(token, "-"):
			return options, fmt.Errorf("无法识别的参数 %q（秒数必须是非负整数）", token)
		default:
			if options.Interface != "" {
				return options, fmt.Errorf("无法识别的多余参数 %q", token)
			}

			options.Interface = token
		}
	}

	return options, nil
}

// isSniffDuration 判断 token 是否为纯数字秒数。
func isSniffDuration(token string) bool {
	if token == "" {
		return false
	}

	for _, char := range token {
		if char < '0' || char > '9' {
			return false
		}
	}

	return true
}

// isSniffOutputFile 识别输出文件：显式路径分隔符或 pcap/cap 后缀。
func isSniffOutputFile(token string) bool {
	if strings.ContainsAny(token, `/\`) {
		return true
	}

	lower := strings.ToLower(token)

	return strings.HasSuffix(lower, ".pcap") || strings.HasSuffix(lower, ".cap")
}

// defaultCaptureInterface 优先取无线网卡；枚举失败（如纯有线主机）
// 退回承担默认路由的网卡，让命令在任何联网环境都可用。
func defaultCaptureInterface() string {
	if wifi, err := FindWirelessInterface(); err == nil && wifi.Name != "" {
		return wifi.Name
	}

	if iface, _, _, err := selectInterface(nil); err == nil {
		return iface.Name
	}

	return ""
}

// runCaptureSession 负责抓包会话的完整生命周期：
// 打开源 → 写文件 → 实时循环 → 退出收尾 → 统计汇总。
func runCaptureSession(ctx context.Context, options SniffOptions) error {
	source, err := capture.Open(options.Interface)
	if err != nil {
		return err
	}
	defer source.Close()

	file, err := os.Create(options.OutputPath)
	if err != nil {
		return fmt.Errorf("创建 pcap 文件失败：%w", err)
	}

	writer, err := pcapfile.NewWriter(file, source.LinkType())
	if err != nil {
		_ = file.Close()

		return err
	}

	intro := []string{
		fmt.Sprintf("抓包接口 %s · 链路类型 %s", options.Interface, linkTypeName(source.LinkType())),
		fmt.Sprintf("输出文件 %s · 实时行限速 %d 行/秒（完整帧全部入文件）",
			filepath.Clean(options.OutputPath), sniffLinesPerSecond),
		"按 Ctrl-C 结束抓包并写入统计",
	}
	utilities.Info("%s", strings.Join(intro, "\n"))

	stats := captureLoop(ctx, source, writer)

	if err := file.Sync(); err != nil {
		utilities.Debug("刷盘失败：%v", err)
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf("关闭 pcap 文件失败：%w", err)
	}

	printCaptureSummary(options.OutputPath, stats)

	return nil
}

// captureStats 汇总一次抓包会话的计数器。
type captureStats struct {
	packets  int
	bytes    int
	started  time.Time
	protocol map[string]int
}

// captureLoop 是主读取循环；仅在空闲超时点检查取消信号，
// 收到帧时同步写 pcap + 打印摘要，不需要额外协程。
func captureLoop(ctx context.Context, source capture.Source, writer *pcapfile.Writer) captureStats {
	stats := captureStats{
		started:  time.Now(),
		protocol: make(map[string]int),
	}

	var (
		ticker     = time.NewTicker(sniffStatInterval)
		budget     = sniffLinesPerSecond
		refillAt   = time.Now().Add(time.Second)
		suppressed int
	)

	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return stats
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

			utilities.Error("读取网卡帧失败，抓包中止：%v", readErr)

			return stats
		}

		capturedAt := time.Now()
		if err := writer.WritePacket(frame, capturedAt); err != nil {
			utilities.Error("写入 pcap 失败，抓包中止：%v", err)

			return stats
		}

		summary := ethernet.Summarize(frame)
		stats.packets++
		stats.bytes += len(frame)
		stats.protocol[summary.Proto]++

		budget, suppressed = printSniffLine(stats.packets, summary, len(frame), budget, &refillAt, suppressed)
	}
}

// ticked 用非阻塞方式消费 5 秒统计时钟，避免引入 select 分支打断读循环。
func ticked(ticker *time.Ticker) bool {
	select {
	case <-ticker.C:
		return true
	default:
		return false
	}
}

// printSniffLine 按令牌桶限速打印实时行；被折叠的行数在每秒第一次
// 恢复打印时补一条说明，保证用户知道有帧被省略显示（但没有省略落盘）。
func printSniffLine(
	sequence int,
	summary ethernet.FrameSummary,
	frameLength int,
	budget int,
	refillAt *time.Time,
	suppressed int,
) (int, int) {
	now := time.Now()
	if now.After(*refillAt) {
		if suppressed > 0 {
			utilities.Info("… 上一秒 %d 帧已折叠显示，完整帧均已写入 pcap", suppressed)
		}

		*refillAt = now.Add(time.Second)
		budget = sniffLinesPerSecond
		suppressed = 0
	}

	if budget <= 0 {
		return budget, suppressed + 1
	}

	budget--

	info := summary.Info
	if info != "" {
		utilities.Info("#%-6d %s → %s  %s  %s (%d B)",
			sequence, summary.Src, summary.Dst, summary.Proto, info, frameLength)
	} else {
		utilities.Info("#%-6d %s → %s  %s (%d B)",
			sequence, summary.Src, summary.Dst, summary.Proto, frameLength)
	}

	return budget, suppressed
}

// printCaptureSummary 输出最终统计块与 Wireshark 使用提示，多行一次输出。
func printCaptureSummary(path string, stats captureStats) {
	distribution := formatProtocolDistribution(stats.protocol, 5)

	info, err := os.Stat(path)
	size := int64(0)
	if err == nil {
		size = info.Size()
	}

	lines := []string{
		fmt.Sprintf("抓包结束：%d 帧 · %s · 时长 %s",
			stats.packets, humanizeBytes(stats.bytes), time.Since(stats.started).Round(10*time.Millisecond)),
		"协议分布：" + distribution,
		fmt.Sprintf("文件：%s（%s）", filepath.Clean(path), humanizeBytes(int(size))),
		"Wireshark 打开方式：File → Open → 选择该文件，或执行 wireshark " + filepath.Clean(path),
	}
	utilities.Info("%s", strings.Join(lines, "\n"))
}

// formatProtocolDistribution 按帧数降序取前 limit 个协议，拼成单行。
func formatProtocolDistribution(counts map[string]int, limit int) string {
	type pair struct {
		protocol string
		count    int
	}

	pairs := make([]pair, 0, len(counts))
	for protocol, count := range counts {
		pairs = append(pairs, pair{protocol: protocol, count: count})
	}

	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].count != pairs[j].count {
			return pairs[i].count > pairs[j].count
		}

		return pairs[i].protocol < pairs[j].protocol
	})

	if len(pairs) > limit {
		pairs = pairs[:limit]
	}

	parts := make([]string, 0, len(pairs))
	for _, item := range pairs {
		parts = append(parts, fmt.Sprintf("%s %d", item.protocol, item.count))
	}

	return strings.Join(parts, " · ")
}

// linkTypeName 给出人类可读的 pcap 链路类型名。
func linkTypeName(linkType uint32) string {
	switch linkType {
	case pcapfile.LinkTypeEthernet:
		return "Ethernet（本机网卡视角，DLT 1）"
	case pcapfile.LinkTypeIEEE80211Radio:
		return "802.11 + radiotap（DLT 127）"
	default:
		return fmt.Sprintf("DLT %d", linkType)
	}
}

// humanizeBytes 把字节数渲染为 B/KB/MB 一位小数的紧凑文本。
func humanizeBytes(bytes int) string {
	const unit = 1024

	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}

	value := float64(bytes)

	for _, suffix := range []string{"KB", "MB", "GB"} {
		value /= unit
		if value < unit {
			return fmt.Sprintf("%.1f %s", value, suffix)
		}
	}

	return fmt.Sprintf("%.1f TB", value/unit)
}
