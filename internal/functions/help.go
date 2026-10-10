// help.go 实现 `wifisec help` 与裸跑时的用法总览。
//
// 排版遵循 Unix 命令行工具的 man-page 惯例：ASCII banner、命令按功能
// 分组、签名列按终端显示宽对齐（CJK 占 2 列，复用 cellWidth）、示例行尾
// 灰色注释。输出直接写 stdout 不经 slog——时间戳与级别前缀对帮助文本
// 是噪声，nmap/aircrack-ng 的 usage 同样不带日志前缀。
// stdout 非 TTY（管道/重定向）或设置 NO_COLOR 时自动剥离 ANSI 序列，
// 保证落盘与 CI 日志里没有转义残留。
//
// 命令数据与 cmd/wifisec/main.go 的 commandHandlers 一一对应：
// 新增子命令时必须同步补充对应分组，否则用户只能翻源码才知道怎么传参。
package functions

import (
	"fmt"
	"os"
	"strings"

	"github.com/ctkqiang/wifisec/internal/constants"
)

// helpArt 是 banner 左侧的无线电塔：四行纯 ASCII，任何等宽终端渲染
// 一致，不依赖 Unicode 线框字符；各行的显示宽由 padRight 统一拉齐。
const helpArt = `     |
    /|\
   / | \
  '--|--'`

// helpArtWidth 是塔架四行中最宽一行的显示宽，作右列文字的对齐基准。
const helpArtWidth = 9

// helpSignatureCap 限定签名列最大显示宽：超过的命令签名独占一行、
// 描述换行缩进，避免描述列被单一长命令（brute / clone up）拉出屏幕。
const helpSignatureCap = 34

// helpCommand 是一条子命令的签名与一句话说明。
type helpCommand struct {
	Signature string
	Summary   string
}

// helpGroup 把子命令按功能分组，标题后可附灰色补充说明。
type helpGroup struct {
	Title    string
	Note     string
	Commands []helpCommand
}

// helpExample 是示例条目，注释渲染在行尾灰色区。
type helpExample struct {
	Command string
	Comment string
}

// helpDoc 是文档指引条目。
type helpDoc struct {
	Path    string
	Summary string
}

// helpColorEnabled 在包初始化时探测一次终端能力，help 是一次性输出，
// 无需在每次 paintText 里反复 Stat。
var helpColorEnabled = detectHelpColor()

// helpGroups 按攻击面与特权要求分组：无线攻击走 ESP 协处理器路径，
// 局域网分析是本机直连视角且四平台免 root，维护类与攻击面无关。
var helpGroups = []helpGroup{
	{
		Title: "无线攻击",
		Note:  "经 ESP 协处理器，插板全平台免 root",
		Commands: []helpCommand{
			{Signature: "list", Summary: "枚举本机无线接口与周边网络"},
			{Signature: "serial", Summary: "列出 USB 串口设备与 VID:PID（协处理器入口）"},
			{Signature: "deauth <ssid|bssid> [串口]", Summary: "持续发送 deauth 帧，Ctrl-C 停止并输出统计"},
			{Signature: "brute <ssid|bssid> with-pass: <字典> [串口]", Summary: "在线密码字典爆破，命中即停"},
			{Signature: "clone <ssid>:<密码> up [nokick] [串口]", Summary: "克隆同名热点（Evil Twin），Ctrl-C 结束"},
			{Signature: "clone down [串口]", Summary: "停止固件上的克隆热点"},
		},
	},
	{
		Title: "局域网分析",
		Note:  "本机直连视角，四平台免 root",
		Commands: []helpCommand{
			{Signature: "devices [网卡名]", Summary: "发现局域网在线设备（IP/MAC/主机名/网关角色）"},
			{Signature: "scan_ports <目标> [端口]", Summary: "nmap 风格 TCP 扫描：open/closed/filtered + banner"},
			{Signature: "get_packet [网卡] [秒] [文件]", Summary: "连接态抓包导出 pcap，Wireshark 可直接打开"},
		},
	},
	{
		Title: "维护",
		Commands: []helpCommand{
			{Signature: "upgrade", Summary: "从 GitHub Releases 下载最新版并原地替换"},
			{Signature: "help", Summary: "显示本帮助"},
		},
	},
}

// helpExamples 覆盖每类攻击面的最小可运行示例，注释说明意图而非参数。
var helpExamples = []helpExample{
	{Command: "wifisec list", Comment: "周边网络全景"},
	{Command: "wifisec deauth 'MyWiFi'", Comment: "按 SSID，同名多 AP 全部命中"},
	{Command: "wifisec deauth 01:23:45:67:89:ab", Comment: "按 BSSID 精确锁定"},
	{Command: "wifisec brute 'MyWiFi' with-pass: pass.txt", Comment: "字典爆破，命中即停"},
	{Command: "wifisec clone 'MyWiFi':'same-password' up", Comment: "克隆热点并 kick 真实 AP"},
	{Command: "wifisec devices", Comment: "局域网在线设备"},
	{Command: "wifisec scan_ports 192.168.1.1 22,80,8000-8100", Comment: "自定义端口规格"},
	{Command: "wifisec get_packet en0 30 capture.pcap", Comment: "抓 30 秒并落盘"},
}

// helpDocs 指向仓库内逐命令的深度文档与在线文档站。
var helpDocs = []helpDoc{
	{Path: "docs/feature/wifi_deauth.md", Summary: "串口烧录 · deauth/brute/clone 排错"},
	{Path: "docs/feature/lan_analysis.md", Summary: "局域网三件套原理与授权边界"},
	{Path: "https://ctkqiang.github.io/wifisec", Summary: "在线文档站"},
}

// HelpUsage 输出用法总览。help 文本按惯例绕过 slog 直接写 stdout，
// 日志时间戳前缀对 usage 是噪声。
func HelpUsage(arguements []string) error {
	fmt.Fprint(os.Stdout, renderHelp())

	return nil
}

// detectHelpColor 判断 stdout 是否值得上色：重定向/管道与声明了
// NO_COLOR 约定的环境一律返回 false。
func detectHelpColor() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}

	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}

	return info.Mode()&os.ModeCharDevice != 0
}

// paintText 按 helpColorEnabled 包裹 ANSI 颜色；空色值原样返回，
// 便于调用方表达「该行不上色」而不必写条件分支。
func paintText(color, text string) string {
	if color == "" || !helpColorEnabled {
		return text
	}

	return color + text + constants.ColorReset
}

// padRight 按终端显示宽在尾部补空格；中文占 2 列，len() 不可用。
func padRight(text string, width int) string {
	gap := width - cellWidth(text)
	if gap <= 0 {
		return text
	}

	return text + strings.Repeat(" ", gap)
}

// renderHelp 组装完整 usage：banner、按组命令表、示例、文档与作者。
func renderHelp() string {
	builder := &strings.Builder{}

	builder.WriteString(renderBanner())
	builder.WriteString("\n")

	builder.WriteString(paintText(constants.ColorBold, "用法"))
	builder.WriteString(":\n  wifisec <命令> [参数]\n\n")

	builder.WriteString(renderCommands())

	builder.WriteString(paintText(constants.ColorBold, "示例"))
	builder.WriteString(":\n")
	builder.WriteString(renderList(exampleRows(), exampleColumn()))
	builder.WriteString("\n")

	builder.WriteString(paintText(constants.ColorBold, "文档"))
	builder.WriteString(":\n")
	builder.WriteString(renderList(docRows(), docColumn()))
	builder.WriteString("\n")

	builder.WriteString(renderAuthor())

	return builder.String()
}

// renderBanner 拼装左侧塔架与右侧信息行：塔架四行，右列依次是
// 版本（加粗）、组织、仓库与黄色授权边界，行行对齐。
func renderBanner() string {
	project := strings.TrimSuffix(constants.DeveloperMetadata.ProjectUrl, ".git")

	right := []struct {
		text  string
		color string
	}{
		{text: "wifisec " + constants.DeveloperMetadata.Version, color: constants.ColorBold},
		{text: constants.DeveloperMetadata.Organisation + " · 无线安全审计", color: ""},
		{text: project, color: constants.ColorGray},
		{text: "仅限自有网络或已获书面授权的测试环境使用", color: constants.ColorYellow},
	}

	art := strings.Split(helpArt, "\n")
	builder := &strings.Builder{}

	for row, line := range art {
		builder.WriteString(paintText(constants.ColorCyan, padRight(line, helpArtWidth)))
		builder.WriteString("  ")

		if row < len(right) {
			builder.WriteString(paintText(right[row].color, right[row].text))
		}

		builder.WriteString("\n")
	}

	return builder.String()
}

// signatureColumn 计算签名列显示宽：取未超限签名的最大宽 + 2，
// 长签名不参与计算，保证描述列不会被单一长命令拉宽。
func signatureColumn() int {
	column := 0

	for _, group := range helpGroups {
		for _, command := range group.Commands {
			width := cellWidth(command.Signature)
			if width <= helpSignatureCap && width > column {
				column = width
			}
		}
	}

	return column + 2
}

// renderCommands 输出分组命令表：组标题加粗、备注灰色；超宽签名的
// 描述换行缩进到描述列，与 docker help 的长选项处理一致。
func renderCommands() string {
	column := signatureColumn()
	builder := &strings.Builder{}

	for _, group := range helpGroups {
		builder.WriteString(paintText(constants.ColorBold, group.Title))
		if group.Note != "" {
			builder.WriteString(paintText(constants.ColorGray, " · "+group.Note))
		}
		builder.WriteString(":\n")

		for _, command := range group.Commands {
			if cellWidth(command.Signature) > column {
				fmt.Fprintf(builder, "  %s\n", paintText(constants.ColorBold, command.Signature))
				fmt.Fprintf(builder, "%s%s\n", strings.Repeat(" ", column+2), command.Summary)
				continue
			}

			padding := strings.Repeat(" ", column-cellWidth(command.Signature))
			fmt.Fprintf(
				builder,
				"  %s%s%s\n",
				paintText(constants.ColorBold, command.Signature),
				padding,
				command.Summary,
			)
		}

		builder.WriteString("\n")
	}

	return builder.String()
}

// exampleRows / exampleColumn 把示例表降维成两列数据并计算对齐宽。
func exampleRows() [][2]string {
	rows := make([][2]string, 0, len(helpExamples))
	for _, item := range helpExamples {
		rows = append(rows, [2]string{item.Command, "# " + item.Comment})
	}

	return rows
}

func exampleColumn() int {
	column := 0
	for _, item := range helpExamples {
		if width := cellWidth(item.Command); width > column {
			column = width
		}
	}

	return column + 2
}

// docRows / docColumn 同上，服务于文档指引表。
func docRows() [][2]string {
	rows := make([][2]string, 0, len(helpDocs))
	for _, item := range helpDocs {
		rows = append(rows, [2]string{item.Path, item.Summary})
	}

	return rows
}

func docColumn() int {
	column := 0
	for _, item := range helpDocs {
		if width := cellWidth(item.Path); width > column {
			column = width
		}
	}

	return column + 2
}

// renderList 按「左列对齐 + 右列灰色」渲染示例与文档两类两列表。
func renderList(rows [][2]string, column int) string {
	builder := &strings.Builder{}

	for _, row := range rows {
		padding := strings.Repeat(" ", column-cellWidth(row[0]))
		fmt.Fprintf(builder, "  %s%s%s\n", row[0], padding, paintText(constants.ColorGray, row[1]))
	}

	return builder.String()
}

// renderAuthor 输出 man-page 的 AUTHOR 段与一行法律边界，紧随文档段。
func renderAuthor() string {
	author := constants.DeveloperMetadata

	builder := &strings.Builder{}
	builder.WriteString(paintText(constants.ColorBold, "作者"))
	builder.WriteString(":\n")
	fmt.Fprintf(
		builder,
		"  %s <%s> · 微信 %s · %s\n\n",
		author.Name,
		author.Email,
		author.Weixin,
		author.Organisation,
	)

	builder.WriteString(paintText(
		constants.ColorGray,
		"  对第三方网络使用攻击类命令可能触犯《刑法》第 285/286 条，后果由使用者自负\n",
	))

	return builder.String()
}
