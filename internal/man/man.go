// Package man 提供 wifisec 的内置手册页：页面以经典 man 结构
// （名称/用法/描述/选项/示例/另见）存放在 pages/ 下并随二进制
// embed 分发，渲染器把受限 markdown 子集转成 ANSI 终端文本，
// 无第三方依赖；管道/重定向与 NO_COLOR 场景由调用方传入
// color=false 输出纯文本，保证落盘与 CI 日志没有转义残留。
//
// 页面书写约定（渲染器只识别这一子集）：
//   - 页首恰一个 `# TOPIC(1)`，渲染成左右对齐的标题栏
//   - `## 节名` 加粗输出，节间空行由页面自己保留
//   - 四空格缩进与 ``` 围栏块视为字面块，整体置灰（用法/示例专用）
//   - 选项用定义列表：选项名单独行，说明行以 `: ` 开头；
//     说明需要换行时续行同样以 `: ` 开头——四空格续行会被当成
//     字面块置灰，语义错位
//   - 行内 `code` 染青色、**bold** 加粗、[text](url) 渲染为 text (url)
package man

import (
	"embed"
	"fmt"
	"sort"
	"strings"

	"github.com/ctkqiang/wifisec/internal/constants"
)

// manWidth 是标题栏与页脚的对齐基准：经典 man 输出按 80 列排版，
// 取 72 给窄终端留边距，也避免按运行期终端宽度排版导致同一份
// 手册在不同窗口下换行不一致。
const manWidth = 72

// pages 是全部手册页的 embed 文件系统，按 <主题>.md 命名——
// 文件名即 `wifisec man <主题>` 的查找键，增删页面无需改代码。
//
//go:embed pages/*.md
var pages embed.FS

// Topics 返回全部手册页主题，按字典序排列。
func Topics() []string {
	entries, err := pages.ReadDir("pages")
	if err != nil {
		return nil
	}

	topics := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".md") {
			continue
		}

		topics = append(topics, strings.TrimSuffix(entry.Name(), ".md"))
	}

	sort.Strings(topics)

	return topics
}

// Lookup 读取主题的原始 markdown；主题不存在时返回的错误携带
// 可用主题列表，用户不必再跑一次 `man` 才知道有哪些页。
func Lookup(topic string) (string, error) {
	raw, err := pages.ReadFile("pages/" + topic + ".md")
	if err != nil {
		return "", fmt.Errorf("没有 %q 的手册页（可用主题：%s）", topic, strings.Join(Topics(), ", "))
	}

	return string(raw), nil
}

// Summary 从页面「名称」段提取一行简介：`cmd — 描述` 取描述部分，
// 供 `wifisec man` 的无参列表使用；页面缺失或格式不符时返回空串。
func Summary(topic string) string {
	raw, err := Lookup(topic)
	if err != nil {
		return ""
	}

	lines := strings.Split(raw, "\n")
	for index, line := range lines {
		if strings.TrimSpace(line) != "## 名称" || index+1 >= len(lines) {
			continue
		}

		name := strings.TrimSpace(lines[index+1])
		if dash := strings.Index(name, "—"); dash >= 0 {
			return strings.TrimSpace(name[dash+len("—"):])
		}

		return name
	}

	return ""
}

// RenderPage 是 Lookup + Render 的组合：直接给出可打印的终端文本。
func RenderPage(topic string, color bool) (string, error) {
	raw, err := Lookup(topic)
	if err != nil {
		return "", err
	}

	return Render(topic, raw, color), nil
}

// Render 把页面 markdown 渲染成终端文本；color=false 时输出不含
// 任何 ANSI 序列的纯文本。topic 只用于错误提示与页脚，不参与解析。
func Render(topic, source string, color bool) string {
	paint := func(pigment, text string) string {
		if pigment == "" || !color {
			return text
		}

		return pigment + text + constants.ColorReset
	}

	builder := &strings.Builder{}
	inCode := false

	for _, line := range strings.Split(source, "\n") {
		trimmed := strings.TrimRight(line, " \t")

		switch {
		case strings.HasPrefix(trimmed, "```"):
			inCode = !inCode
		case inCode:
			builder.WriteString("      " + paint(constants.ColorGray, trimmed) + "\n")
		case strings.HasPrefix(trimmed, "# "):
			title := strings.TrimPrefix(trimmed, "# ")
			builder.WriteString(headerBar(title, paint) + "\n")
		case strings.HasPrefix(trimmed, "## "):
			builder.WriteString(paint(constants.ColorBold, strings.TrimPrefix(trimmed, "## ")) + "\n")
		case strings.HasPrefix(trimmed, "    "):
			builder.WriteString("  " + paint(constants.ColorGray, trimmed) + "\n")
		case strings.HasPrefix(trimmed, ": "):
			builder.WriteString("      " + inline(strings.TrimPrefix(trimmed, ": "), paint) + "\n")
		case trimmed == "":
			builder.WriteString("\n")
		default:
			builder.WriteString("  " + inline(trimmed, paint) + "\n")
		}
	}

	builder.WriteString("\n" + footerBar(topic, paint) + "\n")

	return builder.String()
}

// headerBar 渲染页首标题栏：标题靠左靠右各一份，中间灰色居中
// 「wifisec 用户手册」，与 man(1) 的经典页眉一致。
func headerBar(title string, paint func(string, string) string) string {
	center := paint(constants.ColorGray, "wifisec 用户手册")
	gap := manWidth - displayWidth(title)*2 - displayWidth("wifisec 用户手册")
	if gap < 2 {
		gap = 2
	}

	left := gap / 2

	return paint(constants.ColorBold, title) +
		strings.Repeat(" ", left) + center +
		strings.Repeat(" ", gap-left) + paint(constants.ColorBold, title) + "\n"
}

// footerBar 渲染页脚：版本与授权边界置灰，攻击类命令的误用风险提示
// 跟在每一份手册末尾，与 help 输出底部的法律边界一致。
func footerBar(topic string, paint func(string, string) string) string {
	left := paint(constants.ColorGray,
		"wifisec "+constants.DeveloperMetadata.Version+" · 仅限自有网络或已获书面授权的测试环境使用")
	right := paint(constants.ColorBold, strings.ToUpper(topic)+"(1)")

	gap := manWidth - displayWidth("wifisec "+constants.DeveloperMetadata.Version+" · 仅限自有网络或已获书面授权的测试环境使用") - displayWidth(strings.ToUpper(topic)+"(1)")
	if gap < 1 {
		gap = 1
	}

	return left + strings.Repeat(" ", gap) + right
}

// inline 处理行内标记：`code` 染青、**bold** 加粗、[text](url)
// 渲染为 text (url)。逐段切分而非正则——嵌套与未闭合标记按字面
// 输出，页面写错了也不会吃掉正文。
func inline(text string, paint func(string, string) string) string {
	text = applyLinks(text, paint)
	text = applyPaired(text, "**", func(s string) string { return paint(constants.ColorBold, s) })
	text = applyPaired(text, "`", func(s string) string { return paint(constants.ColorCyan, s) })

	return text
}

// applyLinks 把 [text](url) 展开为 text (url)，url 置灰；
// 找不到配对括号时原样保留，避免吞掉正文里的方括号。
func applyLinks(text string, paint func(string, string) string) string {
	var builder strings.Builder

	for {
		open := strings.Index(text, "](")
		if open < 0 {
			builder.WriteString(text)

			return builder.String()
		}

		start := strings.LastIndex(text[:open], "[")
		end := strings.Index(text[open+2:], ")")
		if start < 0 || end < 0 {
			builder.WriteString(text)

			return builder.String()
		}

		label := text[start+1 : open]
		url := text[open+2 : open+2+end]

		builder.WriteString(text[:start])
		builder.WriteString(label)
		builder.WriteString(paint(constants.ColorGray, " ("+url+")"))

		text = text[open+2+end+1:]
	}
}

// applyPaired 把成对分隔符（如 ** 或 `）包裹的片段交给 paintFn
// 上色；未闭合的分隔符按字面输出。
func applyPaired(text, marker string, paintFn func(string) string) string {
	var builder strings.Builder

	for {
		start := strings.Index(text, marker)
		if start < 0 {
			builder.WriteString(text)

			return builder.String()
		}

		end := strings.Index(text[start+len(marker):], marker)
		if end < 0 {
			builder.WriteString(text)

			return builder.String()
		}

		builder.WriteString(text[:start])
		builder.WriteString(paintFn(text[start+len(marker) : start+len(marker)+end]))

		text = text[start+len(marker)+end+len(marker):]
	}
}

// displayWidth 计算终端显示宽：CJK 等双宽字符占 2 列，区间与
// internal/functions/lists.go 的 isWideRune 保持一致——两处分开
// 维护是因为 functions 依赖本包，反向引入会成环。
func displayWidth(text string) int {
	width := 0

	for _, current := range text {
		if isWideRune(current) {
			width += 2
		} else {
			width++
		}
	}

	return width
}

// isWideRune 判定双宽字符，区间定义见 displayWidth 的说明。
func isWideRune(current rune) bool {
	switch {
	case current >= 0x1100 && current <= 0x115F,
		current >= 0x2E80 && current <= 0xA4CF,
		current >= 0xAC00 && current <= 0xD7A3,
		current >= 0xF900 && current <= 0xFAFF,
		current >= 0xFE30 && current <= 0xFE4F,
		current >= 0xFF00 && current <= 0xFF60,
		current >= 0xFFE0 && current <= 0xFFE6:
		return true
	default:
		return false
	}
}
