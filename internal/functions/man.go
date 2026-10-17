// man.go 是 `wifisec man` 的命令行入口：渲染 internal/man 内嵌的
// 手册页。无参时列出全部主题与一行简介，带主题时输出整页手册。
// 与 help 一样直接写 stdout 不经 slog——usage 类输出带时间戳前缀
// 是噪声；颜色开关复用 helpColorEnabled，管道/重定向/NO_COLOR
// 自动降级为纯文本。
package functions

import (
	"fmt"
	"os"
	"strings"

	"github.com/ctkqiang/wifisec/internal/constants"
	"github.com/ctkqiang/wifisec/internal/man"
)

// RunMan 渲染指定主题的手册页；无参时输出主题列表。
// 主题名大小写不敏感，与 shell 的 man 命令习惯一致。
func RunMan(arguments []string) error {
	if len(arguments) == 0 {
		fmt.Fprint(os.Stdout, renderManTopics())

		return nil
	}

	topic := strings.ToLower(strings.TrimSpace(arguments[0]))

	page, err := man.RenderPage(topic, helpColorEnabled)
	if err != nil {
		return err
	}

	fmt.Fprint(os.Stdout, page)

	return nil
}

// renderManTopics 输出无参场景的主题列表：主题名染青按列对齐，
// 简介取自各页「名称」段，底部附用法提示。对齐宽度取全部主题的
// 最大显示宽，CJK 主题名（若有）按 2 列计。
func renderManTopics() string {
	topics := man.Topics()

	column := 0
	for _, topic := range topics {
		if width := cellWidth(topic); width > column {
			column = width
		}
	}
	column += 2

	builder := &strings.Builder{}
	builder.WriteString(paintText(constants.ColorBold, "内置手册页"))
	builder.WriteString(":\n")

	for _, topic := range topics {
		builder.WriteString("  ")
		builder.WriteString(paintText(constants.ColorCyan, padRight(topic, column)))
		builder.WriteString(man.Summary(topic))
		builder.WriteString("\n")
	}

	builder.WriteString("\n用法: wifisec man <主题>\n")

	return builder.String()
}
