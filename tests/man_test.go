package tests

import (
	"strings"
	"testing"

	"github.com/ctkqiang/wifisec/internal/man"
)

// TestManTopicsCoverAllCommands 断言手册页覆盖全部子命令：
// 新增子命令忘了补手册页时，这张表会让 CI 直接红掉。
func TestManTopicsCoverAllCommands(t *testing.T) {
	expected := []string{
		"bind", "brute", "clone", "deauth", "devices", "extract",
		"get_packet", "heatmap", "help", "ids", "jam", "list",
		"man", "pmkid", "scan_ports", "serial", "shell", "sniff",
		"upgrade", "wifisec",
	}

	topics := man.Topics()
	if len(topics) != len(expected) {
		t.Fatalf("主题数 %d，期望 %d：%v", len(topics), len(expected), topics)
	}

	for index, topic := range expected {
		if topics[index] != topic {
			t.Errorf("topics[%d] = %q，期望 %q", index, topics[index], topic)
		}
	}
}

// TestManLookupUnknown 断言未知主题的错误信息携带可用主题列表，
// 用户不必再跑一次无参 man 才知道有哪些页。
func TestManLookupUnknown(t *testing.T) {
	_, err := man.Lookup("nosuchtopic")
	if err == nil {
		t.Fatal("未知主题应返回错误")
	}

	if !strings.Contains(err.Error(), "sniff") || !strings.Contains(err.Error(), "deauth") {
		t.Errorf("错误信息应列出可用主题：%v", err)
	}
}

// TestManSummary 断言「名称」段解析：取 — 之后的描述部分。
func TestManSummary(t *testing.T) {
	summary := man.Summary("sniff")
	if summary == "" {
		t.Fatal("sniff 简介为空")
	}

	if strings.Contains(summary, "sniff") && strings.Contains(summary, "—") {
		t.Errorf("简介不应残留命令名与破折号：%q", summary)
	}

	if got := man.Summary("nosuchtopic"); got != "" {
		t.Errorf("未知主题简介应为空串，得到 %q", got)
	}
}

// TestManRenderPlain 断言无色渲染不含任何 ANSI 转义序列，
// 且页眉页脚、分节标题结构完整——管道落盘场景的正确性靠它保证。
func TestManRenderPlain(t *testing.T) {
	page, err := man.RenderPage("sniff", false)
	if err != nil {
		t.Fatalf("RenderPage 失败：%v", err)
	}

	if strings.Contains(page, "\x1b[") {
		t.Error("无色输出不应包含 ANSI 转义序列")
	}

	for _, want := range []string{"SNIFF(1)", "名称", "用法", "示例", "另见"} {
		if !strings.Contains(page, want) {
			t.Errorf("输出缺少分节 %q", want)
		}
	}
}

// TestManRenderColor 断言有色渲染带 ANSI 序列且结构不丢失。
func TestManRenderColor(t *testing.T) {
	page, err := man.RenderPage("sniff", true)
	if err != nil {
		t.Fatalf("RenderPage 失败：%v", err)
	}

	if !strings.Contains(page, "\x1b[") {
		t.Error("有色输出应包含 ANSI 转义序列")
	}

	if !strings.Contains(page, "SNIFF(1)") {
		t.Error("标题文本不应被颜色序列吃掉")
	}
}

// TestManRenderToleratesBadMarkup 断言渲染器对脏输入的容忍度：
// 未闭合的 **、`、[ 按字面输出，不吞正文、不 panic。
func TestManRenderToleratesBadMarkup(t *testing.T) {
	source := "# T(1)\n\n## 名称\nt — x\n\n**未闭合加粗\n`未闭合代码\n[未闭合链接\n"

	page := man.Render("t", source, false)

	for _, want := range []string{"**未闭合加粗", "`未闭合代码", "[未闭合链接"} {
		if !strings.Contains(page, want) {
			t.Errorf("未闭合标记 %q 应按字面输出", want)
		}
	}
}

// TestManRenderEveryPage 遍历全部内嵌页面：任何一页渲染失败或
// 产出空内容都视为回归——embed 资源在编译期已绑定，运行期不应出错。
func TestManRenderEveryPage(t *testing.T) {
	for _, topic := range man.Topics() {
		page, err := man.RenderPage(topic, false)
		if err != nil {
			t.Errorf("渲染 %q 失败：%v", topic, err)
			continue
		}

		if !strings.Contains(page, strings.ToUpper(topic)+"(1)") {
			t.Errorf("%q 输出缺少标题栏", topic)
		}
	}
}
