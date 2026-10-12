package functions

import (
	"strings"
	"testing"
)

// TestDisplayWidth 锁定终端显示宽度口径：CJK 占 2 格、
// ANSI 转义序列占 0 格——TUI 全屏对齐的根基，错一格满屏错位。
func TestDisplayWidth(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		text string
		want int
	}{
		{"空串", "", 0},
		{"纯 ASCII", "abc -45", 7},
		{"纯中文", "隐藏网络", 8},
		{"中英混排", "目标 MyWiFi 中", 14}, // 2+2+1+6+1+2
		{"全角符号", "（）·", 5},          // (· 为半角)
		{"转义序列零宽", "\x1b[1;31m警告\x1b[0m", 4},
		{"色块包裹空格", "\x1b[48;5;46m  \x1b[0m", 2},
		{"复合行", "\x1b[1m 目标 \x1b[36m家居网\x1b[0m\x1b[K", 12}, // (1+2+2+1)+(2×3)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := displayWidth(tt.text); got != tt.want {
				t.Errorf("displayWidth(%q) = %d, 期望 %d", tt.text, got, tt.want)
			}
		})
	}
}

// TestClipCells 覆盖按显示格截断：中英混排、宽字符跨界
// （限宽只剩 1 格时下个汉字 2 格必须整体舍弃，不能画半个字）。
func TestClipCells(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		text  string
		limit int
		want  string
	}{
		{"短于限宽原样返回", "abc", 10, "abc"},
		{"恰好限宽原样返回", "ab", 2, "ab"},
		{"ASCII 截断补省略号", "abcdef", 4, "abc…"},
		{"中文截断", "隐藏网络名称", 5, "隐藏…"},
		{"宽字符跨界整体舍弃", "ab中文cd", 4, "ab…"},
		{"限宽 1 只剩省略号", "abc", 1, "…"},
		{"混排按格计", "家居WiFi名称", 7, "家居Wi…"}, // 家居Wi=6 格，F 会冲破 limit-1，整体舍弃
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := clipCells(tt.text, tt.limit); got != tt.want {
				t.Errorf("clipCells(%q, %d) = %q, 期望 %q", tt.text, tt.limit, got, tt.want)
			}
		})
	}
}

// TestPadCells 覆盖按显示格补齐：含中文的 SSID 必须补到
// 指定显示宽而非 rune 数，否则面板后续列垂直错位。
func TestPadCells(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		text  string
		width int
		want  int // 结果的显示宽度
	}{
		{"ASCII 补齐", "abc", 6, 6},
		{"中文按两格计", "家居", 6, 6},
		{"已等宽不补", "abcdef", 6, 6},
		{"超宽不截断（裁剪是 clipCells 的职责）", "abcdefgh", 6, 8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := padCells(tt.text, tt.width)
			if w := displayWidth(got); w != tt.want {
				t.Errorf("padCells(%q, %d) 显示宽 = %d, 期望 %d", tt.text, tt.width, w, tt.want)
			}
		})
	}
}

// TestFitCells 覆盖含 ANSI 转义整行的裁剪：转义序列必须原样
// 保留（半截序列会把终端状态机弄乱），截断后必须补 reset。
func TestFitCells(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		line  string
		limit int
		check func(t *testing.T, got string)
	}{
		{
			name:  "短行原样返回",
			line:  "\x1b[90m状态\x1b[0m",
			limit: 20,
			check: func(t *testing.T, got string) {
				if got != "\x1b[90m状态\x1b[0m" {
					t.Errorf("短行应原样返回，实际 %q", got)
				}
			},
		},
		{
			name:  "超宽截断且保留前缀转义",
			line:  "\x1b[1m标题文字超长\x1b[0m",
			limit: 5,
			check: func(t *testing.T, got string) {
				if !strings.HasPrefix(got, "\x1b[1m") {
					t.Errorf("转义前缀应保留，实际 %q", got)
				}

				if !strings.HasSuffix(got, "\x1b[0m") {
					t.Errorf("截断后应补 reset 防颜色泄漏，实际 %q", got)
				}

				// reset 的 4 字节转义零宽，可见宽度不超 limit
				if w := displayWidth(got); w > 5 {
					t.Errorf("截断后可见宽度 %d 超过限宽 5", w)
				}
			},
		},
		{
			name:  "裁剪不把转义序列切断",
			line:  "\x1b[38;5;220m▒▒\x1b[0m后缀文字",
			limit: 3,
			check: func(t *testing.T, got string) {
				if strings.Count(got, "\x1b[") < 2 {
					t.Errorf("前缀转义与补的 reset 都应完整存在，实际 %q", got)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.check(t, fitCells(tt.line, tt.limit))
		})
	}
}
