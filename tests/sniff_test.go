package tests

import (
	"testing"

	"github.com/ctkqiang/wifisec/internal/functions"
)

// TestParseSniffCommandArgs 覆盖 sniff 命令的参数解析：
// 布尔开关、带值 flag、位置参数等价性与冲突检测。
func TestParseSniffCommandArgs(t *testing.T) {
	cases := []struct {
		name      string
		arguments []string
		want      functions.SniffCommandOptions
		wantError string
	}{
		{
			name:      "无参数：被动嗅探自动选网卡",
			arguments: nil,
			want:      functions.SniffCommandOptions{},
		},
		{
			name:      "--spoof 布尔开关",
			arguments: []string{"--spoof"},
			want:      functions.SniffCommandOptions{Spoof: true},
		},
		{
			name:      "--targets 逗号分隔列表",
			arguments: []string{"--spoof", "--targets", "192.168.1.66,192.168.1.107"},
			want: functions.SniffCommandOptions{
				Spoof:   true,
				Targets: []string{"192.168.1.66", "192.168.1.107"},
			},
		},
		{
			name:      "--targets 去重与空段跳过",
			arguments: []string{"--targets", "192.168.1.66,,192.168.1.66"},
			want:      functions.SniffCommandOptions{Targets: []string{"192.168.1.66"}},
		},
		{
			name:      "--iface 带值",
			arguments: []string{"--iface", "en0"},
			want:      functions.SniffCommandOptions{Interface: "en0"},
		},
		{
			name:      "位置参数与 --iface 等价",
			arguments: []string{"en0", "--spoof"},
			want:      functions.SniffCommandOptions{Interface: "en0", Spoof: true},
		},
		{
			name:      "网卡名重复指定视为冲突",
			arguments: []string{"--iface", "en0", "en1"},
			wantError: "多余参数",
		},
		{
			name:      "targets 缺值",
			arguments: []string{"--targets"},
			wantError: "需要逗号分隔",
		},
		{
			name:      "targets 非法地址",
			arguments: []string{"--targets", "abc"},
			wantError: "不是有效的 IPv4",
		},
		{
			name:      "targets 全为空段",
			arguments: []string{"--targets", ","},
			wantError: "至少一个",
		},
		{
			name:      "iface 缺值",
			arguments: []string{"--iface"},
			wantError: "需要网卡名",
		},
		{
			name:      "未知参数",
			arguments: []string{"--frobnicate"},
			wantError: "无法识别",
		},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			options, err := functions.ParseSniffCommandArgs(item.arguments)

			if item.wantError != "" {
				if err == nil {
					t.Fatalf("期望错误包含 %q，实际无错误", item.wantError)
				}

				return
			}

			if err != nil {
				t.Fatalf("意外错误：%v", err)
			}

			if options.Interface != item.want.Interface {
				t.Errorf("Interface = %q，期望 %q", options.Interface, item.want.Interface)
			}

			if options.Spoof != item.want.Spoof {
				t.Errorf("Spoof = %v，期望 %v", options.Spoof, item.want.Spoof)
			}

			if len(options.Targets) != len(item.want.Targets) {
				t.Fatalf("Targets = %v，期望 %v", options.Targets, item.want.Targets)
			}

			for index, target := range item.want.Targets {
				if options.Targets[index] != target {
					t.Errorf("Targets[%d] = %q，期望 %q", index, options.Targets[index], target)
				}
			}
		})
	}
}
