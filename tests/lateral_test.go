// lateral_test.go 横向移动通道的黑盒测试：
// 参数解析表驱动 + bind/client 本机回环端到端全链路。
// 全部无硬件依赖，localhost 自对话即可跑，CI 无需任何特权。
package tests

import (
	"bytes"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ctkqiang/wifisec/internal/functions"
	"github.com/ctkqiang/wifisec/internal/lateral"
)

func TestParseLateralArgs(t *testing.T) {
	t.Setenv("WIFISEC_TOKEN", "")

	cases := []struct {
		name        string
		arguments   []string
		wantHost    string
		wantPort    int
		wantToken   string
		wantCommand []string
		wantErr     bool
	}{
		{
			name:        "IP 嗅探形态-交互",
			arguments:   []string{"192.168.1.123", "bash"},
			wantHost:    "192.168.1.123",
			wantPort:    lateral.DefaultPort,
			wantToken:   "",
			wantCommand: []string{"bash"},
		},
		{
			name:        "显式 shell 前缀-单命令",
			arguments:   []string{"shell", "M2.local", "uname", "-a"},
			wantHost:    "M2.local",
			wantPort:    lateral.DefaultPort,
			wantToken:   "",
			wantCommand: []string{"uname", "-a"},
		},
		{
			name:        "标志交错-分离取值",
			arguments:   []string{"10.0.0.8", "id", "--token", "t1", "--port", "7000"},
			wantHost:    "10.0.0.8",
			wantPort:    7000,
			wantToken:   "t1",
			wantCommand: []string{"id"},
		},
		{
			name:        "等号取值形态",
			arguments:   []string{"192.168.1.1", "--token=abc", "--port=8888", "whoami"},
			wantHost:    "192.168.1.1",
			wantPort:    8888,
			wantToken:   "abc",
			wantCommand: []string{"whoami"},
		},
		{
			name:      "缺少主机",
			arguments: []string{"--token", "t"},
			wantErr:   true,
		},
		{
			name:      "port 缺取值",
			arguments: []string{"192.168.1.1", "bash", "--port"},
			wantErr:   true,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			host, port, token, command, err := functions.ParseLateralArgs(testCase.arguments)

			if testCase.wantErr {
				if err == nil {
					t.Fatal("期望解析失败，实际成功")
				}
				return
			}

			if err != nil {
				t.Fatalf("解析失败：%v", err)
			}

			if host != testCase.wantHost {
				t.Errorf("host = %q, want %q", host, testCase.wantHost)
			}

			if port != testCase.wantPort {
				t.Errorf("port = %d, want %d", port, testCase.wantPort)
			}

			if token != testCase.wantToken {
				t.Errorf("token = %q, want %q", token, testCase.wantToken)
			}

			if strings.Join(command, " ") != strings.Join(testCase.wantCommand, " ") {
				t.Errorf("command = %v, want %v", command, testCase.wantCommand)
			}
		})
	}
}

func TestParseLateralArgsEnvToken(t *testing.T) {
	t.Setenv("WIFISEC_TOKEN", "env-token")

	_, _, token, _, err := functions.ParseLateralArgs([]string{"192.168.1.5", "id"})
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}

	if token != "env-token" {
		t.Fatalf("环境变量令牌未生效：token = %q", token)
	}
}

func TestBindClientEndToEnd(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败：%v", err)
	}
	defer listener.Close()

	bind := lateral.NewBind(listener, "e2e-token", 10*time.Second)
	go bind.Serve() //nolint:errcheck — 测试进程随用例结束，Serve 错误无需断言

	client, err := lateral.Dial(listener.Addr().String(), "e2e-token")
	if err != nil {
		t.Fatalf("连接失败：%v", err)
	}
	defer client.Close()

	t.Run("单命令输出与退出码", func(t *testing.T) {
		var output bytes.Buffer

		exitCode, err := client.Execute("echo lateral-ok", &output)
		if err != nil {
			t.Fatalf("执行失败：%v", err)
		}

		if exitCode != 0 {
			t.Fatalf("退出码 = %d, want 0", exitCode)
		}

		if strings.TrimSpace(output.String()) != "lateral-ok" {
			t.Fatalf("输出 = %q", output.String())
		}
	})

	t.Run("stderr 合并回传", func(t *testing.T) {
		var output bytes.Buffer

		if _, err := client.Execute("echo oops 1>&2", &output); err != nil {
			t.Fatalf("执行失败：%v", err)
		}

		if strings.TrimSpace(output.String()) != "oops" {
			t.Fatalf("stderr 未合并：输出 = %q", output.String())
		}
	})

	t.Run("非零退出码", func(t *testing.T) {
		exitCode, err := client.Execute("exit 3", &bytes.Buffer{})
		if err != nil {
			t.Fatalf("执行失败：%v", err)
		}

		if exitCode != 3 {
			t.Fatalf("退出码 = %d, want 3", exitCode)
		}
	})

	t.Run("命令超时击杀回 124", func(t *testing.T) {
		slowListener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("监听失败：%v", err)
		}
		defer slowListener.Close()

		slowBind := lateral.NewBind(slowListener, "e2e-token", 150*time.Millisecond)
		go slowBind.Serve() //nolint:errcheck — 同上

		slowClient, err := lateral.Dial(slowListener.Addr().String(), "e2e-token")
		if err != nil {
			t.Fatalf("连接失败：%v", err)
		}
		defer slowClient.Close()

		exitCode, err := slowClient.Execute("sleep 5", &bytes.Buffer{})
		if err != nil {
			t.Fatalf("执行失败：%v", err)
		}

		if exitCode != 124 {
			t.Fatalf("超时退出码 = %d, want 124", exitCode)
		}
	})
}

func TestBindRejectsWrongToken(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败：%v", err)
	}
	defer listener.Close()

	bind := lateral.NewBind(listener, "real-token", 10*time.Second)
	go bind.Serve() //nolint:errcheck — 同上

	if _, err := lateral.Dial(listener.Addr().String(), "bad-token"); !errors.Is(err, lateral.ErrAuthFailed) {
		t.Fatalf("错误令牌应返回 ErrAuthFailed，实际：%v", err)
	}
}
