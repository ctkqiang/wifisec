// lateral.go 是 `wifisec bind` 与 `wifisec shell/<ip>` 的命令编排层。
//
// 两条入口：
//   - 被控端：wifisec bind [--port N] [--token 令牌] [--timeout 秒]
//   - 控制端：wifisec shell <主机> [命令...] 与 wifisec <ip> [命令...]
//     （后者由 argv.go 对首参做 IP 嗅探路由而来）
//
// 令牌解析优先级：命令行 --token > 环境变量 WIFISEC_TOKEN > 被控端
// 自动生成。令牌经 argv 出现在 ps 里对单用户实验机可接受，
// 多用户机器建议走环境变量——文档与帮助中已提示。
package functions

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/ctkqiang/wifisec/internal/lateral"
	"github.com/ctkqiang/wifisec/internal/utilities"
)

// tokenEnvVar 是双方共享的令牌环境变量：避免令牌出现在 shell 历史与 ps。
const tokenEnvVar = "WIFISEC_TOKEN"

// lateralConfig 是控制端参数的解析结果。
type lateralConfig struct {
	host    string
	port    int
	token   string
	command []string // 空 = 仅指明主机（提示用法），bash/sh = 交互，其余 = 单命令
}

// lateralFlag 是控制端/被控端共用的标志定义，解析逻辑共享一套。
type lateralFlag struct {
	name     string
	hasValue bool
}

// ParseLateralArgs 解析控制端参数（导出供表驱动测试与外部复用）。
// 标志与位置参数可交错：wifisec 192.168.1.123 uname -a --token t 合法。
// 返回值依次为：主机、端口、令牌、命令词（空表示仅指明主机）。
func ParseLateralArgs(arguments []string) (string, int, string, []string, error) {
	config, err := parseLateralArgs(arguments)
	return config.host, config.port, config.token, config.command, err
}

// RunBind 启动被控端：监听 TCP 等待控制端接入并执行下发命令。
func RunBind(arguments []string) error {
	port, token, timeout, err := parseBindArgs(arguments)
	if err != nil {
		return err
	}

	// 空令牌自动生成：无认证的命令执行服务等于给全局域网开后门，
	// 宁可让用户复制一次令牌也不提供「裸奔模式」。
	if token == "" {
		token, err = generateToken()
		if err != nil {
			return fmt.Errorf("生成随机令牌失败：%w", err)
		}
		utilities.Warn("未提供 --token，已自动生成令牌：%s（控制端需携带同一令牌）", token)
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("监听 %d 端口失败：%w", port, err)
	}

	utilities.Warn("横向移动 bind 服务仅限自有网络或已获书面授权的环境使用")
	utilities.Info("bind 已监听 :%d · 命令超时 %s · Ctrl-C 退出", port, timeout)

	return lateral.NewBind(listener, token, timeout).Serve()
}

// RunShellClient 是控制端入口：交互会话或单命令一步执行。
// arguments 可能以 "shell" 开头（显式子命令路由）或以 IP 开头
// （argv.go 嗅探路由），解析层统一剥掉。
func RunShellClient(arguments []string) error {
	config, err := parseLateralArgs(arguments)
	if err != nil {
		return err
	}

	if len(config.command) == 0 {
		return errors.New("缺少命令：bash 进入交互会话，或直接跟要执行的命令（如 whoami）")
	}

	if config.token == "" {
		return errors.New("缺少认证令牌：--token 或环境变量 WIFISEC_TOKEN（被控端启动时会打印）")
	}

	addr := fmt.Sprintf("%s:%d", config.host, config.port)

	client, err := lateral.Dial(addr, config.token)
	if err != nil {
		return err
	}
	defer client.Close()

	// bash/sh 关键字进入交互会话；其余整句下发改远端 shell 解释，
	// 保留管道与重定向语义。
	if lateral.IsInteractiveKeyword(config.command[0]) {
		return client.Interactive()
	}

	exitCode, err := client.Execute(strings.Join(config.command, " "), os.Stdout)
	if err != nil {
		return err
	}

	// 单命令模式把远端退出码映射成本地退出码，
	// 脚本化的横向移动链才能正确判断每一步成败。
	if exitCode != 0 {
		return fmt.Errorf("远端命令退出码 %d", exitCode)
	}

	return nil
}

// parseLateralArgs 解析控制端参数的内部实现。
func parseLateralArgs(arguments []string) (lateralConfig, error) {
	config := lateralConfig{port: lateral.DefaultPort}

	// 显式 shell 子命令路由会传 "shell" 首参，IP 嗅探路由不会，
	// 统一剥掉后解析逻辑只面对一种形态。
	if len(arguments) > 0 && arguments[0] == "shell" {
		arguments = arguments[1:]
	}

	flags := map[string]lateralFlag{
		"--port":  {name: "port", hasValue: true},
		"--token": {name: "token", hasValue: true},
	}

	var positionals []string

	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]

		flag, isFlag := flags[argument]
		if isFlag {
			if index+1 >= len(arguments) {
				return lateralConfig{}, fmt.Errorf("%s 缺少取值", argument)
			}

			index++
			switch flag.name {
			case "port":
				if _, err := fmt.Sscanf(arguments[index], "%d", &config.port); err != nil {
					return lateralConfig{}, fmt.Errorf("端口格式错误：%s", arguments[index])
				}
			case "token":
				config.token = arguments[index]
			}
			continue
		}

		if value, found := strings.CutPrefix(argument, "--port="); found {
			if _, err := fmt.Sscanf(value, "%d", &config.port); err != nil {
				return lateralConfig{}, fmt.Errorf("端口格式错误：%s", value)
			}
			continue
		}

		if value, found := strings.CutPrefix(argument, "--token="); found {
			config.token = value
			continue
		}

		positionals = append(positionals, argument)
	}

	if len(positionals) == 0 {
		return lateralConfig{}, errors.New("缺少目标主机：wifisec shell <ip|主机名> [命令]")
	}

	config.host = positionals[0]
	config.command = positionals[1:]

	// 令牌三级回退：命令行 > 环境变量 > 空（由调用方决定是否报错）。
	if config.token == "" {
		config.token = os.Getenv(tokenEnvVar)
	}

	return config, nil
}

// parseBindArgs 解析被控端参数：--port/--token/--timeout。
func parseBindArgs(arguments []string) (int, string, time.Duration, error) {
	port := lateral.DefaultPort
	token := os.Getenv(tokenEnvVar)
	timeout := 60 * time.Second

	for index := 0; index < len(arguments); index++ {
		switch arguments[index] {
		case "--port":
			if index+1 >= len(arguments) {
				return 0, "", 0, errors.New("--port 缺少取值")
			}
			index++
			if _, err := fmt.Sscanf(arguments[index], "%d", &port); err != nil {
				return 0, "", 0, fmt.Errorf("端口格式错误：%s", arguments[index])
			}
		case "--token":
			if index+1 >= len(arguments) {
				return 0, "", 0, errors.New("--token 缺少取值")
			}
			index++
			token = arguments[index]
		case "--timeout":
			if index+1 >= len(arguments) {
				return 0, "", 0, errors.New("--timeout 缺少取值")
			}
			index++
			seconds := 0
			if _, err := fmt.Sscanf(arguments[index], "%d", &seconds); err != nil || seconds <= 0 {
				return 0, "", 0, fmt.Errorf("超时秒数格式错误：%s", arguments[index])
			}
			timeout = time.Duration(seconds) * time.Second
		default:
			return 0, "", 0, fmt.Errorf("未知参数：%s（仅支持 --port/--token/--timeout）", arguments[index])
		}
	}

	return port, token, timeout, nil
}

// generateToken 生成 128 位随机令牌的十六进制表示：
// 对局域网离线爆破而言 2^128 空间已不可穷举，无需更长。
func generateToken() (string, error) {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}

	return hex.EncodeToString(raw), nil
}
