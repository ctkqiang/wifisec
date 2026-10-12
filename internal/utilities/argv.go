package utilities

import (
	"fmt"
	"net"
	"os"

	"github.com/ctkqiang/wifisec/internal/model"
)

var globalCommandRegistry = make(map[string]CommandFunction)

type CommandFunction func(arguments []string) error

func RegisterCommand(name string, targetFunction CommandFunction) {
	globalCommandRegistry[name] = targetFunction
}

func ArgumentsHandler() {
	var command model.Command

	if len(os.Args) < 2 {
		command = model.Command{Name: "help"}
	} else {
		command = model.Command{
			Name:      os.Args[1],
			Arguments: os.Args[2:],
		}
	}

	targetFunction, exists := globalCommandRegistry[command.Name]
	if !exists {
		// 首参是 IP 时路由到横向移动控制端：`wifisec 192.168.1.123 bash`
		// 等价 `wifisec shell 192.168.1.123 bash`。IP 不进注册表——
		// 注册表按子命令名组织，IP 是运行期才知道的值。
		if net.ParseIP(command.Name) != nil {
			if shellHandler, ok := globalCommandRegistry["shell"]; ok {
				full := append([]string{command.Name}, command.Arguments...)

				if executionError := shellHandler(full); executionError != nil {
					fmt.Printf("执行错误: %v\n", executionError)
					os.Exit(1)
				}

				return
			}
		}

		fmt.Printf("错误: 未知函数 '%s'\n", command.Name)
		fmt.Printf("用法: %s <函数名> [参数...]\n", os.Args[0])
		os.Exit(1)
	}

	if executionError := targetFunction(command.Arguments); executionError != nil {
		fmt.Printf("执行错误: %v\n", executionError)
		os.Exit(1)
	}
}
