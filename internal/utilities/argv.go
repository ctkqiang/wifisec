package utilities

import (
	"fmt"
	"os"
	"wifisec/internal/model"
)

var globalCommandRegistry = make(map[string]CommandFunction)

type CommandFunction func(arguments []string) error

func RegisterCommand(name string, targetFunction CommandFunction) {
	globalCommandRegistry[name] = targetFunction
}

func ArgumentsHandler() {
	var command model.Command

	if len(os.Args) < 2 {
		// 未输入子命令时默认展示帮助，而非直接报错退出，
		// 降低新用户首次运行的心智门槛。
		command = model.Command{Name: "help"}
	} else {
		command = model.Command{
			Name:      os.Args[1],
			Arguments: os.Args[2:],
		}
	}

	targetFunction, exists := globalCommandRegistry[command.Name]
	if !exists {
		fmt.Printf("错误: 未知函数 '%s'\n", command.Name)
		fmt.Printf("用法: %s <函数名> [参数...]\n", os.Args[0])
		os.Exit(1)
	}

	if executionError := targetFunction(command.Arguments); executionError != nil {
		fmt.Printf("执行错误: %v\n", executionError)
		os.Exit(1)
	}
}
