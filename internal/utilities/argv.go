package utilities

import (
	"fmt"
	"github.com/ctkqiang/wifisec/internal/model"
	"os"
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
		fmt.Printf("错误: 未知函数 '%s'\n", command.Name)
		fmt.Printf("用法: %s <函数名> [参数...]\n", os.Args[0])
		os.Exit(1)
	}

	if executionError := targetFunction(command.Arguments); executionError != nil {
		fmt.Printf("执行错误: %v\n", executionError)
		os.Exit(1)
	}
}
