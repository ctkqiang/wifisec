package main

import (
	"os"
	"os/signal"
	"syscall"
	"wifisec/internal/constants"
	"wifisec/internal/functions"
	"wifisec/internal/utilities"
)

var (
	defaultMinLevel = constants.LevelInfo
	commandHandlers = map[string]utilities.CommandFunction{
		"deauth": functions.WifiDeauther,
		"list":   functions.WifiList,
		"help":   functions.HelpUsage,
	}
)

func init() {
	for name, handler := range commandHandlers {
		utilities.RegisterCommand(name, handler)
	}
}

func main() {
	sessionSignalChannel := make(chan os.Signal, 1)

	utilities.Init(defaultMinLevel)

	signal.Notify(
		sessionSignalChannel,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
	)

	go func() {
		sig := <-sessionSignalChannel
		utilities.Debug("收到信号：%v", sig)

		os.Exit(0)
	}()

	// 分发命令行子命令；此前注册表只登记不分发，导致任何子命令都不会执行。
	utilities.ArgumentsHandler()
}
