package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/ctkqiang/wifisec/internal/constants"
	"github.com/ctkqiang/wifisec/internal/functions"
	platformdarwin "github.com/ctkqiang/wifisec/internal/platform/darwin"
	"github.com/ctkqiang/wifisec/internal/utilities"
)

var (
	defaultMinLevel = constants.LevelInfo
	commandHandlers = map[string]utilities.CommandFunction{
		"deauth": functions.WifiDeauther,
		"list":   functions.WifiList,
		"serial": functions.Serial,
		"brute":  functions.BruteForceConnectToWiFi,
		"help":   functions.HelpUsage,
	}
)

func init() {
	for name, handler := range commandHandlers {
		utilities.RegisterCommand(name, handler)
	}
}

func main() {
	// macOS 定位授权自举实例：由 LaunchServices 激活，只弹授权窗不做终端交互，
	// 必须在任何子命令分发之前接管并退出。
	if platformdarwin.HandleBootstrap() {
		os.Exit(0)
	}

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
