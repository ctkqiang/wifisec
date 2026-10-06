package main

import (
	"os"
	"os/signal"
	"syscall"
	"wifisec/internal/constants"
	"wifisec/internal/functions"
	"wifisec/internal/model"
	"wifisec/internal/utilities"
)

var (
	session           = utilities.NewSession()
	developerMetadata = model.Developer{
		Id:           nil,
		Name:         "钟智强",
		Organisation: "哪吒网络安全",
		Email:        "johnmelodymel@qq.com",
		Weixin:       "ctkqiang",
		Version:      "v0.0.1",
		ProjectUrl:   "https://github.com/ctkqiang/wifisec.git",
		SessionId:    session.ID,
	}
	defaultMinLevel = constants.LevelInfo
)

var commandHandlers = map[string]utilities.CommandFunction{
	"deauth": functions.WifiDeauther,
	"list":   functions.WifiList,
}

func init() {
	for name, handler := range commandHandlers {
		utilities.RegisterCommand(name, handler)
	}
}

func main() {
	sessionSignalChannel := make(chan os.Signal, 1)

	utilities.Init(defaultMinLevel)
	utilities.Info(
		"%s",
		developerMetadata.String(),
	)

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
}
