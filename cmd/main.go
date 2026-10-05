package main

import (
	"wifisec/internal/functions"
	"wifisec/internal/model"
	"wifisec/internal/utilities"
)

var (
	developerMetadata = model.Developer{
		Id:           nil,
		Name:         "钟智强",
		Organisation: "哪吒网络安全",
		Email:        "johnmelodymel@qq.com",
		Weixin:       "ctkqiang",
		Version:      "v0.0.1",
		ProjectUrl:   "https://github.com/ctkqiang/wifisec.git",
	}
	defaultMinLevel = utilities.LevelInfo
)

func init() {
	utilities.RegisterCommand("deauth", functions.WifiDeauther)
}

func main() {
	utilities.Init(defaultMinLevel)
	utilities.Info("%s", developerMetadata.String())
}
