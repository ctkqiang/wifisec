package main

import (
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
	}
	defaultMinLevel = utilities.LevelInfo
)

func main() {
	utilities.Init(defaultMinLevel)
	utilities.Info(developerMetadata.ToString())
}
