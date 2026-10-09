package constants

import "runtime/debug"

// BuildVersion 供构建时经 -ldflags "-X .../constants.BuildVersion=vX.Y.Z" 注入。
// 留空则回落到 debug.ReadBuildInfo：go install pkg@version 构建的二进制
// 无法注入 ldflags，模块版本只存在于 BuildInfo 中，是唯一可靠的来源。
var BuildVersion = ""

// EffectiveVersion 返回可展示的版本号，优先级：
// ldflags 注入值 > go install/go get 记录的模块版本 > 开发构建占位。
// "(devel)" 是 go build/go run 本地构建的占位值，不代表任何发布版本。
func EffectiveVersion() string {
	if BuildVersion != "" {
		return BuildVersion
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}
