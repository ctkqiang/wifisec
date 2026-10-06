package utilities

import (
	"runtime"
)

const (
	Unknown OSName = iota
	Windows
	Linux
	Darwin
	Android
)

type OSName int

func (o OSName) String() string {
	switch o {
	case Windows:
		return "Windows"
	case Linux:
		return "Linux"
	case Darwin:
		return "macOS"
	case Android:
		return "Android (Termux)"
	default:
		return "未知操作系统"
	}
}

func GetOS() OSName {
	switch runtime.GOOS {
	case "windows":
		return Windows
	case "linux":
		// 在 Android/Termux 中，runtime.GOOS 可能是 "android"
		// 如果是在纯 Linux 环境，则是 "linux"
		return Linux
	case "darwin":
		return Darwin
	case "android":
		return Android
	default:
		return Unknown
	}
}
