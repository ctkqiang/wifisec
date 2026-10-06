package constants

import "log/slog"

const (
	PID_FILE        = "/var/run/deauth.pid"
	WIRELESS_FILE   = "/proc/net/wireless"
	DEV_FILE        = "/proc/net/dev"
	DEFAULT_PKT_CNT = 2000
)

const (
	ColorReset   = "\033[0m"
	ColorGray    = "\033[90m"
	ColorBlue    = "\033[34m"
	ColorYellow  = "\033[33m"
	ColorRed     = "\033[31m"
	ColorMagenta = "\033[35m"
	ColorWhite   = "\033[37m"
)

const (
	LevelVerbose = slog.LevelDebug - 4
	LevelDebug   = slog.LevelDebug
	LevelInfo    = slog.LevelInfo
	LevelWarn    = slog.LevelWarn
	LevelError   = slog.LevelError
)
