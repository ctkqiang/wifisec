package utilities

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"
)

const (
	colorReset   = "\033[0m"
	colorGray    = "\033[90m"
	colorBlue    = "\033[34m"
	colorYellow  = "\033[33m"
	colorRed     = "\033[31m"
	colorMagenta = "\033[35m"
	colorWhite   = "\033[37m"
)

const (
	LevelVerbose = slog.LevelDebug - 4
	LevelDebug   = slog.LevelDebug
	LevelInfo    = slog.LevelInfo
	LevelWarn    = slog.LevelWarn
	LevelError   = slog.LevelError
)

var (
	logger *slog.Logger
	once   sync.Once
	level  *slog.LevelVar
)

type ColoredHandler struct {
	slog.Handler
	writer io.Writer
}

func Init(minLevel slog.Level) {
	once.Do(func() {
		level = &slog.LevelVar{}
		level.Set(minLevel)

		opts := &slog.HandlerOptions{
			Level: level,
			ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
				if a.Key == slog.TimeKey {
					return slog.String("time", a.Value.Time().Format("15:04:05.000"))
				}
				return a
			},
		}

		handler := NewColoredHandler(os.Stdout, opts)
		logger = slog.New(handler)
	})
}

func getLogger() *slog.Logger {
	if logger == nil {
		Init(LevelVerbose)
	}

	return logger
}

func Verbose(format string, args ...any) {
	logMsg(LevelVerbose, "[详细]", colorGray, format, args...)
}

func Debug(format string, args ...any) {
	logMsg(LevelDebug, "[调试]", colorWhite, format, args...)
}

func Info(format string, args ...any) {
	logMsg(LevelInfo, "[信息]", colorBlue, format, args...)
}

func Warn(format string, args ...any) {
	logMsg(LevelWarn, "[警告]", colorYellow, format, args...)
}

func Error(format string, args ...any) {
	logMsg(LevelError, "[错误]", colorRed, format, args...)
}

func Fatal(format string, args ...any) {
	logMsg(LevelError, "[致命]", colorMagenta, format, args...)
	os.Exit(1)
}

func logMsg(lvl slog.Level, levelStr string, color string, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	l := getLogger()

	if l.Enabled(context.Background(), lvl) {
		timestamp := time.Now().Format("15:04:05.000")
		fmt.Printf("%s %s %s%s%s\n", timestamp, color+levelStr+colorReset, color, msg, colorReset)
	}
}

func NewColoredHandler(w io.Writer, opts *slog.HandlerOptions) *ColoredHandler {
	return &ColoredHandler{
		Handler: slog.NewTextHandler(w, opts),
		writer:  w,
	}
}
