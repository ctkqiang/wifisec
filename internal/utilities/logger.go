package utilities

import (
	"context"
	"fmt"
	"github.com/ctkqiang/wifisec/internal/constants"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"
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
		Init(constants.LevelVerbose)
	}

	return logger
}

func Verbose(format string, args ...any) {
	logMsg(
		constants.LevelVerbose,
		"[详细]",
		constants.ColorGray,
		format,
		args...,
	)
}

func Debug(format string, args ...any) {
	logMsg(constants.LevelDebug, "[调试]", constants.ColorWhite, format, args...)
}

func Info(format string, args ...any) {
	logMsg(constants.LevelInfo, "[信息]", constants.ColorBlue, format, args...)
}

func Warn(format string, args ...any) {
	logMsg(constants.LevelWarn, "[警告]", constants.ColorYellow, format, args...)
}

func Error(format string, args ...any) {
	logMsg(
		constants.LevelError,
		"[错误]",
		constants.ColorRed,
		format,
		args...,
	)
}

func Fatal(format string, args ...any) {
	logMsg(
		constants.LevelError,
		"[致命]",
		constants.ColorMagenta,
		format,
		args...,
	)
	os.Exit(1)
}

func logMsg(lvl slog.Level, levelStr string, color string, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	l := getLogger()

	if !l.Enabled(context.Background(), lvl) {
		return
	}

	timestamp := time.Now().Format("15:04:05.000")

	fmt.Printf(
		"%s %s %s%s%s\n",
		timestamp,
		color+levelStr+constants.ColorReset,
		color,
		msg,
		constants.ColorReset,
	)
}

func NewColoredHandler(w io.Writer, opts *slog.HandlerOptions) *ColoredHandler {
	return &ColoredHandler{
		Handler: slog.NewTextHandler(w, opts),
		writer:  w,
	}
}
