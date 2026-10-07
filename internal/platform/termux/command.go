package termux

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// run 以参数列表执行 termux-api 命令并返回标准输出，不经过 shell。
func run(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return "", &commandError{name: name, output: strings.TrimSpace(string(output)), cause: err}
	}

	return string(output), nil
}

type commandError struct {
	name   string
	output string
	cause  error
}

func (e *commandError) Error() string {
	if e.output != "" {
		return e.name + ": " + e.output
	}

	return e.name + ": " + e.cause.Error()
}

func (e *commandError) Unwrap() error {
	return e.cause
}
