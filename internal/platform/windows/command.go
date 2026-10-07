package windows

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// run 以参数列表执行外部命令并返回标准输出，禁止经过 shell 解释。
// netsh 的错误提示同样走 stdout/混合输出，合并后便于上层呈现。
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
