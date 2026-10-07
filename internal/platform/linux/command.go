package linux

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// run 以参数列表执行外部命令并返回标准输出，禁止经过 shell 解释：
// 接口名等外部输入即便被篡改也无法注入额外命令。
// stderr 合并进错误信息，便于把内核权限错误（Operation not permitted）
// 原样传递给上层做权限引导。
func run(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return "", &commandError{name: name, output: strings.TrimSpace(string(output)), cause: err}
	}

	return string(output), nil
}

// commandError 同时保留失败命令名与系统输出，上层可据此识别权限类错误。
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
