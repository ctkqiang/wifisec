package security

import (
	"errors"
	"os"
	"os/exec"
	"runtime"
)

type PrivilegeChecker interface {
	Check() error
}

type RootChecker struct{}

// AdminChecker 校验 Windows 管理员权限。
// Npcap 的 wpcap.dll 在打开适配器句柄时会触发驱动访问检查，
// 非管理员进程会被直接拒绝，因此必须在尝试注入前显式拦截。
type AdminChecker struct{}

func IsRoot() bool {
	return os.Geteuid() == 0
}

// IsAdmin 通过 `net session` 判断当前进程是否拥有管理员令牌。
// 该命令无需参数、纯查询、无副作用，是 Windows 上最轻量的权限探针；
// 非管理员执行返回非零退出码，且与系统语言无关。
func IsAdmin() bool {
	if runtime.GOOS != "windows" {
		return false
	}

	return exec.Command("net", "session").Run() == nil
}

func (r RootChecker) Check() error {
	if !IsRoot() {
		return errors.New("权限不足->需要root权限")
	}

	return nil
}

func (a AdminChecker) Check() error {
	if !IsAdmin() {
		return errors.New("权限不足->需要管理员权限（请以管理员身份运行终端）")
	}

	return nil
}
