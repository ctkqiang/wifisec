//go:build darwin

package darwin

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// BootstrapFlag 是授权自举实例的内部参数：经 open 激活的 .app 实例
// 只负责触发定位弹窗并等待用户选择，不执行扫描等终端交互。
const BootstrapFlag = "--wifisec-location-bootstrap"

// bootstrapPromptTimeout 是自举实例等待用户在弹窗中选择的最长时间。
const bootstrapPromptTimeout = 120 * time.Second

// HandleBootstrap 在进程由 LaunchServices 以自举模式拉起时接管进程：
// 触发系统定位授权弹窗并等待结果，随后直接退出。
// 返回 true 表示当前进程即自举实例，调用方必须立即结束进程。
func HandleBootstrap() bool {
	isBootstrap := false

	for _, arg := range os.Args[1:] {
		if arg == BootstrapFlag {
			isBootstrap = true
			break
		}
	}

	if !isBootstrap {
		return false
	}

	RequestLocationAuthorization(bootstrapPromptTimeout)
	return true
}

// EnsureAuthorization 保证定位授权在终端调用场景下可被授予。
//
// 裸 CLI 在终端内请求定位时，TCC 的责任进程是终端宿主（系统终端 / IDE），
// 宿主通常未声明 NSLocation 用途，系统因此静默丢弃弹窗请求。
// 解决办法是把自己以 .app 形态经 LaunchServices 再激活一次：
// 该实例的责任进程是应用自身，弹窗得以呈现；授权按签名身份落账后，
// 终端内继续运行的同一二进制即可读到 BSSID。
//
// 返回最终授权状态；无法自举（go run、二进制脱离 bundle）时返回当前状态，
// 由上层给出手动授权指引。
func EnsureAuthorization(wait time.Duration) AuthorizationStatus {
	status := LocationStatus()
	if status != AuthNotDetermined {
		return status
	}

	bundlePath, err := ownBundlePath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[诊断] 定位 bundle 失败：%v\n", err)
		return status
	}

	// -n 强制新实例：与终端内当前实例并存，互不抢占。
	open := exec.Command("open", "-n", bundlePath, "--args", BootstrapFlag)
	if err := open.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "[诊断] open 启动失败：%v\n", err)
		return status
	}

	deadline := time.Now().Add(wait)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for range ticker.C {
		if status = LocationStatus(); status != AuthNotDetermined {
			fmt.Fprintf(os.Stderr, "[诊断] 授权状态变为 %d，结束等待\n", status)
			return status
		}

		if time.Now().After(deadline) {
			fmt.Fprintf(os.Stderr, "[诊断] 等待授权超时（%s），状态仍为未决定\n", wait)
			return status
		}
	}

	return status
}

// ownBundlePath 依据当前可执行文件路径反查所属 .app bundle 根目录。
// 通过符号链接（build/wifisec）启动时先 EvalSymlinks 解析到 bundle 内
// 二进制的真实路径，再向上截取 .app 根目录。
func ownBundlePath() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}

	// build/wifisec 是指向 bundle 内二进制的符号链接，os.Executable 在 macOS
	// 上返回符号链接自身路径，必须先解析到真实目标才能定位 .app。
	if resolved, err := filepath.EvalSymlinks(executable); err == nil {
		executable = resolved
	}

	// 期望形态：<Foo.app>/Contents/MacOS/<binary>。
	marker := ".app" + string(os.PathSeparator)
	index := strings.LastIndex(executable, marker)
	if index < 0 {
		return "", fmt.Errorf("可执行文件 %s 不在 .app bundle 内", executable)
	}

	bundlePath := executable[:index] + ".app"
	infoPlist := filepath.Join(bundlePath, "Contents", "Info.plist")
	if _, err := os.Stat(infoPlist); err != nil {
		return "", fmt.Errorf("bundle 不完整：%w", err)
	}

	return bundlePath, nil
}
