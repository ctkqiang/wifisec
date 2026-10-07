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
		return status
	}

	// -n 强制新实例：与终端内当前实例并存，互不抢占。
	open := exec.Command("open", "-n", bundlePath, "--args", BootstrapFlag)
	if err := open.Start(); err != nil {
		return status
	}

	deadline := time.Now().Add(wait)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for range ticker.C {
		if status = LocationStatus(); status != AuthNotDetermined {
			return status
		}

		if time.Now().After(deadline) {
			return status
		}
	}

	return status
}

// ownBundlePath 依据当前可执行文件路径反查所属 .app bundle 根目录。
// 通过符号链接（build/wifisec）启动时，os.Executable 返回链接目标的
// 评估路径，因此两种调用方式都能定位到同一个 bundle。
func ownBundlePath() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", err
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
