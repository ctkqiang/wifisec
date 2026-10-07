//go:build darwin

package darwin

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	// BootstrapFlag 是授权/扫描 helper 实例的内部参数：经 open 激活的
	// .app 实例负责与系统交互（弹窗、扫描），不执行终端渲染。
	BootstrapFlag = "--wifisec-location-bootstrap"

	// scanOutFlag 把 helper 结果文件路径传给 helper 实例。
	// LaunchServices 不继承终端环境变量与文件描述符，故结果只能经文件回传。
	scanOutFlag = "--wifisec-scan-out"
)

// helperPromptTimeout 是 helper 实例等待用户在系统弹窗中选择的最长时间。
const helperPromptTimeout = 120 * time.Second

// helperResult 是 helper 实例写回终端实例的结果文件结构。
type helperResult struct {
	Status   AuthorizationStatus `json:"status"`
	Networks []Network           `json:"networks"`
}

// HandleBootstrap 在进程由 LaunchServices 以 helper 模式拉起时接管进程：
// 完成定位授权（首次会弹系统窗）与 CoreWLAN 扫描，把结果原子写入
// --wifisec-scan-out 指定的文件后退出。
// 返回 true 表示当前进程即 helper 实例，调用方必须立即结束进程。
func HandleBootstrap() bool {
	var outputPath string

	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		if args[i] == BootstrapFlag {
			// 标记存在即可，路径在其后一个参数中。
			continue
		}

		if args[i] == scanOutFlag && i+1 < len(args) {
			outputPath = args[i+1]
			i++
		}
	}

	if !hasBootstrapFlag() || outputPath == "" {
		return false
	}

	status := RequestLocationAuthorization(helperPromptTimeout)
	result := helperResult{Status: status}

	if status.Authorized() {
		// 已授权（含本轮弹窗刚授予）时扫描才会返回真实 BSSID；
		// 失败时保持空列表，终端侧据此输出降级提示。
		if networks, err := ScanNetworks(); err == nil {
			result.Networks = networks
		}
	}

	writeHelperResult(outputPath, result)
	return true
}

// hasBootstrapFlag 仅判断当前进程是否为 helper 实例，
// 与参数提取拆开以避免一次遍历里同时处理两种语义。
func hasBootstrapFlag() bool {
	for _, arg := range os.Args[1:] {
		if arg == BootstrapFlag {
			return true
		}
	}

	return false
}

// writeHelperResult 以 0600 权限、临时文件 + rename 的方式原子落盘，
// 终端轮询到文件时内容必然完整，不会读到半截 JSON。
func writeHelperResult(outputPath string, result helperResult) {
	payload, err := json.Marshal(result)
	if err != nil {
		return
	}

	// 目录由终端实例创建（0700）；此处失败说明路径不可信，直接放弃回传。
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o700); err != nil {
		return
	}

	temporaryPath := outputPath + ".tmp"
	if err := os.WriteFile(temporaryPath, payload, 0o600); err != nil {
		return
	}

	_ = os.Rename(temporaryPath, outputPath)
}

// ScanViaHelper 经 LaunchServices 唤起 .app helper 实例完成授权与扫描，
// 等待并回收其结果文件。终端内进程的 TCC 责任进程归属终端宿主，
// 无法直接获得定位授权与未脱敏 BSSID，必须经由 helper 身份完成。
func ScanViaHelper(wait time.Duration) ([]Network, AuthorizationStatus, error) {
	outputPath, err := helperOutputPath()
	if err != nil {
		return nil, AuthNotDetermined, err
	}
	defer os.Remove(outputPath)

	bundlePath, err := ownBundlePath()
	if err != nil {
		return nil, AuthNotDetermined, err
	}

	// -n 强制新实例：与终端内当前实例并存，互不抢占。
	open := exec.Command("open", "-n", bundlePath, "--args",
		BootstrapFlag, scanOutFlag, outputPath)
	if err := open.Run(); err != nil {
		return nil, AuthNotDetermined, fmt.Errorf("启动定位 helper 失败：%w", err)
	}

	deadline := time.Now().Add(wait)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for range ticker.C {
		payload, err := os.ReadFile(outputPath)
		if err == nil {
			var result helperResult
			if json.Unmarshal(payload, &result) == nil {
				return result.Networks, result.Status, nil
			}
		}

		if time.Now().After(deadline) {
			return nil, AuthNotDetermined, fmt.Errorf("等待定位 helper 超时（%s）", wait)
		}
	}

	return nil, AuthNotDetermined, nil
}

// helperOutputPath 在用户缓存目录下生成本次调用专属的结果文件路径，
// 并发多次 list 互不覆盖；目录权限 0700，仅当前用户可访问。
func helperOutputPath() (string, error) {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}

	directory := filepath.Join(cacheDir, "wifisec")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", err
	}

	return filepath.Join(directory, fmt.Sprintf("scan-%d-%d.json", os.Getpid(), time.Now().UnixNano())), nil
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
