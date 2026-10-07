package linux

import (
	"errors"
	"os/exec"
	"strings"
	"time"
)

const (
	// scanTimeout 覆盖 iw 逐信道主动探测的耗时（实测数秒到十几秒）。
	scanTimeout = 30 * time.Second

	// linkTimeout 与 infoTimeout 只是单次内核查询，保持短促。
	linkTimeout = 5 * time.Second
)

// ErrPermissionDenied 表示主动扫描被内核权限策略拦截（缺少 CAP_NET_ADMIN）。
// 上层据此给出 sudo 引导，而不是输出含糊的执行失败。
var ErrPermissionDenied = errors.New("无线扫描需要 root 权限（CAP_NET_ADMIN）")

// Scan 在指定无线接口上执行主动扫描并解析全部 BSS。
// 未安装 iw、权限不足等环境问题以带可执行建议的错误返回。
func Scan(device string) ([]Network, error) {
	if _, err := exec.LookPath("iw"); err != nil {
		return nil, errors.New("未找到 iw 命令，请先安装发行版的 iw 包（如 apt install iw）")
	}

	output, err := run(scanTimeout, "iw", "dev", device, "scan")
	if err != nil {
		detail := err.Error()
		if strings.Contains(detail, "Operation not permitted") || strings.Contains(detail, "permission denied") {
			return nil, ErrPermissionDenied
		}

		return nil, errors.New("iw 扫描失败：" + detail)
	}

	return ParseScan(output, device), nil
}

// ConnectedBSSID 查询当前关联的 AP BSSID；`iw link` 不需要 root，
// 未连接或命令不可用时返回空串，由上层静默跳过。
func ConnectedBSSID(device string) string {
	output, err := run(linkTimeout, "iw", "dev", device, "link")
	if err != nil {
		return ""
	}

	return ParseConnectedLink(output)
}

// InterfaceMode 通过 iw 查询接口工作模式（managed / monitor）；
// 未安装 iw 时返回空串。
func InterfaceMode(device string) string {
	output, err := run(linkTimeout, "iw", "dev", device, "info")
	if err != nil {
		return ""
	}

	return ParseInterfaceMode(output)
}
