package functions

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/ctkqiang/wifisec/internal/constants"
	"github.com/ctkqiang/wifisec/internal/utilities"
)

const (
	// upgradeAPI 查询最新 Release 元数据（tag 与产物清单）。
	upgradeAPI = "https://api.github.com/repos/ctkqiang/wifisec/releases/latest"

	// upgradeHTTPTimeout 覆盖 API 查询与二进制下载两个请求；
	// Release 产物走 GitHub CDN，国内网络偶发慢速，15 秒是可用性与耐心的折中。
	upgradeHTTPTimeout = 15 * time.Second
)

// githubRelease 是 Releases API 响应的最小子集，只取升级所需的字段。
type githubRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

// SelfUpgrade 从 GitHub Releases 拉取最新版本并原地替换当前二进制。
// 用法：wifisec upgrade
//
// 替换策略：先落盘 <exe>.new 再两次 rename——rename 在同目录下是原子的，
// 中途断电/中断不会留下半个二进制。旧版本改名 .old 暂存，
// Windows 不允许删除运行中的映像，.old 删除失败属预期，下次升级时清掉。
func SelfUpgrade(args []string) error {
	current := constants.EffectiveVersion()
	utilities.Info("当前版本：%s，查询最新 Release…", current)

	rel, err := fetchLatestRelease()
	if err != nil {
		return err
	}

	if rel.TagName == current {
		utilities.Info("已是最新版本（%s），无需升级", current)
		return nil
	}
	utilities.Info("发现新版本：%s → %s", current, rel.TagName)

	assetName, err := assetNameForPlatform()
	if err != nil {
		return err
	}

	assetURL := ""
	for _, a := range rel.Assets {
		if a.Name == assetName {
			assetURL = a.URL
			break
		}
	}
	if assetURL == "" {
		return fmt.Errorf("Release %s 中未找到本平台的产物 %s", rel.TagName, assetName)
	}

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("定位当前可执行文件失败：%w", err)
	}
	// go install 产物是真实文件，但 Homebrew 等方式可能经符号链接引用；
	// 替换必须落在真实路径上，否则只会换掉链接本身。
	if resolved, rerr := filepath.EvalSymlinks(exePath); rerr == nil {
		exePath = resolved
	}

	utilities.Info("下载 %s…", assetName)
	tmpFile, err := downloadToTemp(assetURL)
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile)

	if filepath.Ext(assetName) == ".zip" {
		extracted, err := extractMacAppBinary(tmpFile)
		if err != nil {
			return err
		}
		defer os.Remove(extracted)
		tmpFile = extracted
	}

	if err := os.Chmod(tmpFile, 0o755); err != nil {
		return fmt.Errorf("设置可执行权限失败：%w", err)
	}

	if err := replaceExecutable(exePath, tmpFile); err != nil {
		return err
	}

	utilities.Info("升级完成：%s → %s，重新运行任意命令即生效", current, rel.TagName)
	return nil
}

// fetchLatestRelease 拉取最新 Release 的 tag 与产物清单。
func fetchLatestRelease() (*githubRelease, error) {
	client := &http.Client{Timeout: upgradeHTTPTimeout}

	req, err := http.NewRequest(http.MethodGet, upgradeAPI, nil)
	if err != nil {
		return nil, err
	}
	// GitHub 要求显式声明 API 版本协商头，缺省也工作但行为不保证稳定。
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("查询最新版本失败（检查网络/代理）：%w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("查询最新版本失败：GitHub API 返回 %s", resp.Status)
	}

	var rel githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("解析 Release 信息失败：%w", err)
	}
	if rel.TagName == "" {
		return nil, errors.New("仓库尚未发布任何 Release")
	}
	return &rel, nil
}

// assetNameForPlatform 把 GOOS/GOARCH 映射到 Release 产物文件名。
// 产物命名与 CI release 步骤一一对应，新增平台时两边必须同步。
func assetNameForPlatform() (string, error) {
	switch {
	case runtime.GOOS == "darwin":
		return "wifisec-macos-app.zip", nil
	case runtime.GOOS == "linux" && runtime.GOARCH == "amd64":
		return "wifisec-linux-amd64", nil
	case runtime.GOOS == "linux" && runtime.GOARCH == "arm64":
		return "wifisec-linux-arm64", nil
	case runtime.GOOS == "android" && runtime.GOARCH == "arm64":
		return "wifisec-android-arm64", nil
	case runtime.GOOS == "windows" && runtime.GOARCH == "amd64":
		return "wifisec-windows-amd64.exe", nil
	}
	return "", fmt.Errorf("平台 %s/%s 无预编译产物，请到 Releases 页手动下载或 go install 升级",
		runtime.GOOS, runtime.GOARCH)
}

// downloadToTemp 下载产物到系统临时目录，返回文件路径。
func downloadToTemp(url string) (string, error) {
	client := &http.Client{Timeout: upgradeHTTPTimeout}

	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("下载失败：%w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("下载失败：HTTP %s", resp.Status)
	}

	f, err := os.CreateTemp("", "wifisec-upgrade-*")
	if err != nil {
		return "", err
	}
	defer f.Close()

	if _, err := io.Copy(f, resp.Body); err != nil {
		os.Remove(f.Name())
		return "", fmt.Errorf("写入临时文件失败：%w", err)
	}
	return f.Name(), nil
}

// extractMacAppBinary 从 macOS 的 .app zip 中取出真正的可执行文件。
// macOS 产物是 bundle 而非裸二进制：升级的是 ~/go/bin/wifisec 这类 CLI 安装，
// 只需 bundle 内的 Mach-O，不需要 Info.plist 与目录结构。
func extractMacAppBinary(zipPath string) (string, error) {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return "", fmt.Errorf("解压 macOS 产物失败：%w", err)
	}
	defer r.Close()

	const want = "wifisec.app/Contents/MacOS/wifisec"
	for _, f := range r.File {
		if f.Name != want {
			continue
		}
		src, err := f.Open()
		if err != nil {
			return "", err
		}
		defer src.Close()

		out, err := os.CreateTemp("", "wifisec-upgrade-bin-*")
		if err != nil {
			return "", err
		}
		if _, err := io.Copy(out, src); err != nil {
			out.Close()
			os.Remove(out.Name())
			return "", err
		}
		out.Close()
		return out.Name(), nil
	}
	return "", fmt.Errorf("macOS 产物中缺少 %s", want)
}

// replaceExecutable 用 newBin 原子替换 exePath。
// 旧版本改名 .old 而非直接删除：Windows 锁定运行中映像的删除与覆盖，
// 但允许同目录 rename；.old 清理由下次升级或用户手动完成。
func replaceExecutable(exePath, newBin string) error {
	oldPath := exePath + ".old"
	newPath := exePath + ".new"

	os.Remove(oldPath)

	if err := copyFile(newBin, newPath); err != nil {
		return fmt.Errorf("写入新版二进制失败：%w", err)
	}
	if err := os.Chmod(newPath, 0o755); err != nil {
		os.Remove(newPath)
		return err
	}

	if err := os.Rename(exePath, oldPath); err != nil {
		os.Remove(newPath)
		return fmt.Errorf("备份当前版本失败（权限不足或被占用）：%w", err)
	}
	if err := os.Rename(newPath, exePath); err != nil {
		os.Rename(oldPath, exePath) // 回滚，尽力恢复原状
		return fmt.Errorf("替换二进制失败：%w", err)
	}

	os.Remove(oldPath)
	return nil
}

// copyFile 跨设备复制文件内容（临时目录与 exePath 可能不在同一文件系统，
// 不能直接 rename）。
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
