package functions

import (
	"strings"

	"github.com/ctkqiang/wifisec/internal/constants"
	"github.com/ctkqiang/wifisec/internal/utilities"
)

// helpUsageLines 汇总全部子命令的用法说明，与 cmd/wifisec/main.go 的
// commandHandlers 一一对应：新增子命令时必须同步补充对应行，
// 否则用户只能翻源码才知道怎么传参。
// 文本整块经一次 Info 输出，避免逐行 printf 打散日志前缀。
var helpUsageLines = []string{
	constants.DeveloperMetadata.String(),
	"",
	"用法: wifisec <命令> [参数]",
	"",
	"命令:",
	"  list                        列出本机无线接口与周边网络",
	"  serial                      列出 USB 串口设备（确认协处理器端口与 VID:PID）",
	"  deauth <ssid|bssid> [串口]  对目标持续发送 deauth 帧，Ctrl-C 停止并输出统计",
	"  brute <ssid|bssid> with-pass: <字典> [串口]  在线密码字典爆破，命中即停",
	"  help                        显示本帮助",
	"",
	"示例:",
	"  wifisec list",
	"  wifisec serial",
	"  wifisec deauth 'MyWiFi'                # 按 SSID，同名多 AP 全部命中",
	"  wifisec deauth 01:23:45:67:89:ab       # 按 BSSID 精确锁定",
	"  wifisec deauth 01:23:45:67:89:ab /dev/cu.usbserial-XXXX   # 手动指定串口",
	"  wifisec brute 'MyWiFi' with-pass: pass.txt               # 按 SSID 爆破",
	"  wifisec brute 01:23:45:67:89:ab pass.txt /dev/cu.usbserial-XXXX  # 按 BSSID，指定串口",
	"",
	"串口缺省时自动探测唯一 USB 串口；烧录与排错见 docs/feature/wifi_deauth.md。",
}

// HelpUsage 输出开发者信息与全部子命令的用法。
func HelpUsage(arguements []string) error {
	utilities.Info("%s", strings.Join(helpUsageLines, "\n"))

	return nil
}
