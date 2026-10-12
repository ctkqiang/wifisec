//go:build linux || android

package writer

import (
	platformlinux "github.com/ctkqiang/wifisec/internal/platform/linux"
)

// open 在指定网卡上打开 AF_PACKET 原始套接字。
// linux.OpenInjector 本就以「接口名」为参数、发送原始以太网帧，
// 对 managed 网卡（连接态 Wi-Fi / 有线）同样适用，直接复用。
func open(ifaceName string) (Port, error) {
	return platformlinux.OpenInjector(ifaceName)
}
