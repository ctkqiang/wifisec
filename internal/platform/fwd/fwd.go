// Package fwd 是「临时打开内核 IP 转发并压制 ICMP 重定向」的跨平台端口。
//
// ARP 欺骗把目标的流量引到本机后，必须打开转发才能把包继续送往真实
// 网关，否则欺骗退化成断网攻击；同时网关与本机同处一个二层网段，
// 内核转发时会向目标发 ICMP Redirect「教」它直连网关，ARP 毒化随即
// 失效——所以转发与重定向压制必须成对开启、成对恢复。
//
// Enable 读取并保存所有受影响开关的旧值后置为新值，返回 Token；
// Disable 按旧值原样恢复。进程被 kill -9 时无法恢复，这是本模块
// 无法弥补的边界，文档中必须明示。
package fwd

import "errors"

// ErrSpoofUnsupported 表示该平台无法完成透明转发，ARP 欺骗拒绝执行。
// Windows 的 IPEnableRouter 需要注册表改动加服务重启，无法做到
// 「随时开、退出即恢复」，按项目平台限制惯例给出精确原因而非硬来。
var ErrSpoofUnsupported = errors.New(
	"ARP 欺骗在 Windows 上不可用：IPEnableRouter 需注册表改动与服务重启，" +
		"无法做到退出即恢复透明转发；被动嗅探不受影响",
)

// Token 持有 Enable 期间读出的全部旧值，是 Disable 的恢复依据。
// 平台实现各自定义字段，应用层不感知细节。
type Token struct {
	inner any
}

// Enable 打开 IP 转发并压制 ICMP 重定向，返回恢复令牌。
func Enable(ifaceName string) (*Token, error) {
	inner, err := enable(ifaceName)
	if err != nil {
		return nil, err
	}

	return &Token{inner: inner}, nil
}

// Disable 按 Token 里的旧值恢复全部开关，幂等。
func Disable(token *Token) error {
	if token == nil || token.inner == nil {
		return nil
	}

	return disable(token.inner)
}
