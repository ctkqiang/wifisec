// Package ap 提供宿主机直接承载克隆热点的能力适配。
//
// 宿主机路径仅 Linux 可行：hostapd 是事实标准，能在指定无线接口上
// 以 AP 模式运行并管理关联站点。其余平台由 ap_other.go 提供带精确
// 技术说明的错误桩——macOS 无公开的 AP hosting API（CoreWLAN 的
// IBSS 仅支持 WEP/开放网络）、Windows 的 hostednetwork 已被 Microsoft
// 废弃、Android 应用层禁止第三方进程承载 AP；这些平台应改走 ESP
// 协处理器路径（platformesp），克隆 AP 由板载射频承载。
//
// 事件模型：Up 成功后 StationEvents 返回客户端接入/离开事件流，
// Down 之后事件流关闭，消费端据此结束会话循环。
package ap

// StationEvent 描述一台客户端接入或离开克隆 AP。
type StationEvent struct {
	MAC    string // 客户端 MAC 地址（小写、冒号分隔）
	Joined bool   // true 接入 / false 离开
}

// KickInjector 是 deauth 帧注入器的最小契约。
// ESP 路径由 platformesp.Injector 直接满足（AP 与注入共用一块板子）；
// hostapd 路径因 AP 接口被 hostapd 独占，无法在同一接口上注入自由帧，
// 由第二块无线网卡创建 monitor 接口实现（monitorKicker）。
type KickInjector interface {
	Write(frame []byte) error
	SetChannel(channel int) error
	Close() error
}
