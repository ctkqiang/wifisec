// host.go 维护一张「IP → 主机画像」表，把 ARP/IPv4 摘要里零散出现的
// (IP, MAC) 对收敛成单一来源，供嗅探控制台、网关识别与厂商聚合共用。
// 不做活性探测——所有时间戳都来自被动观察到的帧；Preload 用于会话开始时
// 把系统 ARP 表灌进来当冷启动底图，避免「明明有设备却报新发现」。
package ethernet

import (
	"bytes"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/ctkqiang/wifisec/internal/platform/lan"
)

// Host 是单台主机在嗅探期间累积的画像；MAC/Vendor 在首帧到来时填一次，
// 后续只更新时间戳与事件计数，避免每帧都跑 LookupVendor。
type Host struct {
	IP        net.IP
	MAC       net.HardwareAddr
	Vendor    string
	FirstSeen time.Time
	LastSeen  time.Time
	Events    int
	Role      string // "gateway" / "self" / ""
}

// HostTracker 是并发安全的主机索引；self/gateway 在构造期固定，
// 之后只读，避免角色判断在每次 Observe 都重算一次。
type HostTracker struct {
	mu      sync.Mutex
	hosts   map[string]*Host
	self    net.IP
	gateway net.IP
}

// NewHostTracker 初始化一张空表；self 与 gateway 仅用于 Role 标注，
// 任一为空都允许，调用方自己负责后续 Observe 时把它们补齐。
func NewHostTracker(self, gateway net.IP) *HostTracker {
	return &HostTracker{
		hosts:   make(map[string]*Host),
		self:    self.To4(),
		gateway: gateway.To4(),
	}
}

// Observe 注册一次 (IP, MAC) 观测；首次出现时返回 isNew=true。
// 已有主机只刷 LastSeen 与事件计数，MAC 缺失时才补——抓到 ARP 之前先抓到 IP 帧的情况。
func (t *HostTracker) Observe(ip net.IP, mac net.HardwareAddr) (Host, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	key := ipKey(ip)
	if key == "" {
		return Host{}, false
	}

	now := time.Now()
	if existing, ok := t.hosts[key]; ok {
		existing.LastSeen = now
		existing.Events++
		if len(existing.MAC) == 0 && len(mac) == 6 {
			existing.MAC = mac
			existing.Vendor = LookupVendor(mac)
		}

		return *existing, false
	}

	host := &Host{
		IP:        ip.To4(),
		MAC:       mac,
		Vendor:    LookupVendor(mac),
		FirstSeen: now,
		LastSeen:  now,
		Events:    1,
		Role:      t.roleFor(ip),
	}
	t.hosts[key] = host

	return *host, true
}

// Seen 累加事件计数；只更新时间戳与计数，不补 MAC，调用方应已经 Observe 过。
func (t *HostTracker) Seen(ip net.IP) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if host, ok := t.hosts[ipKey(ip)]; ok {
		host.Events++
		host.LastSeen = time.Now()
	}
}

// Snapshot 返回按 IP 升序排列的主机列表；用于控制台一次性渲染。
// 返回值是值拷贝，调用方修改不会回灌到表里。
func (t *HostTracker) Snapshot() []Host {
	t.mu.Lock()
	defer t.mu.Unlock()

	snapshot := make([]Host, 0, len(t.hosts))
	for _, host := range t.hosts {
		snapshot = append(snapshot, *host)
	}

	slices.SortFunc(snapshot, func(a, b Host) int {
		return bytes.Compare(a.IP, b.IP)
	})

	return snapshot
}

// Preload 把系统 ARP 邻居表灌入主机索引；已存在的条目跳过，避免覆盖实测时间戳。
// 不触发"新发现"事件——这些条目来自系统 ARP 缓存，是会话冷启动的底图而非新鲜观测。
func (t *HostTracker) Preload(neighbors []lan.Neighbor) {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	for _, neighbor := range neighbors {
		key := ipKey(neighbor.IP)
		if key == "" {
			continue
		}

		if _, ok := t.hosts[key]; ok {
			continue
		}

		t.hosts[key] = &Host{
			IP:        neighbor.IP.To4(),
			MAC:       neighbor.HWAddr,
			Vendor:    LookupVendor(neighbor.HWAddr),
			FirstSeen: now,
			LastSeen:  now,
			Events:    0,
			Role:      t.roleFor(neighbor.IP),
		}
	}
}

// roleFor 用构造期固化的 self/gateway 判定角色；两者都未配置时返回空串。
func (t *HostTracker) roleFor(ip net.IP) string {
	ip4 := ip.To4()
	if ip4 == nil {
		return ""
	}

	switch {
	case t.gateway != nil && ip4.Equal(t.gateway):
		return "gateway"
	case t.self != nil && ip4.Equal(t.self):
		return "self"
	}

	return ""
}

// ipKey 用 IPv4 字符串做 map 键；IPv4 在家用网络里是常态，IPv6 走 To4 后回落到完整字节串。
func ipKey(ip net.IP) string {
	if ip == nil {
		return ""
	}

	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}

	return ip.String()
}
