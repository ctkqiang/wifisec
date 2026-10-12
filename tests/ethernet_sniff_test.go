package tests

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"

	"github.com/ctkqiang/wifisec/internal/ethernet"
	"github.com/ctkqiang/wifisec/internal/mitm"
)

// sniff 测试的固定地址材料：192.168.1.1 为网关，.10 为本机，.66/.107 为目标。
var (
	sniffGatewayIP  = net.IP{192, 168, 1, 1}
	sniffSelfMAC    = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}
	sniffGatewayMAC = net.HardwareAddr{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01}
)

// recordingPort 收集 Spoofer 注入的全部帧，供字节级断言。
type recordingPort struct {
	frames [][]byte
}

func (port *recordingPort) Write(frame []byte) error {
	port.frames = append(port.frames, append([]byte(nil), frame...))

	return nil
}

func (port *recordingPort) Close() error { return nil }

// mustIPv4Frame 拼一层以太网 + IPv4 头 + 指定四层载荷；协议号由调用方给出。
func mustIPv4Frame(t *testing.T, protocol byte, l4 []byte) []byte {
	t.Helper()

	frame := make([]byte, 0, 14+20+len(l4))
	frame = append(frame, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff) // 广播 dst
	frame = append(frame, sniffSelfMAC...)                    // src
	frame = append(frame, 0x08, 0x00)                         // IPv4

	ip := make([]byte, 20)
	ip[0] = 0x45 // 版本 4 + IHL 5
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(l4)))
	ip[8] = 64
	ip[9] = protocol
	copy(ip[12:16], net.IP{192, 168, 1, 66}.To4())
	copy(ip[16:20], sniffGatewayIP.To4())
	frame = append(frame, ip...)
	frame = append(frame, l4...)

	return frame
}

// dnsQueryUDP 构造 UDP/53 上的标准查询报文（QR=0，单问题 A 记录）。
func dnsQueryUDP(name string) []byte {
	var question bytes.Buffer
	for label := range strings.SplitSeq(name, ".") {
		question.WriteByte(byte(len(label)))
		question.WriteString(label)
	}
	question.WriteByte(0)
	question.Write([]byte{0x00, 0x01, 0x00, 0x01}) // A IN

	header := []byte{
		0x12, 0x34, // 事务 ID
		0x01, 0x00, // flags：QR=0 递归期望
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // QD=1 其余为 0
	}

	dns := append(header, question.Bytes()...)

	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], 40000)
	binary.BigEndian.PutUint16(udp[2:4], 53)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(dns)))

	return append(udp, dns...)
}

// httpRequestTCP 构造 TCP/80 上的最小 GET 请求。
func httpRequestTCP() []byte {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], 50000)
	binary.BigEndian.PutUint16(tcp[2:4], 80)
	tcp[12] = 5 << 4 // data offset = 20 字节

	return append(tcp, "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"...)
}

// tlsClientHelloTCP 构造 TCP/443 上的带 SNI 扩展的 ClientHello。
func tlsClientHelloTCP(serverName string) []byte {
	sniEntry := []byte{0x00, 0x00, 0x00} // list_length 保留位 + entry_type=host_name
	sniEntry = append(sniEntry, byte(len(serverName)>>8), byte(len(serverName)))
	sniEntry = append(sniEntry, serverName...)

	extension := []byte{0x00, 0x00} // 扩展类型 server_name(0x0000)
	extension = append(extension, byte(len(sniEntry)>>8), byte(len(sniEntry)))
	extension = append(extension, sniEntry...)

	clientHello := []byte{0x03, 0x03}                         // legacy_version TLS1.2
	clientHello = append(clientHello, make([]byte, 32)...)    // random
	clientHello = append(clientHello, 0x00)                   // session_id 长度 0
	clientHello = append(clientHello, 0x00, 0x02, 0x13, 0x01) // 单密码套件
	clientHello = append(clientHello, 0x01, 0x00)             // 压缩方法：仅 null
	clientHello = append(clientHello, byte(len(extension)>>8), byte(len(extension)))
	clientHello = append(clientHello, extension...)

	handshake := append([]byte{0x01, 0x00, byte(len(clientHello) >> 8), byte(len(clientHello))}, clientHello...)

	record := append([]byte{0x16, 0x03, 0x01, byte(len(handshake) >> 8), byte(len(handshake))}, handshake...)

	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], 50001)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	tcp[12] = 5 << 4

	return append(tcp, record...)
}

// TestBuildArpReplyFrameLayout 逐字段断言 42 字节应答帧布局。
func TestBuildArpReplyFrameLayout(t *testing.T) {
	senderIP := net.IP{192, 168, 1, 1}
	senderMAC := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01}
	targetIP := net.IP{192, 168, 1, 66}
	targetMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x66}

	frame, err := ethernet.BuildArpReply(senderIP, senderMAC, targetIP, targetMAC)
	if err != nil {
		t.Fatalf("BuildArpReply 失败：%v", err)
	}

	if len(frame) != 42 {
		t.Fatalf("帧长度 %d，期望 42", len(frame))
	}

	expectations := []struct {
		name string
		got  []byte
		want []byte
	}{
		{"以太网目的 MAC", frame[0:6], targetMAC},
		{"以太网源 MAC", frame[6:12], senderMAC},
		{"EtherType", frame[12:14], []byte{0x08, 0x06}},
		{"硬件类型", frame[14:16], []byte{0x00, 0x01}},
		{"协议类型", frame[16:18], []byte{0x08, 0x00}},
		{"硬件地址长度", frame[18:20], []byte{6, 4}},
		{"操作码（应答）", frame[20:22], []byte{0x00, 0x02}},
		{"发送方 MAC", frame[22:28], senderMAC},
		{"发送方 IP", frame[28:32], senderIP.To4()},
		{"目标 MAC", frame[32:38], targetMAC},
		{"目标 IP", frame[38:42], targetIP.To4()},
	}

	for _, item := range expectations {
		if !bytes.Equal(item.got, item.want) {
			t.Errorf("%s = %x，期望 %x", item.name, item.got, item.want)
		}
	}
}

// TestBuildArpRequestFrameLayout 验证请求帧：目标 MAC 全零、以太网层广播。
func TestBuildArpRequestFrameLayout(t *testing.T) {
	frame, err := ethernet.BuildArpRequest(net.IP{192, 168, 1, 66}, sniffSelfMAC, sniffGatewayIP)
	if err != nil {
		t.Fatalf("BuildArpRequest 失败：%v", err)
	}

	if !bytes.Equal(frame[0:6], net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) {
		t.Errorf("请求帧目的 MAC = %x，期望广播", frame[0:6])
	}

	if binary.BigEndian.Uint16(frame[20:22]) != 1 {
		t.Errorf("操作码 = %d，期望 1（请求）", binary.BigEndian.Uint16(frame[20:22]))
	}

	if !bytes.Equal(frame[32:38], make([]byte, 6)) {
		t.Errorf("请求帧目标 MAC = %x，期望全零占位", frame[32:38])
	}
}

// TestBuildArpFrameRejectsInvalidInput 覆盖构造器的防御分支。
func TestBuildArpFrameRejectsInvalidInput(t *testing.T) {
	cases := []struct {
		name      string
		senderMAC net.HardwareAddr
		senderIP  net.IP
		targetIP  net.IP
	}{
		{"发送方 MAC 过短", net.HardwareAddr{0xaa, 0xbb}, net.IP{192, 168, 1, 1}, net.IP{192, 168, 1, 2}},
		{"发送方为 IPv6", sniffSelfMAC, net.ParseIP("fd00::1"), net.IP{192, 168, 1, 2}},
		{"目标为 IPv6", sniffSelfMAC, net.IP{192, 168, 1, 1}, net.ParseIP("fd00::2")},
	}

	for _, item := range cases {
		if _, err := ethernet.BuildArpReply(item.senderIP, item.senderMAC, item.targetIP, sniffSelfMAC); err == nil {
			t.Errorf("%s：应返回错误", item.name)
		}
	}
}

// TestSummarizeWithL7Protocols 验证三种应用层协议的命中与 L7 标签。
func TestSummarizeWithL7Protocols(t *testing.T) {
	cases := []struct {
		name   string
		frame  []byte
		l7     string
		expect string
	}{
		{"DNS 查询", mustIPv4Frame(t, 17, dnsQueryUDP("router.local")), ethernet.L7DNS, "router.local"},
		{"HTTP 请求", mustIPv4Frame(t, 6, httpRequestTCP()), ethernet.L7HTTP, "Host: example.com"},
		{"TLS SNI", mustIPv4Frame(t, 6, tlsClientHelloTCP("www.example.com")), ethernet.L7SNI, "www.example.com"},
	}

	for _, item := range cases {
		summary := ethernet.SummarizeWithL7(item.frame)
		if summary.L7 != item.l7 {
			t.Errorf("%s：L7 = %q，期望 %q", item.name, summary.L7, item.l7)
		}

		if !strings.Contains(summary.Info, item.expect) {
			t.Errorf("%s：Info = %q，未包含 %q", item.name, summary.Info, item.expect)
		}
	}
}

// TestSummarizeWithL7SurvivesTruncation 对三种合法帧做逐字节截断：
// 解析器在任意截断点都只能返回短摘要，绝不 panic 或越界。
func TestSummarizeWithL7SurvivesTruncation(t *testing.T) {
	frames := [][]byte{
		mustIPv4Frame(t, 17, dnsQueryUDP("router.local")),
		mustIPv4Frame(t, 6, httpRequestTCP()),
		mustIPv4Frame(t, 6, tlsClientHelloTCP("www.example.com")),
	}

	for index, frame := range frames {
		for cut := range len(frame) + 1 {
			ethernet.SummarizeWithL7(frame[:cut]) // 返回值不关心，只验证不 panic
			_ = index
		}
	}
}

// TestSummarizeWithL7IgnoresNonL7Traffic 普通流量不应被误标注。
func TestSummarizeWithL7IgnoresNonL7Traffic(t *testing.T) {
	payload := append(make([]byte, 8), []byte{0x12, 0x34, 0x81, 0x00}...) // UDP/53 但 QR=1 是应答

	summary := ethernet.SummarizeWithL7(mustIPv4Frame(t, 17, payload))
	if summary.L7 != "" {
		t.Errorf("DNS 应答不应命中 L7=%q", summary.L7)
	}

	if summary.Proto != "UDP" {
		t.Errorf("基础摘要协议 = %q，期望 UDP", summary.Proto)
	}
}

// TestSpooferPoisonAndRestore 验证毒化/恢复双向帧的方向与地址材料：
// 毒化帧以本机 MAC 冒充双方，恢复帧用收集到的真实 MAC 说回真话。
func TestSpooferPoisonAndRestore(t *testing.T) {
	targets := []mitm.Target{
		{IP: net.IP{192, 168, 1, 66}, MAC: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x66}},
		{IP: net.IP{192, 168, 1, 107}, MAC: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x6b}},
	}

	port := &recordingPort{}
	spoofer, err := mitm.NewSpoofer(port, sniffSelfMAC, sniffGatewayIP, sniffGatewayMAC, targets)
	if err != nil {
		t.Fatalf("NewSpoofer 失败：%v", err)
	}

	spoofer.Start()

	// 立即 Stop：毒化只有 Start 的首轮，ticker 尚未触发。
	spoofer.Stop()

	// 2 目标 × 2 方向毒化 + 2 目标 × 2 方向 × 5 轮恢复 = 24 帧。
	if got := len(port.frames); got != 24 {
		t.Fatalf("注入帧数 %d，期望 24", got)
	}

	// 前 4 帧是毒化：sender MAC 全部冒充为本机。
	for _, frame := range port.frames[:4] {
		if !bytes.Equal(frame[22:28], sniffSelfMAC) {
			t.Fatalf("毒化帧 sender MAC = %x，期望本机 MAC", frame[22:28])
		}
	}

	// 后 20 帧是恢复：sender MAC 必须是真实 MAC。
	for _, frame := range port.frames[4:] {
		senderMAC := net.HardwareAddr(frame[22:28])
		if bytes.Equal(senderMAC, sniffSelfMAC) {
			t.Fatal("恢复帧仍冒充本机 MAC，ARP 条目无法还原")
		}

		if !bytes.Equal(senderMAC, sniffGatewayMAC) && !targetsMACContains(targets, senderMAC) {
			t.Fatalf("恢复帧 sender MAC = %x，不属于任何真实地址", senderMAC)
		}
	}

	// 恢复帧必须把真实绑定写回两边：对网关恢复 target 绑定、对目标恢复网关绑定。
	restored := 0
	for _, frame := range port.frames[4:] {
		senderIP := net.IP(frame[28:32])
		if senderIP.Equal(targets[0].IP) || senderIP.Equal(targets[1].IP) || senderIP.Equal(sniffGatewayIP) {
			restored++
		}
	}

	if restored != 20 {
		t.Errorf("恢复帧中 sender IP 属于会话参与者共 %d 帧，期望 20", restored)
	}

	if got := spoofer.FramesSent(); got != 24 {
		t.Errorf("FramesSent = %d，期望 24", got)
	}
}

// targetsMACContains 判断 MAC 是否属于某个毒化目标。
func targetsMACContains(targets []mitm.Target, mac net.HardwareAddr) bool {
	for _, target := range targets {
		if bytes.Equal(target.MAC, mac) {
			return true
		}
	}

	return false
}

// TestSpooferObserveAnswersArpRequest 目标 who-has 网关时立即补双向毒化；
// 陌生主机的请求不响应。
func TestSpooferObserveAnswersArpRequest(t *testing.T) {
	target := mitm.Target{IP: net.IP{192, 168, 1, 66}, MAC: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x66}}

	port := &recordingPort{}
	spoofer, err := mitm.NewSpoofer(port, sniffSelfMAC, sniffGatewayIP, sniffGatewayMAC, []mitm.Target{target})
	if err != nil {
		t.Fatalf("NewSpoofer 失败：%v", err)
	}

	spoofer.Start()
	base := len(port.frames)

	// 目标发起「who-has 网关」：应答 2 帧（告诉目标网关在我这、告诉网关目标在我这）。
	request, err := ethernet.BuildArpRequest(target.IP, target.MAC, sniffGatewayIP)
	if err != nil {
		t.Fatalf("构造请求帧失败：%v", err)
	}

	spoofer.Observe(request)

	if got := len(port.frames) - base; got != 2 {
		t.Fatalf("Observe 应答帧数 %d，期望 2", got)
	}

	toTarget := port.frames[len(port.frames)-2]
	toGateway := port.frames[len(port.frames)-1]

	if !bytes.Equal(toTarget[0:6], target.MAC) || !bytes.Equal(toTarget[22:28], sniffSelfMAC) {
		t.Errorf("对目标的应答帧 dst=%x sender=%x，期望 dst=%x sender=本机", toTarget[0:6], toTarget[22:28], target.MAC)
	}

	if !bytes.Equal(toGateway[0:6], sniffGatewayMAC) || !bytes.Equal(toGateway[28:32], target.IP.To4()) {
		t.Errorf("对网关的应答帧 dst=%x senderIP=%x，期望 dst=网关 senderIP=目标", toGateway[0:6], toGateway[28:32])
	}

	// 陌生主机发问不应触发应答。
	stranger := net.IP{192, 168, 1, 200}
	alien, err := ethernet.BuildArpRequest(stranger, net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0xc8}, sniffGatewayIP)
	if err != nil {
		t.Fatalf("构造陌生请求帧失败：%v", err)
	}

	spoofer.Observe(alien)

	if got := len(port.frames) - base - 2; got != 0 {
		t.Errorf("陌生主机的请求触发了 %d 帧，期望 0", got)
	}

	spoofer.Stop()
}

// TestNewSpooferRejectsBadMaterials 构造期拦截非法地址材料。
func TestNewSpooferRejectsBadMaterials(t *testing.T) {
	target := mitm.Target{IP: net.IP{192, 168, 1, 66}, MAC: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x66}}

	cases := []struct {
		name       string
		selfMAC    net.HardwareAddr
		gatewayIP  net.IP
		gatewayMAC net.HardwareAddr
		targets    []mitm.Target
	}{
		{"本机 MAC 过短", net.HardwareAddr{0x02}, sniffGatewayIP, sniffGatewayMAC, []mitm.Target{target}},
		{"网关 MAC 过短", sniffSelfMAC, sniffGatewayIP, net.HardwareAddr{0xaa}, []mitm.Target{target}},
		{"网关为 IPv6", sniffSelfMAC, net.ParseIP("fd00::1"), sniffGatewayMAC, []mitm.Target{target}},
		{"目标列表为空", sniffSelfMAC, sniffGatewayIP, sniffGatewayMAC, nil},
		{"目标 MAC 过短", sniffSelfMAC, sniffGatewayIP, sniffGatewayMAC,
			[]mitm.Target{{IP: target.IP, MAC: net.HardwareAddr{0x02, 0x00}}}},
	}

	for _, item := range cases {
		if _, err := mitm.NewSpoofer(&recordingPort{}, item.selfMAC, item.gatewayIP, item.gatewayMAC, item.targets); err == nil {
			t.Errorf("%s：应返回错误", item.name)
		}
	}
}
