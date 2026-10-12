// l7.go 在帧摘要之上追加应用层语义：DNS 查询域名、HTTP 请求行、
// TLS SNI。定位是「控制台瞄一眼」的尽力而为解析，不做 TCP 流重组、
// 不解析 DNS 应答与跨段分片；任何一步长度越界都直接返回空串，
// 嗅探循环不能因为一个畸形包停下来。
package ethernet

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// FrameSummary 增加 L7 字段：命中应用层解析时填 "dns"/"http"/"sni"，
// 未命中为空。字段对 get_packet 的旧输出无影响（它只打印 Info）。
const (
	L7DNS  = "dns"
	L7HTTP = "http"
	L7SNI  = "sni"
)

// 常用明文/明文可观测端口：仅对「客户端→服务器」方向做请求解析。
const (
	dnsPort  = 53
	httpPort = 80
	tlsPort  = 443

	// 域名与 HTTP 首段的解析上限，防畸形包把循环拖成 O(n²)。
	maxDNSNameLength = 255
	maxHTTPPeek      = 4096
)

// SummarizeWithL7 先取基础摘要，再按端口尝试应用层解析；
// 命中时把结果追加到 Info 并回填 L7 标签。
func SummarizeWithL7(frame []byte) FrameSummary {
	summary := Summarize(frame)

	detail, kind := parseL7(frame)
	if kind == "" {
		return summary
	}

	if summary.Info != "" {
		summary.Info += " · "
	}
	summary.Info += detail
	summary.L7 = kind

	return summary
}

// parseL7 复走一次网络层/传输层头拿到端口与载荷，
// 再分派到对应协议解析器。与 fillIPv4 的偏移逻辑保持同构，
// 但不共用私有函数：展示层语义变化不应牵动帧解析主路径。
func parseL7(frame []byte) (string, string) {
	offset, etherType := decodeVLAN(frame)

	var (
		payload   []byte
		dstPort   int
		direction string
	)

	switch etherType {
	case etherTypeIPv4:
		if len(frame) < offset+20 {
			return "", ""
		}

		headerLen := int(frame[offset]&0x0f) * 4
		if headerLen < 20 || len(frame) < offset+headerLen {
			return "", ""
		}

		payload = frame[offset+headerLen:]
		if len(payload) < 4 {
			return "", ""
		}

		switch frame[offset+9] {
		case protoTCP:
			dstPort = int(binary.BigEndian.Uint16(payload[2:4]))
			direction = "tcp"
		case protoUDP:
			dstPort = int(binary.BigEndian.Uint16(payload[2:4]))
			direction = "udp"
		default:
			return "", ""
		}
	case etherTypeIPv6:
		if len(frame) < offset+40 {
			return "", ""
		}

		payload = frame[offset+40:]
		if len(payload) < 4 {
			return "", ""
		}

		switch frame[offset+6] {
		case protoTCP:
			dstPort = int(binary.BigEndian.Uint16(payload[2:4]))
			direction = "tcp"
		case protoUDP:
			dstPort = int(binary.BigEndian.Uint16(payload[2:4]))
			direction = "udp"
		default:
			return "", ""
		}
	default:
		return "", ""
	}

	// 传输层头长度：TCP 头可变（取 data offset），UDP 固定 8。
	switch direction {
	case "udp":
		if len(payload) < 8 {
			return "", ""
		}
		payload = payload[8:]
	case "tcp":
		if len(payload) < 20 {
			return "", ""
		}
		dataOffset := int(payload[12]>>4) * 4
		if dataOffset < 20 || len(payload) < dataOffset {
			return "", ""
		}
		payload = payload[dataOffset:]
	}

	switch {
	case direction == "udp" && dstPort == dnsPort:
		if name := ParseDNSQuery(payload); name != "" {
			return "dns 查询 " + name, L7DNS
		}
	case direction == "tcp" && dstPort == httpPort:
		if request := ParseHTTPRequest(payload); request != "" {
			return request, L7HTTP
		}
	case direction == "tcp" && dstPort == tlsPort:
		if name := ParseTLSSNI(payload); name != "" {
			return "SNI " + name, L7SNI
		}
	}

	return "", ""
}

// ParseDNSQuery 从 UDP DNS 查询载荷提取第一个 Question 的域名。
// 只认 QR=0 的标准查询；应答与畸形报文一律返回空。
func ParseDNSQuery(payload []byte) string {
	if len(payload) < 12 {
		return ""
	}

	flags := binary.BigEndian.Uint16(payload[2:4])
	questions := binary.BigEndian.Uint16(payload[4:6])
	if flags&0x8000 != 0 || questions == 0 {
		return ""
	}

	var (
		name    strings.Builder
		offset  = 12
		lookups = 0
	)

	for offset < len(payload) {
		lookups++
		if lookups > maxDNSNameLength {
			return ""
		}

		length := int(payload[offset])
		if length == 0 {
			break
		}

		// 标签长度 0x40/0x80 位是 EDNS/压缩前缀，查询首问不会出现。
		if length > 63 || offset+1+length > len(payload) {
			return ""
		}

		if name.Len() > 0 {
			name.WriteByte('.')
		}
		name.Write(payload[offset+1 : offset+1+length])
		offset += 1 + length
	}

	if name.Len() == 0 {
		return ""
	}

	return name.String()
}

// ParseHTTPRequest 从 TCP 载荷提取 HTTP 请求行与 Host 头。
// 只认「方法 SP 路径 SP HTTP/」形态的首段，不跨段重组；
// TLS 流量或二进制协议在首个字节就不再匹配，代价为零。
func ParseHTTPRequest(payload []byte) string {
	if len(payload) == 0 || len(payload) > maxHTTPPeek {
		return ""
	}

	head := payload
	if index := bytes.IndexAny(payload, "\r\n"); index >= 0 {
		head = payload[:index]
	}
	requestLine := string(head)

	if !looksLikeRequestLine(requestLine) {
		return ""
	}

	result := requestLine
	if host := findHTTPHost(payload); host != "" {
		result += " · Host: " + host
	}

	return result
}

// looksLikeRequestLine 校验首行是否为「METHOD SP TARGET SP HTTP/x」。
// 方法集固定，避免把任意以大写字母开头的二进制流误判成 HTTP。
func looksLikeRequestLine(line string) bool {
	methods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT "}
	for _, method := range methods {
		if strings.HasPrefix(line, method) && strings.Contains(line, " HTTP/") {
			return true
		}
	}

	return false
}

// findHTTPHost 在首段里做大小写不敏感的 Host 头查找。
func findHTTPHost(payload []byte) string {
	lower := bytes.ToLower(payload[:min(len(payload), maxHTTPPeek)])
	index := bytes.Index(lower, []byte("\r\nhost:"))
	if index < 0 {
		return ""
	}

	rest := payload[index+len("\r\nhost:"):]
	end := bytes.IndexAny(rest, "\r\n")
	if end < 0 {
		end = len(rest)
	}

	host := strings.TrimSpace(string(rest[:end]))

	return host
}

// ParseTLSSNI 从 TLS ClientHello 提取 server_name 扩展。
// 记录层(0x16)→握手层(0x01)→扩展区(0x0000) 三层逐字段前进，
// 任何一步长度不足即返回空，绝不索引越界。
func ParseTLSSNI(payload []byte) string {
	// TLS 记录头：type(1) + version(2) + length(2)。
	if len(payload) < 5 || payload[0] != 0x16 {
		return ""
	}

	handshake := payload[5:]
	// 握手头：type(1) + length(3)；ClientHello = 0x01。
	if len(handshake) < 4 || handshake[0] != 0x01 {
		return ""
	}

	// ClientHello 体：version(2) + random(32) + session_id 块 + cipher 块 + compression 块。
	body := handshake[4:]
	if len(body) < 2+32+1 {
		return ""
	}

	offset := 2 + 32
	sessionIDLength := int(body[offset])
	offset += 1 + sessionIDLength
	if len(body) < offset+2 {
		return ""
	}

	cipherLength := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2 + cipherLength
	if len(body) < offset+1 {
		return ""
	}

	compressionLength := int(body[offset])
	offset += 1 + compressionLength
	if len(body) < offset+2 {
		return ""
	}

	// 扩展区：总长(2) 后接若干 type(2)+length(2)+data。
	extensions := body[offset+2:]
	for len(extensions) >= 4 {
		extType := binary.BigEndian.Uint16(extensions[0:2])
		extLength := int(binary.BigEndian.Uint16(extensions[2:4]))
		if extLength > len(extensions)-4 {
			return ""
		}

		if extType == 0x0000 {
			return parseSNIExtension(extensions[4 : 4+extLength])
		}

		extensions = extensions[4+extLength:]
	}

	return ""
}

// parseSNIExtension 解析 server_name 扩展体：
// list_length(2) + entry_type(1)=0 + name_length(2) + name。
func parseSNIExtension(data []byte) string {
	if len(data) < 5 || data[2] != 0 {
		return ""
	}

	nameLength := int(binary.BigEndian.Uint16(data[3:5]))
	if nameLength == 0 || 5+nameLength > len(data) {
		return ""
	}

	return string(data[5 : 5+nameLength])
}
