// cred.go 从明文 HTTP 请求里抽取凭据：Basic Auth、Cookie、表单口令。
// 嗅探阶段不会做 TLS 解密，目标只覆盖端口 80 上仍在跑明文的服务
// （老旧路由器后台、家庭网关、内部 OA）。命中即返回 Credential，
// 调用方决定是打印告警还是落盘取证；本文件不写日志，避免凭据外泄。
package ethernet

import (
	"bytes"
	"encoding/base64"
	"net/url"
	"strings"
)

// credentialCookieCap 限制 Cookie 字段保留长度，避免巨型 Set-Cookie 反向塞满摘要。
const credentialCookieCap = 64

// formUserFields / formPassFields / formTokenFields 是表单字段名集合；
// 大小写敏感匹配——表单名罕用驼峰，多半是 user/pass 这种小写习惯。
var (
	formUserFields  = []string{"user", "username", "login", "account", "email"}
	formPassFields  = []string{"pass", "password", "passwd", "pwd"}
	formTokenFields = []string{"token"}
)

// Credential 是一次抽取出来的凭据；按 Type 区分来源，其余字段按需填充。
type Credential struct {
	Type   string // "basic" / "cookie" / "form"
	User   string
	Pass   string
	Cookie string
}

// ParseCredential 从 HTTP 请求字节流里识别凭据；命中返回对应 Credential 与 true。
// 优先级 basic → cookie → form：basic 命中即返回，避免被后段 cookie 拖慢。
func ParseCredential(payload []byte) (Credential, bool) {
	if cred, ok := parseBasicAuth(payload); ok {
		return cred, true
	}

	if cred, ok := parseCookieHeader(payload); ok {
		return cred, true
	}

	if cred, ok := parseFormBody(payload); ok {
		return cred, true
	}

	return Credential{}, false
}

// parseBasicAuth 大小写不敏感地查找 Authorization: Basic 头，解码 base64 后按首个冒号拆分。
// 头里没有冒号的畸形值一律放弃，宁可丢一条也不要误报。
func parseBasicAuth(payload []byte) (Credential, bool) {
	lower := bytes.ToLower(payload)
	index := bytes.Index(lower, []byte("\r\nauthorization: basic "))
	if index < 0 {
		return Credential{}, false
	}

	rest := payload[index+len("\r\nauthorization: basic "):]
	end := bytes.IndexAny(rest, "\r\n")
	if end < 0 {
		end = len(rest)
	}

	encoded := strings.TrimSpace(string(rest[:end]))
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return Credential{}, false
	}

	colon := bytes.IndexByte(decoded, ':')
	if colon < 0 {
		return Credential{}, false
	}

	return Credential{
		Type: "basic",
		User: string(decoded[:colon]),
		Pass: string(decoded[colon+1:]),
	}, true
}

// parseCookieHeader 抓取 Cookie 头原值并截断到 credentialCookieCap；
// Cookie 是凭据但不区分用户口令，统一落到 Cookie 字段。
func parseCookieHeader(payload []byte) (Credential, bool) {
	lower := bytes.ToLower(payload)
	index := bytes.Index(lower, []byte("\r\ncookie:"))
	if index < 0 {
		return Credential{}, false
	}

	rest := payload[index+len("\r\ncookie:"):]
	end := bytes.IndexAny(rest, "\r\n")
	if end < 0 {
		end = len(rest)
	}

	value := strings.TrimSpace(string(rest[:end]))
	if value == "" {
		return Credential{}, false
	}

	if len(value) > credentialCookieCap {
		value = value[:credentialCookieCap]
	}

	return Credential{Type: "cookie", Cookie: value}, true
}

// parseFormBody 在 POST + application/x-www-form-urlencoded 的前提下扫表单字段。
// 表单体通常是 `\r\n\r\n` 之后的载荷；找不到分隔符时退回扫描整个 payload，
// 抓包截断导致缺头时仍有机会漏到末尾的字段。
func parseFormBody(payload []byte) (Credential, bool) {
	if len(payload) == 0 || !bytes.HasPrefix(payload, []byte("POST ")) {
		return Credential{}, false
	}

	if !bytes.Contains(bytes.ToLower(payload), []byte("application/x-www-form-urlencoded")) {
		return Credential{}, false
	}

	body := payload
	if sep := bytes.Index(payload, []byte("\r\n\r\n")); sep >= 0 {
		body = payload[sep+len("\r\n\r\n"):]
	}

	cred := Credential{Type: "form"}
	for pair := range strings.SplitSeq(string(body), "&") {
		equal := strings.IndexByte(pair, '=')
		if equal < 0 {
			continue
		}

		name := pair[:equal]
		rawValue := pair[equal+1:]
		if name == "" || rawValue == "" {
			continue
		}

		value, err := url.QueryUnescape(rawValue)
		if err != nil {
			continue
		}

		assignFormField(&cred, name, value)
	}

	if cred.User == "" && cred.Pass == "" {
		return Credential{}, false
	}

	return cred, true
}

// assignFormField 按字段名归类填进 User / Pass：用户名族先填 User，
// 口令族填 Pass，token 作为兜底只在没有显式用户名时落到 User。
func assignFormField(cred *Credential, name, value string) {
	switch {
	case contains(formUserFields, name):
		if cred.User == "" {
			cred.User = value
		}
	case contains(formPassFields, name):
		if cred.Pass == "" {
			cred.Pass = value
		}
	case contains(formTokenFields, name):
		if cred.User == "" {
			cred.User = value
		}
	}
}

// contains 是为 form 字段名小集合写的最小线性查找；集合只有 4-5 个元素，
// 走 sort.Search 或 map 反而让读者多一层心智负担。
func contains(haystack []string, needle string) bool {
	for _, item := range haystack {
		if item == needle {
			return true
		}
	}

	return false
}
