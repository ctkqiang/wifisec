package pmkid

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/ctkqiang/wifisec/internal/ieee80211"
	"github.com/ctkqiang/wifisec/internal/rsnie"
)

// 测试固定身份：AP 与本次攻击无关的第三方 STA。
var (
	apMAC         = net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	thirdPartyMAC = net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	broadcastMAC  = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
)

// fixturePMKID 是测试用的 16 字节 PMKID，字节递增便于断言归属。
var fixturePMKID = []byte{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
}

// chanReader 是帧读取的测试替身：预载帧排队发出，AP 应答由 fakeWriter 投递。
type chanReader struct {
	frames  chan []byte
	onEmpty func() []byte // 队列耗尽时的补充帧（模拟 AP 持续广播信标）
}

// newChanReader 预载初始帧（通常是每轮尝试一份信标）。
func newChanReader(initial ...[]byte) *chanReader {
	r := &chanReader{frames: make(chan []byte, 32)}
	for _, f := range initial {
		r.frames <- f
	}

	return r
}

// push 向接收队列追加帧（模拟 AP 对请求的响应）。
func (r *chanReader) push(frames ...[]byte) {
	for _, f := range frames {
		r.frames <- f
	}
}

// Read 非阻塞取帧：队列为空时优先走 onEmpty 补充（持续信标），
// 再无来源返回错误，客户端按"本周期无帧"处理。
func (r *chanReader) Read() ([]byte, error) {
	select {
	case f := <-r.frames:
		return f, nil
	default:
		if r.onEmpty != nil {
			return r.onEmpty(), nil
		}

		return nil, errors.New("当前无帧")
	}
}

// fakeWriter 是帧注入的测试替身：按写入帧的子类型回放预设的 AP 应答，
// 并记录全部写入帧供断言（重试换 MAC、STA 地址归属等）。
type fakeWriter struct {
	reader    *chanReader
	authResp  [][]byte // 收到认证请求后回放
	assocResp [][]byte // 收到关联请求后回放（M1 单列，紧跟其后）
	m1        []byte
	written   [][]byte
}

// Write 模拟 AP 行为：认证请求 → 回认证响应；关联请求 → 回关联响应 + M1。
func (w *fakeWriter) Write(frame []byte) error {
	w.written = append(w.written, append([]byte(nil), frame...))

	switch frame[8] >> 4 {
	case ieee80211.SubtypeAuth:
		w.reader.push(w.authResp...)
	case ieee80211.SubtypeAssocReq:
		w.reader.push(w.assocResp...)
		if w.m1 != nil {
			w.reader.push(w.m1)
		}
	}

	return nil
}

// mgmtHeader 组 24 字节管理帧 MAC 头（FC + Duration + 3 地址 + SeqCtl）。
func mgmtHeader(fc0, fc1 byte, addr1, addr2, addr3 net.HardwareAddr) []byte {
	header := make([]byte, 24)
	header[0], header[1] = fc0, fc1
	copy(header[4:10], addr1)
	copy(header[10:16], addr2)
	copy(header[16:22], addr3)

	return header
}

// rsnPayload 组一份最小合法 RSN IE 载荷：CCMP 组/成对加密 + 指定 AKM，
// pmkid 非空时附带 PMKID count=1 字段。
func rsnPayload(akm byte, pmkid []byte) []byte {
	payload := []byte{0x01, 0x00}                     // Version = 1
	payload = append(payload, 0x00, 0x0f, 0xac, 0x04) // group CCMP-128
	payload = append(payload, 0x01, 0x00)             // pairwise count = 1
	payload = append(payload, 0x00, 0x0f, 0xac, 0x04) // pairwise CCMP-128
	payload = append(payload, 0x01, 0x00)             // AKM count = 1
	payload = append(payload, 0x00, 0x0f, 0xac, akm)
	payload = append(payload, 0x0c, 0x00) // capabilities

	if pmkid != nil {
		payload = append(payload, 0x01, 0x00)
		payload = append(payload, pmkid...)
	}

	return payload
}

// rsnTLV 给 RSN IE 载荷套上 TLV 头（id 0x30 + length）。
func rsnTLV(payload []byte) []byte {
	return append([]byte{0x30, byte(len(payload))}, payload...)
}

// buildBeacon 构造信标帧：SSID IE 恒在首位（空 SSID 即隐藏网络），
// rsn 为完整 TLV（nil = 不携带）。
func buildBeacon(ssid string, rsn []byte) []byte {
	frame := mgmtHeader(0x80, 0x00, broadcastMAC, apMAC, apMAC)
	frame = append(frame, make([]byte, 12)...) // timestamp(8) + interval(2) + capability(2)
	frame = append(frame, 0x00, byte(len(ssid)))
	frame = append(frame, ssid...)
	if rsn != nil {
		frame = append(frame, rsn...)
	}

	return frame
}

// buildAuthResp 构造 AP 的认证应答（Open System、事务序号 2、指定状态码）。
func buildAuthResp(status uint16) []byte {
	frame := mgmtHeader(0xB0, 0x00, thirdPartyMAC, apMAC, apMAC)
	frame = append(frame, 0x00, 0x00, 0x02, 0x00, byte(status), byte(status>>8))

	return frame
}

// buildAssocResp 构造 AP 的关联应答（指定状态码，可携带 RSN IE TLV）。
func buildAssocResp(status uint16, rsn []byte) []byte {
	frame := mgmtHeader(0x10, 0x00, thirdPartyMAC, apMAC, apMAC)
	frame = append(frame, 0x31, 0x04, byte(status), byte(status>>8), 0x01, 0x00)
	if rsn != nil {
		frame = append(frame, rsn...)
	}

	return frame
}

// buildM1 构造 AP → STA 的 EAPOL M1 数据帧（fromDS=1），
// keyData 为 EAPOL-Key 的 Key Data 区（可携带 RSN IE TLV）。
func buildM1(keyData []byte) []byte {
	bodyLen := 95 + len(keyData)
	eapol := []byte{0x02, 0x03, byte(bodyLen >> 8), byte(bodyLen)} // version 2 + EAPOL-Key
	eapol = append(eapol, 0x02)                                    // descriptor = RSN
	eapol = append(eapol, 0x00, 0x8A)                              // keyInfo：ver2 + pairwise + ACK（M1 特征）
	eapol = append(eapol, 0x00, 0x10)                              // keyLen = 16
	eapol = append(eapol, make([]byte, 8)...)                      // replay counter
	for i := range 32 {
		eapol = append(eapol, byte(i+1)) // ANonce 非零
	}
	eapol = append(eapol, make([]byte, 16+8+8+16)...) // IV + RSC + KeyID + MIC
	eapol = append(eapol, byte(len(keyData)>>8), byte(len(keyData)))
	eapol = append(eapol, keyData...)

	frame := mgmtHeader(0x08, 0x02, thirdPartyMAC, apMAC, apMAC)
	frame = append(frame, 0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E)

	return append(frame, eapol...)
}

// buildRadiotapFrame 给帧体套上带信道与信号强度的 radiotap 头，
// 验证信道与 RSSI 的成对绑定。
func buildRadiotapFrame(channel int, rssi int8, body []byte) []byte {
	freq := uint16(2412 + (channel-1)*5)
	if channel > 14 {
		freq = uint16(5000 + channel*5)
	}

	header := []byte{
		0x00, 0x00, // version + pad
		13, 0x00, // 头长 13：固定 8 + channel 4 + signal 1
		0x28, 0x00, 0x00, 0x00, // present：bit3(channel) + bit5(signal)
		byte(freq), byte(freq >> 8), 0x00, 0x00, // 频率 + 标志
		byte(rssi),
	}

	return append(header, body...)
}

// runClient 以测试默认配置运行客户端，mutate 覆盖个别字段。
func runClient(t *testing.T, reader *chanReader, writer *fakeWriter, mutate func(*Config)) (*Result, error) {
	t.Helper()

	config := Config{
		BSSID:          apMAC.String(),
		Channel:        6,
		Reader:         reader,
		Writer:         writer,
		AttemptTimeout: 100 * time.Millisecond,
	}
	if mutate != nil {
		mutate(&config)
	}

	return NewClient(config).Run(context.Background())
}

// requireFailure 断言错误可归约为指定失败分类。
func requireFailure(t *testing.T, err error, want Failure) *Error {
	t.Helper()

	if err == nil {
		t.Fatal("期望失败，实际返回 nil 错误")
	}

	var pmkidErr *Error
	if !errors.As(err, &pmkidErr) {
		t.Fatalf("错误无法归约为 *Error：%v", err)
	}
	if pmkidErr.Failure != want {
		t.Fatalf("失败分类 = %s，期望 %s（详情：%s）", pmkidErr.Failure, want, pmkidErr.Detail)
	}

	return pmkidErr
}

func TestClientSuccessViaAssocResp(t *testing.T) {
	beacon := buildBeacon("HomeNet", rsnTLV(rsnPayload(rsnie.AKMTypePSK, nil)))
	reader := newChanReader(beacon)
	writer := &fakeWriter{
		reader:    reader,
		authResp:  [][]byte{buildAuthResp(0)},
		assocResp: [][]byte{buildAssocResp(0, rsnTLV(rsnPayload(rsnie.AKMTypePSK, fixturePMKID)))},
	}

	result, err := runClient(t, reader, writer, nil)
	if err != nil {
		t.Fatalf("关联响应路径命中失败：%v", err)
	}

	if result.PMKID != [16]byte(fixturePMKID) {
		t.Errorf("PMKID 不符：%x", result.PMKID)
	}
	if result.ESSID != "HomeNet" || !result.ESSIDKnown {
		t.Errorf("ESSID = %q（known=%v），期望 HomeNet", result.ESSID, result.ESSIDKnown)
	}
	if result.Channel != 6 {
		t.Errorf("Channel = %d，期望 6", result.Channel)
	}
	if result.MACAP != "aabbccddeeff" {
		t.Errorf("MACAP = %s，期望 aabbccddeeff", result.MACAP)
	}
	if result.Attempt != 1 {
		t.Errorf("Attempt = %d，期望首轮命中", result.Attempt)
	}
	if result.PMKIDSHA256 {
		t.Error("PMKIDSHA256 = true，普通 PSK 应为 false")
	}

	// STA 地址归属：结果中的假客户端 MAC 必须与实际发出的关联请求一致，
	// 且本地管理位置位、组播位清零。
	assocFrame := writer.written[1]
	staMAC := net.HardwareAddr(assocFrame[18:24])
	if result.MACSTA != hex.EncodeToString(staMAC) {
		t.Errorf("MACSTA = %s，与关联请求发送方 %x 不一致", result.MACSTA, staMAC)
	}
	if staMAC[0]&0x02 == 0 {
		t.Errorf("假客户端 MAC %x 未置位本地管理位", staMAC)
	}
	if staMAC[0]&0x01 != 0 {
		t.Errorf("假客户端 MAC %x 组播位未清零", staMAC)
	}
}

func TestClientSuccessViaM1KeyData(t *testing.T) {
	beacon := buildBeacon("HomeNet", rsnTLV(rsnPayload(rsnie.AKMTypePSK, nil)))
	reader := newChanReader(beacon)
	writer := &fakeWriter{
		reader:    reader,
		authResp:  [][]byte{buildAuthResp(0)},
		assocResp: [][]byte{buildAssocResp(0, nil)}, // 关联响应不带 RSN IE
		m1:        buildM1(rsnTLV(rsnPayload(rsnie.AKMTypePSK, fixturePMKID))),
	}

	result, err := runClient(t, reader, writer, nil)
	if err != nil {
		t.Fatalf("M1 key data 路径命中失败：%v", err)
	}

	if result.PMKID != [16]byte(fixturePMKID) {
		t.Errorf("PMKID 不符：%x", result.PMKID)
	}
	if result.ESSID != "HomeNet" {
		t.Errorf("ESSID = %q，期望 HomeNet", result.ESSID)
	}
}

func TestClientSuccessViaAKMPSKSHA256(t *testing.T) {
	beacon := buildBeacon("PMFNet", rsnTLV(rsnPayload(rsnie.AKMTypePSKSHA256, nil)))
	reader := newChanReader(beacon)
	writer := &fakeWriter{
		reader:    reader,
		authResp:  [][]byte{buildAuthResp(0)},
		assocResp: [][]byte{buildAssocResp(0, rsnTLV(rsnPayload(rsnie.AKMTypePSKSHA256, fixturePMKID)))},
	}

	result, err := runClient(t, reader, writer, nil)
	if err != nil {
		t.Fatalf("PSK-SHA256 路径命中失败：%v", err)
	}

	if !result.PMKIDSHA256 {
		t.Error("PMKIDSHA256 = false，AKM 00-0F-AC:6 应置位")
	}
}

func TestClientRadiotapChannelBinding(t *testing.T) {
	// 多 AP 同名场景的核心保障：信道/RSSI 来自帧自身 radiotap 而非配置值。
	beacon := buildRadiotapFrame(11, -55, buildBeacon("HomeNet", rsnTLV(rsnPayload(rsnie.AKMTypePSK, nil))))
	reader := newChanReader(beacon)
	writer := &fakeWriter{
		reader:    reader,
		authResp:  [][]byte{buildAuthResp(0)},
		assocResp: [][]byte{buildAssocResp(0, rsnTLV(rsnPayload(rsnie.AKMTypePSK, fixturePMKID)))},
	}

	result, err := runClient(t, reader, writer, nil)
	if err != nil {
		t.Fatalf("radiotap 绑定验证失败：%v", err)
	}

	if result.Channel != 11 {
		t.Errorf("Channel = %d，期望取自 radiotap 的 11 而非配置的 6", result.Channel)
	}
	if result.RSSI != -55 {
		t.Errorf("RSSI = %d，期望 -55", result.RSSI)
	}
}

func TestClientHiddenSSID(t *testing.T) {
	beacon := buildBeacon("", rsnTLV(rsnPayload(rsnie.AKMTypePSK, nil)))

	t.Run("无法恢复则判死", func(t *testing.T) {
		reader := newChanReader(beacon)
		writer := &fakeWriter{reader: reader}

		_, err := runClient(t, reader, writer, nil)
		requireFailure(t, err, FailureHiddenSSID)

		if len(writer.written) != 0 {
			t.Errorf("隐藏 SSID 应在发送任何帧之前判死，实际已写 %d 帧", len(writer.written))
		}
	})

	t.Run("用户显式指定则恢复", func(t *testing.T) {
		reader := newChanReader(beacon)
		writer := &fakeWriter{
			reader:    reader,
			authResp:  [][]byte{buildAuthResp(0)},
			assocResp: [][]byte{buildAssocResp(0, rsnTLV(rsnPayload(rsnie.AKMTypePSK, fixturePMKID)))},
		}

		result, err := runClient(t, reader, writer, func(c *Config) { c.SSID = "HiddenNet" })
		if err != nil {
			t.Fatalf("显式 SSID 恢复失败：%v", err)
		}

		if result.ESSID != "HiddenNet" || !result.ESSIDKnown {
			t.Errorf("ESSID = %q（known=%v），期望 HiddenNet", result.ESSID, result.ESSIDKnown)
		}
	})
}

func TestClientImmediateAbort(t *testing.T) {
	t.Run("无 RSN IE", func(t *testing.T) {
		reader := newChanReader(buildBeacon("OpenNet", nil))
		writer := &fakeWriter{reader: reader}

		_, err := runClient(t, reader, writer, nil)
		requireFailure(t, err, FailureNoRSNIE)

		if len(writer.written) != 0 {
			t.Errorf("能力预检失败应立即终止，实际已写 %d 帧", len(writer.written))
		}
	})

	t.Run("非 PSK（企业级）", func(t *testing.T) {
		reader := newChanReader(buildBeacon("CorpNet", rsnTLV(rsnPayload(rsnie.AKMType8021X, nil))))
		writer := &fakeWriter{reader: reader}

		_, err := runClient(t, reader, writer, nil)
		pmkidErr := requireFailure(t, err, FailureNonPSK)

		if pmkidErr.AKMSummary != "802.1X/Enterprise" {
			t.Errorf("AKMSummary = %q，期望 802.1X/Enterprise", pmkidErr.AKMSummary)
		}
		if len(writer.written) != 0 {
			t.Errorf("非 PSK 应立即终止，实际已写 %d 帧", len(writer.written))
		}
	})
}

func TestClientRetryChangesMAC(t *testing.T) {
	// 认证连续被拒（MAC 过滤场景）：每轮必须换一个随机 STA MAC。
	// onEmpty 模拟真实 AP 的持续信标广播：队列里的 AP 应答先被消费，
	// 信标只在空闲时补充，避免预载信标在 FIFO 队列里抢在应答之前。
	beacon := buildBeacon("HomeNet", rsnTLV(rsnPayload(rsnie.AKMTypePSK, nil)))
	reader := newChanReader()
	reader.onEmpty = func() []byte { return beacon }
	writer := &fakeWriter{reader: reader, authResp: [][]byte{buildAuthResp(1)}}

	_, err := runClient(t, reader, writer, func(c *Config) { c.Attempts = 2 })
	pmkidErr := requireFailure(t, err, FailureAuthReject)

	if pmkidErr.Attempt != 2 {
		t.Errorf("Attempt = %d，期望最后一轮 2", pmkidErr.Attempt)
	}
	if len(writer.written) != 2 {
		t.Fatalf("认证帧写入数 = %d，期望 2", len(writer.written))
	}

	first := net.HardwareAddr(writer.written[0][18:24])
	second := net.HardwareAddr(writer.written[1][18:24])
	if first.String() == second.String() {
		t.Errorf("重试未更换 STA MAC：%x", first)
	}
}

func TestClientFailureClassification(t *testing.T) {
	// 超时家族：失败分类由"已推进到的阶段"决定，而非笼统的超时。
	cases := []struct {
		name  string
		setup func() (*chanReader, *fakeWriter)
		want  Failure
	}{
		{"no-beacon：目标信道无信标", func() (*chanReader, *fakeWriter) {
			reader := newChanReader()

			return reader, &fakeWriter{reader: reader}
		}, FailureNoBeacon},
		{"timeout：认证通过但关联无应答", func() (*chanReader, *fakeWriter) {
			reader := newChanReader(buildBeacon("HomeNet", rsnTLV(rsnPayload(rsnie.AKMTypePSK, nil))))

			return reader, &fakeWriter{reader: reader, authResp: [][]byte{buildAuthResp(0)}}
		}, FailureTimeout},
		{"assoc-reject：关联被拒", func() (*chanReader, *fakeWriter) {
			reader := newChanReader(buildBeacon("HomeNet", rsnTLV(rsnPayload(rsnie.AKMTypePSK, nil))))

			return reader, &fakeWriter{
				reader:    reader,
				authResp:  [][]byte{buildAuthResp(0)},
				assocResp: [][]byte{buildAssocResp(12, nil)},
			}
		}, FailureAssocReject},
		{"rsn-no-pmkid：流程完整但无 PMKID", func() (*chanReader, *fakeWriter) {
			reader := newChanReader(buildBeacon("HomeNet", rsnTLV(rsnPayload(rsnie.AKMTypePSK, nil))))

			return reader, &fakeWriter{
				reader:    reader,
				authResp:  [][]byte{buildAuthResp(0)},
				assocResp: [][]byte{buildAssocResp(0, nil)},
				m1:        buildM1(nil), // M1 无 key data RSN IE
			}
		}, FailureRSNNoPMKID},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reader, writer := c.setup()
			_, err := runClient(t, reader, writer, func(cfg *Config) { cfg.Attempts = 1 })
			requireFailure(t, err, c.want)
		})
	}
}

func TestClientContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	reader := newChanReader(buildBeacon("HomeNet", rsnTLV(rsnPayload(rsnie.AKMTypePSK, nil))))
	writer := &fakeWriter{reader: reader}

	config := Config{
		BSSID:          apMAC.String(),
		Channel:        6,
		Reader:         reader,
		Writer:         writer,
		AttemptTimeout: time.Second,
	}

	if _, err := NewClient(config).Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("ctx 取消应上抛 context.Canceled，实际：%v", err)
	}
}
