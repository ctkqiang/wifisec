package eapol

import (
	"encoding/binary"
	"testing"
)

// keyInfo 组合位域的便捷构造（默认 keyver=2，HMAC-SHA1）。
func keyInfoOf(pairwise, ack, mic, secure bool) uint16 {
	info := uint16(2) // keyver 2
	if pairwise {
		info |= keyInfoPairwiseBit
	}
	if ack {
		info |= keyInfoACKBit
	}
	if mic {
		info |= keyInfoMICBit
	}
	if secure {
		info |= keyInfoSecureBit
	}

	return info
}

// buildKeyFrame 构造完整 EAPOL-Key 包体（自 version 字节起）。
func buildKeyFrame(keyInfo uint16, replay uint64, nonce, mic []byte, keyData []byte) []byte {
	payload := make([]byte, keyDataOffset+len(keyData))
	payload[0] = 2 // EAPOL version 2004
	payload[1] = eapolTypeKey
	binary.BigEndian.PutUint16(payload[2:4], uint16(len(payload)-4))
	payload[4] = 2 // RSN descriptor
	binary.BigEndian.PutUint16(payload[5:7], keyInfo)
	binary.BigEndian.PutUint16(payload[7:9], 16) // key length
	binary.BigEndian.PutUint64(payload[9:17], replay)
	copy(payload[keyNonceOffset:keyNonceOffset+32], nonce)
	copy(payload[keyMICOffset:keyMICOffset+16], mic)
	binary.BigEndian.PutUint16(payload[keyDataLenOffset:keyDataLenOffset+2], uint16(len(keyData)))
	copy(payload[keyDataOffset:], keyData)

	return payload
}

// buildEthernetFrame 组以太网帧（DLT 1）。
func buildEthernetFrame(dst, src []byte, etherType uint16, payload []byte) []byte {
	frame := make([]byte, 14+len(payload))
	copy(frame[0:6], dst)
	copy(frame[6:12], src)
	binary.BigEndian.PutUint16(frame[12:14], etherType)
	copy(frame[14:], payload)

	return frame
}

// build80211Data 组 802.11 数据帧（LLC/SNAP 封 EAPOL）。
// Frame Control 拆两字节：frame[0] = subtype<<4 | type<<2，
// frame[1] = flags（bit0 toDS / bit1 fromDS）。
func build80211Data(toDS bool, addr1, addr2, addr3 []byte, payload []byte) []byte {
	body := append([]byte{0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E}, payload...)

	frame := make([]byte, 24+len(body))
	frame[0] = 0x08 // subtype 0 | type 2（数据帧）
	if toDS {
		frame[1] = 0x01
	} else {
		frame[1] = 0x02
	}
	copy(frame[4:10], addr1)
	copy(frame[10:16], addr2)
	copy(frame[16:22], addr3)
	copy(frame[24:], body)

	return frame
}

// radiotapWrap 加一个仅含 Channel 字段的 radiotap 头。
func radiotapWrap(frame []byte, channel int) []byte {
	freq := 2412 + (channel-1)*5

	out := make([]byte, 0, 12+len(frame))
	out = append(out, 0x00, 0x00, 0x0c, 0x00, 0x08, 0x00, 0x00, 0x00)
	out = append(out, byte(freq), byte(freq>>8), 0x10, 0x01)
	out = append(out, frame...)

	return out
}

// buildBeacon 组携带 SSID 的信标帧（供 ESSID 映射学习）。
func buildBeacon(ap []byte, ssid string) []byte {
	body := make([]byte, 12)
	body[8] = 0x64 // beacon interval
	body = append(body, 0x00, byte(len(ssid)))
	body = append(body, ssid...)

	frame := make([]byte, 24+len(body))
	frame[0] = 0x80 // subtype beacon
	copy(frame[4:10], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(frame[10:16], ap)
	copy(frame[16:22], ap)
	copy(frame[24:], body)

	return frame
}

// rsnIEPayload 组带 PMKID 的 RSN IE 载荷（WPA2-PSK/CCMP）。
func rsnIEPayload(pmkid []byte) []byte {
	payload := []byte{0x01, 0x00}
	payload = append(payload, 0x00, 0x0f, 0xac, 0x04)
	payload = append(payload, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04)
	payload = append(payload, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02)
	payload = append(payload, 0x0c, 0x00)

	if pmkid != nil {
		payload = append(payload, 0x01, 0x00)
		payload = append(payload, pmkid...)
	}

	return payload
}

// buildAssocResp 组携带 RSN IE 的关联响应帧。
func buildAssocResp(ap, sta, rsnPayload []byte) []byte {
	body := make([]byte, 6) // capability + status + AID
	body = append(body, 0x30, byte(len(rsnPayload)))
	body = append(body, rsnPayload...)

	frame := make([]byte, 24+len(body))
	frame[0] = 0x10 // subtype assoc-resp
	copy(frame[4:10], sta)
	copy(frame[10:16], ap)
	copy(frame[16:22], ap)
	copy(frame[24:], body)

	return frame
}

func TestParseKeyMessageClassification(t *testing.T) {
	nonce := make([]byte, 32)
	nonce[0] = 0xAA
	zeroNonce := make([]byte, 32)
	mic := make([]byte, 16)

	cases := []struct {
		name    string
		keyInfo uint16
		nonce   []byte
		want    Message
	}{
		{"M1", keyInfoOf(true, true, false, false), nonce, MessageM1},
		{"M2", keyInfoOf(true, false, true, false), nonce, MessageM2},
		{"M3", keyInfoOf(true, false, true, true), nonce, MessageM3},
		{"M4", keyInfoOf(true, false, true, false), zeroNonce, MessageM4},
		{"组密钥握手忽略", keyInfoOf(false, true, false, false), nonce, MessageNone},
		{"ACK+MIC 按优先级归入 M2", keyInfoOf(true, true, true, false), nonce, MessageM2},
	}

	for _, c := range cases {
		frame, err := ParseKey(buildKeyFrame(c.keyInfo, 1, c.nonce, mic, nil))
		if err != nil {
			t.Fatalf("%s：解析失败 %v", c.name, err)
		}

		if got := frame.Message(); got != c.want {
			t.Errorf("%s：Message = %v，期望 %v", c.name, got, c.want)
		}
	}
}

func TestParseKeyTruncated(t *testing.T) {
	full := buildKeyFrame(keyInfoOf(true, true, false, false), 1, make([]byte, 32), make([]byte, 16), nil)
	for cut := range 99 {
		if _, err := ParseKey(full[:cut]); err == nil {
			t.Fatalf("截断至 %d 字节未报错", cut)
		}
	}
}

func TestParseKeyNonEAPOLKey(t *testing.T) {
	payload := buildKeyFrame(keyInfoOf(true, true, false, false), 1, make([]byte, 32), make([]byte, 16), nil)
	payload[1] = 0 // 非 EAPOL-Key

	if _, err := ParseKey(payload); err == nil {
		t.Fatal("Packet Type 非 3 未报错")
	}
}

func TestAnalyzerM1M2Pair(t *testing.T) {
	a := NewAnalyzer(LinkTypeEthernet)
	a.SetESSID("aa:bb:cc:dd:ee:ff", "TestNet")

	apMAC := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	staMAC := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	anonce := make([]byte, 32)
	anonce[31] = 0x01
	snonce := make([]byte, 32)
	snonce[31] = 0x02

	// M1 由 AP 发出：src=AP、dst=STA。
	m1 := buildKeyFrame(keyInfoOf(true, true, false, false), 100, anonce, make([]byte, 16), nil)
	if candidates := a.Feed(buildEthernetFrame(staMAC, apMAC, 0x888E, m1)); len(candidates) != 0 {
		t.Fatalf("M1 不应产出候选，得到 %d 条", len(candidates))
	}

	// M2 由 STA 发出：src=STA、dst=AP。
	m2 := buildKeyFrame(keyInfoOf(true, false, true, false), 100, snonce, []byte{1, 2, 3}, nil)
	candidates := a.Feed(buildEthernetFrame(apMAC, staMAC, 0x888E, m2))
	if len(candidates) != 1 {
		t.Fatalf("M1M2 应产出 1 条候选，得到 %d 条", len(candidates))
	}

	c := candidates[0]
	if c.Kind != KindEAPOL || c.MessagePair != MessagePairM1M2 {
		t.Errorf("候选形态不符：%v mp=%02x", c.Kind, c.MessagePair)
	}
	if c.MACAP != "aabbccddeeff" || c.MACSTA != "112233445566" {
		t.Errorf("角色判定错误：ap=%s sta=%s", c.MACAP, c.MACSTA)
	}
	if c.ANonce[31] != 0x01 || c.SNonce[31] != 0x02 {
		t.Error("ANONCE/SNONCE 归属错误")
	}
	if c.ESSID != "TestNet" || !c.ESSIDKnown {
		t.Errorf("ESSID 解析错误：%q known=%v", c.ESSID, c.ESSIDKnown)
	}
	if c.Channel != 0 {
		t.Errorf("以太网视角信道应为 0，得到 %d", c.Channel)
	}

	stats := a.Stats()
	if stats.EAPOLFrames != 2 || stats.M1Count != 1 || stats.M2Count != 1 || stats.Pairs != 1 {
		t.Errorf("统计不符：%+v", stats)
	}
}

func TestAnalyzerDuplicateSuppressed(t *testing.T) {
	a := NewAnalyzer(LinkTypeEthernet)

	apMAC := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	staMAC := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	anonce := make([]byte, 32)
	snonce := make([]byte, 32)
	snonce[0] = 0x99

	a.Feed(buildEthernetFrame(staMAC, apMAC, 0x888E, buildKeyFrame(keyInfoOf(true, true, false, false), 5, anonce, make([]byte, 16), nil)))

	// 首次配对应产出；随后的同帧重传（counter/MIC 相同）被去重拦截。
	m2 := buildKeyFrame(keyInfoOf(true, false, true, false), 5, snonce, []byte{9, 9}, nil)
	if candidates := a.Feed(buildEthernetFrame(apMAC, staMAC, 0x888E, m2)); len(candidates) != 1 {
		t.Fatalf("首次配对应产出 1 条，得到 %d", len(candidates))
	}

	for range 3 {
		if candidates := a.Feed(buildEthernetFrame(apMAC, staMAC, 0x888E, m2)); len(candidates) != 0 {
			t.Fatalf("重传不应重复产出候选")
		}
	}

	if a.Stats().Pairs != 1 {
		t.Errorf("Pairs = %d，期望 1（重传被去重）", a.Stats().Pairs)
	}
}

func TestAnalyzerReplayCounterMismatchRejected(t *testing.T) {
	a := NewAnalyzer(LinkTypeEthernet)

	apMAC := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	staMAC := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	snonce := make([]byte, 32)
	snonce[0] = 0x77

	a.Feed(buildEthernetFrame(staMAC, apMAC, 0x888E, buildKeyFrame(keyInfoOf(true, true, false, false), 100, make([]byte, 32), make([]byte, 16), nil)))

	// 应答 counter 100 < 请求 counter 200：乱序/跨握手错配，拒绝。
	m2 := buildKeyFrame(keyInfoOf(true, false, true, false), 50, snonce, []byte{7}, nil)
	if candidates := a.Feed(buildEthernetFrame(apMAC, staMAC, 0x888E, m2)); len(candidates) != 0 {
		t.Fatal("Replay Counter 倒退的配对应被拒绝")
	}

	// 修正 counter 后可正常配对。
	m2fixed := buildKeyFrame(keyInfoOf(true, false, true, false), 100, snonce, []byte{7}, nil)
	if candidates := a.Feed(buildEthernetFrame(apMAC, staMAC, 0x888E, m2fixed)); len(candidates) != 1 {
		t.Fatal("合法 counter 的配对被误拒")
	}
}

func TestAnalyzerM3M4AndM2M3Fallback(t *testing.T) {
	apMAC := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	staMAC := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	anonce := make([]byte, 32)
	anonce[0] = 0xAA
	snonce := make([]byte, 32)
	snonce[0] = 0x55

	// 场景一：M2 先到（无 M1），M3 到达组 M2M3。
	a := NewAnalyzer(LinkTypeEthernet)
	a.Feed(buildEthernetFrame(apMAC, staMAC, 0x888E, buildKeyFrame(keyInfoOf(true, false, true, false), 10, snonce, []byte{1}, nil)))
	candidates := a.Feed(buildEthernetFrame(staMAC, apMAC, 0x888E, buildKeyFrame(keyInfoOf(true, false, true, true), 10, anonce, make([]byte, 16), nil)))
	if len(candidates) != 1 || candidates[0].MessagePair != MessagePairM2M3 {
		t.Fatalf("M2M3 后备配对失败：%v", candidates)
	}
	if candidates[0].EAPOLFrame == nil || candidates[0].EAPOLFrame[6] != 0x0A {
		t.Error("M2M3 的 EAPOL 帧应取 M2")
	}

	// 场景二：M3 先池化，M4 到达组 M3M4。
	b := NewAnalyzer(LinkTypeEthernet)
	b.Feed(buildEthernetFrame(staMAC, apMAC, 0x888E, buildKeyFrame(keyInfoOf(true, false, true, true), 20, anonce, make([]byte, 16), nil)))
	candidates = b.Feed(buildEthernetFrame(apMAC, staMAC, 0x888E, buildKeyFrame(keyInfoOf(true, false, true, false), 20, make([]byte, 32), []byte{2}, nil)))
	if len(candidates) != 1 || candidates[0].MessagePair != MessagePairM3M4 {
		t.Fatalf("M3M4 配对失败：%v", candidates)
	}

	// 场景三：仅 M1 与 M4，退化组 M1M4。
	c := NewAnalyzer(LinkTypeEthernet)
	c.Feed(buildEthernetFrame(staMAC, apMAC, 0x888E, buildKeyFrame(keyInfoOf(true, true, false, false), 30, anonce, make([]byte, 16), nil)))
	candidates = c.Feed(buildEthernetFrame(apMAC, staMAC, 0x888E, buildKeyFrame(keyInfoOf(true, false, true, false), 30, make([]byte, 32), []byte{3}, nil)))
	if len(candidates) != 1 || candidates[0].MessagePair != MessagePairM1M4 {
		t.Fatalf("M1M4 退化配对失败：%v", candidates)
	}
}

func TestAnalyzer80211WithRadiotap(t *testing.T) {
	a := NewAnalyzer(LinkTypeIEEE80211Radio)

	apMAC := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	staMAC := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	anonce := make([]byte, 32)
	anonce[0] = 0xA1
	snonce := make([]byte, 32)
	snonce[0] = 0xB2

	// M1 是 fromDS：addr1=STA、addr2=AP；信标先学 ESSID。
	a.Feed(radiotapWrap(buildBeacon(apMAC, "HomeNet"), 6))
	a.Feed(radiotapWrap(build80211Data(false, staMAC, apMAC, apMAC, buildKeyFrame(keyInfoOf(true, true, false, false), 7, anonce, make([]byte, 16), nil)), 6))

	m2 := build80211Data(true, apMAC, staMAC, apMAC, buildKeyFrame(keyInfoOf(true, false, true, false), 7, snonce, []byte{0xC3}, nil))
	candidates := a.Feed(radiotapWrap(m2, 6))
	if len(candidates) != 1 {
		t.Fatalf("802.11 路径应产出 1 条候选，得到 %d", len(candidates))
	}

	if candidates[0].Channel != 6 {
		t.Errorf("Channel = %d，期望 6（radiotap 解析）", candidates[0].Channel)
	}
	if candidates[0].ESSID != "HomeNet" {
		t.Errorf("ESSID = %q，期望 HomeNet（信标学习）", candidates[0].ESSID)
	}
	if candidates[0].MACAP != "aabbccddeeff" || candidates[0].MACSTA != "112233445566" {
		t.Errorf("802.11 角色判定错误：ap=%s sta=%s", candidates[0].MACAP, candidates[0].MACSTA)
	}
}

func TestAnalyzerPMKIDFromAssocResp(t *testing.T) {
	a := NewAnalyzer(LinkTypeIEEE80211Radio)

	apMAC := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	staMAC := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	pmkid := make([]byte, 16)
	pmkid[0] = 0xAB

	// 先用信标建立 BSSID→ESSID 映射（多 AP 同名场景的关键绑定）。
	a.Feed(radiotapWrap(buildBeacon(apMAC, "PMKNet"), 11))

	resp := buildAssocResp(apMAC, staMAC, rsnIEPayload(pmkid))
	candidates := a.Feed(radiotapWrap(resp, 11))
	if len(candidates) != 1 {
		t.Fatalf("关联响应应产出 1 条 PMKID 候选，得到 %d", len(candidates))
	}

	c := candidates[0]
	if c.Kind != KindPMKID || c.PMKID[0] != 0xAB {
		t.Errorf("PMKID 候选不符：%v", c)
	}
	if c.MessagePair != MessagePairPMKIDFromAP {
		t.Errorf("messagepair = %02x，期望 01", c.MessagePair)
	}
	if c.ESSID != "PMKNet" || c.Channel != 11 {
		t.Errorf("ESSID/信道绑定错误：essid=%q ch=%d", c.ESSID, c.Channel)
	}
	if c.MACAP != "aabbccddeeff" || c.MACSTA != "112233445566" {
		t.Errorf("PMKID 角色判定错误：ap=%s sta=%s", c.MACAP, c.MACSTA)
	}
}

func TestAnalyzerPMKIDFromM1KeyData(t *testing.T) {
	a := NewAnalyzer(LinkTypeIEEE80211Radio)

	apMAC := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	staMAC := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	pmkid := make([]byte, 16)
	pmkid[5] = 0xCD

	a.Feed(radiotapWrap(buildBeacon(apMAC, "M1Net"), 1))

	// PMF 场景：PMKID 藏在 EAPOL M1 的 Key Data（RSN IE）里。
	rsnTLV := append([]byte{0x30, byte(len(rsnIEPayload(pmkid)))}, rsnIEPayload(pmkid)...)
	m1 := buildKeyFrame(keyInfoOf(true, true, false, false), 9, make([]byte, 32), make([]byte, 16), rsnTLV)
	candidates := a.Feed(radiotapWrap(build80211Data(false, staMAC, apMAC, apMAC, m1), 1))
	if len(candidates) != 1 {
		t.Fatalf("M1 key data 应产出 1 条 PMKID 候选，得到 %d", len(candidates))
	}

	if candidates[0].Kind != KindPMKID || candidates[0].PMKID[5] != 0xCD {
		t.Errorf("PMKID 候选不符：%v", candidates[0])
	}
}

func TestAnalyzerPendingLimitEvictsOldest(t *testing.T) {
	a := NewAnalyzer(LinkTypeEthernet)

	apMAC := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	m1 := buildKeyFrame(keyInfoOf(true, true, false, false), 1, make([]byte, 32), make([]byte, 16), nil)

	// 塞满 257 个不同 STA 的 M1 触发 FIFO 淘汰（末尾两字节避免循环别名）。
	for i := range pendingLimit + 1 {
		staMAC := []byte{0x11, 0x22, 0x33, 0x00, byte(i >> 8), byte(i)}
		a.Feed(buildEthernetFrame(staMAC, apMAC, 0x888E, m1))
	}

	// 最旧的池项已被淘汰：补发 M2 应无配对。
	oldest := []byte{0x11, 0x22, 0x33, 0x00, 0x00, 0x00}
	m2 := buildKeyFrame(keyInfoOf(true, false, true, false), 1, make([]byte, 32), []byte{1}, nil)
	if candidates := a.Feed(buildEthernetFrame(apMAC, oldest, 0x888E, m2)); len(candidates) != 0 {
		t.Fatal("淘汰策略失效：最旧 M1 仍可配对")
	}
}
