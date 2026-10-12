package rsnie

import (
	"math/rand"
	"testing"
)

// suite 组一个 4 字节套件选择器（标准 OUI + 类型）。
func suite(t byte) []byte {
	return []byte{0x00, 0x0f, 0xac, t}
}

// buildPayload 组一个最小合法 RSN IE 载荷：可指定 AKM 类型与 PMKID 数量，
// PMKID 以递增字节填充便于断言归属。不依赖测试框架，可作 Fuzz 种子。
func buildPayload(akmType byte, pmkidCount int) []byte {
	payload := []byte{0x01, 0x00} // Version = 1
	payload = append(payload, suite(0x04)...)
	payload = append(payload, 0x01, 0x00) // pairwise count = 1
	payload = append(payload, suite(0x04)...)
	payload = append(payload, 0x01, 0x00) // AKM count = 1
	payload = append(payload, suite(akmType)...)
	payload = append(payload, 0x0c, 0x00) // capabilities：PTKSA/GTKSA 重放计数

	if pmkidCount > 0 {
		payload = append(payload, byte(pmkidCount), 0x00)
		for i := range pmkidCount {
			for j := range 16 {
				payload = append(payload, byte(i*16+j))
			}
		}
	}

	return payload
}

// rsnSeedPSK 是 Fuzz 语料用的典型 WPA2-PSK/CCMP 载荷。
var rsnSeedPSK = buildPayload(AKMTypePSK, 1)

func TestParseRSNIEValidPSK(t *testing.T) {
	info, err := ParseRSNIE(buildPayload(AKMTypePSK, 1))
	if err != nil {
		t.Fatalf("合法 PSK IE 解析失败：%v", err)
	}

	if info.Version != 1 {
		t.Errorf("Version = %d，期望 1", info.Version)
	}
	if got := info.GroupCipher.String(); got != "00-0f-ac:04" {
		t.Errorf("GroupCipher = %s，期望 00-0f-ac:04", got)
	}
	if len(info.PairwiseCiphers) != 1 || info.PairwiseCiphers[0].String() != "00-0f-ac:04" {
		t.Errorf("PairwiseCiphers 解析不符：%v", info.PairwiseCiphers)
	}
	if len(info.AKMSuites) != 1 || info.AKMSuites[0].String() != "00-0f-ac:02" {
		t.Errorf("AKMSuites 解析不符：%v", info.AKMSuites)
	}
	if info.Capabilities.Raw != 0x000c {
		t.Errorf("Capabilities = %#04x，期望 0x000c", info.Capabilities.Raw)
	}
	if !info.HasPMKID() {
		t.Fatal("HasPMKID = false，期望 true")
	}
	if !info.IsPSK() {
		t.Error("IsPSK = false，期望 true")
	}
	// PMKID 字节归属断言：确认 16 字节块是按序填充而非错位。
	if info.PMKIDs[0][0] != 0x00 || info.PMKIDs[0][15] != 0x0f {
		t.Errorf("PMKID 字节错位：首字节 %#x，尾字节 %#x", info.PMKIDs[0][0], info.PMKIDs[0][15])
	}
}

func TestParseRSNIEWithoutPMKIDField(t *testing.T) {
	// 最小合法 IE 止于 capabilities，PMKID 字段整体省略——合法。
	info, err := ParseRSNIE(buildPayload(AKMTypePSK, 0))
	if err != nil {
		t.Fatalf("无 PMKID 字段的 IE 解析失败：%v", err)
	}

	if info.HasPMKID() {
		t.Error("HasPMKID = true，期望 false")
	}
}

func TestParseRSNIEAKMClassification(t *testing.T) {
	cases := []struct {
		akm     byte
		psk     bool
		summary string
	}{
		{AKMTypePSK, true, "WPA2-PSK"},
		{AKMTypePSKSHA256, true, "WPA2-PSK"},
		{AKMType8021X, false, "802.1X/Enterprise"},
		{AKMTypeSAE, false, "WPA3-SAE"},
		{AKMTypeFTPSK, false, "802.11r FT-PSK"},
	}

	for _, c := range cases {
		info, err := ParseRSNIE(buildPayload(c.akm, 0))
		if err != nil {
			t.Fatalf("AKM %d 解析失败：%v", c.akm, err)
		}

		if info.IsPSK() != c.psk {
			t.Errorf("AKM %d IsPSK = %v，期望 %v", c.akm, info.IsPSK(), c.psk)
		}
		if info.AKMSummary() != c.summary {
			t.Errorf("AKM %d AKMSummary = %q，期望 %q", c.akm, info.AKMSummary(), c.summary)
		}
	}
}

func TestParseRSNIECountMismatch(t *testing.T) {
	// pairwise count = 3 但只留 1 个套件的字节：count 与实际不符必须报错。
	payload := []byte{0x01, 0x00}
	payload = append(payload, suite(0x04)...)
	payload = append(payload, 0x03, 0x00)
	payload = append(payload, suite(0x04)...)

	if _, err := ParseRSNIE(payload); err == nil {
		t.Fatal("pairwise count 与字节数不符未报错")
	}

	// PMKID count = 3 但只留 16 字节（1 个完整块）。
	payload = buildPayload(AKMTypePSK, 1)
	payload[len(payload)-18] = 0x03 // 尾部布局 = count(2)+PMKID(16)，改写 count 低字节

	if _, err := ParseRSNIE(payload); err == nil {
		t.Fatal("PMKID count 与字节数不符未报错")
	}
}

func TestParseRSNIEWrongVersion(t *testing.T) {
	// version = 2：不是 RSN IE（常见于误传入 WPA 厂商 IE 载荷）。
	payload := []byte{0x02, 0x00}
	payload = append(payload, suite(0x01)...)

	if _, err := ParseRSNIE(payload); err == nil {
		t.Fatal("version != 1 未报错")
	}
}

func TestParseRSNIETruncatedNeverPanics(t *testing.T) {
	// 属性：任何截断深度都只产生 error 或完整结果，绝不 panic/越界。
	for _, pmkidCount := range []int{0, 1, 3} {
		payload := buildPayload(AKMTypePSK, pmkidCount)
		for cut := range len(payload) {
			// 返回值直接丢弃：目标只是证明调用安全。
			info, err := ParseRSNIE(payload[:cut])
			if err == nil && info == nil {
				t.Fatalf("截断至 %d 字节时返回了 nil, nil", cut)
			}
		}
	}
}

func TestParseRSNIEDirtyRandom(t *testing.T) {
	// 固定种子的随机脏数据：让"绝不 panic"成为回归测试而非偶然。
	rng := rand.New(rand.NewSource(20261012))

	for range 2000 {
		buf := make([]byte, rng.Intn(72))
		if _, err := rng.Read(buf); err != nil {
			t.Fatalf("读取随机数失败：%v", err)
		}

		_, _ = ParseRSNIE(buf)
	}
}

func TestParseRSNIEEmptyPayload(t *testing.T) {
	if _, err := ParseRSNIE(nil); err == nil {
		t.Fatal("空载荷未报错")
	}
}

func FuzzParseRSNIE(f *testing.F) {
	// 种子语料：合法 PSK/PMKID IE 与典型截断，`go test` 默认执行种子，
	// `-fuzz` 时扩展为随机探索。
	f.Add(rsnSeedPSK)
	f.Add(buildPayload(AKMType8021X, 0))
	f.Add([]byte{0x01, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		info, err := ParseRSNIE(data)
		if err == nil && info == nil {
			t.Fatal("解析成功却返回 nil 结果")
		}
	})
}
