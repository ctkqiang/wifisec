package eapol

import (
	"encoding/hex"
	"strings"
	"testing"
)

// goldenPMKIDCandidate 是 golden 测试共用的 PMKID 候选。
func goldenPMKIDCandidate() Candidate {
	var pmkid [16]byte
	for i := range 16 {
		pmkid[i] = byte(i)
	}

	return Candidate{
		Kind:        KindPMKID,
		MessagePair: MessagePairPMKIDFromAP,
		PMKID:       pmkid,
		MACAP:       "aabbccddeeff",
		MACSTA:      "112233445566",
		ESSID:       "Test",
		ESSIDKnown:  true,
		Channel:     6,
	}
}

func TestFormat22000PMKIDGolden(t *testing.T) {
	line, err := Format22000(goldenPMKIDCandidate())
	if err != nil {
		t.Fatalf("PMKID 行格式化失败：%v", err)
	}

	// hashcat v7.1.2 m22000.py：type01 = WPA*01*<pmkid>*<ap>*<sta>*<essid>***<mp>
	want := "WPA*01*000102030405060708090a0b0c0d0e0f*aabbccddeeff*112233445566*54657374***01"
	if line != want {
		t.Errorf("PMKID golden 不符：\n 得到 %s\n 期望 %s", line, want)
	}
}

func TestFormat22000EAPOLGolden(t *testing.T) {
	mic := make([]byte, 16)
	for i := range 16 {
		mic[i] = 0xFF
	}
	anonce := make([]byte, 32)
	for i := range 32 {
		anonce[i] = 0x11
	}
	snonce := make([]byte, 32)
	snonce[0] = 0x22

	frame := buildKeyFrame(keyInfoOf(true, false, true, false), 1, snonce, mic, nil)

	candidate := Candidate{
		Kind:        KindEAPOL,
		MessagePair: MessagePairM1M2,
		MIC:         [16]byte(mic),
		MACAP:       "aabbccddeeff",
		MACSTA:      "112233445566",
		ESSID:       "Test",
		ESSIDKnown:  true,
		ANonce:      [32]byte(anonce),
		EAPOLFrame:  frame,
		Channel:     1,
	}

	line, err := Format22000(candidate)
	if err != nil {
		t.Fatalf("EAPOL 行格式化失败：%v", err)
	}

	parts := strings.Split(line, "*")
	if len(parts) != 9 || parts[0] != "WPA" || parts[1] != "02" {
		t.Fatalf("字段数/前缀不符：%s", line)
	}
	if parts[2] != strings.Repeat("ff", 16) {
		t.Error("field2 应为真实 MIC")
	}
	if parts[3] != "aabbccddeeff" || parts[4] != "112233445566" || parts[5] != "54657374" {
		t.Errorf("MAC/ESSID 字段不符：%v", parts[3:6])
	}
	if parts[6] != strings.Repeat("11", 32) {
		t.Error("field6 应为 ANONCE")
	}

	// hashcat 约定：存储帧的 MIC 区（偏移 81-96）必须清零。
	eapol, err := hex.DecodeString(parts[7])
	if err != nil {
		t.Fatalf("EAPOL 字段非合法 hex：%v", err)
	}
	if len(eapol) != len(frame) {
		t.Fatalf("EAPOL 帧长度变化：%d != %d", len(eapol), len(frame))
	}
	for i := keyMICOffset; i < keyMICOffset+16; i++ {
		if eapol[i] != 0x00 {
			t.Fatalf("MIC 区未清零：偏移 %d = %#x", i, eapol[i])
		}
	}

	// SNonce 首字节（偏移 17）应原样保留——清零只动 MIC 区。
	if eapol[keyNonceOffset] != 0x22 {
		t.Error("清零操作破坏了 Nonce 区")
	}

	if parts[8] != "00" {
		t.Errorf("messagepair = %s，期望 00", parts[8])
	}
}

func TestFormat22000UnknownESSIDRejected(t *testing.T) {
	candidate := goldenPMKIDCandidate()
	candidate.ESSID = ""
	candidate.ESSIDKnown = false

	if _, err := Format22000(candidate); err == nil {
		t.Fatal("未知 ESSID 未被拒绝：空 salt 会产出不可解 hash")
	}
}

func TestFormat16800Golden(t *testing.T) {
	line, err := Format16800(goldenPMKIDCandidate())
	if err != nil {
		t.Fatalf("16800 行格式化失败：%v", err)
	}

	// 16800（已弃用）：PMKID:MAC_AP:MAC_STA:ESSID_HEX，冒号分隔。
	want := "000102030405060708090a0b0c0d0e0f:aabbccddeeff:112233445566:54657374"
	if line != want {
		t.Errorf("16800 golden 不符：\n 得到 %s\n 期望 %s", line, want)
	}
}

func TestFormat16800RejectsEAPOL(t *testing.T) {
	candidate := Candidate{Kind: KindEAPOL, ESSIDKnown: true, ESSID: "Test"}

	if _, err := Format16800(candidate); err == nil {
		t.Fatal("16800 接受了 EAPOL 候选")
	}
}
