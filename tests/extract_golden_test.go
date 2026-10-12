package tests

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctkqiang/wifisec/internal/functions"
	"github.com/ctkqiang/wifisec/internal/pcapfile"
)

// extract_golden_test.go 用现场构造的 pcap fixture 驱动 RunExtract 全链路
// （读帧 → Analyzer 配对 → 分组 → 择优 → 落盘），golden 比对 22000/16800 行。
//
// 帧构造逻辑独立复刻而非复用 internal/eapol 的测试 helper：golden 期望值
// 必须来自被测代码之外的生成路径，否则是"用被测物验证被测物"的循环。

// EAPOL-Key 包体布局偏移（IEEE 802.11i-2004 §8.5.2，与 eapol/key.go 一致）。
const (
	goldKeyNonceOffset   = 17
	goldKeyMICOffset     = 81
	goldKeyDataLenOffset = 97
	goldKeyDataOffset    = 99

	// Key Information 位域：keyver=2 基础值 + pairwise/ACK/MIC 组合。
	goldKeyInfoPairwise = 1 << 3
	goldKeyInfoACK      = 1 << 7
	goldKeyInfoMIC      = 1 << 8

	// keyInfoM1/M2：M1 = ver2|pairwise|ACK，M2 = ver2|pairwise|MIC。
	goldKeyInfoM1 = 2 | goldKeyInfoPairwise | goldKeyInfoACK
	goldKeyInfoM2 = 2 | goldKeyInfoPairwise | goldKeyInfoMIC
)

// goldWritePCAP 把帧集落成 pcap 文件；失败直接终止当前子测试。
func goldWritePCAP(t *testing.T, path string, linkType uint32, frames [][]byte) {
	t.Helper()

	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("创建 fixture 失败：%v", err)
	}

	writer, err := pcapfile.NewWriter(file, linkType)
	if err != nil {
		_ = file.Close()
		t.Fatalf("创建写入器失败：%v", err)
	}

	for _, frame := range frames {
		if err := writer.WritePacket(frame, time.Unix(1700000000, 0)); err != nil {
			_ = file.Close()
			t.Fatalf("写入 fixture 帧失败：%v", err)
		}
	}

	if err := file.Close(); err != nil {
		t.Fatalf("关闭 fixture 失败：%v", err)
	}
}

// goldEAPOLKey 构造完整 EAPOL-Key 包体（自 version 字节起）。
func goldEAPOLKey(keyInfo uint16, replay uint64, nonce, mic []byte) []byte {
	payload := make([]byte, goldKeyDataOffset)
	payload[0] = 2 // EAPOL version 2004
	payload[1] = 3 // packet type: EAPOL-Key
	binary.BigEndian.PutUint16(payload[2:4], uint16(len(payload)-4))
	payload[4] = 2 // RSN key descriptor
	binary.BigEndian.PutUint16(payload[5:7], keyInfo)
	binary.BigEndian.PutUint16(payload[7:9], 16) // key length
	binary.BigEndian.PutUint64(payload[9:17], replay)
	copy(payload[goldKeyNonceOffset:goldKeyNonceOffset+32], nonce)
	copy(payload[goldKeyMICOffset:goldKeyMICOffset+16], mic)

	return payload
}

// goldEthEAPOL 组以太网帧（DLT 1，连接态抓包视角）。
func goldEthEAPOL(dst, src []byte, payload []byte) []byte {
	frame := make([]byte, 14+len(payload))
	copy(frame[0:6], dst)
	copy(frame[6:12], src)
	binary.BigEndian.PutUint16(frame[12:14], 0x888E)
	copy(frame[14:], payload)

	return frame
}

// goldRadiotapWrap 加一个仅含 Channel 字段的 radiotap 头。
func goldRadiotapWrap(frame []byte, channel int) []byte {
	freq := 2412 + (channel-1)*5

	out := make([]byte, 0, 12+len(frame))
	out = append(out, 0x00, 0x00, 0x0c, 0x00, 0x08, 0x00, 0x00, 0x00)
	out = append(out, byte(freq), byte(freq>>8), 0x10, 0x01)

	return append(out, frame...)
}

// goldBeacon 组携带 SSID 的信标帧（供 Analyzer 学 BSSID→ESSID 映射）。
func goldBeacon(ap []byte, ssid string) []byte {
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

// goldData80211 组 802.11 数据帧（LLC/SNAP 封 EAPOL）。
// toDS=false 即 fromDS（AP 发出），toDS=true 即 STA 发出。
func goldData80211(toDS bool, addr1, addr2, addr3 []byte, payload []byte) []byte {
	body := append([]byte{0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E}, payload...)

	frame := make([]byte, 24+len(body))
	frame[0] = 0x08 // type 2（数据帧），subtype 0
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

// goldRSNIEWithPMKID 组带 PMKID 的 RSN IE 载荷（WPA2-PSK/CCMP，
// AKM = 00-0F-AC:02，PMKID count = 1）。
func goldRSNIEWithPMKID(pmkid []byte) []byte {
	payload := []byte{0x01, 0x00}
	payload = append(payload, 0x00, 0x0f, 0xac, 0x04)
	payload = append(payload, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04)
	payload = append(payload, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02)
	payload = append(payload, 0x0c, 0x00)
	payload = append(payload, 0x01, 0x00)

	return append(payload, pmkid...)
}

// goldAssocResp 组携带 RSN IE 的关联响应（PMKID 在此暴露）。
func goldAssocResp(ap, sta, rsnPayload []byte) []byte {
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

// goldReadFile 读整个文件并去掉结尾换行，供单行 golden 比对。
func goldReadFile(t *testing.T, path string) string {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 %s 失败：%v", path, err)
	}

	return strings.TrimRight(string(data), "\n")
}

func TestRunExtractGolden(t *testing.T) {
	apMAC := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	staMAC := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	pmkid := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	anonce := make([]byte, 32)
	anonce[31] = 0xA1
	snonce := make([]byte, 32)
	snonce[31] = 0xB2
	mic := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	m2 := goldEAPOLKey(goldKeyInfoM2, 100, snonce, mic)

	dir := t.TempDir()

	t.Run("同一 AP 同时有 PMKID 与握手时 22000 只写 PMKID 行", func(t *testing.T) {
		capture := filepath.Join(dir, "pmkid-preferred.pcap")
		goldWritePCAP(t, capture, 127, [][]byte{
			goldRadiotapWrap(goldBeacon(apMAC, "PMKNet"), 6),
			goldRadiotapWrap(goldAssocResp(apMAC, staMAC, goldRSNIEWithPMKID(pmkid)), 6),
			goldRadiotapWrap(goldData80211(false, staMAC, apMAC, apMAC, goldEAPOLKey(goldKeyInfoM1, 100, anonce, make([]byte, 16))), 6),
			goldRadiotapWrap(goldData80211(true, apMAC, staMAC, apMAC, m2), 6),
		})

		hashcatOut := filepath.Join(dir, "pmkid-preferred.22000")
		pmkidOut := filepath.Join(dir, "pmkid-preferred.16800")
		if err := functions.RunExtract([]string{capture, "--hashcat", hashcatOut, "--pmkid", pmkidOut}); err != nil {
			t.Fatalf("RunExtract 失败：%v", err)
		}

		// ESSID "PMKNet" 的 hex 为 504d4b4e6574；messagepair 01 = 来自 AP。
		want := "WPA*01*00112233445566778899aabbccddeeff*aabbccddeeff*112233445566*504d4b4e6574***01"
		if line := goldReadFile(t, hashcatOut); line != want {
			t.Errorf("22000 行不符：\n got %s\nwant %s", line, want)
		}

		want16800 := "00112233445566778899aabbccddeeff:aabbccddeeff:112233445566:504d4b4e6574"
		if line := goldReadFile(t, pmkidOut); line != want16800 {
			t.Errorf("16800 行不符：\n got %s\nwant %s", line, want16800)
		}
	})

	t.Run("仅握手时兜底产出 22000 且 MIC 区清零", func(t *testing.T) {
		capture := filepath.Join(dir, "handshake.pcap")
		goldWritePCAP(t, capture, 1, [][]byte{
			goldEthEAPOL(staMAC, apMAC, goldEAPOLKey(goldKeyInfoM1, 100, anonce, make([]byte, 16))),
			goldEthEAPOL(apMAC, staMAC, m2),
		})

		out := filepath.Join(dir, "handshake.22000")
		if err := functions.RunExtract([]string{capture, "--hashcat", out, "--bssid", "AA:BB:CC:DD:EE:FF", "--ssid", "TestNet"}); err != nil {
			t.Fatalf("RunExtract 失败：%v", err)
		}

		fields := strings.Split(goldReadFile(t, out), "*")
		if len(fields) != 9 {
			t.Fatalf("22000 行应为 9 字段，实际 %d：%v", len(fields), fields)
		}

		if fields[1] != "02" {
			t.Errorf("field1 应为 hash 子类型 02（EAPOL），实际 %s", fields[1])
		}
		if fields[2] != "0102030405060708090a0b0c0d0e0f10" {
			t.Errorf("field2 应为真实 MIC，实际 %s", fields[2])
		}
		if fields[3] != "aabbccddeeff" || fields[4] != "112233445566" {
			t.Errorf("MAC 记法应为小写无冒号，实际 ap=%s sta=%s", fields[3], fields[4])
		}
		if fields[5] != "546573744e6574" {
			t.Errorf("field5 应为 ESSID hex（TestNet），实际 %s", fields[5])
		}
		if fields[6] != "00000000000000000000000000000000000000000000000000000000000000a1" {
			t.Errorf("field6 应为 ANONCE，实际 %s", fields[6])
		}

		// EAPOL 字段为 99 字节包体的 hex；偏移 81-96 的 MIC 区必须清零，
		// 否则 hashcat 重算 MIC 永不匹配（废 hash）。
		if len(fields[7]) != 99*2 {
			t.Fatalf("field7 应为 %d 个 hex 字符，实际 %d", 99*2, len(fields[7]))
		}
		if got := fields[7][81*2 : 97*2]; got != strings.Repeat("0", 32) {
			t.Errorf("MIC 区应清零，实际 %s", got)
		}

		if fields[8] != "00" {
			t.Errorf("messagepair 应为 00（M1M2），实际 %s", fields[8])
		}
	})

	t.Run("ESSID 未知时拒绝产出且不创建文件", func(t *testing.T) {
		capture := filepath.Join(dir, "unknown-essid.pcap")
		goldWritePCAP(t, capture, 1, [][]byte{
			goldEthEAPOL(staMAC, apMAC, goldEAPOLKey(goldKeyInfoM1, 100, anonce, make([]byte, 16))),
			goldEthEAPOL(apMAC, staMAC, m2),
		})

		out := filepath.Join(dir, "unknown-essid.22000")
		if err := functions.RunExtract([]string{capture, "--hashcat", out}); err != nil {
			t.Fatalf("RunExtract 失败：%v", err)
		}

		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatal("ESSID 未知时 22000 文件不应创建（空 salt 无法计算 PBKDF2）")
		}
	})

	t.Run("bssid 过滤只保留目标 AP 的行", func(t *testing.T) {
		otherAP := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x02}
		capture := filepath.Join(dir, "two-aps.pcap")
		goldWritePCAP(t, capture, 127, [][]byte{
			goldRadiotapWrap(goldBeacon(apMAC, "NetA"), 1),
			goldRadiotapWrap(goldBeacon(otherAP, "NetB"), 6),
			goldRadiotapWrap(goldData80211(false, staMAC, apMAC, apMAC, goldEAPOLKey(goldKeyInfoM1, 100, anonce, make([]byte, 16))), 1),
			goldRadiotapWrap(goldData80211(true, apMAC, staMAC, apMAC, m2), 1),
			goldRadiotapWrap(goldData80211(false, staMAC, otherAP, otherAP, goldEAPOLKey(goldKeyInfoM1, 200, anonce, make([]byte, 16))), 6),
			goldRadiotapWrap(goldData80211(true, otherAP, staMAC, otherAP, m2), 6),
		})

		out := filepath.Join(dir, "two-aps.22000")
		if err := functions.RunExtract([]string{capture, "--hashcat", out, "--bssid", "AA:BB:CC:DD:EE:FF"}); err != nil {
			t.Fatalf("RunExtract 失败：%v", err)
		}

		line := goldReadFile(t, out)
		if !strings.Contains(line, "4e657441") { // hex("NetA") = 4e657441
			t.Errorf("应保留 NetA 的行，实际 %s", line)
		}
		if strings.Contains(line, "4e657442") { // hex("NetB")
			t.Errorf("NetB 的行应被 --bssid 过滤掉，实际 %s", line)
		}
	})
}
