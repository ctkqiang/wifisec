// format.go 把 Candidate 渲染成 hashcat 攻击行。
//
// 22000 格式依据（规格来源已逐一核对，未来版本变动以 FormatVersion
// 常量为准分流）：
//   - hashcat wiki "Cracking WPA/WPA2"（hash mode 22000，v6.0.0+）
//   - hashcat v7.1.2 docs/hashcat-example-hashes.md 真实样例行
//   - hashcat v7.1.2 tools/test_modules/m22000.py 字段序与校验逻辑
//
// 行布局（星号分隔，字段全部小写 hex，无冒号 MAC）：
//
//	PMKID: WPA*01*<PMKID>*<MAC_AP>*<MAC_STA>*<ESSID_HEX>***<MP>
//	EAPOL: WPA*02*<MIC>*<MAC_AP>*<MAC_STA>*<ESSID_HEX>*<ANONCE>*<EAPOL>*<MP>
//
// 关键约定：EAPOL 字段 = 完整 EAPOL 包体（version 起至 key data 止），
// 其中偏移 81 的 16 字节 MIC 区必须清零——hashcat 用 field2 的 MIC
// 之外的内容重算 MIC 并与 field2 比对，不清零会产出永不可解的废 hash。
package eapol

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// FormatVersion 标明本实现锁定的 hashcat 22000 规格版本。
const FormatVersion = "hashcat-v7.1.2"

// MessagePair 位域（hashcat wiki，低 4 位为消息对编号）：
const (
	// MessagePairM1M2：EAPOL 字段存 M2。
	MessagePairM1M2 byte = 0x00
	// MessagePairM1M4：EAPOL 字段存 M4。
	MessagePairM1M4 byte = 0x01
	// MessagePairM2M3：EAPOL 字段存 M2。
	MessagePairM2M3 byte = 0x02
	// MessagePairM3M4：EAPOL 字段存 M4。
	MessagePairM3M4 byte = 0x05

	// PMKID 行的 messagepair 位域（与握手对编号共用低 4 位语义）：
	// bit0 置位表示 PMKID 来自 AP（关联响应 / EAPOL M1），
	// bit1 置位表示 AKM 为 SHA-256 变体（00-0F-AC:6）。
	MessagePairPMKIDFromAP byte = 0x01
	MessagePairPMKIDSHA256 byte = 0x02
)

// Format22000 渲染 hashcat -m 22000 攻击行。
// ESSID 未知（隐藏网络且无法恢复、或以太网视角未指定 --ssid）时
// 返回错误：空 salt 的 PBKDF2 不是合法 hash，宁缺毋滥。
func Format22000(c Candidate) (string, error) {
	if !c.ESSIDKnown || c.ESSID == "" {
		return "", errors.New("ESSID 未知：PBKDF2 需要它作为 salt，隐藏 SSID 请先从 probe response 恢复或用 --ssid 显式指定")
	}

	essidHex := hex.EncodeToString([]byte(c.ESSID))

	switch c.Kind {
	case KindPMKID:
		return strings.Join([]string{
			"WPA*01",
			hex.EncodeToString(c.PMKID[:]),
			c.MACAP,
			c.MACSTA,
			essidHex,
			"", // 第 6 段：PMKID 行固定为空
			"", // 第 7 段：固定为空
			fmt.Sprintf("%02x", c.MessagePair),
		}, "*"), nil

	case KindEAPOL:
		frame := append([]byte(nil), c.EAPOLFrame...)
		if len(frame) < keyMICOffset+16 {
			return "", errors.New("EAPOL 帧不完整，无法构造 hash 行")
		}

		// hashcat 约定：存储帧的 MIC 区清零，真实 MIC 单独放 field2。
		for i := keyMICOffset; i < keyMICOffset+16; i++ {
			frame[i] = 0x00
		}

		return strings.Join([]string{
			"WPA*02",
			hex.EncodeToString(c.MIC[:]),
			c.MACAP,
			c.MACSTA,
			essidHex,
			hex.EncodeToString(c.ANonce[:]),
			hex.EncodeToString(frame),
			fmt.Sprintf("%02x", c.MessagePair),
		}, "*"), nil

	default:
		return "", fmt.Errorf("未知候选类型 %d", c.Kind)
	}
}

// Format16800 渲染已弃用的 hashcat -m 16800 行
// （PMKID:MAC_AP:MAC_STA:ESSID_HEX，冒号分隔）——仅为旧版 hashcat
// 管道兼容保留，新场景一律走 22000。
func Format16800(c Candidate) (string, error) {
	if c.Kind != KindPMKID {
		return "", errors.New("16800 仅接受 PMKID 候选")
	}

	if !c.ESSIDKnown || c.ESSID == "" {
		return "", errors.New("ESSID 未知：16800 同样需要它作为 salt")
	}

	return strings.Join([]string{
		hex.EncodeToString(c.PMKID[:]),
		c.MACAP,
		c.MACSTA,
		hex.EncodeToString([]byte(c.ESSID)),
	}, ":"), nil
}
