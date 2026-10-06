package functions

import (
	"fmt"
	"regexp"
	"strings"
	"wifisec/internal/constants"
	"wifisec/internal/radio"
	"wifisec/internal/utilities"
)

// iwRegPattern 从 `iw reg get` 输出中提取内核当前生效的法规域国码。
var iwRegPattern = regexp.MustCompile(`(?m)^country ([A-Z]{2}):`)

// verdictColumns 复用泛型表格渲染，保持与主扫描表一致的排版与自适应行为。
var verdictColumns = []tableColumn[verdictRow]{
	{
		Header: "国码",
		Value: func(r verdictRow) string {
			return r.Code
		},
		Priority: 1,
	},
	{
		Header:   "国家/地区",
		Value:    rowCountry,
		Priority: 2,
	},
	{
		Header:   "信道状态",
		Value:    func(r verdictRow) string { return r.Status.String() },
		Color:    verdictColor,
		Priority: 3,
	},
}

// verdictRow 是法规对照表的一行：某法规域对目标信道的判定。
type verdictRow struct {
	Code, Country string
	Status        radio.ChannelVerdict
	Current       bool // 是否为内核当前生效的法规域
}

// rowCountry 在内核当前生效的法规域后标出 ←。
func rowCountry(r verdictRow) string {
	if r.Current {
		return r.Country + " ←"
	}

	return r.Country
}

// ExplainNetworks 在锁定模式下对命中的目标网络输出全面技术解读：
// 法规合规、DFS 约束、安全态势与链路质量，全部基于扫描到的真实字段。
// countryOverride 非空时只从指定法规域视角展开（国码大小写不敏感）。
func ExplainNetworks(networks []WiFiNetwork, countryOverride string) {
	if len(networks) == 0 {
		return
	}

	domains, err := radio.Load()
	if err != nil {
		// 法规数据缺失只影响解读，不影响已完成的扫描结果。
		utilities.Warn("%s，跳过法规合规解读", err)
	}

	countryOverride = strings.ToUpper(strings.TrimSpace(countryOverride))
	if countryOverride != "" && domains != nil {
		if _, ok := domains[countryOverride]; !ok {
			known := make([]string, 0, len(domains))
			for _, domain := range radio.SortedDomains(domains) {
				known = append(known, domain.Country)
			}

			utilities.Warn("未知国码 %s，已收录：%s；回退为全法规域对照", countryOverride, strings.Join(known, " "))
			countryOverride = ""
		}
	}

	for i := range networks {
		explainOne(&networks[i], domains, countryOverride)
	}
}

// explainOne 输出单个 BSS 的完整解读；同一 ESSID 的 2.4/5GHz 各自独立成节，
// 因为它们的信道合规性、干扰环境与链路质量完全不同。
func explainOne(network *WiFiNetwork, domains map[string]radio.Domain, countryOverride string) {
	identity := network.ESSID
	if network.BSSID != "" && network.BSSID != placeholder {
		identity += " · " + network.BSSID
	}

	fmt.Printf("\n%s── 目标解读 · %s %s\n", constants.ColorCyan, identity, constants.ColorReset)

	explainProfile(network)
	explainRegulatory(network, domains, countryOverride)
	explainSecurity(network)
	explainLinkQuality(network)
}

// explainProfile 呈现物理层档案：频段、信道、中心频率、带宽与协议代际。
func explainProfile(network *WiFiNetwork) {
	explainSection("目标档案")

	lines := []string{
		"  ESSID      " + valueOrPlaceholder(network.ESSID),
		"  BSSID      " + valueOrPlaceholder(network.BSSID),
	}

	if network.Channel != 0 {
		lines = append(lines, fmt.Sprintf("  信道       %d（%s，中心频率 %d MHz）",
			network.Channel, network.Freq, channelToFreq(network.Channel)))
	} else {
		lines = append(lines, "  信道       "+placeholder)
	}

	if network.ChannelWidth != 0 {
		lines = append(lines, fmt.Sprintf("  带宽       %d MHz（%s）",
			network.ChannelWidth, widthBrief(network.ChannelWidth)))
	}

	if network.PHY != "" && network.PHY != placeholder {
		lines = append(lines, fmt.Sprintf("  PHY        %s（%s）", network.PHY, wifiGeneration(network.PHY)))
	}

	fmt.Println(strings.Join(lines, "\n"))
}

// explainRegulatory 以法规域数据解读目标信道的合规性。
// 默认输出全法规域对照表；检测到内核法规域时高亮该行；
// 指定国码时只展开该域的细节说明。
func explainRegulatory(network *WiFiNetwork, domains map[string]radio.Domain, countryOverride string) {
	explainSection("法规合规")

	if network.Channel == 0 || len(domains) == 0 {
		fmt.Printf("  信道未知或法规数据不可用，无法判定合规性\n")
		return
	}

	if countryOverride != "" {
		domain := domains[countryOverride]
		verdict := radio.Verdict(domain, network.Channel)
		fmt.Printf("  %s（%s）：%s%s%s\n", domain.Country, domain.Name,
			verdictColor(verdict.String()), verdict, constants.ColorReset)
		explainVerdictDetail(network, verdict)
		return
	}

	kernel := kernelRegDomain()
	rows := make([]verdictRow, 0, len(domains))
	for _, domain := range radio.SortedDomains(domains) {
		rows = append(rows, verdictRow{
			Code:    domain.Country,
			Country: domain.Name,
			Status:  radio.Verdict(domain, network.Channel),
			Current: kernel != "" && domain.Country == kernel,
		})
	}

	if kernel != "" {
		fmt.Printf("  当前内核法规域：%s（iw reg get），对照表中已用 ← 标出\n", kernel)
	}

	renderTable(fmt.Sprintf("信道 %d 各法规域对照", network.Channel), verdictColumns, rows)

	// 任一法规域判定为 DFS 时都补充说明，因为 DFS 直接影响 AP 的可用性表现。
	for _, row := range rows {
		if row.Status == radio.DFSRequired {
			explainDFS(network.Channel)
			return
		}
	}
}

// explainVerdictDetail 在单国视角下解释判定结果背后的操作含义。
func explainVerdictDetail(network *WiFiNetwork, verdict radio.ChannelVerdict) {
	switch verdict {
	case radio.Legal:
		fmt.Printf("  该信道可直接发射使用，无需额外检测。\n")
	case radio.DFSRequired:
		explainDFS(network.Channel)
	case radio.Prohibited:
		fmt.Printf("  该信道在此法规域下禁止发射；AP 若工作于此信道，说明其法规域配置与此地不符，\n" +
			"  或属于违规部署，在机场、气象站附近尤其值得警惕。\n")
	}
}

// explainDFS 说明 DFS 信道的约束：发射前监听雷达（CAC），
// TDWR 气象雷达段（120/124/128）的检测时长是常规信道的十倍。
func explainDFS(channel int) {
	cac := 60
	if channel == 120 || channel == 124 || channel == 128 {
		// TDWR（终端多普勒气象雷达）频段，ETSI 规定 CAC 长达 600 秒。
		cac = 600
	}

	fmt.Printf("  信道 %d 属 DFS 段：发射前须监听雷达 %d 秒（CAC），运行中检测到雷达脉冲必须立即换道。\n"+
		"  这也解释了 DFS 信道上的 AP 为何偶发消失——并非故障，而是在给雷达让路。\n", channel, cac)
}

// explainSecurity 按加密代际与套件评估攻击面，结论面向安全研究视角。
func explainSecurity(network *WiFiNetwork) {
	explainSection("安全态势")

	if network.Enc == "" || network.Enc == placeholder {
		fmt.Printf("  加密信息未知（当前平台未提供套件明细）\n")
		return
	}

	line := fmt.Sprintf("  加密       %s%s%s", encryptionColor(network.Enc), network.Enc, constants.ColorReset)
	if network.Cipher != "" && network.Cipher != placeholder {
		line += " · 套件 " + network.Cipher
	}
	if network.Auth != "" && network.Auth != placeholder {
		line += " · 认证 " + network.Auth
	}

	fmt.Println(line)

	for _, note := range securityNotes(network) {
		fmt.Printf("  %s\n", note)
	}
}

// securityNotes 返回加密组合对应的已知攻击面说明，按风险从旧到新排列。
func securityNotes(network *WiFiNetwork) []string {
	switch network.Enc {
	case "OPEN":
		return []string{
			"无加密：全部流量明文，任何嗅探器可直接读取，门户认证（Captive Portal）不保护空口。",
			"风险：会话劫持、敏感信息泄露；勿在此网络传输凭证。",
		}
	case "WEP":
		return []string{
			"RC4 + 24 位 IV：FMS 攻击可在数分钟内恢复密钥，IEEE 自 2004 年起已废弃。",
			"结论：等同无加密，抓到足够 IV 即告破。",
		}
	case "WPA":
		return []string{
			"TKIP 基于 RC4，存在 Beck–Tews 包注入攻击，2009 年起被 WPA2 取代。",
			"结论：仅作过渡兼容存在，可视作弱加密目标。",
		}
	case "WPA2":
		notes := []string{}
		if strings.Contains(network.Auth, "PSK") || network.Auth == "" {
			notes = append(notes, "PSK 模式：四次握手（含 PMKID 免握手抓取）可被嗅探后离线字典爆破，口令强度是唯一短板。")
		} else {
			notes = append(notes, "企业级认证（802.1X/RADIUS）：无 PSK 弱口令面，攻击面转向认证基础设施。")
		}

		if network.Cipher == "TKIP" {
			notes = append(notes, "套件为 TKIP：过渡方案，802.11n 起规定 TKIP 下速率不得超 54 Mbps，且存在注入攻击。")
		}

		return append(notes, "KRACK（2017，密钥重装攻击）已在主流设备修复，剩余风险集中在弱口令。")
	case "WPA3":
		return []string{
			"SAE（Dragonfly）握手：前向保密，抓包无法离线爆破口令。",
			"Dragonblood 侧信道（2019）已在主流实现修复；剩余面为降级攻击与过渡模式的 WPA2 弱点。",
			"结论：当前最稳固的民用方案，不建议作为软目标。",
		}
	default:
		return []string{"未识别的加密代际，无法给出攻击面评估。"}
	}
}

// explainLinkQuality 解读信号与信噪比的工程含义，并对 2.4GHz 补充邻频干扰说明。
func explainLinkQuality(network *WiFiNetwork) {
	explainSection("链路质量")

	lines := []string{}
	if network.Signal != 0 {
		lines = append(lines, fmt.Sprintf("  信号       %d dBm（%s）%s",
			network.Signal, signalGrade(network.Signal), signalBar(network.Signal)))
	}

	if network.SNR != 0 {
		lines = append(lines, fmt.Sprintf("  信噪比     %d dB（%s）", network.SNR, snrGrade(network.SNR)))
	} else if network.NoiseFloor != 0 {
		lines = append(lines, fmt.Sprintf("  噪声底     %d dBm", network.NoiseFloor))
	}

	if network.Rate != 0 {
		lines = append(lines, fmt.Sprintf("  当前速率   %d Mbps", network.Rate))
	}

	if len(lines) > 0 {
		fmt.Println(strings.Join(lines, "\n"))
	}

	if network.Channel >= 1 && network.Channel <= 14 {
		explain24GInterference(network.Channel)
	}
}

// explain24GInterference 说明 2.4GHz 的信道重叠问题：
// 信道带宽 22 MHz 而间隔仅 5 MHz，只有 1/6/11（部分地区 1/5/9/13）互不重叠。
func explain24GInterference(channel int) {
	switch channel {
	case 14:
		fmt.Printf("  注意       信道 14 仅日本法规域开放，且仅限 802.11b（DSSS），现代设备多不支持\n")
	case 1, 6, 11:
		fmt.Printf("  干扰       信道 %d 属 1/6/11 不重叠组，邻频干扰最小\n", channel)
	default:
		fmt.Printf("  干扰       2.4GHz 信道间隔仅 5 MHz 而带宽 22 MHz，信道 %d 与 ±4 内信道存在频谱重叠\n", channel)
	}
}

// explainSection 输出解读区块的小标题，青色与主表格的着色系保持一致。
func explainSection(title string) {
	fmt.Printf("\n%s【%s】%s\n", constants.ColorCyan, title, constants.ColorReset)
}

// kernelRegDomain 读取 Linux 内核当前生效的法规域；其他平台无此概念，返回空串。
func kernelRegDomain() string {
	if utilities.GetOS() != utilities.Linux {
		return ""
	}

	output, err := runCommand("iw", "reg", "get")
	if err != nil {
		return ""
	}

	return matchGroup(iwRegPattern, output)
}

// channelToFreq 是 freqToChannel 的逆运算：信道号换算中心频率（MHz）。
func channelToFreq(channel int) int {
	switch {
	case channel == 14:
		return 2484
	case channel >= 1 && channel <= 13:
		return 2407 + channel*5
	case channel >= 32 && channel <= 177:
		return 5000 + channel*5
	default:
		return 0
	}
}

// wifiGeneration 把 PHY 协议串映射为 Wi-Fi 联盟的市场代际名，便于非专业读者理解。
func wifiGeneration(phy string) string {
	switch {
	case strings.Contains(phy, "be"):
		return "Wi-Fi 7"
	case strings.Contains(phy, "ax"):
		return "Wi-Fi 6/6E"
	case strings.Contains(phy, "ac"):
		return "Wi-Fi 5"
	case strings.Contains(phy, "n"):
		return "Wi-Fi 4"
	default:
		return "802.11 legacy"
	}
}

// widthBrief 解释信道带宽的工程取舍：带宽翻倍吞吐翻倍，但占用的频谱也翻倍。
func widthBrief(width int) string {
	switch width {
	case 20:
		return "兼容性最好，抗干扰最强"
	case 40:
		return "吞吐翻倍，2.4GHz 下会侵占邻频"
	case 80:
		return "Wi-Fi 5/6 主流配置"
	case 160:
		return "需连续 160 MHz 频谱，几乎必然落入 DFS 段"
	default:
		return ""
	}
}

// signalGrade 信号强度分级，阈值沿用无线勘测的通行经验。
func signalGrade(dbm int) string {
	switch {
	case dbm >= -50:
		return "极佳，AP 近在眼前"
	case dbm >= -60:
		return "良好"
	case dbm >= -70:
		return "可用"
	case dbm >= -80:
		return "偏弱，高阶调制难以维持"
	default:
		return "差，仅能勉强维持关联"
	}
}

// snrGrade 信噪比分级：低于 15 dB 时误码率显著上升，高阶 MCS 会掉档。
func snrGrade(snr int) string {
	switch {
	case snr >= 40:
		return "优秀"
	case snr >= 25:
		return "良好"
	case snr >= 15:
		return "一般，高阶调制会掉档"
	default:
		return "差，重传率高"
	}
}

// verdictColor 给法规判定着色：合法绿、DFS 黄、禁用红，风险一眼可辨。
func verdictColor(status string) string {
	switch status {
	case radio.Legal.String():
		return constants.ColorGreen
	case radio.DFSRequired.String():
		return constants.ColorYellow
	default:
		return constants.ColorRed
	}
}

// valueOrPlaceholder 统一空值渲染，与主表格的占位风格一致。
func valueOrPlaceholder(value string) string {
	if value == "" {
		return placeholder
	}

	return value
}
