// extract.go 实现 `wifisec extract`：对已抓取的 pcap 做离线破解
// 素材提取。纯文件分析，不碰网卡、不需要特权：
//
//	wifisec extract capture.pcap                       # 摘要：握手数 / PMKID 有无 / 各帧合法性
//	wifisec extract capture.pcap --hashcat out.22000   # 22000 攻击行（PMKID 优先，握手对兜底）
//	wifisec extract capture.pcap --pmkid out.16800     # 旧版 hashcat 16800（仅 PMKID）
//
// 分析引擎是 internal/eapol.Analyzer（与 get_packet --eapol 实时路径
// 共用同一套配对逻辑），本文件只做编排：读帧、过滤、分组、渲染。
package functions

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ctkqiang/wifisec/internal/eapol"
	"github.com/ctkqiang/wifisec/internal/pcapfile"
	"github.com/ctkqiang/wifisec/internal/utilities"
)

// ExtractOptions 是 extract 子命令解析后的参数集。
type ExtractOptions struct {
	Input      string // 位置参数 1：输入 pcap
	HashcatOut string // --hashcat：22000 行落盘路径
	PMKIDOut   string // --pmkid：16800 行落盘路径
	BSSID      string // --bssid：只看指定 AP
	SSID       string // --ssid：ESSID 兜底 salt（隐藏网络/以太网视角）
	JSON       bool   // --json：机器可读输出
}

// extractGroup 是按 AP 归组后的候选集合：PMKID 与握手对分开持有，
// 择优逻辑（PMKID 优先）与 JSON 全量展示共用同一份分组。
type extractGroup struct {
	MACAP      string
	ESSID      string
	ESSIDKnown bool
	Channel    int
	PMKIDs     []eapol.Candidate
	EAPOLs     []eapol.Candidate
}

// extractJSONStats 是 --json 的全局统计；unrecognized 字段暴露
// "有 EtherType 但不构成合法 Key 帧"的数量，即各帧合法性的量化。
type extractJSONStats struct {
	Frames          int `json:"frames"`
	EAPOLKeyFrames  int `json:"eapol_key_frames"`
	M1              int `json:"m1"`
	M2              int `json:"m2"`
	M3              int `json:"m3"`
	M4              int `json:"m4"`
	HandshakePairs  int `json:"handshake_pairs"`
	PMKIDCandidates int `json:"pmkid_candidates"`
}

// extractJSONGroup 是 --json 的分组结构；PMKID 与握手行都给出，
// 择优只发生在 --hashcat 文件里，JSON 保持全量信息。
type extractJSONGroup struct {
	MACAP      string   `json:"mac_ap"`
	ESSID      string   `json:"essid"`
	ESSIDKnown bool     `json:"essid_known"`
	Channel    int      `json:"channel"`
	PMKID22000 []string `json:"pmkid_22000,omitempty"`
	EAPOL22000 []string `json:"eapol_22000,omitempty"`
	PMKID16800 []string `json:"pmkid_16800,omitempty"`
}

// extractJSONReport 是 --json 的顶层输出。
type extractJSONReport struct {
	Input    string             `json:"input"`
	LinkType uint32             `json:"link_type"`
	Stats    extractJSONStats   `json:"stats"`
	Groups   []extractJSONGroup `json:"groups"`
}

// RunExtract 是 `wifisec extract` 的入口。
func RunExtract(arguments []string) error {
	options, err := ParseExtractArgs(arguments)
	if err != nil {
		return err
	}

	utilities.Warn("hash 行可直接用于离线爆破，与口令同级敏感，仅限授权网络使用并妥善保管")

	file, err := os.Open(options.Input)
	if err != nil {
		return fmt.Errorf("打开 pcap 失败：%w", err)
	}
	defer file.Close()

	reader, err := pcapfile.NewReader(file)
	if err != nil {
		return err
	}

	analyzer := eapol.NewAnalyzer(int(reader.LinkType))

	// 以太网视角（连接态抓包）看不到信标学 SSID：--bssid + --ssid
	// 预绑定让候选在生成时就带上 salt，而不是事后补救。
	if options.BSSID != "" && options.SSID != "" {
		analyzer.SetESSID(normalizeMAC(options.BSSID), options.SSID)
	}

	frames := 0
	var candidates []eapol.Candidate

	for {
		frame, _, err := reader.ReadPacket()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			return fmt.Errorf("读取 pcap 失败（第 %d 帧之后）：%w", frames, err)
		}

		frames++
		candidates = append(candidates, analyzer.Feed(frame)...)
	}

	return reportExtract(options, reader.LinkType, frames, analyzer.Stats(), candidates)
}

// ParseExtractArgs 解析位置参数（输入 pcap）与 flag：
// --hashcat/--pmkid/--bssid/--ssid 带值，--json 为布尔。
func ParseExtractArgs(arguments []string) (ExtractOptions, error) {
	options := ExtractOptions{}

	for index := 0; index < len(arguments); index++ {
		token := strings.TrimSpace(arguments[index])
		if token == "" {
			continue
		}

		switch {
		case token == "--hashcat":
			if index+1 >= len(arguments) {
				return options, errors.New("--hashcat 需要输出文件路径，例如 --hashcat out.22000")
			}

			index++
			options.HashcatOut = strings.TrimSpace(arguments[index])
		case token == "--pmkid":
			if index+1 >= len(arguments) {
				return options, errors.New("--pmkid 需要输出文件路径，例如 --pmkid out.16800")
			}

			index++
			options.PMKIDOut = strings.TrimSpace(arguments[index])
		case token == "--bssid":
			if index+1 >= len(arguments) {
				return options, errors.New("--bssid 需要 MAC 地址，例如 --bssid aa:bb:cc:dd:ee:ff")
			}

			index++
			if _, err := net.ParseMAC(strings.TrimSpace(arguments[index])); err != nil {
				return options, fmt.Errorf("非法 BSSID %q：%v", arguments[index], err)
			}

			options.BSSID = normalizeMAC(arguments[index])
		case token == "--ssid":
			if index+1 >= len(arguments) {
				return options, errors.New("--ssid 需要网络名，例如 --ssid MyWiFi")
			}

			index++
			options.SSID = strings.TrimSpace(arguments[index])
		case token == "--json":
			options.JSON = true
		case strings.HasPrefix(token, "-"):
			return options, fmt.Errorf("无法识别的参数 %q（支持 --hashcat/--pmkid/--bssid/--ssid/--json）", token)
		default:
			if options.Input != "" {
				return options, fmt.Errorf("无法识别的多余参数 %q", token)
			}

			options.Input = token
		}
	}

	if options.Input == "" {
		return options, errors.New("用法：wifisec extract <capture.pcap> [--hashcat out.22000] [--pmkid out.16800] [--bssid xx:xx..] [--ssid 网络名] [--json]")
	}

	return options, nil
}

// reportExtract 渲染分析结果：人类摘要 + 22000/16800 落盘 + JSON。
// --ssid 在输出阶段兜底补 salt（预绑定只覆盖 --bssid 同给的场景），
// --bssid 在输出阶段过滤，分析器始终喂全量帧保持统计完整。
func reportExtract(options ExtractOptions, linkType uint32, frames int, stats eapol.Stats, candidates []eapol.Candidate) error {
	if options.SSID != "" {
		for i := range candidates {
			if candidates[i].ESSID == "" {
				candidates[i].ESSID = options.SSID
				candidates[i].ESSIDKnown = true
			}
		}
	}

	if options.BSSID != "" {
		// candidate.MACAP 采用 hash 行记法（小写无冒号 hex），先对齐再比较。
		want := strings.ReplaceAll(normalizeMAC(options.BSSID), ":", "")

		filtered := make([]eapol.Candidate, 0, len(candidates))
		for _, candidate := range candidates {
			if candidate.MACAP == want {
				filtered = append(filtered, candidate)
			}
		}

		candidates = filtered
	}

	groups := groupCandidates(candidates)
	optimalLines, optimalWarnings := extractOptimal22000(groups)
	pmkidLines, pmkidWarnings := extract16800Lines(groups)

	printExtractSummary(options, linkType, frames, stats, groups, optimalLines)

	for _, warning := range append(optimalWarnings, pmkidWarnings...) {
		utilities.Warn("%s", warning)
	}

	if options.HashcatOut != "" {
		if len(optimalLines) == 0 {
			utilities.Warn("没有可写入的 22000 行（缺握手对且缺 PMKID，或 ESSID 未知），%s 未创建", options.HashcatOut)
		} else if err := writeHashLines(options.HashcatOut, optimalLines); err != nil {
			return err
		} else {
			utilities.Info("22000 行已写入 %s（%d 行）：hashcat -m 22000 %s 字典.txt", options.HashcatOut, len(optimalLines), options.HashcatOut)
		}
	}

	if options.PMKIDOut != "" {
		if len(pmkidLines) == 0 {
			utilities.Warn("未发现 PMKID 候选，%s 未创建；握手对可用 --hashcat 路径导出", options.PMKIDOut)
		} else if err := writeHashLines(options.PMKIDOut, pmkidLines); err != nil {
			return err
		} else {
			utilities.Info("16800 行已写入 %s（%d 行）：hashcat -m 16800 %s 字典.txt（旧版 hashcat）", options.PMKIDOut, len(pmkidLines), options.PMKIDOut)
		}
	}

	if options.JSON {
		return printExtractJSON(options, linkType, frames, stats, groups)
	}

	return nil
}

// groupCandidates 按 AP MAC 归组；输出按 MACAP 排序保证结果稳定。
func groupCandidates(candidates []eapol.Candidate) []extractGroup {
	index := make(map[string]*extractGroup)

	for _, candidate := range candidates {
		group := index[candidate.MACAP]
		if group == nil {
			group = &extractGroup{MACAP: candidate.MACAP}
			index[candidate.MACAP] = group
		}

		// ESSID/信道取组内首个非零值：多候选同 AP 时信息一致。
		if group.ESSID == "" && candidate.ESSID != "" {
			group.ESSID = candidate.ESSID
			group.ESSIDKnown = candidate.ESSIDKnown
		}
		if group.Channel == 0 && candidate.Channel != 0 {
			group.Channel = candidate.Channel
		}

		if candidate.Kind == eapol.KindPMKID {
			group.PMKIDs = append(group.PMKIDs, candidate)
		} else {
			group.EAPOLs = append(group.EAPOLs, candidate)
		}
	}

	groups := make([]extractGroup, 0, len(index))
	for _, group := range index {
		groups = append(groups, *group)
	}

	sort.Slice(groups, func(i, j int) bool { return groups[i].MACAP < groups[j].MACAP })

	return groups
}

// extractOptimal22000 按组择优产出 22000 行：同一 AP 有 PMKID 时只写
// PMKID（长期有效、不依赖握手时序），否则退回全部握手对候选——
// hashcat 对重复 hash 自行去重，多一条候选就多一分命中概率。
// ESSID 未知（隐藏网络且无 --ssid）的候选跳过并给出可行动提示。
func extractOptimal22000(groups []extractGroup) ([]string, []string) {
	var (
		lines    []string
		warnings []string
	)

	for _, group := range groups {
		source := group.EAPOLs
		if len(group.PMKIDs) > 0 {
			source = group.PMKIDs
		}

		for _, candidate := range source {
			line, err := eapol.Format22000(candidate)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("AP %s 的候选被跳过：%v（重跑时加 --ssid）", candidate.MACAP, err))
				continue
			}

			lines = append(lines, line)
		}
	}

	return lines, warnings
}

// extract16800Lines 产出旧版 hashcat 16800 行（仅 PMKID 候选）。
func extract16800Lines(groups []extractGroup) ([]string, []string) {
	var (
		lines    []string
		warnings []string
	)

	for _, group := range groups {
		for _, candidate := range group.PMKIDs {
			line, err := eapol.Format16800(candidate)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("AP %s 的 PMKID 被 16800 跳过：%v", candidate.MACAP, err))
				continue
			}

			lines = append(lines, line)
		}
	}

	return lines, warnings
}

// writeHashLines 以 0600 落盘 hash 行集合（每行一条，结尾换行）。
func writeHashLines(path string, lines []string) error {
	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), pmkidHashFileMode); err != nil {
		return fmt.Errorf("写入 %s 失败：%w", path, err)
	}

	return nil
}

// printExtractSummary 输出人类可读摘要：三项核心指标（完整握手数、
// PMKID 有无、各帧合法性）在前，逐 AP 明细在后。
func printExtractSummary(options ExtractOptions, linkType uint32, frames int, stats eapol.Stats, groups []extractGroup, optimalLines []string) {
	head := []string{
		fmt.Sprintf("pcap 分析完成：%s", filepath.Clean(options.Input)),
		fmt.Sprintf("  链路 DLT %d · 共 %d 帧 · EAPOL-Key %d 帧", linkType, frames, stats.EAPOLFrames),
		fmt.Sprintf("  M1 %d · M2 %d · M3 %d · M4 %d · 完整握手配对 %d · PMKID 候选 %d",
			stats.M1Count, stats.M2Count, stats.M3Count, stats.M4Count, stats.Pairs, stats.PMKIDCandidates),
	}

	if len(groups) == 0 {
		head = append(head, "  未发现可离线破解的候选：无握手对、无 PMKID（可检查 pcap 是否覆盖了目标 AP 的信道）")
		utilities.Info("%s", strings.Join(head, "\n"))

		return
	}

	head = append(head, fmt.Sprintf("  覆盖 AP %d 个 · 择优后 %d 条 hash 行", len(groups), len(optimalLines)))

	for _, group := range groups {
		essid := "<未知（--ssid 可补 salt）>"
		if group.ESSIDKnown {
			essid = group.ESSID
		}

		detail := fmt.Sprintf("  AP %s（%.32s", group.MACAP, essid)
		if group.Channel != 0 {
			detail += fmt.Sprintf(" · 信道 %d", group.Channel)
		}
		detail += "）"

		lines := []string{detail}

		if len(group.PMKIDs) > 0 {
			lines = append(lines, fmt.Sprintf("    PMKID   有（%s）", hexOfPMKID(group.PMKIDs[0])))
		} else {
			lines = append(lines, "    PMKID   无")
		}

		if counts := messagePairCounts(group.EAPOLs); counts != "" {
			lines = append(lines, "    握手    "+counts)
		} else {
			lines = append(lines, "    握手    无完整配对")
		}

		head = append(head, lines...)
	}

	utilities.Info("%s", strings.Join(head, "\n"))
}

// hexOfPMKID 渲染 PMKID 的小写无冒号 hex（摘要展示用）。
func hexOfPMKID(candidate eapol.Candidate) string {
	return hex.EncodeToString(candidate.PMKID[:])
}

// messagePairCounts 汇总组内握手对的 messagepair 分布。
func messagePairCounts(candidates []eapol.Candidate) string {
	if len(candidates) == 0 {
		return ""
	}

	names := map[byte]string{
		eapol.MessagePairM1M2: "M1M2",
		eapol.MessagePairM1M4: "M1M4",
		eapol.MessagePairM2M3: "M2M3",
		eapol.MessagePairM3M4: "M3M4",
	}

	counts := make(map[byte]int)
	for _, candidate := range candidates {
		counts[candidate.MessagePair]++
	}

	// 固定顺序输出，保证同输入同输出（map 遍历序不稳定）。
	order := []byte{eapol.MessagePairM1M2, eapol.MessagePairM2M3, eapol.MessagePairM3M4, eapol.MessagePairM1M4}

	parts := make([]string, 0, len(counts))
	for _, pair := range order {
		if counts[pair] > 0 {
			parts = append(parts, fmt.Sprintf("%s ×%d", names[pair], counts[pair]))
		}
	}

	return strings.Join(parts, " · ")
}

// printExtractJSON 输出机器可读报告。
func printExtractJSON(options ExtractOptions, linkType uint32, frames int, stats eapol.Stats, groups []extractGroup) error {
	report := extractJSONReport{
		Input:    filepath.Clean(options.Input),
		LinkType: linkType,
		Stats: extractJSONStats{
			Frames:          frames,
			EAPOLKeyFrames:  stats.EAPOLFrames,
			M1:              stats.M1Count,
			M2:              stats.M2Count,
			M3:              stats.M3Count,
			M4:              stats.M4Count,
			HandshakePairs:  stats.Pairs,
			PMKIDCandidates: stats.PMKIDCandidates,
		},
		Groups: make([]extractJSONGroup, 0, len(groups)),
	}

	for _, group := range groups {
		jsonGroup := extractJSONGroup{
			MACAP:      group.MACAP,
			ESSID:      group.ESSID,
			ESSIDKnown: group.ESSIDKnown,
			Channel:    group.Channel,
		}

		for _, candidate := range group.PMKIDs {
			if line, err := eapol.Format22000(candidate); err == nil {
				jsonGroup.PMKID22000 = append(jsonGroup.PMKID22000, line)
			}
			if line, err := eapol.Format16800(candidate); err == nil {
				jsonGroup.PMKID16800 = append(jsonGroup.PMKID16800, line)
			}
		}

		for _, candidate := range group.EAPOLs {
			if line, err := eapol.Format22000(candidate); err == nil {
				jsonGroup.EAPOL22000 = append(jsonGroup.EAPOL22000, line)
			}
		}

		report.Groups = append(report.Groups, jsonGroup)
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	fmt.Println(string(data))

	return nil
}
