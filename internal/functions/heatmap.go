// heatmap.go 实现 `wifisec heatmap` 无线走位勘测 TUI：
// 把终端变成一个可交互的平面图——方向键移动光标标记"我现在站在这里"，
// 空格触发一轮真实扫描把目标 AP 的 RSSI 钉进当前格子，
// 网格用 ANSI 256 色按信号分级渲染，未采样区域做 IDW 插值，
// 右侧实时列出周边 AP 与风险徽章（复用 wids.SecurityLevel 口径）。
//
// 设计取向：全部数据来自 scanNetworks() 的真实扫描，零伪造、零模拟；
// 插值半径有硬上限，宁可留白也不远距离编造覆盖。退出自动落盘 JSON，
// 可复测、可归档、可交给其他工具消费。
//
// 终端控制只用标准转义序列（备用屏幕 + 光标寻址 + 256 色），
// 原始输入靠 golang.org/x/term；不引入任何 TUI 框架。
package functions

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ctkqiang/wifisec/internal/heatmap"
	"github.com/ctkqiang/wifisec/internal/utilities"
	"github.com/ctkqiang/wifisec/internal/wids"
	"golang.org/x/term"
)

// 面板宽度与网格最低尺寸。面板 36 列刚好放下
// "SSID（截断）+ dBm + 加密"一行；终端太窄时放弃面板保网格。
const (
	heatPanelWidth = 36
	heatMinCols    = 20
	heatMinRows    = 8
	heatMaxTargets = 9
)

// heatTarget 是勘测目标（一个 AP）。BSSID 被系统隐藏
// （macOS 未授权定位）时按 SSID 匹配采样，Key 退化为 "ssid:<ESSID>"。
type heatTarget struct {
	Key     string // BSSID（大写）或 ssid:<ESSID>
	SSID    string
	BSSID   string
	Channel int
	Signal  int
	Enc     string
	Cipher  string
}

// HeatmapOptions 是 heatmap 子命令的参数集。
type HeatmapOptions struct {
	SSID     string // 目标 SSID（空 = 信号最强者）
	PlanPath string // 可选 ASCII 平面图文件
}

// ParseHeatmapArgs 按位置语义解析：存在的文件路径是平面图，
// 其余首个 token 是目标 SSID；多余 token 报错。
func ParseHeatmapArgs(arguments []string) (HeatmapOptions, error) {
	options := HeatmapOptions{}

	for _, raw := range arguments {
		token := strings.TrimSpace(raw)
		if token == "" {
			continue
		}

		switch {
		case strings.HasPrefix(token, "-"):
			return options, fmt.Errorf("无法识别的参数 %q", token)
		case fileExists(token):
			if options.PlanPath != "" {
				return options, fmt.Errorf("平面图只能指定一个：%q 多余", token)
			}

			options.PlanPath = token
		default:
			if options.SSID != "" {
				return options, fmt.Errorf("无法识别的多余参数 %q", token)
			}

			options.SSID = token
		}
	}

	return options, nil
}

// fileExists 判定路径是否为存在的普通文件（目录不算）。
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// heatSession 是一次 TUI 勘测会话的全部可变状态。
type heatSession struct {
	surveys  map[string]*heatmap.Survey // target key → 独立网格
	targets  []heatTarget
	current  int // 当前目标下标
	cursorX  int
	cursorY  int
	gridCols int
	gridRows int
	termCols int
	termRows int
	status   string
	plan     []string
}

// RunHeatmap 是 `wifisec heatmap` 的入口。
func RunHeatmap(arguments []string) error {
	options, err := ParseHeatmapArgs(arguments)
	if err != nil {
		return err
	}

	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		return fmt.Errorf("热力图需要交互式终端（检测到管道/重定向），请直接在终端中运行")
	}

	utilities.Warn("勘测数据包含周边网络信号指纹，仅限自有场所或已获书面授权的环境使用")

	var plan []string

	if options.PlanPath != "" {
		raw, err := os.ReadFile(options.PlanPath)
		if err != nil {
			return fmt.Errorf("读取平面图 %s 失败：%w", options.PlanPath, err)
		}

		plan = strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")
	}

	networks, err := scanNetworks()
	if err != nil {
		return fmt.Errorf("初始扫描失败：%w", err)
	}

	targets := CollectHeatTargets(networks)
	if len(targets) == 0 {
		return fmt.Errorf("未发现任何无线网络，无法勘测")
	}

	current := 0
	if options.SSID != "" {
		matched := -1
		for index, target := range targets {
			if target.SSID == options.SSID {
				matched = index
				break
			}
		}

		if matched < 0 {
			return fmt.Errorf("目标 SSID %q 当前不可见：请确认在信号覆盖范围内并检查拼写", options.SSID)
		}

		current = matched
	}

	return runHeatTUI(targets, current, plan)
}

// CollectHeatTargets 把扫描结果按 AP 去重（BSSID 优先，隐藏时按 SSID），
// 同 AP 多条记录保留信号最强者，按信号降序排列。
// BSSID 缺失（"-"/":"）必须退回 SSID 键，否则全部网络坍缩成一个目标。
func CollectHeatTargets(networks []WiFiNetwork) []heatTarget {
	byKey := make(map[string]heatTarget)

	for _, network := range networks {
		key := ""
		if bssidPresent(network.BSSID) {
			key = normalizeMAC(network.BSSID)
		}

		if key == "" {
			key = "ssid:" + network.ESSID
		}

		if existing, ok := byKey[key]; ok && existing.Signal >= network.Signal {
			continue
		}

		byKey[key] = heatTarget{
			Key:     key,
			SSID:    network.ESSID,
			BSSID:   key,
			Channel: network.Channel,
			Signal:  network.Signal,
			Enc:     network.Enc,
			Cipher:  network.Cipher,
		}
	}

	targets := make([]heatTarget, 0, len(byKey))
	for _, target := range byKey {
		targets = append(targets, target)
	}

	sort.Slice(targets, func(i, j int) bool {
		return targets[i].Signal > targets[j].Signal
	})

	if len(targets) > heatMaxTargets {
		targets = targets[:heatMaxTargets]
	}

	return targets
}

// runHeatTUI 进入原始模式 + 备用屏幕的交互主循环。
func runHeatTUI(targets []heatTarget, current int, plan []string) error {
	termCols, termRows, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		return fmt.Errorf("读取终端尺寸失败：%w", err)
	}

	panel := 0
	if termCols >= heatPanelWidth+heatMinCols*2 {
		panel = heatPanelWidth
	}

	gridCols := (termCols - panel) / 2
	gridRows := termRows - 3 // 标题行 + 图例行 + 状态行

	if gridCols < heatMinCols || gridRows < heatMinRows {
		return fmt.Errorf("终端窗口太小（%dx%d），网格至少需要 %dx%d", termCols, termRows, heatMinCols*2+panel, heatMinRows+3)
	}

	session := &heatSession{
		surveys:  make(map[string]*heatmap.Survey),
		targets:  targets,
		current:  current,
		gridCols: gridCols,
		gridRows: gridRows,
		termCols: termCols,
		termRows: termRows,
		status:   "方向键/hjkl 移动 · 空格 采样 · Tab 切换目标 · x 清除 · s 保存 · q 退出",
		plan:     plan,
	}

	// 恢复终端是硬约束：任何退出路径都不能把用户留在原始模式。
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("进入原始模式失败：%w", err)
	}

	defer func() {
		fmt.Fprint(os.Stdout, "\x1b[?25h\x1b[?1049l")
		_ = term.Restore(int(os.Stdin.Fd()), oldState)
	}()

	fmt.Fprint(os.Stdout, "\x1b[?1049h\x1b[?25l")
	renderHeat(session)

	keys := make(chan byte, 64)
	go readHeatKeys(keys)

	saved := ""

	for {
		key := <-keys

		switch key {
		case 'q', 0x03: // q 或 Ctrl-C
			return finishHeatSession(session, saved)
		case 'k', 'K':
			session.cursorY = maxInt(0, session.cursorY-1)
		case 'j', 'J':
			session.cursorY = minInt(session.gridRows-1, session.cursorY+1)
		case 'h', 'H':
			session.cursorX = maxInt(0, session.cursorX-1)
		case 'l', 'L':
			session.cursorX = minInt(session.gridCols-1, session.cursorX+1)
		case 0x1b: // 方向键：ESC [ A/B/C/D
			handleHeatArrow(session, keys)
		case ' ', '\r':
			sampleHeatCell(session)
		case '\t':
			session.current = (session.current + 1) % len(session.targets)
			session.status = fmt.Sprintf("目标切换为 %q（各目标网格独立）", session.targets[session.current].SSID)
		case 'x', 'X':
			session.survey().Clear(session.cursorX, session.cursorY)
			session.status = "已清除当前格采样"
		case 's', 'S':
			if path, err := saveHeatSurveys(session); err != nil {
				session.status = "保存失败：" + err.Error()
			} else {
				saved = path
				session.status = "已保存到 " + path
			}
		}

		renderHeat(session)
	}
}

// survey 返回当前目标的网格，首次访问时创建。
func (session *heatSession) survey() *heatmap.Survey {
	target := session.targets[session.current]

	if existing, ok := session.surveys[target.Key]; ok {
		return existing
	}

	created := heatmap.NewSurvey(target.SSID, target.BSSID, session.gridCols, session.gridRows, session.plan)
	session.surveys[target.Key] = created

	return created
}

// readHeatKeys 持续从原始终端读取按键字节送进通道；
// 方向键的 ESC 序列拆成多字节到达，由主循环的 handleHeatArrow 续读。
func readHeatKeys(keys chan<- byte) {
	buffer := make([]byte, 64)

	for {
		n, err := os.Stdin.Read(buffer)
		if err != nil {
			close(keys)
			return
		}

		for index := 0; index < n; index++ {
			keys <- buffer[index]
		}
	}
}

// handleHeatArrow 续读方向键转义序列的剩余字节（"[A" 等）。
// 序列不完整时静默丢弃——多丢一次方向键不比死循环可怕。
func handleHeatArrow(session *heatSession, keys <-chan byte) {
	select {
	case bracket := <-keys:
		if bracket != '[' {
			return
		}
	case <-time.After(50 * time.Millisecond):
		return
	}

	select {
	case arrow := <-keys:
		switch arrow {
		case 'A':
			session.cursorY = maxInt(0, session.cursorY-1)
		case 'B':
			session.cursorY = minInt(session.gridRows-1, session.cursorY+1)
		case 'C':
			session.cursorX = minInt(session.gridCols-1, session.cursorX+1)
		case 'D':
			session.cursorX = maxInt(0, session.cursorX-1)
		}
	case <-time.After(50 * time.Millisecond):
	}
}

// sampleHeatCell 触发一轮真实扫描，把目标在当前位置的 RSSI 钉进网格。
// 目标本轮不可见（走出覆盖/扫描抖动）时不写入，状态行明说。
func sampleHeatCell(session *heatSession) {
	target := session.targets[session.current]
	session.status = fmt.Sprintf("正在扫描 %q…", target.SSID)
	renderHeat(session)

	networks, err := scanNetworks()
	if err != nil {
		session.status = "扫描失败：" + err.Error()
		return
	}

	best := 0
	found := false

	for _, network := range networks {
		matched := false

		if strings.HasPrefix(target.Key, "ssid:") {
			matched = network.ESSID == target.SSID
		} else {
			matched = normalizeMAC(network.BSSID) == target.BSSID
		}

		if matched && (!found || network.Signal > best) {
			best = network.Signal
			found = true
		}
	}

	if !found {
		session.status = fmt.Sprintf("目标 %q 本轮不可见，未记录（可能走出覆盖）", target.SSID)
		return
	}

	session.survey().Set(session.cursorX, session.cursorY, best)
	session.status = fmt.Sprintf("(%d,%d) 采样 %d dBm · 累计 %d 格", session.cursorX, session.cursorY, best, session.survey().SampleCount())
}

// saveHeatSurveys 把全部目标的网格各存一个 JSON 文件，返回文件名列表。
func saveHeatSurveys(session *heatSession) (string, error) {
	if len(session.surveys) == 0 {
		return "", fmt.Errorf("还没有任何采样")
	}

	stamp := time.Now().Format("20060102-150405")
	names := make([]string, 0, len(session.surveys))

	for _, survey := range session.surveys {
		if survey.SampleCount() == 0 {
			continue
		}

		name := fmt.Sprintf("heatmap-%s-%s.json", sanitizeFilename(survey.SSID), stamp)
		if err := survey.Save(name); err != nil {
			return "", err
		}

		names = append(names, name)
	}

	if len(names) == 0 {
		return "", fmt.Errorf("还没有任何采样")
	}

	return strings.Join(names, ", "), nil
}

// sanitizeFilename 把 SSID 折算成文件名片段：路径分隔符与空白替换为下划线。
func sanitizeFilename(ssid string) string {
	var builder strings.Builder

	for _, r := range ssid {
		switch {
		case r == '/' || r == '\\' || r == ' ':
			builder.WriteByte('_')
		default:
			builder.WriteRune(r)
		}
	}

	name := strings.Trim(builder.String(), "_")
	if name == "" {
		return "unnamed"
	}

	return name
}

// finishHeatSession 退出收尾：有采样则自动落盘，打印统计。
func finishHeatSession(session *heatSession, saved string) error {
	fmt.Fprint(os.Stdout, "\x1b[?25h\x1b[?1049l")

	total := 0
	for _, survey := range session.surveys {
		total += survey.SampleCount()
	}

	if total == 0 {
		utilities.Info("本次勘测未采样，未生成文件")
		return nil
	}

	if saved == "" {
		if path, err := saveHeatSurveys(session); err == nil {
			saved = path
		}
	}

	for _, survey := range session.surveys {
		if survey.SampleCount() == 0 {
			continue
		}

		minimum, average, maximum := survey.Stats()

		utilities.Info(
			"目标 %q：采样 %d 格 · 信号 %d ~ %d dBm（均值 %d）",
			survey.SSID, survey.SampleCount(), minimum, maximum, average,
		)

		if col, row, rssi, ok := survey.StrongestCell(); ok {
			utilities.Info("目标 %q 的 AP 方位估计：格 (%d,%d) 信号最强（%d dBm）", survey.SSID, col, row, rssi)
		}
	}

	if saved != "" {
		utilities.Info("勘测数据已保存：%s", saved)
	}

	return nil
}

// renderHeat 全量重绘：标题行 + 网格 + 侧栏 + 图例 + 状态行，
// 组装进一个 buffer 一次写出，避免逐格写造成的闪烁。
//
// raw 模式下终端关闭了 ONLCR，"\n" 只下移光标不回车——行尾必须写
// "\r\n"，否则每行从前一行的结束列开始画，整屏呈楼梯状错位。
// 每行再裁剪到终端显示宽度（CJK 占 2 格），杜绝超宽折行打乱行序。
func renderHeat(session *heatSession) {
	var buffer bytes.Buffer

	buffer.WriteString("\x1b[H") // 光标归位（备用屏幕内全量覆盖）

	target := session.targets[session.current]
	survey := session.survey()

	title := fmt.Sprintf(
		"\x1b[1m wifisec heatmap · 目标 \x1b[36m%s\x1b[0m\x1b[1m · 采样 %d 格 · 目标 %d/%d\x1b[0m",
		target.SSID, survey.SampleCount(), session.current+1, len(session.targets),
	)

	buffer.WriteString(fitCells(title, session.termCols))
	buffer.WriteString("\x1b[K\r\n")

	strongestCol, strongestRow, _, hasStrongest := survey.StrongestCell()

	for row := 0; row < session.gridRows; row++ {
		for col := 0; col < session.gridCols; col++ {
			buffer.WriteString(renderHeatCell(session, survey, col, row, strongestCol, strongestRow, hasStrongest))
		}

		if panelLine, ok := renderHeatPanelLine(session, row); ok {
			buffer.WriteByte(' ')
			buffer.WriteString(fitCells(panelLine, session.termCols-session.gridCols*2-1))
		}

		buffer.WriteString("\x1b[K\r\n")
	}

	renderHeatLegend(&buffer, session.termCols)
	buffer.WriteString("\r\n")

	buffer.WriteString(fitCells("\x1b[90m "+session.status+"\x1b[0m", session.termCols))

	_, _ = os.Stdout.Write(buffer.Bytes())
}

// renderHeatCell 渲染一个网格单元（2 字符宽）：
// 精确采样=实色块，插值=▒ 点阵，最强采样点叠加 @@ 标记 AP 方位，
// 光标格反显。未采样处透出平面图字符（暗灰）。
func renderHeatCell(session *heatSession, survey *heatmap.Survey, col, row, strongestCol, strongestRow int, hasStrongest bool) string {
	isCursor := col == session.cursorX && row == session.cursorY

	if rssi, exact := survey.At(col, row); exact {
		color := heatmap.LevelColor(heatmap.RSSILevel(rssi))

		if hasStrongest && col == strongestCol && row == strongestRow {
			return fmt.Sprintf("\x1b[48;5;%dm\x1b[1;37m@@\x1b[0m", color)
		}

		if isCursor {
			return fmt.Sprintf("\x1b[48;5;%dm\x1b[7;1m▓▓\x1b[0m", color)
		}

		return fmt.Sprintf("\x1b[48;5;%dm  \x1b[0m", color)
	}

	if rssi, ok := survey.Interpolated(col, row); ok {
		color := heatmap.LevelColor(heatmap.RSSILevel(rssi))

		if isCursor {
			return fmt.Sprintf("\x1b[38;5;%dm\x1b[7m▓▓\x1b[0m", color)
		}

		return fmt.Sprintf("\x1b[38;5;%dm▒▒\x1b[0m", color)
	}

	if isCursor {
		return "\x1b[48;5;250m\x1b[30m<>\x1b[0m"
	}

	if char := survey.PlanChar(col, row); char != 0 && char != ' ' {
		return fmt.Sprintf("\x1b[38;5;240m%c \x1b[0m", char)
	}

	return "  "
}

// renderHeatPanelLine 渲染右侧 AP 列表面板的第 row 行。
// 每个 AP 两行：首行 SSID+信号+加密，次行 BSSID+信道+风险徽章。
// SSID 按显示宽度截断并补齐（CJK 占 2 格），保证后续列垂直对齐。
func renderHeatPanelLine(session *heatSession, row int) (string, bool) {
	if session.termCols-session.gridCols*2 < heatPanelWidth {
		return "", false
	}

	if row == 0 {
		return "\x1b[1m 周边 AP（信号降序）\x1b[0m", true
	}

	if row == 1 {
		return "\x1b[90m " + strings.Repeat("─", heatPanelWidth-2) + "\x1b[0m", true
	}

	index := (row - 2) / 2
	if index < 0 || index >= len(session.targets) {
		return "", false
	}

	target := session.targets[index]
	pointer := "  "

	if index == session.current {
		pointer = "\x1b[36m►\x1b[0m "
	}

	if (row-2)%2 == 0 {
		ssid := target.SSID
		if ssid == "" {
			ssid = "(隐藏)"
		}

		return fmt.Sprintf(
			"%s%s \x1b[1m%4d\x1b[0m dBm %s",
			pointer, padCells(clipCells(ssid, 14), 14), target.Signal, strings.ToUpper(target.Enc),
		), true
	}

	badge, badgeColor := riskBadge(target.Enc, target.Cipher)

	return fmt.Sprintf(
		"  \x1b[90m%s ch%d\x1b[0m %s%s\x1b[0m",
		clipCells(target.BSSID, 17), target.Channel, badgeColor, badge,
	), true
}

// riskBadge 按 wids.SecurityLevel 口径生成风险徽章文本与颜色。
func riskBadge(enc, cipher string) (string, string) {
	switch wids.SecurityLevel(enc, cipher) {
	case 0:
		return "[开放]", "\x1b[1;31m"
	case 1:
		return "[WEP]", "\x1b[1;31m"
	case 2:
		return "[弱加密]", "\x1b[33m"
	default:
		return "", ""
	}
}

// renderHeatLegend 输出图例行：分级色块 + dBm 区间 + 符号说明。
// 终端太窄时丢弃尾部说明文字，只保色块区间——折行会打乱全屏行序。
func renderHeatLegend(buffer *bytes.Buffer, termCols int) {
	labels := [5]string{"<-80", "-80", "-70", "-60", "≥-50"}

	var line strings.Builder
	line.WriteString(" ")

	for level := heatmap.LevelDead; level <= heatmap.LevelExcellent; level++ {
		fmt.Fprintf(
			&line,
			"\x1b[48;5;%dm  \x1b[0m\x1b[90m%s\x1b[0m ",
			heatmap.LevelColor(level), labels[level],
		)
	}

	line.WriteString("\x1b[90mdBm · ▒▒=插值 @@=AP方位估计 · 空格=在此采样\x1b[0m")

	buffer.WriteString(fitCells(line.String(), termCols))
}

// displayWidth 返回字符串的终端显示宽度：CJK/全角字符占 2 格，
// ANSI 转义序列占 0 格。TUI 对齐全靠它——Go 的 len/%-Ns 按字节或
// rune 计数，遇到中文必然错位。
func displayWidth(text string) int {
	width := 0
	inEscape := false
	gotBracket := false

	for _, r := range text {
		switch {
		case inEscape:
			// CSI 结构：ESC '[' 参数字节(0x30-0x3F) 收尾字节(0x40-0x7E)。
			// '[' 自身也在收尾区间内，必须先单独吞掉，否则序列被提前截断。
			if !gotBracket {
				gotBracket = r == '['
				continue
			}

			if r >= 0x40 && r <= 0x7e {
				inEscape = false
				gotBracket = false
			}
		case r == 0x1b:
			inEscape = true
		case isWideRune(r):
			width += 2
		default:
			width++
		}
	}

	return width
}

// clipCells 按显示宽度截断纯文本（不含转义序列），超长补 …。
func clipCells(text string, limit int) string {
	if displayWidth(text) <= limit {
		return text
	}

	if limit <= 1 {
		return "…"
	}

	var builder strings.Builder
	width := 0

	for _, r := range text {
		rw := 1
		if isWideRune(r) {
			rw = 2
		}

		if width+rw > limit-1 {
			break
		}

		builder.WriteRune(r)
		width += rw
	}

	return builder.String() + "…"
}

// padCells 把纯文本右侧补空格到恰好 width 个显示格。
func padCells(text string, width int) string {
	gap := width - displayWidth(text)
	if gap <= 0 {
		return text
	}

	return text + strings.Repeat(" ", gap)
}

// fitCells 把含 ANSI 转义的整行裁剪到终端宽度内：
// 转义序列原样保留（零宽度），可见字符按显示格计，
// 超限直接截断并补 reset，保证残余颜色不泄漏到下一行。
func fitCells(line string, limit int) string {
	if displayWidth(line) <= limit {
		return line
	}

	var builder strings.Builder
	width := 0
	inEscape := false
	gotBracket := false

	for _, r := range line {
		switch {
		case inEscape:
			builder.WriteRune(r)
			if !gotBracket {
				gotBracket = r == '['
				continue
			}

			if r >= 0x40 && r <= 0x7e {
				inEscape = false
				gotBracket = false
			}
		case r == 0x1b:
			inEscape = true
			builder.WriteRune(r)
		default:
			rw := 1
			if isWideRune(r) {
				rw = 2
			}

			if width+rw > limit {
				builder.WriteString("\x1b[0m")
				return builder.String()
			}

			builder.WriteRune(r)
			width += rw
		}
	}

	return builder.String()
}

// maxInt/minInt 是局部小工具，避免为两个分支引入 math 包。
func maxInt(a, b int) int {
	if a > b {
		return a
	}

	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}

	return b
}
