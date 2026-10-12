// Package heatmap 是走位勘测（site survey）的纯数据层：
// 维护"网格坐标 → 信号强度（dBm）"的采样表，提供 IDW 插值把离散
// 采样点渲染成连续热力图，并负责勘测结果的 JSON 持久化。
//
// 包内不触碰终端与系统资源：渲染由 functions 层的 TUI 负责，
// 这样网格数学可以完整表驱动测试。
//
// 物理常识写进实现注释：RSSI 是负值，越接近 0 越强；
// 自由空间路径损耗下距离翻倍信号约 -6dB，隔墙一次约 -3~-12dB，
// 因此 IDW 的 1/d² 权重是对室内衰减的一阶近似——不是精确模型，
// 但足以让"走到哪测到哪"的离散点连成可读的渐变面。
package heatmap

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"time"
)

// 信号分级边界（dBm）。分级口径对齐行业惯例：
// ≥-50 极好（贴着 AP）、-60 良好（高清会议无压力）、
// -70 可用（网页/标清）、-80 勉强（ roaming 阈值附近）、
// 再低视同死角。颜色索引对应 ANSI 256 色板。
const (
	LevelExcellent = 4
	LevelGood      = 3
	LevelFair      = 2
	LevelWeak      = 1
	LevelDead      = 0
)

// levelColors 是各分级的 ANSI 256 背景色：
// 绿→黄绿→金→橙→红，色弱用户也能按亮度递增读图。
var levelColors = [5]int{196, 208, 220, 112, 46}

// LevelColor 返回分级对应的 ANSI 256 色号，渲染层直接取用。
func LevelColor(level int) int {
	if level < LevelDead {
		return levelColors[LevelDead]
	}

	if level > LevelExcellent {
		return levelColors[LevelExcellent]
	}

	return levelColors[level]
}

// RSSILevel 把 dBm 折算成 0-4 的分级。
// 输入为 0（扫描器缺数据，物理上 Wi-Fi 不可能正好 0 dBm）按死角处理——
// 宁可保守标红也不虚报覆盖。
func RSSILevel(rssi int) int {
	if rssi == 0 {
		return LevelDead
	}

	switch {
	case rssi >= -50:
		return LevelExcellent
	case rssi >= -60:
		return LevelGood
	case rssi >= -70:
		return LevelFair
	case rssi >= -80:
		return LevelWeak
	default:
		return LevelDead
	}
}

// cellKey 把 (col,row) 折叠成 map 键。
func cellKey(col, row, cols int) int {
	return row*cols + col
}

// Survey 是一次走位勘测的全部状态。
// Cells 的键为 row*Cols+col，值为 dBm（负值）。
type Survey struct {
	SSID      string        `json:"ssid"`  // 目标网络
	BSSID     string        `json:"bssid"` // 目标 AP（macOS 隐藏时为空，按 SSID 采样）
	Cols      int           `json:"cols"`  // 网格列数（每格 2 字符宽）
	Rows      int           `json:"rows"`  // 网格行数
	Cells     map[int]int   `json:"cells"` // 采样点
	Plan      []string      `json:"plan"`  // 可选平面图背景（逐行字符）
	StartedAt time.Time     `json:"started_at"`
	updated   map[int]int64 // 内部：采样时间戳（毫秒），不入 JSON
}

// NewSurvey 创建勘测。plan 可为 nil；行数超出网格的部分裁剪，
// 不足部分留空，渲染层按行号直接取。
func NewSurvey(ssid, bssid string, cols, rows int, plan []string) *Survey {
	if len(plan) > rows {
		plan = plan[:rows]
	}

	return &Survey{
		SSID:      ssid,
		BSSID:     bssid,
		Cols:      cols,
		Rows:      rows,
		Cells:     make(map[int]int),
		Plan:      plan,
		StartedAt: time.Now(),
		updated:   make(map[int]int64),
	}
}

// Set 在 (col,row) 记录一次采样；同点重复采样取最新值——
// 走位勘测的意义就是"现在站在这"，旧值没有保留价值。
func (survey *Survey) Set(col, row, rssi int) {
	if col < 0 || col >= survey.Cols || row < 0 || row >= survey.Rows {
		return
	}

	key := cellKey(col, row, survey.Cols)
	survey.Cells[key] = rssi
	survey.updated[key] = time.Now().UnixMilli()
}

// Clear 移除 (col,row) 的采样（按错格子的后悔药）。
func (survey *Survey) Clear(col, row int) {
	key := cellKey(col, row, survey.Cols)
	delete(survey.Cells, key)
	delete(survey.updated, key)
}

// At 返回 (col,row) 的精确采样值。
func (survey *Survey) At(col, row int) (int, bool) {
	rssi, ok := survey.Cells[cellKey(col, row, survey.Cols)]
	return rssi, ok
}

// SampleCount 返回已采样格数。
func (survey *Survey) SampleCount() int {
	return len(survey.Cells)
}

// interpolationRadius 返回插值影响半径（格）：
// 网格越大半径越大，上限 12 防止远端样本污染局部判断。
// 采样点稀疏时宁可留白（显示平面图）也不远距离脑补——
// 隔墙衰减不遵守 1/d²，远距离插值是在编造覆盖。
func (survey *Survey) interpolationRadius() int {
	radius := (survey.Cols + survey.Rows) / 6

	switch {
	case radius < 4:
		return 4
	case radius > 12:
		return 12
	default:
		return radius
	}
}

// Interpolated 返回 (col,row) 的 IDW 插值：精确采样优先，
// 否则对半径内全部采样点做 1/d² 加权平均；半径内无采样点返回 false。
func (survey *Survey) Interpolated(col, row int) (int, bool) {
	if rssi, ok := survey.At(col, row); ok {
		return rssi, true
	}

	radius := survey.interpolationRadius()
	var weighted, weights float64

	for key, rssi := range survey.Cells {
		sampleCol := key % survey.Cols
		sampleRow := key / survey.Cols

		distance := math.Hypot(float64(col-sampleCol), float64(row-sampleRow))
		if distance < 1 || distance > float64(radius) {
			continue
		}

		weight := 1 / (distance * distance)
		weighted += weight * float64(rssi)
		weights += weight
	}

	if weights == 0 {
		return 0, false
	}

	return int(math.Round(weighted / weights)), true
}

// StrongestCell 返回信号最强的采样格——采样点中最接近 AP 的位置，
// 作为 AP 方位的粗估计在图上标记。无采样返回 false。
func (survey *Survey) StrongestCell() (col, row, rssi int, ok bool) {
	first := true

	for key, value := range survey.Cells {
		if first || value > rssi {
			col = key % survey.Cols
			row = key / survey.Cols
			rssi = value
			ok = true
			first = false
		}
	}

	return
}

// Stats 汇总采样统计：最低/平均/最高 dBm。
func (survey *Survey) Stats() (minRSSI, avgRSSI, maxRSSI int) {
	if len(survey.Cells) == 0 {
		return 0, 0, 0
	}

	sum := 0
	first := true

	for _, rssi := range survey.Cells {
		if first || rssi < minRSSI {
			minRSSI = rssi
		}

		if first || rssi > maxRSSI {
			maxRSSI = rssi
		}

		first = false
		sum += rssi
	}

	return minRSSI, sum / len(survey.Cells), maxRSSI
}

// surveyJSON 是落盘格式：cells 展开为 "row,col" 字符串键，
// 比内部 int 键可读、可手工修补，也方便其他工具消费。
type surveyJSON struct {
	SSID      string         `json:"ssid"`
	BSSID     string         `json:"bssid"`
	Cols      int            `json:"cols"`
	Rows      int            `json:"rows"`
	Cells     map[string]int `json:"cells"`
	Plan      []string       `json:"plan,omitempty"`
	StartedAt time.Time      `json:"started_at"`
	SavedAt   time.Time      `json:"saved_at"`
}

// Save 把勘测写入 JSON 文件。
func (survey *Survey) Save(path string) error {
	cells := make(map[string]int, len(survey.Cells))

	for key, rssi := range survey.Cells {
		cells[fmt.Sprintf("%d,%d", key/survey.Cols, key%survey.Cols)] = rssi
	}

	payload := surveyJSON{
		SSID:      survey.SSID,
		BSSID:     survey.BSSID,
		Cols:      survey.Cols,
		Rows:      survey.Rows,
		Cells:     cells,
		Plan:      survey.Plan,
		StartedAt: survey.StartedAt,
		SavedAt:   time.Now(),
	}

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化勘测数据失败：%w", err)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("写入 %s 失败：%w", path, err)
	}

	return nil
}

// PlanChar 返回 (col,row) 处的平面图字符；无平面图或越界返回 0。
func (survey *Survey) PlanChar(col, row int) rune {
	if row < 0 || row >= len(survey.Plan) {
		return 0
	}

	line := []rune(survey.Plan[row])
	if col < 0 || col >= len(line) {
		return 0
	}

	return line[col]
}

// SortedKeys 返回排序后的内部键列表，调试与测试用。
func (survey *Survey) SortedKeys() []int {
	keys := make([]int, 0, len(survey.Cells))
	for key := range survey.Cells {
		keys = append(keys, key)
	}

	sort.Ints(keys)

	return keys
}
