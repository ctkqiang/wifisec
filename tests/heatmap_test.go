package tests

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ctkqiang/wifisec/internal/functions"
	"github.com/ctkqiang/wifisec/internal/heatmap"
)

// TestRSSILevel 覆盖信号分级的全部边界：分级口径是产品承诺，
// 偏移一档都会误导勘测结论。
func TestRSSILevel(t *testing.T) {
	tests := []struct {
		rssi  int
		level int
	}{
		{-30, heatmap.LevelExcellent},
		{-50, heatmap.LevelExcellent},
		{-51, heatmap.LevelGood},
		{-60, heatmap.LevelGood},
		{-61, heatmap.LevelFair},
		{-70, heatmap.LevelFair},
		{-71, heatmap.LevelWeak},
		{-80, heatmap.LevelWeak},
		{-81, heatmap.LevelDead},
		{-95, heatmap.LevelDead},
		{0, heatmap.LevelDead}, // 缺数据按死角处理
	}

	for _, test := range tests {
		if level := heatmap.RSSILevel(test.rssi); level != test.level {
			t.Errorf("RSSI %d 应为等级 %d，实际 %d", test.rssi, test.level, level)
		}
	}
}

// TestSurveySetClear 覆盖采样的写入、覆盖语义（同点取最新）与清除。
func TestSurveySetClear(t *testing.T) {
	survey := heatmap.NewSurvey("Corp", "AA:00:00:00:00:01", 10, 8, nil)

	survey.Set(3, 4, -55)
	survey.Set(3, 4, -62) // 同点重采应覆盖
	survey.Set(9, 7, -80)
	survey.Set(-1, 0, -40) // 越界应静默忽略
	survey.Set(10, 0, -40)

	if survey.SampleCount() != 2 {
		t.Fatalf("应为 2 个采样格，实际 %d", survey.SampleCount())
	}

	if rssi, ok := survey.At(3, 4); !ok || rssi != -62 {
		t.Fatalf("(3,4) 应为最新值 -62，实际 %d（ok=%v）", rssi, ok)
	}

	survey.Clear(3, 4)

	if _, ok := survey.At(3, 4); ok {
		t.Fatal("清除后 (3,4) 不应再有采样")
	}
}

// TestSurveyInterpolation 覆盖 IDW 插值：精确采样优先、
// 邻近加权（近的权重大）、半径外留白不编造。
func TestSurveyInterpolation(t *testing.T) {
	survey := heatmap.NewSurvey("Corp", "", 60, 20, nil)

	survey.Set(5, 5, -50)
	survey.Set(6, 5, -70)

	// 精确采样原样返回，不被插值稀释。
	if rssi, ok := survey.Interpolated(5, 5); !ok || rssi != -50 {
		t.Fatalf("精确采样应原样返回 -50，实际 %d", rssi)
	}

	// 两点正中间的格：距两点各 0.5/1.118…，近点权重显著更大。
	// (5,5) 与 (6,5) 之间无中间整格，取 (5,6)：距 (5,5) 为 1、距 (6,5) 为 √2。
	rssi, ok := survey.Interpolated(5, 6)
	if !ok {
		t.Fatal("(5,6) 在半径内应有插值")
	}

	// 权重 1/1² vs 1/2 → -50×1 + -70×0.5 / 1.5 = -56.67 → -57。
	if rssi != -57 {
		t.Fatalf("IDW 加权结果应为 -57（近点主导），实际 %d", rssi)
	}

	// 半径外留白：网格对角距采样点远超半径上限 12。
	if _, ok := survey.Interpolated(55, 18); ok {
		t.Fatal("半径外不应编造插值")
	}
}

// TestSurveyStrongest 覆盖 AP 方位估计：返回信号最强的采样格。
func TestSurveyStrongest(t *testing.T) {
	survey := heatmap.NewSurvey("Corp", "", 10, 8, nil)

	if _, _, _, ok := survey.StrongestCell(); ok {
		t.Fatal("无采样时不应有最强格")
	}

	survey.Set(1, 1, -80)
	survey.Set(4, 2, -45)
	survey.Set(7, 6, -70)

	col, row, rssi, ok := survey.StrongestCell()
	if !ok || col != 4 || row != 2 || rssi != -45 {
		t.Fatalf("最强格应为 (4,2)@-45，实际 (%d,%d)@%d", col, row, rssi)
	}
}

// TestSurveyStats 覆盖统计：最低/平均/最高。
func TestSurveyStats(t *testing.T) {
	survey := heatmap.NewSurvey("Corp", "", 10, 8, nil)

	if min, avg, max := survey.Stats(); min != 0 || avg != 0 || max != 0 {
		t.Fatalf("空勘测统计应全零：%d/%d/%d", min, avg, max)
	}

	survey.Set(0, 0, -50)
	survey.Set(1, 0, -60)
	survey.Set(2, 0, -70)

	minimum, average, maximum := survey.Stats()
	if minimum != -70 || average != -60 || maximum != -50 {
		t.Fatalf("统计应为 -70/-60/-50，实际 %d/%d/%d", minimum, average, maximum)
	}
}

// TestSurveySaveLoad 覆盖 JSON 落盘格式：键为 "row,col" 且内容完整。
func TestSurveySaveLoad(t *testing.T) {
	survey := heatmap.NewSurvey("Corp", "AA:00:00:00:00:01", 10, 8, []string{"####", "#  #"})
	survey.Set(3, 4, -55)
	survey.Set(9, 7, -80)

	path := filepath.Join(t.TempDir(), "survey.json")
	if err := survey.Save(path); err != nil {
		t.Fatalf("保存失败：%v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取落盘文件失败：%v", err)
	}

	content := string(data)
	for _, want := range []string{`"ssid": "Corp"`, `"4,3": -55`, `"7,9": -80`, `"cols": 10`} {
		if !contains(content, want) {
			t.Errorf("落盘内容缺少 %q", want)
		}
	}
}

// TestSurveyPlanChar 覆盖平面图字符的取出与越界安全。
func TestSurveyPlanChar(t *testing.T) {
	survey := heatmap.NewSurvey("Corp", "", 10, 2, []string{"####", "#  #", "溢出的一行"})

	// 平面图行数超出网格行数应被裁剪。
	if len(survey.Plan) != 2 {
		t.Fatalf("平面图应裁剪为 2 行，实际 %d", len(survey.Plan))
	}

	if char := survey.PlanChar(1, 0); char != '#' {
		t.Fatalf("(1,0) 应为 '#'，实际 %q", char)
	}

	if char := survey.PlanChar(9, 9); char != 0 {
		t.Fatalf("越界应返回 0，实际 %q", char)
	}
}

// TestCollectHeatTargets 覆盖目标去重：BSSID 隐藏（"-"）时按 SSID 分键
// 绝不坍缩；同 BSSID 多条保留最强信号；结果按信号降序。
func TestCollectHeatTargets(t *testing.T) {
	networks := []functions.WiFiNetwork{
		{ESSID: "Corp", BSSID: "aa:00:00:00:00:01", Signal: -50, Channel: 36},
		{ESSID: "Corp", BSSID: "aa:00:00:00:00:01", Signal: -70, Channel: 36}, // 同 AP 弱读数
		{ESSID: "Home", BSSID: "-", Signal: -60, Channel: 6},                  // BSSID 隐藏
		{ESSID: "Cafe", BSSID: "-", Signal: -75, Channel: 1},                  // 同样隐藏，绝不能与 Home 坍缩
		{ESSID: "Corp5G", BSSID: "BB:00:00:00:00:02", Signal: -65, Channel: 40},
	}

	targets := functions.CollectHeatTargets(networks)

	if len(targets) != 4 {
		t.Fatalf("应去重为 4 个目标，实际 %d：%+v", len(targets), targets)
	}

	if targets[0].Signal != -50 {
		t.Fatalf("应按信号降序，首位 -50，实际 %d", targets[0].Signal)
	}

	homeSeen, cafeSeen := false, false
	for _, target := range targets {
		if target.SSID == "Home" {
			homeSeen = true
		}

		if target.SSID == "Cafe" {
			cafeSeen = true
		}
	}

	if !homeSeen || !cafeSeen {
		t.Fatal("BSSID 隐藏的不同 SSID 必须各自成目标，不得坍缩")
	}
}

// TestParseHeatmapArgs 覆盖参数位置语义：存在的文件是平面图，
// 其余首个 token 是 SSID，多余 token 报错。
func TestParseHeatmapArgs(t *testing.T) {
	planFile := filepath.Join(t.TempDir(), "floor.txt")
	if err := os.WriteFile(planFile, []byte("####\n"), 0o644); err != nil {
		t.Fatalf("构造平面图失败：%v", err)
	}

	tests := []struct {
		name      string
		args      []string
		wantSSID  string
		wantPlan  string
		wantError bool
	}{
		{name: "空参数", args: nil},
		{name: "仅 SSID", args: []string{"Corp"}, wantSSID: "Corp"},
		{name: "SSID 加平面图", args: []string{"Corp", planFile}, wantSSID: "Corp", wantPlan: planFile},
		{name: "平面图在前", args: []string{planFile, "Corp"}, wantSSID: "Corp", wantPlan: planFile},
		{name: "重复 SSID", args: []string{"a", "b"}, wantError: true},
		{name: "重复平面图", args: []string{planFile, planFile}, wantError: true},
		{name: "横杠开头", args: []string{"-x"}, wantError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options, err := functions.ParseHeatmapArgs(test.args)

			if test.wantError {
				if err == nil {
					t.Fatalf("应拒绝参数 %v", test.args)
				}

				return
			}

			if err != nil {
				t.Fatalf("参数 %v 不应报错：%v", test.args, err)
			}

			if options.SSID != test.wantSSID || options.PlanPath != test.wantPlan {
				t.Fatalf("解析结果不符：%+v", options)
			}
		})
	}
}
