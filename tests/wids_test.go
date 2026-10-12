package tests

import (
	"net"
	"testing"
	"time"

	"github.com/ctkqiang/wifisec/internal/functions"
	"github.com/ctkqiang/wifisec/internal/ieee80211"
	"github.com/ctkqiang/wifisec/internal/wids"
)

// widsSnapshot 是测试里构造一轮快照的快捷方式。
func widsSnapshot(ssid, bssid string, channel int, enc string) wids.Observation {
	return wids.Observation{SSID: ssid, BSSID: bssid, Channel: channel, Enc: enc}
}

// alertKinds 把告警列表折叠成"类别→条数"映射，方便表断言。
func alertKinds(alerts []wids.Alert) map[wids.Kind]int {
	kinds := make(map[wids.Kind]int)
	for _, alert := range alerts {
		kinds[alert.Kind]++
	}

	return kinds
}

// TestWIDSInventoryBaseline 覆盖首轮扫描：只做安全盘点不做差分，
// WEP 报警告、开放/TKIP 报提示、WPA2/WPA3 静默。
func TestWIDSInventoryBaseline(t *testing.T) {
	engine := wids.NewEngine()
	at := time.Unix(1700000000, 0)

	baseline := []wids.Observation{
		widsSnapshot("企业网", "AA:00:00:00:00:01", 36, "WPA3"),
		widsSnapshot("家宽", "AA:00:00:00:00:02", 6, "WPA2"),
		widsSnapshot("古董路由", "AA:00:00:00:00:03", 11, "WEP"),
		widsSnapshot("咖啡店", "AA:00:00:00:00:04", 1, "OPEN"),
		widsSnapshot("老笔记本", "AA:00:00:00:00:05", 3, "WPA"),
	}

	alerts := engine.Observe(baseline, at)

	if kinds := alertKinds(alerts); kinds[wids.KindWeakCrypto] != 2 || kinds[wids.KindOpenNetwork] != 1 {
		t.Fatalf("首轮盘点告警不符合预期：%v（%+v）", kinds, alerts)
	}

	for _, alert := range alerts {
		if alert.Kind == wids.KindWeakCrypto && alert.Subject == "古董路由" && alert.Severity != wids.SevWarning {
			t.Errorf("WEP 应为警告级，实际 %v", alert.Severity)
		}

		if alert.Kind == wids.KindWeakCrypto && alert.Subject == "老笔记本" && alert.Severity != wids.SevInfo {
			t.Errorf("WPA/TKIP 应为提示级，实际 %v", alert.Severity)
		}

		if alert.Kind == wids.KindOpenNetwork && alert.Severity != wids.SevInfo {
			t.Errorf("开放网络应为提示级，实际 %v", alert.Severity)
		}
	}

	// 同一批 BSSID 再来一轮：盘点只做一次，不应重复告警。
	if repeat := engine.Observe(baseline, at.Add(time.Minute)); len(repeat) != 0 {
		t.Fatalf("重复快照不应再触发盘点告警：%+v", repeat)
	}
}

// TestWIDSRogueAP 覆盖伪造 AP 判定：同 SSID 第二个 BSSID 且
// 信道/加密不一致 → 警告；配置一致 → 提示（可能是合法 Mesh）。
func TestWIDSRogueAP(t *testing.T) {
	engine := wids.NewEngine()
	at := time.Unix(1700000000, 0)

	base := []wids.Observation{widsSnapshot("MyWiFi", "AA:00:00:00:00:01", 11, "WPA3")}
	if alerts := engine.Observe(base, at); len(alerts) != 0 {
		t.Fatalf("WPA3 基线不应产生告警：%+v", alerts)
	}

	// 信道与加密都不同的第二个 BSSID：Evil Twin 特征。
	twin := []wids.Observation{
		base[0],
		widsSnapshot("MyWiFi", "BB:00:00:00:00:02", 6, "WPA2"),
	}

	alerts := engine.Observe(twin, at.Add(time.Minute))
	if kinds := alertKinds(alerts); kinds[wids.KindRogueAP] != 1 {
		t.Fatalf("应触发一条伪造 AP 告警：%v", kinds)
	}

	if alerts[0].Severity != wids.SevWarning {
		t.Errorf("伪造 AP 应为警告级，实际 %v", alerts[0].Severity)
	}

	// 配置完全一致的第二 BSSID：Mesh/漫游特征，提示级。
	// 用干净引擎——若 SSID 已有伪造成员，任何新成员与伪造者必然
	// 配置冲突，继续按警告处理才符合"污染 SSID 从严"的原则。
	meshEngine := wids.NewEngine()
	mesh := []wids.Observation{
		widsSnapshot("MeshNet", "AA:00:00:00:00:01", 11, "WPA3"),
		widsSnapshot("MeshNet", "CC:00:00:00:00:03", 11, "WPA3"),
	}

	meshAlerts := meshEngine.Observe(mesh, at)
	if len(meshAlerts) != 1 || meshAlerts[0].Kind != wids.KindRogueAP || meshAlerts[0].Severity != wids.SevInfo {
		t.Fatalf("配置一致的 BSSID 应只产生提示级告警：%+v", meshAlerts)
	}

	// 双频路由器拓扑回归：同一 SSID 在 5GHz 与 2.4GHz 各起一个 BSSID
	// 是默认形态，跨频段出现绝不告警——否则每台双频路由器都是误报源。
	dualEngine := wids.NewEngine()
	dual := []wids.Observation{
		widsSnapshot("kelvin172", "AA:00:00:00:00:01", 36, "WPA2"),
		widsSnapshot("kelvin172", "3C:64:CF:2B:64:34", 5, "WPA2"),
	}

	if dualAlerts := dualEngine.Observe(dual, at); len(dualAlerts) != 0 {
		t.Fatalf("双频合一拓扑不应产生任何告警：%+v", dualAlerts)
	}
}

// TestWIDSDowngrade 覆盖加密降级：同一 BSSID 从 WPA3 跌到 WEP
// 触发严重级告警；等级回升不报（升级是好事）。
func TestWIDSDowngrade(t *testing.T) {
	engine := wids.NewEngine()
	at := time.Unix(1700000000, 0)

	engine.Observe([]wids.Observation{widsSnapshot("Corp", "AA:00:00:00:00:01", 36, "WPA3")}, at)

	alerts := engine.Observe(
		[]wids.Observation{widsSnapshot("Corp", "AA:00:00:00:00:01", 36, "WEP")},
		at.Add(time.Minute),
	)

	if len(alerts) != 1 || alerts[0].Kind != wids.KindDowngrade || alerts[0].Severity != wids.SevCritical {
		t.Fatalf("WPA3→WEP 应触发严重级降级告警：%+v", alerts)
	}
}

// TestWIDSKarma 覆盖 KARMA 判定：同一 BSSID 累计宣称
// karmaSSIDThreshold 个不同 SSID 后触发一次严重级告警。
func TestWIDSKarma(t *testing.T) {
	engine := wids.NewEngine()
	at := time.Unix(1700000000, 0)

	bssid := "AA:00:00:00:00:99"
	var triggered int

	for round := 0; round < 8; round++ {
		ssid := "karma-" + string(rune('A'+round))
		alerts := engine.Observe([]wids.Observation{widsSnapshot(ssid, bssid, 6, "WPA2")}, at.Add(time.Duration(round)*time.Second))
		triggered += len(alerts)
	}

	if triggered != 1 {
		t.Fatalf("KARMA 应只触发一次告警，实际 %d 次", triggered)
	}
}

// TestWIDSDeauthStorm 覆盖帧级阈值：滑窗内 12 帧触发、
// 冷却期内不重复、目标为本机时在证据里点名。
func TestWIDSDeauthStorm(t *testing.T) {
	engine := wids.NewEngine()
	engine.SetOurMAC("11:22:33:44:55:66")
	base := time.Unix(1700000000, 0)

	var alerts []wids.Alert

	for frame := 0; frame < 12; frame++ {
		incoming := engine.ObserveFrame(
			wids.FrameDeauth,
			"AA:00:00:00:00:01",
			"11:22:33:44:55:66",
			base.Add(time.Duration(frame)*100*time.Millisecond),
		)
		alerts = append(alerts, incoming...)
	}

	if len(alerts) != 1 || alerts[0].Kind != wids.KindDeauth {
		t.Fatalf("12 帧应触发一次去认证风暴告警：%+v", alerts)
	}

	if want := "目标为本机"; !contains(alerts[0].Detail, want) {
		t.Errorf("针对本机的 deauth 应在证据里点名：%q", alerts[0].Detail)
	}

	// 冷却期（60 秒）内再来 12 帧不重复报；越过后再报。
	repeatAt := base.Add(30 * time.Second)
	for frame := 0; frame < 12; frame++ {
		repeatAlerts := engine.ObserveFrame(
			wids.FrameDeauth, "AA:00:00:00:00:01", "FF:FF:FF:FF:FF:FF",
			repeatAt.Add(time.Duration(frame)*100*time.Millisecond),
		)
		if len(repeatAlerts) != 0 {
			t.Fatalf("冷却期内不应重复告警：%+v", repeatAlerts)
		}
	}

	afterCooldown := engine.ObserveFrame(
		wids.FrameDeauth, "AA:00:00:00:00:01", "FF:FF:FF:FF:FF:FF",
		base.Add(2*time.Minute),
	)
	// 单帧不足以再触发（旧窗口已滑走），确认窗口确实被剪枝。
	if len(afterCooldown) != 0 {
		t.Fatalf("窗口滑走后单帧不应触发：%+v", afterCooldown)
	}
}

// TestWIDSBeaconFlood 覆盖信标泛洪：短窗口内出现去重发送方
// 达到阈值即告警，且只告警一次。
func TestWIDSBeaconFlood(t *testing.T) {
	engine := wids.NewEngine()
	base := time.Unix(1700000000, 0)

	var alerts []wids.Alert

	for index := 0; index < 40; index++ {
		mac := net.HardwareAddr{0xAA, 0x00, 0x00, 0x00, 0x00, byte(index)}
		incoming := engine.ObserveFrame(wids.FrameBeacon, mac.String(), "FF:FF:FF:FF:FF:FF", base)
		alerts = append(alerts, incoming...)
	}

	if len(alerts) != 1 || alerts[0].Kind != wids.KindBeaconFlood || alerts[0].Severity != wids.SevCritical {
		t.Fatalf("40 个发送方应触发一次信标泛洪告警：%+v", alerts)
	}

	// 冷却期内的后续泛洪被抑制。
	if repeat := engine.ObserveFrame(wids.FrameBeacon, "AA:00:00:00:00:64", "FF:FF:FF:FF:FF:FF", base.Add(time.Second)); len(repeat) != 0 {
		t.Fatalf("泛洪告警冷却期内不应重复：%+v", repeat)
	}
}

// TestWIDSSummary 覆盖总结：帧累计计数与重点来源排序。
func TestWIDSSummary(t *testing.T) {
	engine := wids.NewEngine()
	base := time.Unix(1700000000, 0)

	for frame := 0; frame < 15; frame++ {
		engine.ObserveFrame(wids.FrameDeauth, "AA:00:00:00:00:01", "FF:FF:FF:FF:FF:FF", base.Add(time.Duration(frame)*time.Second))
	}

	for frame := 0; frame < 4; frame++ {
		engine.ObserveFrame(wids.FrameDisassoc, "BB:00:00:00:00:02", "FF:FF:FF:FF:FF:FF", base)
	}

	report := engine.Summary()

	if report.FrameDeauth != 15 || report.FrameDisassoc != 4 {
		t.Fatalf("帧累计计数不符：deauth=%d disassoc=%d", report.FrameDeauth, report.FrameDisassoc)
	}

	if len(report.Offenders) == 0 || report.Offenders[0].MAC != "AA:00:00:00:00:01" {
		t.Fatalf("重点来源应按帧数降序，首位应为 AA:00:00:00:00:01：%+v", report.Offenders)
	}

	if report.TrackedAPs != 0 {
		t.Errorf("没有扫描快照时追踪数应为 0，实际 %d", report.TrackedAPs)
	}
}

// TestParseManagement 覆盖 802.11 管理帧解码：beacon 的 SSID、
// deauth 的 Reason Code、radiotap 剥离与非管理帧拒绝。
func TestParseManagement(t *testing.T) {
	bssid, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")

	// 复用真实编码器构造 deauth 帧（自带 8 字节 radiotap），验证剥离与解析。
	deauthFrame, err := ieee80211.BuildDeauthFrame(bssid)
	if err != nil {
		t.Fatalf("构造 deauth 帧失败：%v", err)
	}

	radiotapLen, ok := ieee80211.RadioTapLen(deauthFrame)
	if !ok || radiotapLen != 8 {
		t.Fatalf("radiotap 长度应为 8，实际 %d（ok=%v）", radiotapLen, ok)
	}

	info, err := ieee80211.ParseManagement(deauthFrame[radiotapLen:])
	if err != nil {
		t.Fatalf("解析 deauth 帧失败：%v", err)
	}

	if info.Subtype != ieee80211.SubtypeDeauth || info.ReasonCode != ieee80211.ReasonClass3FromNonAssoc {
		t.Fatalf("deauth 解析结果不符：%+v", info)
	}

	if info.Transmitter.String() != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("发送方应为 BSSID 本身：%v", info.Transmitter)
	}

	// 手工构造 beacon：FC=0x80，地址三元组，12 字节固定参数 + SSID IE。
	beacon := append([]byte{
		0x80, 0x00, // Frame Control：beacon
		0x00, 0x00, // Duration
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // addr1 广播
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // addr2 发送方
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // addr3 BSSID
		0x00, 0x00, // Sequence Control
	}, make([]byte, 12)...) // 时间戳 8 + 间隔 2 + 能力 2

	beacon = append(beacon, 0x00, byte(len("IDS-Test"))) // SSID IE 头
	beacon = append(beacon, []byte("IDS-Test")...)
	beacon = append(beacon, 0x03, 0x01, 0x06) // DS Parameter Set：信道 6

	info, err = ieee80211.ParseManagement(beacon)
	if err != nil {
		t.Fatalf("解析 beacon 失败：%v", err)
	}

	if info.Subtype != ieee80211.SubtypeBeacon || info.SSID != "IDS-Test" {
		t.Fatalf("beacon 解析结果不符：%+v", info)
	}

	if info.Receiver.String() != "ff:ff:ff:ff:ff:ff" {
		t.Errorf("beacon 接收方应为广播：%v", info.Receiver)
	}

	// 数据帧必须被拒绝：FC 类型位 = 10（数据帧）。
	dataFrame := []byte{0x08, 0x00}
	dataFrame = append(dataFrame, make([]byte, 24)...)
	if _, err := ieee80211.ParseManagement(dataFrame); err == nil {
		t.Fatal("数据帧应被 ParseManagement 拒绝")
	}

	// 畸形 radiotap 长度应被识别为不可信。
	if _, ok := ieee80211.RadioTapLen([]byte{0x00, 0x00, 0x02, 0x00}); ok {
		t.Fatal("声称长度 2 的 radiotap 头应判为无效")
	}
}

// TestParseIDSArgs 覆盖参数位置语义：纯整数是秒数，非网卡名的
// 文本是锁定 SSID，重复 token 与 `-` 开头一律报错。
func TestParseIDSArgs(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantSSID  string
		wantSec   int
		wantError bool
	}{
		{name: "空参数", args: nil},
		{name: "仅秒数", args: []string{"300"}, wantSec: 300},
		{name: "仅 SSID", args: []string{"Corp-WiFi"}, wantSSID: "Corp-WiFi"},
		{name: "SSID 加秒数", args: []string{"Corp-WiFi", "600"}, wantSSID: "Corp-WiFi", wantSec: 600},
		{name: "秒数在前", args: []string{"600", "Corp-WiFi"}, wantSSID: "Corp-WiFi", wantSec: 600},
		{name: "重复 SSID", args: []string{"a", "b"}, wantError: true},
		{name: "横杠开头", args: []string{"-x"}, wantError: true},
		{name: "负秒数", args: []string{"-5"}, wantError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options, err := functions.ParseIDSArgs(test.args)

			if test.wantError {
				if err == nil {
					t.Fatalf("应拒绝参数 %v", test.args)
				}

				return
			}

			if err != nil {
				t.Fatalf("参数 %v 不应报错：%v", test.args, err)
			}

			if options.SSID != test.wantSSID || options.Seconds != test.wantSec {
				t.Fatalf("解析结果不符：%+v（期望 SSID=%q 秒数=%d）", options, test.wantSSID, test.wantSec)
			}
		})
	}
}

// TestWIDSWatchFilter 覆盖锁定模式：引擎只评估目标 SSID/BSSID 的
// 观察与帧，其余空域活动静默；泛洪类检测不受锁定影响（由其他用例覆盖）。
func TestWIDSWatchFilter(t *testing.T) {
	engine := wids.NewEngine()
	engine.SetWatch("Corp", map[string]bool{"AA:00:00:00:00:01": true})
	at := time.Unix(1700000000, 0)

	// 非目标观察：WEP 开放全放一边，连盘点都不做。
	noise := []wids.Observation{
		widsSnapshot("邻居", "BB:00:00:00:00:02", 1, "WEP"),
		widsSnapshot("咖啡店", "BB:00:00:00:00:03", 6, "OPEN"),
	}

	if alerts := engine.Observe(noise, at); len(alerts) != 0 {
		t.Fatalf("锁定模式下非目标观察不应产生任何告警：%+v", alerts)
	}

	if report := engine.Summary(); report.TrackedAPs != 0 {
		t.Fatalf("非目标不应进入基线：TrackedAPs=%d", report.TrackedAPs)
	}

	// 目标观察正常入库与盘点。
	target := []wids.Observation{widsSnapshot("Corp", "AA:00:00:00:00:01", 36, "WPA3")}
	if alerts := engine.Observe(target, at); len(alerts) != 0 {
		t.Fatalf("WPA3 目标基线不应告警：%+v", alerts)
	}

	if report := engine.Summary(); report.TrackedAPs != 1 {
		t.Fatalf("目标应进入基线：TrackedAPs=%d", report.TrackedAPs)
	}

	// 目标降级照常报警。
	downgraded := engine.Observe(
		[]wids.Observation{widsSnapshot("Corp", "AA:00:00:00:00:01", 36, "WEP")},
		at.Add(time.Minute),
	)

	if len(downgraded) != 1 || downgraded[0].Kind != wids.KindDowngrade {
		t.Fatalf("锁定目标的降级应触发告警：%+v", downgraded)
	}

	// 帧级：与目标无收发关系的风暴帧静默。
	for frame := 0; frame < 12; frame++ {
		incoming := engine.ObserveFrame(
			wids.FrameDeauth, "CC:00:00:00:00:09", "DD:00:00:00:00:08",
			at.Add(time.Duration(frame)*100*time.Millisecond),
		)
		if len(incoming) != 0 {
			t.Fatalf("与目标无关的风暴帧不应告警：%+v", incoming)
		}
	}

	// 发送方命中目标 BSSID 的风暴帧照常计数报警。
	var storm []wids.Alert

	for frame := 0; frame < 12; frame++ {
		incoming := engine.ObserveFrame(
			wids.FrameDeauth, "AA:00:00:00:00:01", "FF:FF:FF:FF:FF:FF",
			at.Add(time.Duration(frame)*100*time.Millisecond),
		)
		storm = append(storm, incoming...)
	}

	if len(storm) != 1 || storm[0].Kind != wids.KindDeauth {
		t.Fatalf("针对目标的风暴应触发一次告警：%+v", storm)
	}
}

// contains 是测试内的小工具，避免为了一个断言引入 strings。
func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}

	return -1
}
