package tests

import (
	"os"
	"path/filepath"
	"testing"
	"wifisec/internal/radio"
)

const fixtureJSON = `{
  "XX": {
    "country": "XX",
    "name": "测试域甲",
    "bands": {
      "2.4GHz": {"channels": [1, 6, 11]},
      "5GHz": {"non_dfs": [36, 40], "dfs": [52, 56, 120]},
      "6GHz": {"channels": [], "optional": true}
    }
  },
  "YY": {
    "country": "YY",
    "name": "测试域乙",
    "bands": {
      "2.4GHz": {"channels": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]},
      "5GHz": {"non_dfs": [36, 40, 44, 48], "dfs": [52, 56, 60, 64]}
    }
  }
}`

func writeFixture(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "regulatory.json")
	if err := os.WriteFile(path, []byte(fixtureJSON), 0o644); err != nil {
		t.Fatalf("写入测试数据失败：%v", err)
	}

	return path
}

func TestLoadFrom(t *testing.T) {
	domains, err := radio.LoadFrom(writeFixture(t))
	if err != nil {
		t.Fatalf("加载失败：%v", err)
	}

	if len(domains) != 2 {
		t.Fatalf("期望 2 个法规域，实际 %d", len(domains))
	}

	xx := domains["XX"]
	if xx.Name != "测试域甲" {
		t.Errorf("XX 名称错误：%s", xx.Name)
	}

	if got := xx.Bands["5GHz"].DFS; len(got) != 3 || got[2] != 120 {
		t.Errorf("XX 5GHz DFS 解析错误：%v", got)
	}
}

func TestLoadFromInvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "regulatory.json")
	if err := os.WriteFile(path, []byte("{broken"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := radio.LoadFrom(path); err == nil {
		t.Fatal("损坏的 JSON 应返回错误")
	}
}

func TestLoadFromMissingFile(t *testing.T) {
	if _, err := radio.LoadFrom(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("不存在的文件应返回错误")
	}
}

func TestVerdict(t *testing.T) {
	domains, err := radio.LoadFrom(writeFixture(t))
	if err != nil {
		t.Fatalf("加载失败：%v", err)
	}

	xx := domains["XX"]

	tests := []struct {
		name    string
		channel int
		want    radio.ChannelVerdict
	}{
		{"2.4GHz 直开信道", 6, radio.Legal},
		{"2.4GHz 未收录信道", 13, radio.Prohibited},
		{"5GHz non-DFS", 36, radio.Legal},
		{"5GHz DFS", 52, radio.DFSRequired},
		{"5GHz TDWR 段 DFS", 120, radio.DFSRequired},
		{"5GHz 未收录信道", 149, radio.Prohibited},
		{"信道 0 无频段归属", 0, radio.Prohibited},
		{"信道 15 属 2.4/5GHz 之外", 15, radio.Prohibited},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := radio.Verdict(xx, tt.channel); got != tt.want {
				t.Errorf("Verdict(XX, %d) = %s，期望 %s", tt.channel, got, tt.want)
			}
		})
	}
}

func TestVerdictString(t *testing.T) {
	tests := []struct {
		verdict radio.ChannelVerdict
		want    string
	}{
		{radio.Legal, "合法"},
		{radio.DFSRequired, "DFS"},
		{radio.Prohibited, "禁用"},
	}

	for _, tt := range tests {
		if got := tt.verdict.String(); got != tt.want {
			t.Errorf("ChannelVerdict(%d).String() = %s，期望 %s", tt.verdict, got, tt.want)
		}
	}
}

func TestSortedDomains(t *testing.T) {
	domains, err := radio.LoadFrom(writeFixture(t))
	if err != nil {
		t.Fatalf("加载失败：%v", err)
	}

	sorted := radio.SortedDomains(domains)
	if len(sorted) != 2 || sorted[0].Country != "XX" || sorted[1].Country != "YY" {
		t.Errorf("排序结果错误：%v", sorted)
	}
}
