// Package radio 承载射频领域的法规域（regulatory domain）知识：
// 各国家/地区对 Wi-Fi 信道的开放范围不同，扫描到的信道是否合法、
// 是否需要雷达避让（DFS），都以此为判定依据。
package radio

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
)

// Band 描述一个频段在某法规域下的可用信道。
// 2.4GHz/6GHz 仅使用 Channels；5GHz 区分 NonDFS（免雷达检测）与 DFS。
type Band struct {
	Channels []int `json:"channels"`
	NonDFS   []int `json:"non_dfs"`
	DFS      []int `json:"dfs"`
	Optional bool  `json:"optional"`
}

// Domain 是一个国家/地区的完整法规域定义，对应 regulatory.json 的一条记录。
type Domain struct {
	Country string           `json:"country"`
	Name    string           `json:"name"`
	Bands   map[string]*Band `json:"bands"`
}

// ChannelVerdict 表示信道在某法规域下的使用状态。
type ChannelVerdict int

const (
	// Prohibited 该信道在此法规域下被禁用，发射即违法。
	Prohibited ChannelVerdict = iota
	// Legal 该信道可直接使用。
	Legal
	// DFSRequired 该信道可用，但发射前必须完成雷达检测（CAC），
	// 运行中检测到雷达脉冲须立即让道。
	DFSRequired
)

func (verdict ChannelVerdict) String() string {
	switch verdict {
	case Legal:
		return "合法"
	case DFSRequired:
		return "DFS"
	default:
		return "禁用"
	}
}

var (
	domainsOnce sync.Once
	domains     map[string]Domain
	domainsErr  error
)

// Load 懒加载默认数据文件（进程内只解析一次）。
// 路径查找策略见 locateDataFile。
func Load() (map[string]Domain, error) {
	domainsOnce.Do(func() {
		path, err := locateDataFile()
		if err != nil {
			domainsErr = err
			return
		}

		domains, domainsErr = LoadFrom(path)
	})

	return domains, domainsErr
}

// LoadFrom 从指定路径解析法规数据，是与运行环境无关的纯函数，便于测试。
func LoadFrom(path string) (map[string]Domain, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取法规数据 %s 失败：%w", path, err)
	}

	parsed := make(map[string]Domain)
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("解析法规数据 %s 失败：%w", path, err)
	}

	return parsed, nil
}

// locateDataFile 按优先级查找 data/regulatory.json：
// 环境变量 WIFISEC_DATA > 当前目录（仓库根运行）> 上级目录（tests/、build/ 运行）
// > 可执行文件的上级目录（build/wifisec 直接执行）。
func locateDataFile() (string, error) {
	candidates := make([]string, 0, 4)

	if dir := os.Getenv("WIFISEC_DATA"); dir != "" {
		candidates = append(candidates, filepath.Join(dir, "regulatory.json"))
	}

	candidates = append(candidates,
		filepath.Join("data", "regulatory.json"),
		filepath.Join("..", "data", "regulatory.json"),
	)

	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "..", "data", "regulatory.json"))
	}

	for _, path := range candidates {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path, nil
		}
	}

	return "", errors.New("未找到 data/regulatory.json，请在仓库根目录运行或设置 WIFISEC_DATA 环境变量")
}

// Verdict 查询信道在指定法规域下的使用状态；无法归属频段的信道一律视为禁用，
// 因为无法证明合法时保守处理是安全研究的底线。
func Verdict(domain Domain, channel int) ChannelVerdict {
	band, ok := domain.Bands[bandKey(channel)]
	if !ok || band == nil {
		return Prohibited
	}

	// 合法优先于 DFS 判定：部分法规域会把同一信道同时列入两份清单，
	// 免检测的使用方式对用户更有价值。
	if slices.Contains(band.Channels, channel) || slices.Contains(band.NonDFS, channel) {
		return Legal
	}

	if slices.Contains(band.DFS, channel) {
		return DFSRequired
	}

	return Prohibited
}

// bandKey 把信道号映射到 regulatory.json 的频段键。
// 6GHz 信道号与 2.4GHz 重叠（均从 1 起编），当前数据未收录 6GHz，
// 因此仅按编号区间映射 2.4/5GHz，无法映射时返回空串由调用方按禁用处理。
func bandKey(channel int) string {
	switch {
	case channel >= 1 && channel <= 14:
		return "2.4GHz"
	case channel >= 32 && channel <= 177:
		return "5GHz"
	default:
		return ""
	}
}

// SortedDomains 返回按国码排序的法规域列表，保证每次输出顺序稳定。
func SortedDomains(domains map[string]Domain) []Domain {
	keys := make([]string, 0, len(domains))
	for key := range domains {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	sorted := make([]Domain, 0, len(keys))
	for _, key := range keys {
		sorted = append(sorted, domains[key])
	}

	return sorted
}
