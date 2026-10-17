# EXTRACT(1)

## 名称
extract — 离线分析 pcap：握手数/PMKID/帧合法性，择优导出 hash 行

## 用法
    wifisec extract <capture.pcap> [--hashcat out.22000] [--pmkid out.16800] [--bssid xx] [--ssid 名称] [--json]

## 描述
离线分析 pcap：自动识别 PMKID 与 EAPOL 帧，按 BSSID 归组统计完整
握手数、PMKID 存在性与各帧合法性，择优导出 hashcat 行（PMKID 优先
于不完整握手）。输出统一使用 hashcat v7.1.2 标准的 22000 格式。

## 选项
`--hashcat out.22000`
:   导出 hashcat 22000 格式 hash 行。

`--pmkid out.16800`
:   导出旧版 16800 格式（仅兼容用途保留）。

`--bssid xx`
:   只处理指定 BSSID。

`--ssid 名称`
:   隐藏 SSID 场景显式指定网络名。

`--json`
:   以 JSON 输出结构化结果。

## 示例
    wifisec extract capture.pcap
    wifisec extract capture.pcap --hashcat out.22000
    wifisec extract capture.pcap --bssid 01:23:45:67:89:ab --json

## 另见
get_packet(1), pmkid(1), docs/feature/wifi_pmkid.md
