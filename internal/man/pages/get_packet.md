# GET_PACKET(1)

## 名称
get_packet — 连接态抓包导出 pcap，可实时分析 EAPOL 握手与 PMKID

## 用法
    wifisec get_packet [网卡] [秒] [文件] [--eapol] [--pmkid --bssid xx] [--ssid 名称]

## 描述
连接态网卡抓包：Linux AF_PACKET / macOS BPF / Windows Npcap，实时
摘要限速打印，全帧写 pcap 供 Wireshark 分析。与 sniff(1) 的事件流
互不干扰——get_packet 走 Wireshark 风格逐帧列表。

`--eapol` 实时分析四步握手进度；`--pmkid` 主动 PMKID 会话与后台抓包
共存，两条链路互补，同 BSSID 优先输出 PMKID。

## 参数
`[网卡] [秒] [文件]`
:   抓包网卡、时长与 pcap 落盘路径；均有缺省。

## 选项
`--eapol`
:   实时解析 EAPOL 帧，标注握手 1/4-4/4 进度与完整性。

`--pmkid --bssid xx`
:   对指定 BSSID 发起主动 PMKID 获取，抓包同步进行。

`--ssid 名称`
:   隐藏 SSID 场景显式指定网络名。

## 示例
    wifisec get_packet en0 30 capture.pcap
    wifisec get_packet --eapol --ssid 'MyWiFi' 60 eapol.pcap

## 另见
sniff(1), pmkid(1), extract(1), docs/feature/lan_analysis.md
