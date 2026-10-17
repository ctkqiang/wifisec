# DEVICES(1)

## 名称
devices — 发现局域网在线设备（IP/MAC/主机名/网关角色）

## 用法
    wifisec devices [网卡名]

## 描述
本机直连视角的局域网设备发现，四平台免 root：TCP 探针并发刷 ARP
触发内核解析，再读系统邻居表交叉验证（Linux /proc/net/arp、
macOS arp -an、Windows arp -a），输出 IP/MAC/主机名/角色，网关与
本机单独标注。

## 参数
`[网卡名]`
:   显式指定网卡；缺省自动选择，多网卡/VPN 场景建议指定。

## 示例
    wifisec devices
    wifisec devices en0

## 另见
sniff(1), scan_ports(1), docs/feature/lan_analysis.md
