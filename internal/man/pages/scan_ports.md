# SCAN_PORTS(1)

## 名称
scan_ports — nmap 风格 TCP 扫描：open/closed/filtered + banner

## 用法
    wifisec scan_ports <目标> [端口规格]

## 描述
nmap 风格 TCP connect 扫描，200 并发、1.5s 超时，open/closed/
filtered 三态判定，开放端口被动抓取 banner / HTTP HEAD。四平台
免 root。

## 参数
`<目标>`
:   IPv4 地址或主机名。

`[端口规格]`
:   `top` 常用 47 端口（缺省）；`all` 1-1000；逗号列表如
:   `22,80,443`；区间如 `8000-8100`；可混用 `22,80,8000-8100`。

## 示例
    wifisec scan_ports 192.168.1.1
    wifisec scan_ports 192.168.1.1 22,80,8000-8100
    wifisec scan_ports 192.168.1.1 all

## 另见
devices(1), docs/feature/lan_analysis.md
