# SNIFF(1)

## 名称
sniff — bettercap 风格实时嗅探与 ARP 欺骗 MITM

## 用法
    wifisec sniff [--recon] [--spoof] [--targets ip1,ip2] [--iface 网卡]

## 描述
直读网卡帧（Linux AF_PACKET / macOS BPF / Windows Npcap，需 root 或
管理员），把零散帧收敛成语义事件流：[dns] [http] [sni] [arp] [host]
[cred]，标签按类型配色，40 条/秒限速折叠。主机表只跟踪 RFC1918 私有
IP——公网流量的源 MAC 实为网关 MAC，跟踪它们会把网关 MAC 错配到一堆
公网 IP 上。退出时输出主机表（IP/MAC/厂商/事件数/角色）与协议分布。

WPA2 下被动模式只能看到本机流量与广播帧（ARP/DHCP/mDNS）；观测他人
流量需要 --spoof 做透明 MITM。

## 选项
`--recon`
:   会话启动时主动并发 ARP 扫描整个网段，把在线主机灌入主机表当冷启动
:   底图；已知主机不再触发 [host] 新发现事件（对应 bettercap net.recon）。

`--spoof`
:   叠加双向 ARP 毒化：网关与目标 1s 刷新 + who-has 即时应答，同时开启
:   IP 转发并压制 ICMP redirect（Linux procfs / macOS sysctl）。退出按
:   启动前备份以真实 MAC 重发 5 轮恢复帧完整还原。Windows 因
:   IPEnableRouter 无法即开即还而拒绝欺骗入口，被动嗅探不受影响。

`--targets ip1,ip2`
:   逗号分隔的毒化目标列表，须与本机同网段且不能是本机；缺省毒化全部
:   在线主机（上限 32 台）。MAC 未知的主机跳过——没有真实 MAC 就没有
:   恢复依据，毒化它等于断网。

`--iface 网卡`
:   显式指定网卡；缺省自动选择（优先无线网卡），多网卡/VPN 场景建议指定。

## 事件
`[dns]`   UDP 53 且 QR=0 的查询：域名与记录类型
`[http]`  TCP 80 明文请求：方法/路径/Host
`[sni]`   TCP 443 ClientHello 携带的 server_name
`[arp]`   ARP request（opcode 1）who-has
`[host]`  首次观测到新私有 IP：角色 + IP + MAC + 厂商
`[cred]`  HTTP 明文携带 BasicAuth/表单口令——只标注类型，不落口令值

## 示例
    sudo wifisec sniff
    sudo wifisec sniff --recon
    sudo wifisec sniff --spoof --targets 192.168.1.66
    sudo wifisec sniff --iface en0 --spoof

## 另见
devices(1), scan_ports(1), get_packet(1), docs/feature/wifi_sniff.md
