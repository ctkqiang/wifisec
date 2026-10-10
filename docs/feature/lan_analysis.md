# 局域网分析三件套（`devices` / `scan_ports` / `get_packet`）

连上一个 Wi-Fi 之后，审计链路自然分三步：**谁在这个网络里 → 他们开了什么服务 → 线上到底在传什么**。wifisec 用三个子命令对应这三步，全部沿用项目的六边形架构：应用层只做编排，平台能力（邻居表读取、原始帧捕获、pcap 落盘）收敛在 adapter 层。

| 子命令 | 角色 | 对标工具 | 特权要求 |
|:---|:---|:---|:---|
| `devices` | 列出当前局域网内的在线设备（IP/MAC/主机名/角色） | 路由器 DHCP 客户端列表 + `arp -a` | 全平台免 root |
| `scan_ports` | 对指定主机做 TCP 端口扫描，区分 open/closed/filtered 并抓 banner | `nmap -sT` | 全平台免 root |
| `get_packet` | 在连接态网卡上抓包，实时滚动摘要并导出 pcap | Wireshark / tcpdump | Linux/macOS/Windows 需特权，见 §6 |

三者与 ESP 协处理器无关，**不需要插板子**；也不做 802.11 monitor 模式——抓的是本机内核视角的以太网帧，不会断开当前 Wi-Fi。

## 获取二进制

```bash
go install github.com/ctkqiang/wifisec/cmd/wifisec@latest
```

其他获取方式（Release 下载、源码编译）见仓库 README。

## 1. 推荐工作流

```bash
wifisec devices                          # 第一步：盘点网络，拿到目标 IP
wifisec scan_ports 192.168.1.46          # 第二步：对某台设备扫默认 47 个常用端口
wifisec get_packet en0 30 out.pcap       # 第三步：抓 30 秒流量，Wireshark 离线分析
```

三个命令开头都会打印授权警告：探测会在对端防火墙、交换机日志里留痕，抓包更可能触及同网络他人的通信——**仅限自有网络或已获书面授权的测试环境**。

## 2. `devices` · 局域网设备发现

```bash
wifisec devices [网卡名]
```

网卡名可省略：程序用一次「UDP connect 到 `203.0.113.1:80`」的套接字技巧询问内核默认路由，自动选出当前上网接口（连着 Wi-Fi 时就是无线网卡）。

### 2.1 输出

```text
[信息] 接口 en0 · 本机 192.168.1.109 · 网段 192.168.1.109/24
[信息] 默认网关 192.168.1.1
[信息] 正在并发探测 253 个地址的 80,443,22,445 端口以刷新 ARP 表…

局域网在线设备（数据来源：系统 ARP 邻居表）
IP 地址        MAC 地址           主机名    角色
────────────────────────────────────────────────
192.168.1.1    B4:B0:24:xx:xx:xx  -         网关
192.168.1.46   76:A2:36:xx:xx:xx  -         -
192.168.1.109  12:49:1B:xx:xx:xx  M2.local  本机
[信息] 共 5 台设备 · 探测地址 253 个 · 耗时 5.68s
休眠终端不会回应二层解析，未出现不代表设备离线；精确审计请结合 get_packet
```

| 列 | 数据来源 |
|:---|:---|
| IP 地址 | 系统 ARP/邻居表，限定在本机直连 IPv4 网段内 |
| MAC 地址 | 邻居表硬件地址，全零/广播/组播条目一律剔除 |
| 主机名 | 对每个 IP 做一次反向 DNS（PTR），超时 500ms 即留空 |
| 角色 | 本机与默认网关显式标注，其余留空（表格显示 `-`） |

### 2.2 为什么要先「探测」再读 ARP 表

ARP 表是惰性的：内核只缓存**最近有过二层通信**的邻居。直接 `arp -a` 往往只能看到网关。程序先对网段内每个地址的 `80/443/22/445` 四个端口做 700ms 超时的 TCP 握手（128 并发，握手成功与否无所谓），这会强制内核发 ARP 请求——在线设备无论端口是否开放都会应答，随后邻居表里就有它了。

### 2.3 网段策略

- 按接口地址与掩码枚举全部可用主机位，自动排除网络号、广播地址、本机自身；
- `/16` 等超大网段不全量探测（最坏 6 万个地址 × 4 端口太久），退化为本机所在 `/24`（上限 1024 个地址）；
- 跨平台读取：Linux/Android 解析 `/proc/net/arp`（不依赖 `ip` 命令），macOS 解析 `arp -an`，Windows 解析 `arp -a`；默认网关分别来自 `/proc/net/route`、`route -n get default`、`route print -4`。

### 2.4 已知盲区

- **休眠设备缺席**：熄屏省电的手机/平板不回 ARP，邻居表里没有它——结尾的提示行就是这个含义；要抓瞬时上线的设备请用 `get_packet` 长期监听；
- **随机 MAC**：iOS/Android 默认使用私有地址，每次联网 MAC 都可能不同，无法用它做设备指纹；
- **只覆盖 IPv4 直连网段**：跨三层的设备不在邻居表里；全隧道 VPN 下默认路由接口是 tun，程序会改去枚举 VPN 网段，想扫物理 Wi-Fi 请显式传网卡名。

## 3. `scan_ports` · nmap 风格端口扫描

```bash
wifisec scan_ports <目标 IP 或主机名> [端口规格]
```

### 3.1 端口规格语法

| 写法 | 含义 |
|:---|:---|
| 省略 | 默认 `top`：47 个运维高频端口（22/53/80/443/3306/6379/8080/27017 …） |
| `top` | 同上 |
| `all` | `1-1000`，对标 nmap 默认的最常见 1000 端口 |
| `22,80,443` | 显式逗号列表 |
| `8000-8100` | 闭区间 |
| `22,80,8000-8100` | 列表与区间可混用 |

### 3.2 输出（真机扫描家用路由器）

```text
[信息] 目标 192.168.1.1（192.168.1.1）· 待扫端口 5 个 · 并发 200 · 单端口超时 1.5s

端口扫描结果 · 192.168.1.1（192.168.1.1）
端口  状态  服务    Banner
────────────────────────────────────────────
22    open  ssh     SSH-2.0-dropbear_2011.54
53    open  domain  -
80    open  http    HTTP/1.0 200 OK
443   open  https   -
[信息] open 4 · filtered 0 · closed 1 · 共 5 端口 · 耗时 1.01s
closed=内核收到 RST；filtered=超时/不可达，可能是防火墙丢弃，也可能主机不在线
```

表格只展示 `open` 与 `filtered`（closed 不占行，只在统计里给数量）。

### 3.3 三态判定原理

实现采用 **TCP connect 扫描**而不是原始套接字 SYN 扫描（`nmap -sS`）：三次握手完全交给内核完成，因此四平台免 root，语义仍然精确——

| 状态 | 内核结论 | 含义 |
|:---|:---|:---|
| `open` | 握手成功（收到 SYN-ACK） | 端口有服务监听 |
| `closed` | `ECONNREFUSED` / `ECONNRESET`（收到 RST） | 主机在线但没服务 |
| `filtered` | 超时 / `EHOSTUNREACH` 等 | 防火墙丢弃，或主机根本不在线 |

工程参数：200 并发信号量，单端口 1.5 秒握手超时；结果经 channel 汇聚后按端口号排序，输出顺序确定。

### 3.4 Banner 抓取

对每个 `open` 端口，先**被动读取 600ms**（SSH、SMTP 等服务会主动报家门，如 `SSH-2.0-dropbear_2011.54`）；对 HTTP 族端口（80/81/3000/8000/8080/8888/9000/9090）再补发一发 `HEAD / HTTP/1.0`，拿到状态行即可识别 HTTP 服务。Banner 截断到 60 个 rune，控制字符不可见时不留垃圾。服务名列是静态对照表，未收录的端口不臆造。

### 3.5 能力边界

- 只扫 **TCP**：没有 UDP 扫描、没有 SYN 半开/隐蔽扫描（那需要 root + raw socket）；
- connect 扫描在对端日志里就是一次真实连接，**没有隐蔽性**；
- Banner 只做被动读 + 单条 HTTP HEAD，不做 nmap 那种数百探针的深度服务/版本识别；
- 扫公网高延迟目标时把 1.5s 超时理解为下限，并收窄端口集（如只扫 `22,80,443`）。

## 4. `get_packet` · 抓包导出 pcap

```bash
wifisec get_packet [网卡名] [秒数] [输出文件]
```

### 4.1 参数是「位置语义」，不分先后

解析器按 token 形态归类，三个参数都可省略、顺序随意：

| token 形态 | 归类 | 示例 |
|:---|:---|:---|
| 纯整数 | 抓包秒数；`0` = 抓到 Ctrl-C | `30` |
| 含路径分隔符，或以 `.pcap`/`.cap` 结尾 | 输出文件路径 | `out.pcap`、`/tmp/a.cap` |
| 其余 | 网卡名 | `en0`、`wlan0`、`以太网` |

缺省值：网卡优先自动选择无线接口（找不到再退回默认路由网卡）；文件名为 `wifisec-20060102-150405.pcap`（当前工作目录）；秒数缺省为无限，靠 Ctrl-C 收尾。以 `-` 开头的 token 直接报错（本工具不用 flag，避免歧义）。

### 4.2 会话输出

```text
[信息] 抓包接口 en0 · 链路类型 Ethernet（本机网卡视角，DLT 1）
输出文件 out.pcap · 实时行限速 40 行/秒（完整帧全部入文件）
按 Ctrl-C 结束抓包并写入统计
[信息] #154    192.168.1.66:51752 → 192.168.1.255:5700  UDP (211 B)
[信息] 抓包结束：154 帧 · 52.0 KB · 时长 3.06s
协议分布：TCP 148 · UDP 6
文件：out.pcap（54.5 KB）
Wireshark 打开方式：File → Open → 选择该文件，或执行 wireshark out.pcap
```

- 实时行是 Wireshark 列表风格的一行摘要：序号、五元组方向、协议、TCP 标志位（SYN/ACK/FIN/RST/PSH/URG）、长度；
- 终端限速 **40 行/秒**：手机备份、视频流会瞬间打出几千帧，超出部分只折叠屏幕行——**每一帧都完整落盘，不丢数据**；
- 每 5 秒一行运行中统计；Ctrl-C（或秒数到点）后输出帧数、字节数、时长、协议分布并正常关闭 pcap；
- 摘要解析覆盖 Ethernet/VLAN/ARP（who-has/is-at）/IPv4/IPv6/TCP/UDP/ICMP/ICMPv6/EAPOL（局域网握手）/LLDP，超短帧标 `TRUNC`。

### 4.3 pcap 文件格式

文件由 `internal/pcapfile` 纯 Go 手写，不依赖任何第三方库：经典 pcap 格式（非 pcapng），魔数 `0xa1b2c3d4` 小端微秒时间戳，24 字节全局头 + 每包 16 字节记录头，snaplen 65535，链路层 `LINKTYPE_ETHERNET = 1`。Wireshark、tcpdump、tshark 均可直接打开（已用 `tcpdump -r` 对真机产物做过逐包验证，时间戳与 TCP 选项完整）。

### 4.4 「本机网卡视角」意味着什么

抓的是**承载在 Wi-Fi 上的以太网帧**，不是空中的 802.11 射频帧：

- 看得到：本机收发的全部单播、全网/组播帧（如 ARP、mDNS、SSDP、上文的 UDP 广播）、其他设备发出的广播；
- 看不到：**别的两台设备之间的单播**——AP 不会把寻址到他人的帧转发给你的网卡；这些帧在空口还受 WPA2/WPA3 加密保护；
- 本机 HTTPS 流量同样是 TLS 密文，pcap 里没有明文内容（这是 TLS 的设计目标，不是工具缺陷）；
- 不需要切 monitor、不干扰当前联网、不挑信道；要看裸 802.11 管理帧/信标属于 deauth 那条 monitor 路线，由 ESP 协处理器承载。

## 5. 跨平台实现

| 能力 | Linux | Android/Termux | macOS | Windows |
|:---|:---|:---|:---|:---|
| 邻居表 | 解析 `/proc/net/arp` | 同 Linux | 解析 `arp -an` | 解析 `arp -a` |
| 默认网关 | 解析 `/proc/net/route`（十六进制小端，多默认路由取最小 Metric） | 同 Linux | `route -n get default` | `route print -4` |
| 设备发现 / 端口扫描 | 免 root | 免 root | 免 root | 免 root |
| 抓包数据源 | `AF_PACKET`/`SOCK_RAW` 原始套接字 | 同 Linux | `/dev/bpf0..47`（BIOCSETIF + BPF 缓冲 ioctl） | Npcap `wpcap.dll`（pcap_open/pcap_next_ex） |

抓包平台细节：

- **Linux**：`AF_PACKET` + `SOCK_RAW` + `ETH_P_ALL`，绑定 `SockaddrLinklayer`，`SO_RCVTIMEO` 500ms 产生空闲周期以响应 Ctrl-C；
- **macOS**：按 libpcap 验证过的顺序配置——`BIOCSBLEN`（必须先于 `BIOCSETIF`）→ 绑定接口 → `BIOCIMMEDIATE` → `BIOCSRTIMEOUT` → `BIOCGBLEN` 读回钳制后的缓冲大小（读缓冲小于它会 EINVAL）；一次 read 可含多条记录，按 xnu 的 4 字节 `BPF_WORDALIGN` 步进；`/dev/bpf*` 全部 EBUSY 时自动轮询下一个；
- **Windows**：复用项目注入模块的 wpcap 延迟加载，设备路径经 GUID/友好名归一到 `NPF_` 前缀；超时统一映射为空闲周期哨兵。

## 6. 权限要求与排错

| 现象 | 原因 | 处理 |
|:---|:---|:---|
| `devices` 只有本机一行 | 刚连上网、邻居表还没被探针刷出来；或当前 Wi-Fi 开启了「客户端隔离/AP 隔离」 | AP 隔离下任何二层工具都看不到邻居，需在路由器侧关闭 |
| `devices` 扫到的是 VPN/tun 网段 | 全隧道 VPN 接管默认路由 | 显式传物理网卡名：`wifisec devices en0` |
| `scan_ports` 全部 filtered | 主机不在线，或防火墙丢弃 SYN | 先用 `devices` 确认主机在线；filtered 不等于 closed |
| Linux 抓包 `operation not permitted` | `AF_PACKET` 需要 `CAP_NET_RAW` | `sudo wifisec get_packet …`；或对二进制 `setcap cap_net_raw+ep` |
| macOS 抓包 `permission denied` | `/dev/bpf*` 默认仅 root/`access_bpf` 组可访问 | `sudo wifisec get_packet …`；装过 Wireshark 且用户在 `access_bpf` 组内可免 sudo |
| Windows 报缺少 Npcap / wpcap | 未安装 Npcap | 安装 [Npcap](https://npcap.com/)（安装时勾选 WinPcap API 兼容组件），并以管理员身份运行终端 |
| 抓包秒开即「BPF 记录长度越界」 | 不应出现（已按 4 字节对齐处理）；如复现请带 pcap 提 issue | 升级到最新版 |
| pcap 里只有自己的流量 | 交换式网络 + 单播帧不转发给本机，属正常现象 | 广播/组播与本机单播才是连接态抓包的可见范围，见 §4.4 |
| 想抓空口 802.11 管理帧 | `get_packet` 是以太网视角，没有射频头 | 该需求属于 deauth 的 monitor 路线，由 ESP 协处理器承载 |

## 7. 法律红线

设备发现与端口扫描是对目标**主动发起的探测行为**，抓包还可能记录同网络内他人通信。《中华人民共和国网络安全法》第二十七条禁止未经授权的网络探测与干扰，未经允许对第三方网络扫描或留存他人通信内容可能进一步触犯《中华人民共和国刑法》第二百八十五条。对自己家里的路由器做口令与暴露面自查是合法典型场景；对公司网络请取得书面授权并留存范围说明；对邻居、咖啡厅、任何第三方网络使用即越线。
