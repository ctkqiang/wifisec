# WiFi Sniff（实时嗅探与 ARP 欺骗 MITM）

## 目录

- [获取二进制](#获取二进制)
- [1. 功能概述](#1-功能概述)
- [2. 被动嗅探的可见性边界](#2-被动嗅探的可见性边界)
- [3. ARP 欺骗原理](#3-arp-欺骗原理)
- [4. 应用层解析](#4-应用层解析)
- [5. 架构与平台分发](#5-架构与平台分发)
- [6. 使用方法](#6-使用方法)
- [7. 执行流程与生命周期](#7-执行流程与生命周期)
- [8. 与 get_packet 的对比](#8-与-get_packet-的对比)
- [9. 错误排查](#9-错误排查)
- [10. 安全边界与法律声明](#10-安全边界与法律声明)
- [11. FAQ](#11-faq)

---

## 获取二进制

```bash
go install github.com/ctkqiang/wifisec/cmd/wifisec@latest
```

其他获取方式（Release 下载、源码编译）见仓库 README。

## 1. 功能概述

`wifisec sniff` 是 bettercap 风格的实时流量观测命令：直读当前连接网络的原始以太网帧，按协议解析为语义事件流（DNS 查询、HTTP 请求、TLS SNI、ARP who-has、凭据告警、新主机上线）实时滚动输出。`--recon` 在会话启动时主动 ARP 扫描预填充主机表；`--spoof` 开启 ARP 欺骗（对应 bettercap 的 `net.spoof`），把目标主机与网关之间的流量引到本机透明转发，退出时自动还原全部系统改动。

| 属性 | 值 |
|:---|:---|
| 命令 | `wifisec sniff [--recon] [--spoof] [--targets ip1,ip2] [--iface 网卡]` |
| 运行模式 | 前台运行，`Ctrl-C` 终止并自动清理 |
| 被动模式 | 只读网卡帧，DNS/HTTP/SNI/ARP/主机上线实时标注 |
| 主动侦察 | `--recon` 启动时 ARP 扫描预填充主机表 |
| 欺骗模式 | 双向 ARP 毒化 + IP 转发 + ICMP redirect 压制 |
| 毒化周期 | 1 秒全量刷新，目标 who-has 网关时即时应答 |
| 恢复策略 | 退出时以真实 MAC 重发 5 轮恢复帧 |
| 权限要求 | 全模式需要 root（Linux/macOS）或管理员（Windows） |

---

## 2. 被动嗅探的可见性边界

被动模式不发送任何帧，只读取本机网卡收到的流量。**WPA2/WPA3 加密下，空口单播帧全部加密**，普通连接态网卡只能看到：

| 流量类型 | 可见性 | 说明 |
|:---|:---|:---|
| 本机收发的全部流量 | 完整可见 | 含目的端口与载荷，DNS/HTTP/SNI 可解析 |
| ARP / DHCP / mDNS / SSDP 等广播 | 完整可见 | 广播帧不加密，可观察局域网活动 |
| 其他主机的单播流量 | **不可见** | 交换机/AP 不转发给本机，且 WPA2 加密 |

要看他人单播流量，需要 `--spoof` 让流量途经本机——这正是欺骗模式存在的意义。启动横幅会如实打印这条边界，避免「开了 sniff 为什么看不到别人」的困惑。

---

## 3. ARP 欺骗原理

### 3.1 双向毒化

ARP 协议（RFC 826）无认证机制：任何主机都可以声明「某 IP 由我持有」，接收方无条件更新缓存。欺骗利用这一缺陷实现中间人：

```
毒化前：  target ⇄ 网关（直接通信）
毒化后：  target → 本机 → 网关
          网关 → 本机 → target

对网关发送：ARP 应答「targetIP 的 MAC 是本机」
对目标发送：ARP 应答「gatewayIP 的 MAC 是本机」
```

每 1 秒全量重刷一次（多数系统的 ARP 缓存老化在 20 秒以上），并在抓包循环中监听：当目标发出「who-has 网关」请求时（部分系统发问前会清空旧缓存条目），立即补发应答，不给真实 MAC 重新生效的窗口。

### 3.2 ICMP Redirect 拆台防护

网关与本机在同一二层。本机把目标流量转发回网关时，网关会发 ICMP Redirect 告诉目标「我和你直连，别绕路」——这是对欺骗的自动拆台。因此开启转发的同时必须压制 redirect：

| 平台 | 转发开关 | redirect 压制 |
|:---|:---|:---|
| Linux | `/proc/sys/net/ipv4/ip_forward` 写 1 | `conf/{all,iface}/send_redirects` 写 0 |
| macOS | `sysctl net.inet.ip.forwarding=1` | `net.inet.icmp.icmp_rlim=0` |
| Windows | 不支持（见下） | — |

退出时按启动前备份的旧值逐项还原；半途写入失败会回滚已完成的部分，不留半开状态。

### 3.3 恢复策略与不可恢复场景

启动前通过 TCP 探测（触发内核 ARP 解析）+ 系统邻居表收集网关与每个目标的**真实 MAC**，退出时对每个方向重发 5 轮真实绑定（间隔 150ms，覆盖单帧丢失），网关与目标的 ARP 缓存随即还原。

| 退出方式 | 恢复效果 |
|:---|:---|
| `Ctrl-C` / SIGINT / SIGTERM | 完整恢复 |
| 正常错误返回 | 完整恢复（同一 defer 出口） |
| `kill -9` | **无法恢复**，目标断网直至其 ARP 缓存自然老化（通常 1-5 分钟） |

MAC 未解析成功的主机会在目标筛选阶段被跳过并告警——没有真实 MAC 就没有恢复依据，毒化它等于断网，违背「可完全还原」的设计承诺。

### 3.4 Windows 平台限制

Windows 开启路由转发需写注册表 `IPEnableRouter` 并重启 `RemoteAccess` 服务，无法做到「退出即还原」。因此 `--spoof` 在 Windows 上直接返回精确错误（被动嗅探不受影响），与 `clone` 命令的平台限制惯例一致。

---

## 4. 应用层解析

被动与欺骗模式共用同一套解析器（[internal/ethernet/l7.go](../../internal/ethernet/l7.go)），命中后产出 bettercap 风格的语义事件：

| 事件标签 | 触发条件 | 输出示例 |
|:---|:---|:---|
| `[dns]` | UDP 目的端口 53 且 QR=0 | `[dns] 192.168.1.66  api.example.com (A)` |
| `[http]` | TCP 目的端口 80 且首行匹配方法集 | `[http] 192.168.1.66  GET /index.html · Host: example.com` |
| `[sni]` | TCP 目的端口 443 且 ClientHello 携带 server_name | `[sni] 192.168.1.66  www.example.com` |
| `[arp]` | ARP 请求帧（opcode 1） | `[arp] 192.168.1.66  who-has 192.168.1.1` |
| `[host]` | HostTracker 首次观测到新 IP | `[host] 192.168.1.109  新主机 (aa:bb:cc:dd:ee:ff · Apple)` |
| `[cred]` | HTTP 明文携带 Basic Auth/Cookie/表单口令 | `[cred] 192.168.1.66  POST 命中 basic 凭据` |

解析器为纯字节解析，不做流重组：HTTP 只看首段、TLS 只看首个 ClientHello。所有字段读取前执行长度边界检查，畸形/截断帧返回空摘要，任何一帧都不会中断会话。凭据事件不输出 User/Pass 值，只标注类型，防止口令泄露到终端/日志。

---

## 5. 架构与平台分发

### 5.1 六边形架构映射

```
┌──────────────────────────────────────────────────────┐
│  cmd/wifisec/main.go 注册 "sniff" → RunSniff         │
├──────────────────────────────────────────────────────┤
│  internal/functions/sniff_cmd.go                     │
│    参数解析 · 权限检查 · 目标发现 · 读循环编排        │
├──────────────────────────────────────────────────────┤
│  internal/mitm/spoof.go                              │
│    毒化循环 · 即时应答 · 恢复帧（纯逻辑，端口注入）   │
├──────────────────────────────────────────────────────┤
│  端口层（应用层只见接口）                              │
│    platform/writer  原始帧发送（Write/Close）         │
│    platform/capture 原始帧抓取（Read/LinkType）       │
│    platform/fwd     IP 转发 + redirect 开关           │
│    platform/lan     邻居表 + 默认网关                  │
├──────────────────────────────────────────────────────┤
│  internal/ethernet                                   │
│    arp.go  ARP 帧构造    l7.go  DNS/HTTP/SNI 解析     │
└──────────────────────────────────────────────────────┘
```

### 5.2 平台能力矩阵

| 平台 | 被动嗅探 | ARP 欺骗 | 抓包后端 | 发帧后端 |
|:---|:---|:---|:---|:---|
| Linux | 支持（root） | 支持（root） | AF_PACKET | AF_PACKET |
| macOS | 支持（root，BPF） | 支持（root，BPF） | /dev/bpf* | /dev/bpf*（O_RDWR） |
| Windows | 支持（管理员 + Npcap） | **不支持**（转发无法即开即还） | Npcap | Npcap |
| Android/Termux | 支持（root） | 支持（root） | AF_PACKET | AF_PACKET |

### 5.3 复用关系

| 组件 | 复用来源 |
|:---|:---|
| 抓包 Source / ErrReadTimeout | `platform/capture`（get_packet 同款） |
| 令牌桶限速 / 协议统计 / humanizeBytes | `functions/sniff.go` |
| LAN 发现（网段枚举 / TCP 探测） | `functions/devices.go` |
| 权限 GUI 预弹窗 | `checkRootWithGUI` / `checkAdminWithGUI` |
| 信号处理器 | `setupSignalHandler` |
| ARP 帧构造 | `internal/ethernet/arp.go` |
| OUI 厂商查询 | `internal/ethernet/oui.go` |
| HTTP 凭据提取 | `internal/ethernet/cred.go` |
| 主机跟踪 | `internal/ethernet/host.go` |
| 事件过滤 | `internal/functions/sniff_event.go` |

sniff 新增的代码包括：`ethernet/arp.go`（帧构造 + ParseARP）、`ethernet/l7.go`（应用层解析）、`ethernet/oui.go`（OUI 厂商表）、`ethernet/cred.go`（HTTP 凭据提取）、`ethernet/host.go`（HostTracker 主机跟踪）、`platform/writer/`（三平台发帧端口）、`platform/fwd/`（转发开关）、`mitm/spoof.go`（毒化状态机）、`functions/sniff_event.go`（事件过滤器 + 主机表输出）与 `functions/sniff_cmd.go`（编排）。

---

## 6. 使用方法

### 6.1 被动嗅探

```bash
sudo wifisec sniff
```

自动选择无线网卡（枚举失败回落默认路由网卡），实时输出本机流量与广播帧的事件流。

### 6.2 主动侦察（recon）

```bash
sudo wifisec sniff --recon
```

会话启动时主动并发 ARP 扫描整个网段，把在线主机的 IP/MAC/厂商灌入主机表当冷启动底图。之后的被动嗅探中，已知主机不再触发 `[host]` 新发现事件，只有真正新出现的设备才告警。

`--recon` 可与 `--spoof` 组合使用——先扫描预填充再开启欺骗。

### 6.3 ARP 欺骗 MITM

```bash
# 毒化网段内全部在线主机（最多 32 台，超过截断并告警）
sudo wifisec sniff --spoof

# 只毒化指定目标
sudo wifisec sniff --spoof --targets 192.168.1.66,192.168.1.107

# 指定网卡
sudo wifisec sniff --spoof --targets 192.168.1.66 --iface en0
```

目标未显式指定时自动全网段发现：枚举网段 → TCP 探测触发 ARP 解析 → 查邻居表取 MAC。目标不在线或 MAC 未解析会被跳过并告警。

### 6.4 输出示例

```
实时嗅探接口 en0 · Ctrl-C 结束
WPA2 下被动模式只能看到本机流量与广播帧（ARP/DHCP/mDNS）
要观测他人单播流量请加 --spoof 启用 ARP 欺骗（仅限已授权网络）

[arp] 192.168.1.1  who-has 192.168.1.66
[dns] 192.168.1.109  api.example.com (A)
[sni] 192.168.1.109  www.example.com
[host] 192.168.1.66  新主机 (a4:50:75:11:22:33 · Apple)
[http] 192.168.1.66  GET /login.html · Host: 192.168.1.1
[cred] 192.168.1.66  POST 命中 basic 凭据
… 上一秒 12 条事件已折叠

嗅探期间观测到的主机
┌──────────────┬──────────────────┬──────────┬──────┬──────┐
│ IP 地址      │ MAC 地址         │ 厂商     │ 事件数│ 角色 │
├──────────────┼──────────────────┼──────────┼──────┼──────┤
│ 192.168.1.1  │ a4:50:75:aa:bb:cc│ Apple    │    18│ 网关 │
│ 192.168.1.66 │ a4:50:75:11:22:33│ Apple    │    42│      │
│ 192.168.1.109│ 5c:97:a3:dd:ee:ff│ Apple    │     7│      │
└──────────────┴──────────────────┴──────────┴──────┴──────┘
嗅探结束：1284 帧 · 640.2 KB · 时长 2m13s
协议分布：TCP 612 · UDP 401 · ARP 156 · ICMP6 89 · ...
```

---

## 7. 执行流程与生命周期

```
启动
  │
  ├── 参数解析（ParseSniffCommandArgs）
  ├── Windows + --spoof → 提前返回平台限制错误
  ├── 权限检查（GUI 预弹窗 + root/管理员）
  ├── 网卡选择（--iface / 位置参数 / 自动：无线优先）
  │
  ├── [spoof||recon] 网关获取（lan.DefaultGateway）
  ├── [spoof] 材料收集
  │     ├── 全网段枚举或显式列表 → TCP 探测 → 邻居表 → 真实 MAC
  │     └── MAC 未知的候选跳过并告警
  │
  ├── [spoof] 转发就绪
  │     ├── fwd.Enable：备份旧值 → 开转发 → 压制 redirect
  │     └── writer.Open：独立发送句柄
  │
  ├── capture.Open → 横幅
  ├── HostTracker + EventFilter 就绪
  │
  ├── [recon] 主动 ARP 扫描
  │     ├── planDiscoveryTargets → probeHosts → lan.Neighbors
  │     └── tracker.Preload（静默灌入，不触发 [host] 事件）
  │
  ├── Spoofer.Start（首轮毒化 + 1s ticker）
  │
  ├── 读循环（sniffReadLoop）
  │     ├── 过滤本机自发帧（源 MAC 比对）
  │     ├── Summarize → 协议统计
  │     ├── EventFilter.Filter → [dns]/[http]/[sni]/[arp]/[host]/[cred] 事件
  │     ├── 令牌桶限速打印（40 条/秒）
  │     ├── spoofer.Observe（who-has 网关即时应答）
  │     └── Ctrl-C → 退出循环
  │
  └── 清理（统一 defer 出口）
        ├── Spoofer.Stop：5 轮真实 MAC 恢复帧
        ├── writer.Close
        ├── fwd.Disable：按备份还原转发与 redirect
        └── printSniffHostSummary：主机表 + 统计输出
```

---

## 8. 与 get_packet 的对比

| 属性 | `wifisec get_packet` | `wifisec sniff` |
|:---|:---|:---|
| 定位 | 取证落盘（pcap 文件） | 实时观测（事件流 + 主机表） |
| 输出 | 二进制 pcap，事后 Wireshark 分析 | bettercap 风格语义事件 + 退出主机表 |
| 应用层解析 | 无（EAPOL 除外） | DNS / HTTP / SNI / ARP / 凭据 / 主机跟踪 |
| 主动侦察 | 无 | `--recon` ARP 扫描预填充主机表 |
| ARP 欺骗 | 无 | `--spoof` 双向毒化 MITM |
| 系统改动 | 无 | spoof 模式改转发设置，退出还原 |
| 帧完整性 | 全部落盘 | 只统计与显示，不落盘 |

两者互补：现场观测用 sniff，完整取证用 get_packet。

---

## 9. 错误排查

| 现象 | 可能原因 | 解决方案 |
|:---|:---|:---|
| `操作不被允许` / 打开网卡失败 | 未以 root/管理员运行 | `sudo wifisec sniff`；Windows 用管理员终端 |
| `读取默认网关失败` | 当前无默认路由（未联网） | 先连接 WiFi；或 `--iface` 显式指定有网关的网卡 |
| `网关 x.x.x.x 不在 ARP 邻居表中` | 网关 MAC 尚未解析 | `ping` 一下网关再重试 |
| `目标 x.x.x.x 不在网段内` | 指定的目标与本机不同网段 | ARP 欺骗只在同二层有效，改用同网段地址 |
| `没有可毒化的目标` | 网段内无在线主机或全部被防火墙屏蔽 | `wifisec devices` 先确认在线设备 |
| 被毒化目标断网且不恢复 | 使用了 `kill -9` | 等目标 ARP 缓存自然老化（1-5 分钟）或重启目标网络 |
| macOS 弹出「接收网络流量」授权 | BPF 首次使用系统授权 | 点允许；程序有品牌预提示窗引导 |
| Windows `--spoof` 返回不支持 | IPEnableRouter 无法即开即还 | 平台限制设计如此；被动嗅探不受影响 |
| 被动模式看不到其他设备流量 | WPA2 单播加密 + 交换机不转发 | 属正常边界，需观测他人流量请用 `--spoof`（限授权网络） |

---

## 10. 安全边界与法律声明

ARP 欺骗会截获他人通信内容，法律风险远高于无线干扰类命令：

- **《中华人民共和国刑法》第二百八十五条**：非法获取计算机信息系统中存储、处理或者传输的数据，情节严重的，处三年以下有期徒刑——截获他人上网流量可能触犯本条
- **《中华人民共和国网络安全法》第二十七条**：禁止从事非法侵入他人网络、干扰他人网络正常功能、窃取网络数据等危害网络安全的活动
- 未经授权对他人设备实施 MITM 属于**实时窃听**，无论是否存储内容

本工具仅限**自有网络或已获书面授权**的测试环境使用。即使授权网络内，也应仅对自有设备测试。

---

## 11. FAQ

### Q: 为什么被动模式看不到别人的流量？

WPA2 下空口单播全部加密，且 AP/交换机不会把别人的单播转给你的网卡。这是物理与加密的双重边界，不是工具缺陷。要看他人流量需要 `--spoof` 让流量途经本机，且仅限授权场景。

### Q: --spoof 之后目标会断网吗？

不会。本机开启 IP 转发并压制 ICMP redirect，目标流量透明经过本机继续到达网关，目标无感知。断网只发生在 `kill -9`（跳过恢复帧）或转发未就绪的异常场景。

### Q: 毒化会被发现吗？

从网络表现上不易察觉（流量正常、延迟仅增加一次二层转发），但交换机若开启动态 ARP 检测（DAI）会直接丢弃毒化帧；企业网常见 802.1X + DAI 部署，此时毒化无效。目标侧 `arp -a` 观察网关 MAC 是否频繁变化也可发现。

### Q: --targets 可以填本机或网关吗？

不可以。本机是欺骗的执行者，网关是欺骗的对端，两者都会在解析阶段被拒绝并给出明确错误。

### Q: 恢复帧真的能还原吗？

正常退出（Ctrl-C/SIGTERM/错误返回）下，5 轮恢复帧会立即覆盖毒化条目，网关与目标秒级还原。`kill -9` 无法执行任何 defer，此时等目标缓存自然老化即可，无需人工干预。

### Q: 能保存抓到的流量吗？

sniff 定位是实时观测，不落盘。需要完整 pcap 取证请用 `wifisec get_packet`，两者可以分别运行配合使用。
