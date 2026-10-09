# wifi list — 无线接口与网络扫描

## 概述

`list` 子命令枚举当前主机的无线接口，并扫描周边 Wi-Fi 网络。已连接与未连接的网络合并在同一张表中呈现，输出风格对齐 aircrack-ng 套件：接口视图参考 airmon-ng，扫描视图参考 airodump-ng。

实现位于 `internal/functions/lists.go`，命令入口为 `functions.WifiList`，经 `cmd/wifisec/main.go` 的命令注册表分发。

## 获取二进制

```bash
go install github.com/ctkqiang/wifisec/cmd/wifisec@latest
```

其他获取方式（Release 下载、源码编译）见仓库 README。

## 使用方式

### 全量扫描

```bash
make list
```

等价于：

```bash
go run -race ./cmd/wifisec list
```

先输出无线接口表，随后输出周边网络表。已连接网络置顶，其余按信号强度降序排列。

实际输出示例：

```
无线接口 · 共 1 个
PHY  接口  索引  类型     状态  MAC 地址           驱动                              芯片组
─────────────────────────────────────────────────────────────────────────────────────────────────────
-    en0   11    managed  UP    00:1a:2b:3c:4d:5e  com.apple.DriverKit-AppleBCMWLAN  (0x14E4, 0x4378)

 CH 157 ][ Elapsed: 0 s ][ 2026-10-06 20:46:16

无线网络 · 共 12 个
连接    ESSID            BSSID  PHY       信道  频段  带宽    加密  加密套件  认证  信号         噪声     SNR    MCS  速率
────────────────────────────────────────────────────────────────────────────────────────────────────────
已连接  SkyFiber-5G      -      802.11ax  157   5GHz  80 MHz  WPA2  -         PSK   -56 dBm ▂▄▆  -91 dBm  35 dB  6    648 Mbps
未连接  SkyFiber         -      802.11b/g/n  3  2GHz  20 MHz  WPA2  -         PSK   -53 dBm ▂▄▆  -84 dBm  31 dB  -    -
```

### 目标锁定

```bash
make list TARGET=CafeGuest
```

等价于：

```bash
go run -race ./cmd/wifisec list CafeGuest
```

传入 ESSID 或 BSSID 后进入锁定模式：跳过接口表，只显示命中的目标网络。行为对齐 airodump-ng 的 `--bssid` 过滤。注意 make 会把不带 `TARGET=` 的参数当作构建目标，务必使用 `TARGET=` 传参。

- ESSID：忽略大小写精确匹配
- BSSID：允许省略冒号分隔符，`aabbccddeeff` 与 `aa:bb:cc:dd:ee:ff` 等价
- 同一 ESSID 的 2.4 GHz 与 5 GHz 是两个独立 BSS，均会保留，与 airodump-ng 行为一致
- 未命中时提示 `未找到目标 …，请传入完整 ESSID 或 BSSID`

锁定模式输出示例：

```
 CH hop ][ Elapsed: 3 s ][ 2026-10-06 20:42:04

无线网络 · 共 2 个
连接    ESSID      BSSID  PHY                信道  频段  带宽     加密  加密套件  认证  信号         噪声     SNR    MCS  速率
──────────────────────────────────────────────────────────────────────────────────────────────────────────
未连接  CafeGuest  -      802.11b/g/n/ac/ax  5     2GHz  20 MHz   WPA2  -         PSK   -54 dBm ▂▄▆  -88 dBm  34 dB  -    -
未连接  CafeGuest  -      802.11a/n/ac/ax    40    5GHz  160 MHz  WPA2  -         PSK   -66 dBm ▂     -92 dBm  26 dB  -    -
```

## 终端自适应

表格按终端实际列宽自动调整，PC 大屏与 Termux 窄屏均不横向溢出：

1. Unix（Linux / macOS / Termux）经 `TIOCGWINSZ`、Windows 经 `GetConsoleScreenBufferInfo` 查询终端列数；
2. 宽度不足时按列优先级省略次要列——优先级数值越大越先省略，`0` 为必列；
3. 仍放不下时截断 ESSID 并以 `…` 结尾（唯一允许收缩的列）；
4. 输出被重定向或管道捕获时视为不限宽，落盘数据保持完整。

以 64 列终端为例，接口表会省略「索引」「驱动」，网络表会省略「加密套件」「认证」「噪声」「MCS」；52 列下再省略「芯片组」「PHY」「带宽」等。必要信息（接口名、状态、MAC、连接状态、ESSID、信道、信号）始终保留。

## 输出说明

### 状态栏

```
 CH 157 ][ Elapsed: 0 s ][ 2026-10-06 20:46:16
```

| 段 | 含义 |
| ---- | ---- |
| `CH n` | 已连接时显示所在信道；未连接时显示 `hop`，表示系统在多信道间跳变扫描 |
| `Elapsed: n s` | 本次扫描耗时（秒） |
| 时间戳 | 扫描完成时刻 |

整行反色高亮，为 airodump-ng 式的视觉签名。

### 无线接口表

| 列 | 说明 | 优先级 |
| ---- | ---- | ---- |
| PHY | 物理设备编号（如 `phy0`）；macOS 无此概念，显示 `-` | 3 |
| 接口 | 内核接口名（`wlan0` / `en0` / `Wi-Fi`） | 必列 |
| 索引 | 内核接口索引 | 4 |
| 类型 | 工作模式：`managed` / `monitor` | 2 |
| 状态 | `UP` / `DOWN`，绿色与红色着色 | 必列 |
| MAC 地址 | 硬件地址；macOS 优先取 networksetup 的硬件地址而非随机私有地址 | 必列 |
| 驱动 | 内核驱动标识 | 5 |
| 芯片组 | 硬件型号（PCI ID 或 netsh 描述） | 4 |

### 无线网络表

| 列 | 说明 | 优先级 |
| ---- | ---- | ---- |
| 连接 | `已连接`（绿色）/ `未连接`（灰色） | 必列 |
| ESSID | 网络名称；窄终端下允许截断 | 必列（可收缩） |
| BSSID | AP 的 MAC 地址 | 必列 |
| PHY | 802.11 协议代际（`802.11ax` 等） | 4 |
| 信道 | 信道号 | 必列 |
| 频段 | `2GHz` / `5GHz` | 3 |
| 带宽 | 信道带宽（MHz） | 4 |
| 加密 | `WPA2` / `WPA3` / `WPA` / `WEP` / `OPEN`；`OPEN` 与 `WEP` 红色、`WPA` 黄色、`WPA3` 青色，弱加密一眼可辨 | 1 |
| 加密套件 | `CCMP` / `TKIP` 等 | 5 |
| 认证 | `PSK` / `802.1X` | 5 |
| 信号 | 信号强度（dBm）与 ▂▄▆█ 强度条，按强度着色：绿色 ≥ −50，黄色 ≥ −70，红色更低 | 必列 |
| 噪声 | 噪声底（dBm） | 5 |
| SNR | 信噪比（dB），由信号减噪声推导 | 4 |
| MCS | 调制编码方案索引 | 5 |
| 速率 | 当前传输速率（Mbps） | 3 |

空缺字段统一渲染为 `-`。

## 平台实现

| 平台 | 接口枚举 | 网络扫描 | BSSID | 备注 |
| ---- | ---- | ---- | ---- | ---- |
| macOS | `networksetup -listallhardwareports` + `net.Interfaces` | `system_profiler SPAirPortDataType`（文本模式，`LC_ALL=C` 固定英文） | 仅 root 下经 `wdutil info` 补已连接网络 | 驱动经 ioreg IORegistry 定位；周边网络 BSSID 被系统隐私框架封禁 |
| Linux | `/proc/net/wireless` + sysfs + `iw dev <iface> info` | `iw dev <iface> scan`（需 root） | 每个 BSS 真实 BSSID | 已连接标记来自无需 root 的 `iw dev <iface> link` |
| Windows | `netsh wlan show interfaces` / `show drivers` | `netsh wlan show networks mode=bssid`（无需管理员） | 每个 BSSID 真实 BSSID | 键名中英文兼容；信号由百分比线性换算 dBm |
| Android (Termux) | `/proc/net/wireless` | `termux-wifi-connection-info`，旧版额外尝试 `termux-wifi-scaninfo` | 已连接网络真实 BSSID；周边列表取决于系统是否放行 | 需安装 Termux:API 应用与 `termux-api` 包 |

解析器均为纯函数（`ParseIWScanOutput` / `ParseNetshBSSIDOutput`），接收命令原始文本返回结构体切片，外部命令调用与文本解析严格分离，表驱动测试覆盖 WPA2/WPA3/WEP/开放、隐藏 SSID、双 BSSID 拆分与中文系统键名。

macOS 的 profiler 解析采用相对缩进而非写死层级，避免不同 macOS 版本或权限下的排版差异导致漏读；同一网络同时出现在「当前网络」与「其他网络」时按 ESSID + 信道去重，保留带已连接标记的那条。Linux 与 Windows 每个 BSSID 天然唯一，不去重。

### 各平台字段覆盖

| 字段 | macOS | Linux | Windows | Termux |
| ---- | ---- | ---- | ---- | ---- |
| BSSID | 仅已连接（root） | 全部 | 全部 | 仅已连接 |
| 加密套件 / 认证 | `-` | RSN/WPA IE 明细 | netsh 认证/加密字段 | capabilities 串解析 |
| 信道带宽 | 有 | VHT/HE/HT 推导 | `-` | `-` |
| 噪声 / SNR / MCS / 速率 | 仅已连接 | `-`（beacon 不提供） | `-` | 速率（连接信息） |

## 平台限制

**macOS** 自 14 起将 SSID/BSSID 读取纳入定位服务授权，授权只授予带签名的图形 App，命令行工具（含 sudo，root 没有用户定位上下文）拿到的周边扫描结果中 SSID/BSSID 均为空。因此未连接网络的 BSSID 与加密套件在 macOS 上必然显示 `-`，这不是程序缺陷；唯一例外是 root 下 `wdutil info` 可提供当前已连接 AP 的 BSSID。

| 字段 | 原因 |
| ---- | ---- |
| 未连接网络 BSSID | macOS 隐私框架不对 CLI 暴露（CoreWLAN / system_profiler 均不提供） |
| 加密套件 | profiler 只报告加密代际，不含套件明细 |
| 未连接网络的噪声 / SNR / MCS / 速率 | 链路质量数据仅对已连接网络提供 |

**Linux** 主动扫描（`iw scan`）需要 `CAP_NET_ADMIN`，普通用户执行会收到 `扫描需要 root 权限：请使用 sudo 运行，例如 sudo make list` 的提示。

**Android** 从 9 起对周边扫描结果实施限流与权限封禁，多数设备上 `termux-wifi-scaninfo` 直接失败；此时只显示当前已连接网络。未安装 Termux:API 时会给出明确的安装指引，不会伪造数据。

Wi-Fi 处于关闭状态时，macOS profiler 会省略全部 SSID，程序以警告提示 `未扫描到无线网络，请确认 Wi-Fi 已开启`。

## 常见问题

**接口表 PHY 列显示 `-`？**
macOS 没有 Linux 的 `phyN` 命名，该列仅 Linux 系填充。

**为什么同一个 ESSID 出现两次？**
2.4 GHz 与 5 GHz 是同一 SSID 的两个 BSS，各自独立成行；Linux/Windows 下它们还会显示各自不同的真实 BSSID。

**Linux 下提示需要 root？**
`iw scan` 是主动扫描，必须有 root 或 `CAP_NET_ADMIN`：用 `sudo make list` 运行。已连接网络的关联信息（`iw link`）不需要特权。

**macOS 用 sudo 能看到全部 BSSID 吗？**
不能。sudo 只能通过 `wdutil info` 补出当前已连接 AP 的 BSSID；周边网络 BSSID 被系统隐私框架封禁，任何命令行工具都拿不到。需要完整 BSSID 列表请在 Linux 或 Windows 上运行。

**Termux 下只显示一个网络？**
Android 9+ 默认封禁周边扫描，只能读取当前连接信息。请确认已安装 Termux:API 应用、执行过 `pkg install termux-api` 并授予位置权限。

**信号列的颜色代表什么？**
绿色表示 −50 dBm 以上的强信号，黄色为 −50 至 −70 dBm 的中等信号，红色表示 −70 dBm 以下的弱信号，连接质量已不可靠。

**为什么窄屏下少了几列？**
终端自适应在起作用：Unix 经 `TIOCGWINSZ`、Windows 经 `GetConsoleScreenBufferInfo` 读取列宽，宽度不足时按优先级省略次要列，数据并未丢失，放大窗口或重定向到文件即可看到完整表格。
