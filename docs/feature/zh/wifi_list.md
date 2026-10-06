# wifi list — 无线接口与网络扫描

## 概述

`list` 子命令枚举当前主机的无线接口，并扫描周边 Wi-Fi 网络。已连接与未连接的网络合并在同一张表中呈现，输出风格对齐 aircrack-ng 套件：接口视图参考 airmon-ng，扫描视图参考 airodump-ng。

实现位于 `internal/functions/lists.go`，命令入口为 `functions.WifiList`，经 `cmd/main.go` 的命令注册表分发。

## 使用方式

### 全量扫描

```bash
make list
```

等价于：

```bash
go run -race cmd/main.go list
```

先输出无线接口表，随后输出周边网络表。已连接网络置顶，其余按信号强度降序排列。

实际输出示例：

```
无线接口 · 共 1 个
PHY  接口  索引  类型     状态  MAC 地址           驱动                              芯片组
─────────────────────────────────────────────────────────────────────────────────────────────────────
-    en0   11    managed  UP    9c:3e:53:83:cc:87  com.apple.DriverKit-AppleBCMWLAN  (0x14E4, 0x4378)

 CH 157 ][ Elapsed: 0 s ][ 2026-10-06 20:46:16

无线网络 · 共 12 个
连接    ESSID                  BSSID  PHY       信道  频段  带宽     加密  加密套件  认证  信号     噪声     SNR    MCS  速率
──────────────────────────────────────────────────────────────────────────────────────────────────
已连接  HOME@CelcomFibre_5G    -      802.11ax  157   5GHz  80 MHz   WPA2  -         PSK   -56 dBm  -91 dBm  35 dB  6    648 Mbps
未连接  HOME@CelcomFibre       -      802.11b/g/n 3   2GHz  20 MHz   WPA2  -         PSK   -53 dBm  -84 dBm  31 dB  -    -
```

### 目标锁定

```bash
make list TARGET=kelvin172
```

等价于：

```bash
go run -race cmd/main.go list kelvin172
```

传入 ESSID 或 BSSID 后进入锁定模式：跳过接口表，只显示命中的目标网络。行为对齐 airodump-ng 的 `--bssid` 过滤。

- ESSID：忽略大小写精确匹配
- BSSID：允许省略冒号分隔符，`aabbccddeeff` 与 `aa:bb:cc:dd:ee:ff` 等价
- 同一 ESSID 的 2.4 GHz 与 5 GHz 是两个独立 BSS，均会保留，与 airodump-ng 行为一致
- 未命中时提示 `未找到目标 …，请传入完整 ESSID 或 BSSID`

锁定模式输出示例：

```
 CH hop ][ Elapsed: 3 s ][ 2026-10-06 20:42:04

无线网络 · 共 2 个
连接    ESSID      BSSID  PHY                信道  频段  带宽     加密  加密套件  认证  信号     噪声     SNR    MCS  速率
──────────────────────────────────────────────────────────────────────────────────────────────────
未连接  kelvin172  -      802.11b/g/n/ac/ax  5     2GHz  20 MHz   WPA2  -         PSK   -54 dBm  -88 dBm  34 dB  -    -
未连接  kelvin172  -      802.11a/n/ac/ax    40    5GHz  160 MHz  WPA2  -         PSK   -66 dBm  -92 dBm  26 dB  -    -
```

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

### 无线接口表

| 列 | 说明 |
| ---- | ---- |
| PHY | 物理设备编号（如 `phy0`）；macOS 无此概念，显示 `-` |
| 接口 | 内核接口名（`wlan0` / `en0` / `Wi-Fi`） |
| 索引 | 内核接口索引 |
| 类型 | 工作模式：`managed` / `monitor` |
| 状态 | `UP` / `DOWN`，绿色与红色着色 |
| MAC 地址 | 硬件地址；macOS 优先取 networksetup 的硬件地址而非随机私有地址 |
| 驱动 | 内核驱动标识 |
| 芯片组 | 硬件型号（PCI ID 或 netsh 描述） |

### 无线网络表

| 列 | 说明 |
| ---- | ---- |
| 连接 | `已连接`（绿色）/ `未连接`（灰色） |
| ESSID | 网络名称 |
| BSSID | AP 的 MAC 地址 |
| PHY | 802.11 协议代际（`802.11ax` 等） |
| 信道 | 信道号 |
| 频段 | `2GHz` / `5GHz` |
| 带宽 | 信道带宽（MHz） |
| 加密 | `WPA2` / `WPA3` / `WPA` / `WEP` / `OPEN` |
| 加密套件 | `CCMP` / `TKIP` 等 |
| 认证 | `PSK` / `802.1X` |
| 信号 | 信号强度（dBm），按强度着色：绿色 ≥ −50，黄色 ≥ −70，红色更低 |
| 噪声 | 噪声底（dBm） |
| SNR | 信噪比（dB），由信号减噪声推导 |
| MCS | 调制编码方案索引 |
| 速率 | 当前传输速率（Mbps） |

空缺字段统一渲染为 `-`。

## 平台实现

| 平台 | 接口枚举 | 网络扫描 | 备注 |
| ---- | ---- | ---- | ---- |
| macOS | `networksetup -listallhardwareports` + `net.Interfaces` | `system_profiler SPAirPortDataType`（文本模式，`LC_ALL=C` 固定英文） | 驱动经 ioreg IORegistry 定位；JSON 输出不含 SSID，故走文本解析 |
| Linux | `/proc/net/wireless` + sysfs + `iw dev <iface> info` | 暂未实现 | Termux 环境不调用 iw，接口名按前缀兜底识别 |
| Windows | `netsh wlan show interfaces` / `show drivers` | 暂未实现 | netsh 输出随系统语言变化，键名中英文兼容 |
| Android (Termux) | `/proc/net/wireless` | 暂未实现 | 无 root 时数据有限 |

macOS 的 profiler 解析采用相对缩进而非写死层级，避免不同 macOS 版本或权限下的排版差异导致漏读；同一网络同时出现在「当前网络」与「其他网络」时按 ESSID + 信道去重，保留带已连接标记的那条。

## 平台限制

macOS 由系统不提供以下数据，表中显示 `-`：

| 字段 | 原因 |
| ---- | ---- |
| BSSID | profiler 不输出 |
| 加密套件 | profiler 只报告加密代际，不含套件明细 |
| 未连接网络的噪声 / SNR / MCS / 速率 | 链路质量数据仅对已连接网络提供 |

BSSID 与加密套件待 Linux（`iw scan`）与 Windows（`netsh wlan show networks mode=bssid`）扫描实现后自然补齐。

Wi-Fi 处于关闭状态时，profiler 会省略全部 SSID，程序以警告提示 `未扫描到无线网络，请确认 Wi-Fi 已开启`。

## 常见问题

**接口表 PHY 列显示 `-`？**
macOS 没有 Linux 的 `phyN` 命名，该列仅 Linux 系填充。

**为什么同一个 ESSID 出现两次？**
2.4 GHz 与 5 GHz 是同一 SSID 的两个 BSS，各自独立成行。

**`sudo make list` 有什么不同？**
部分系统信息在非特权模式下可能被裁剪，sudo 可获得更完整的数据。

**信号列的颜色代表什么？**
绿色表示 −50 dBm 以上的强信号，黄色为 −50 至 −70 dBm 的中等信号，红色表示 −70 dBm 以下的弱信号，连接质量已不可靠。
