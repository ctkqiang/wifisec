# WiFi Jammer（全频段干扰）

## 目录

- [获取二进制](#获取二进制)
- [1. 功能概述](#1-功能概述)
- [2. 802.11 协议原理](#2-80211-协议原理)
- [3. 帧结构设计](#3-帧结构设计)
- [4. 架构与平台分发](#4-架构与平台分发)
- [5. 使用方法](#5-使用方法)
- [6. jam all 全频段模式](#6-jam-all-全频段模式)
- [7. 执行流程与生命周期](#7-执行流程与生命周期)
- [8. 与 deauth 的对比](#8-与-deauth-的对比)
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

`wifisec jam` 对目标 AP 同时发送 802.11 deauthentication（0x0C）与 disassociation（0x0A）双帧，覆盖只过滤 deauth 但不过滤 disassoc 的客户端实现。`jam all` 模式扫描全部可见 AP 逐个打击，实现全频段干扰。

| 属性 | 值 |
|:---|:---|
| 命令 | `wifisec jam <ssid\|all\|bssid> [iface\|串口]` |
| 运行模式 | 前台运行，`Ctrl-C` 终止并自动清理 |
| 目标指定 | `all`（全打模式）、SSID（精确匹配）或 BSSID（大小写不敏感） |
| 帧类型 | 广播 deauth + 广播 disassoc 双帧 |
| 发送间隔 | 200ms，无总量上限 |
| 默认注入后端 | ESP 串口协处理器（`EMBEDDED_MODE = true`） |

支持注入的平台：Linux、Windows（Npcap）、Termux（需 root）、以及任何可插 USB 串口的平台（ESP 协处理器模式，含 macOS）。

---

## 2. 802.11 协议原理

### 2.1 deauth 与 disassoc 的区别

802.11 管理帧中，deauthentication（去认证）与 disassociation（解除关联）是两个不同的管理帧子类型：

| 属性 | deauth (subtype 12) | disassoc (subtype 10) |
|:---|:---|:---|
| Frame Control 低字节 | `0xC0` | `0xA0` |
| 语义 | 终止**认证关系**（更彻底） | 终止**关联关系**（保留认证层） |
| 客户端收到后的行为 | 断开并清除认证状态，需重新走完整认证+关联流程 | 断开但保留认证状态，理论上只需重新关联 |
| 帧长度 | 34 字节 | 34 字节 |
| Reason Code 字段 | 有（uint16 小端） | 有（uint16 小端） |

两者帧结构完全相同（Radiotap 8B + MAC 头 24B + Reason Code 2B = 34B），唯一差异是 Frame Control 低字节中的子类型字段（bit 4-7）。

### 2.2 为什么需要双帧

部分客户端实现（尤其是某些 Android 定制 ROM 和嵌入式 IoT 设备）的帧过滤路径对 deauth 与 disassoc 处理不一致：

- 某些实现只检查 deauth 帧的合法性，对 disassoc 直接执行断开
- 某些实现因 PMF 策略配置不对称，deauth 被 PMF 保护但 disassoc 未被保护
- 某些实现在收到 deauth 后仅断开但快速重连，收到 disassoc 后才彻底放弃

同时发送两种帧可覆盖这些不对称实现，提高干扰有效性。

### 2.3 PMF（802.11w）免疫边界

与 deauth 相同，PMF 启用后两种帧都携带 MIC 校验，伪造帧会被客户端直接丢弃：

| 安全代际 | 管理帧保护 | jam 是否有效 |
|:---|:---|:---|
| OPEN / WEP | 无 | 有效 |
| WPA / WPA2 | 默认不启用 | 有效（绝大多数现网） |
| WPA2 + PMF 强制 | 启用 | **无效** |
| WPA3 | 强制启用 | **无效** |
| 6GHz 频段（WiFi 6E/7） | 强制启用 | **无效** |

---

## 3. 帧结构设计

构造逻辑位于 [internal/ieee80211/frame.go](../../internal/ieee80211/frame.go)，纯字节编解码，不做任何系统交互。

两种帧总长度均为 **34 字节** = Radiotap 头 8 字节 + 802.11 MAC 头 24 字节 + Reason Code 2 字节：

```
偏移   字段                  deauth 值              disassoc 值           说明
──────────────────────────────────────────────────────────────────────────────────────
 0-7   Radiotap 头           00 00 08 00 00 00 00 00                       最小头，仅声明自身长度 8
 8-9   Frame Control         C0 00                   A0 00                 type=管理(0), subtype 不同
10-11  Duration              00 00                   00 00                 NAV 置 0
12-17  addr1（Receiver）     FF FF FF FF FF FF                              广播：AP 下所有客户端生效
18-23  addr2（Transmitter）  <目标 BSSID>                                   伪装成 AP 自己发送
24-29  addr3（BSS ID）       <目标 BSSID>                                   标识该 BSS
30-31  Sequence Control      00 00                   00 00                 占位，由芯片填充序列号
32-33  Reason Code           07 00                   07 00                 Class 3 from nonassoc STA
```

Frame Control 由 `buildManagementFrame` 公共构造器生成，子类型参数决定字节值：

```go
// deauth: subtype=12 → 0xC0
// disassoc: subtype=10 → 0xA0
frame[8] = byte(subtype<<4 | frameTypeManagement<<2)
```

`BuildDeauthFrame` 与 `BuildDisassocFrame` 均委托给 `buildManagementFrame`，唯一差异是传入的子类型参数。这种设计确保两种帧在所有字段上完全一致，仅在 Frame Control 子类型位不同，便于测试验证。

---

## 4. 架构与平台分发

### 4.1 六边形架构映射

```
┌──────────────────────────────────────────────────────┐
│  cmd/wifisec/main.go 注册 "jam" → RunJammer          │
├──────────────────────────────────────────────────────┤
│  internal/functions/jammer.go                        │
│    平台路由 · 参数解析 · 目标筛选 · 双帧注入循环编排  │
│    ┌──────────────────────────────┐                 │
│    │ frameWriter 端口（Write）     │  ← 复用 deauther │
│    │ channelSetter 端口             │                 │
│    └──────────────────────────────┘                 │
├──────────────────────────────────────────────────────┤
│  internal/ieee80211                                 │
│    buildManagementFrame → deauth / disassoc 帧构造   │
├──────────────────────────────────────────────────────┤
│  Adapters（与 deauth 共用）                           │
│    platform/esp       USB 串口（全平台）               │
│    platform/linux     AF_PACKET 原始套接字           │
│    platform/windows   Npcap wpcap.dll               │
└──────────────────────────────────────────────────────┘
```

### 4.2 平台能力矩阵

| 平台 | 注入后端 | 权限要求 | 频段 | 关键依赖 |
|:---|:---|:---|:---|:---|
| 任意平台 + ESP 开发板 | 串口协处理器 | 无（Linux 需 dialout 组） | 2.4GHz（ESP32-C5 含 5GHz） | ESP8266/ESP32 板 + 烧录固件 |
| Linux | AF_PACKET | root / CAP_NET_RAW | 2.4 + 5GHz | 网卡支持 monitor 模式 |
| Termux (Android) | AF_PACKET | root | 2.4 + 5GHz | nexmon 固件或 NetHunter |
| Windows | Npcap | 管理员 | 2.4 + 5GHz | Npcap（勾选 raw 802.11） |
| macOS | **不可用** | — | — | Apple 未开放注入 API |

### 4.3 路由逻辑

[jammer.go](../../internal/functions/jammer.go) 的 `RunJammer`：

```go
if constants.EMBEDDED_MODE {
    if err := jamESP(arguments); !errors.Is(err, errNoESPDevice) {
        return err
    }
    // 未插板回落本机路径，与 brute 的双路径策略一致
    utilities.Warn("未检测到 ESP 协处理器，回落本机无线网卡路径")
}
switch utilities.GetOS() {
case Linux, Android:  return jamLinux(...)
case Windows:         return jamWindows(...)
case Darwin:          return jamDarwin(...)  // 精确错误说明（含 ESP 选项）
}
```

回落规则：

- **未显式指定串口**时自动探测 USB 设备，探测失败回落本机路径
- **显式指定串口**（`wifisec jam 'MyWiFi' /dev/cu.usbserial-xxx`）时忠于用户意图，打开失败直接报错不回落
- 回落到 macOS 时给出精确技术说明（无公开注入 API），引导插板或换平台

注入循环 `runJamLoop` 与 deauther 的 `runDeauthLoop` 结构对称，但每轮对每个目标发两帧（deauth + disassoc）。

### 4.4 复用关系

jam 与 deauth 共享以下基础设施，零重复代码：

| 组件 | 复用来源 |
|:---|:---|
| `frameWriter` / `channelSetter` 端口 | `deauther.go` 定义 |
| `setupSignalHandler` 信号处理 | `deauther.go` |
| `SelectDeauthTargets` 目标筛选 | `deauther.go` |
| `selectWirelessInterface` 接口选择 | `deauther.go` |
| `prepareMonitor` monitor 模式 | `deauther.go` |
| `normalizeMAC` MAC 归一化 | `lists.go` |
| ESP 串口注入器 | `platform/esp` |
| Linux AF_PACKET 注入器 | `platform/linux` |
| Windows Npcap 注入器 | `platform/windows` |

jammer.go 新增的代码仅包括：`jamTarget` 结构体（双帧）、`ParseJamArgs`（all 模式解析）、`buildJamTargets`（双帧预构造）、`runJamLoop`（双帧注入循环）和各平台的 jam 路径函数。

---

## 5. 使用方法

### 5.1 按 SSID 干扰

```bash
wifisec jam 'MyWiFi'
```

与 deauth 一样，同名 SSID 的多个 AP（如双频路由器的 2.4GHz + 5GHz）会全部命中并轮流切信道发送双帧。

### 5.2 按 BSSID 精确锁定

```bash
wifisec jam 01:23:45:67:89:ab
```

BSSID 大小写不敏感。适用于只干扰某个特定 AP 的场景。

### 5.3 全频段模式

```bash
wifisec jam all
```

扫描周边全部可见 AP，不按 SSID/BSSID 过滤，逐个发送双帧。这是最激进的模式，会干扰所有可见网络。

### 5.4 指定接口或串口

```bash
# Linux 指定网卡
wifisec jam 'MyWiFi' wlan0

# ESP 指定串口
wifisec jam 'MyWiFi' /dev/cu.usbserial-1410
```

---

## 6. jam all 全频段模式

`jam all` 是 jam 独有的模式，deauth 不支持：

1. 扫描周边全部可见 AP
2. 不过滤，扫描到的每个 AP 都作为目标
3. 为每个 AP 构造 deauth + disassoc 双帧
4. 按各 AP 所在信道轮流切换并发送双帧
5. 200ms 间隔，持续至 Ctrl-C

在 ESP 协处理器路径下，超出固件能力（如 5GHz 信道而固件仅 2.4GHz）的 AP 会逐个跳过并告警，不会导致整个攻击失败。

**适用场景**：红队评估中需要快速瘫痪目标区域所有无线网络的场景（仅限授权测试）。

---

## 7. 执行流程与生命周期

```
启动
  │
  ├── 参数解析（ParseJamArgs）
  │     ├── all → jamAll=true, target=""
  │     ├── BSSID 格式 → targetMAC 解析成功
  │     └── SSID → target 原样保留
  │
  ├── 平台路由
  │     ├── ESP: Open 串口 → 握手 → Scan → 筛选/全取 → 构造双帧
  │     ├── Linux: root 检查 → 选接口 → Scan → 筛选/全取 → 构造双帧 → monitor
  │     └── Windows: admin 检查 → Npcap → Scan → 筛选/全取 → 构造双帧 → monitor
  │
  ├── 注入循环（runJamLoop）
  │     ├── 逐目标：setChannel → Write(deauth) → Write(disassoc)
  │     ├── 200ms 间隔
  │     ├── 每 3s 进度心跳
  │     └── Ctrl-C → 输出统计（总帧数 · 目标数 · 运行时长）
  │
  └── 清理（defer）
        ├── Linux: 删除自建 monitor 接口
        └── Windows: 恢复 managed 模式
```

---

## 8. 与 deauth 的对比

| 属性 | `wifisec deauth` | `wifisec jam` |
|:---|:---|:---|
| 帧类型 | 单帧（deauth） | 双帧（deauth + disassoc） |
| all 模式 | 不支持 | 支持（扫描全部可见 AP） |
| 发送间隔 | 200ms | 200ms |
| 每轮每目标帧数 | 1 | 2 |
| 客户端覆盖面 | 仅过滤 deauth 路径 | 过滤 deauth + disassoc 两条路径 |
| 适用场景 | 精准打击单个目标 | 全频段干扰、覆盖不对称实现 |
| 代码复用 | 基础 | 复用 deauth 的全部端口与适配器 |

---

## 9. 错误排查

| 现象 | 可能原因 | 解决方案 |
|:---|:---|:---|
| `macOS 不支持 802.11 帧注入` | 未插 ESP 板回落到 macOS 本机路径 | 插入 ESP 开发板（`wifisec serial` 查看设备），或切换 Linux/Windows |
| `未检测到 ESP 协处理器，回落本机无线网卡路径`（警告） | EMBEDDED_MODE 下未插板 | 非错误：Linux/Windows 继续用本机网卡干扰（需 root/管理员）；需要板载射频时插入 ESP 板 |
| `扫描未发现任何网络` | `jam all` 模式下无可见 AP | 确认无线接口正常工作，`wifisec list` 先检查 |
| `未找到目标 <SSID>` | 指定 SSID 不可见或拼写错误 | `wifisec list` 确认 SSID 存在 |
| `目标 BSSID 格式异常` | BSSID 不符合 MAC 地址格式 | 检查 BSSID 格式（`xx:xx:xx:xx:xx:xx`） |
| `5GHz 信道不可用` | ESP 固件仅支持 2.4GHz | 使用 ESP32-C5 或切换本机网卡路径 |
| `接口缺少 GUID`（Windows） | Npcap 未正确安装 | 重装 Npcap，勾选 raw 802.11 选项 |
| 串口相关错误 | 与 deauth 相同 | 参见 [wifi_deauth.md §5](wifi_deauth.md) |

---

## 10. 安全边界与法律声明

`wifisec jam` 通过双帧 + 全频段模式实现了比 deauth 更激进的干扰能力，但法律风险也相应更高：

- **《中华人民共和国网络安全法》第二十七条**：禁止任何个人和组织从事非法侵入他人网络、干扰他人网络正常功能等危害网络安全的活动
- **《中华人民共和国刑法》第二百八十六条**：破坏计算机信息系统罪——对他人无线网络实施干扰，造成严重后果的，处五年以下有期徒刑或者拘役
- **`jam all` 全频段模式**会波及所有可见网络，在人口密集区域使用极易误伤第三方网络，法律风险极高

本工具仅限**自有网络或已获书面授权**的测试环境使用。`jam all` 模式即使在授权范围内，也应确认不会影响邻近无关网络。

---

## 11. FAQ

### Q: 没插 ESP 板也能 jam 吗？

可以。`EMBEDDED_MODE` 下未检测到协处理器时自动回落本机无线网卡路径：Linux/Termux 需 root，Windows 需管理员 + Npcap，macOS 因系统无注入 API 仍会给出精确技术说明。显式指定串口参数时不会回落（忠于用户意图）。

### Q: jam 和 deauth 能同时运行吗？

不能。两个命令各自管理独立的信号处理器，但同时操作同一无线接口/串口会产生冲突。请逐个执行。

### Q: jam all 模式下，5GHz AP 会被跳过吗？

在 ESP 协处理器路径下，如果固件仅支持 2.4GHz（大多数 ESP8266/ESP32），5GHz 信道（>14）的 AP 会被逐个跳过并告警。使用 ESP32-C5 或切换本机网卡路径可覆盖 5GHz。

### Q: 为什么每轮发两帧而不是只发 disassoc？

disassoc 的语义是「解除关联但保留认证」，某些客户端实现可能仅重新关联而不完全断开。deauth 更彻底（终止认证关系），但部分实现对其过滤更严格。双帧覆盖两条路径，确保至少一条生效。

### Q: jam all 模式的输出与 jam <SSID> 有什么区别？

`jam all` 在扫描阶段不按 SSID/BSSID 过滤，扫描结果全部作为目标。输出日志会显示「周边 N 个网络，命中目标 N 个」（N 相同），而 `jam <SSID>` 显示「命中目标 M 个」（M ≤ N）。

### Q: 可以限制 jam all 的目标数量吗？

当前版本不支持。`jam all` 的设计意图就是全频段干扰。如需限制目标，请使用 SSID 或 BSSID 模式。
