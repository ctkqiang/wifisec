# WiFi Deauthentication（解除认证攻击）

## 目录

- [1. 功能概述](#1-功能概述)
- [2. 802.11 协议原理](#2-80211-协议原理)
- [3. 帧结构设计](#3-帧结构设计)
- [4. 架构与平台分发](#4-架构与平台分发)
- [5. ESP 协处理器模式（默认）](#5-esp-协处理器模式默认)
- [6. Linux 原生注入路径](#6-linux-原生注入路径)
- [7. Windows Npcap 注入路径](#7-windows-npcap-注入路径)
- [8. 使用方法](#8-使用方法)
- [9. 执行流程与生命周期](#9-执行流程与生命周期)
- [10. 配置项](#10-配置项)
- [11. 错误排查](#11-错误排查)
- [12. 安全边界与法律声明](#12-安全边界与法律声明)
- [13. FAQ](#13-faq)

---

## 1. 功能概述

`wifisec deauth` 向目标 AP 的关联客户端持续广播伪造的 802.11 deauthentication 管理帧，使客户端误判自身关联状态失效而主动断开 Wi-Fi。

| 属性 | 值 |
|:---|:---|
| 命令 | `wifisec deauth <ssid\|bssid> [iface\|串口]` |
| 运行模式 | 前台运行，`Ctrl-C` 终止并自动清理 |
| 目标指定 | 必填参数，SSID（精确匹配）或 BSSID（大小写不敏感） |
| 帧类型 | 广播 deauth（目标地址 `ff:ff:ff:ff:ff:ff`） |
| 发送间隔 | 200ms，无总量上限 |
| 默认注入后端 | ESP 串口协处理器（`EMBEDDED_MODE = true`） |

支持注入的平台：Linux、Windows（Npcap）、Termux（需 root）、以及**任何可插 USB 串口的平台**（ESP 协处理器模式，含 macOS）。

---

## 2. 802.11 协议原理

### 2.1 为什么 deauth 有效

802.11 的关联生命周期由**管理帧**（Management Frame）驱动：

```
客户端                    AP
  │    Probe Request  →    │
  │    ← Probe Response    │
  │    Authentication →    │
  │    ← Authentication    │
  │    Association Req →   │
  │    ← Association Resp  │
  │  ═══ 已关联，开始通信 ═══ │
  │    ← Deauthentication  │  ← 本功能伪造的就是这一帧
  │  ═══ 关联被单方面终止 ═══ │
```

deauthentication 帧的设计初衷是 AP 或客户端**单方面宣告**「关联关系结束」。在 WPA2 及更早的协议中，管理帧**不参与加密与完整性校验**——任何人都可以伪造 AP 的地址发出合法的 deauth 帧，客户端协议栈无从辨别真伪，只能照办断开。

### 2.2 PMF（802.11w）免疫边界

| 安全代际 | 管理帧保护 | deauth 是否有效 |
|:---|:---|:---|
| OPEN / WEP | 无 | 有效 |
| WPA / WPA2 | 默认不启用 | 有效（绝大多数现网） |
| WPA2 + PMF 强制 | 启用 | **无效** |
| WPA3 | 强制启用 | **无效** |
| 6GHz 频段（WiFi 6E/7） | 强制启用 | **无效** |

PMF 启用后，deauth 帧携带由会话密钥计算的 MIC（消息完整性校验），伪造帧因缺少密钥被客户端直接丢弃。这是**协议层防御**，与注入硬件无关——任何工具（含 aircrack-ng）都打不动 PMF 强制的网络。

### 2.3 Reason Code

本实现使用 **Reason Code 7**（`Class 3 frame received from nonassociated STA`）：

> 客户端收到后认为「我在未关联状态下收到了只有关联状态才该出现的帧」，即自身关联状态已失效，从而主动断开并重连。

这是 802.11 标准 §9.4.1.7 定义的标准原因码，所有主流客户端（iOS / Android / Windows / macOS / Linux）都会正确响应。

---

## 3. 帧结构设计

构造逻辑位于 [internal/ieee80211/frame.go](../../internal/ieee80211/frame.go)，纯字节编解码，不做任何系统交互。

总长度 **34 字节** = Radiotap 头 8 字节 + 802.11 MAC 头 24 字节 + Reason Code 2 字节：

```
偏移   字段                  值                      说明
──────────────────────────────────────────────────────────────────
 0-7   Radiotap 头           00 00 08 00 00 00 00 00 最小头，仅声明自身长度 8
 8-9   Frame Control         C0 00                   type=管理(0), subtype=deauth(12)
10-11  Duration              00 00                   NAV 置 0
12-17  addr1（Receiver）     FF FF FF FF FF FF       广播：AP 下所有客户端生效
18-23  addr2（Transmitter）  <目标 BSSID>            伪装成 AP 自己发送
24-29  addr3（BSS ID）       <目标 BSSID>            标识该 BSS
30-31  Sequence Control      00 00                   占位，由芯片填充序列号
32-33  Reason Code           07 00                   Class 3 from nonassoc STA
```

Frame Control 由移位组合生成，非硬编码：

```go
frame[radiotapHeaderLen] = byte(subtypeDeauth<<4 | typeManagement<<2) // = 0xC0
```

**为什么需要 Radiotap 头**：Linux AF_PACKET 注入时，驱动根据 radiotap 头决定发送参数（信道、速率）。最小 8 字节头声明「不携带任何字段」，芯片按当前设置的信道发送。ESP8266 路径不需要它，适配器在发送前自动剥离前 8 字节。

---

## 4. 架构与平台分发

### 4.1 六边形架构映射

```
┌─────────────────────────────────────────────────┐
│  cmd/main.go   注册 "deauth" → WifiDeauther      │
├─────────────────────────────────────────────────┤
│  internal/functions/deauther.go                  │
│    平台路由 · 参数解析 · 目标筛选 · 注入循环编排    │
│    ┌─────────────────────────────┐              │
│    │ frameWriter 端口（Write/Close）│  ← 核心抽象  │
│    └─────────────────────────────┘              │
├─────────────────────────────────────────────────┤
│  internal/ieee80211   帧编解码（纯字节，无系统交互） │
├─────────────────────────────────────────────────┤
│  Adapters                                        │
│    platform/esp       USB 串口（全平台）             │
│    platform/linux     AF_PACKET 原始套接字         │
│    platform/windows   Npcap wpcap.dll            │
└─────────────────────────────────────────────────┘
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

[deauther.go](../../internal/functions/deauther.go) 的 `WifiDeauther`：

```go
if constants.EMBEDDED_MODE {
    return deauthESP(arguments)   // 最前置：串口协处理器，与平台无关
}
switch utilities.GetOS() {
case Linux, Android:  return deauthLinux(...)
case Windows:         return deauthWindows(...)
case Darwin:          return deauthDarwin(...)  // 精确错误说明
}
```

`EMBEDDED_MODE` 定义于 [constant.go](../../internal/constants/constant.go#L8-L10)，当前为 `true`。设为 `false` 即回退到操作系统原生路径。

### 4.4 frameWriter 端口

应用层不直接操作 socket / 串口 / DLL，只依赖一个接口：

```go
type frameWriter interface {
    Write([]byte) error
    Close() error
}
```

三个注入适配器各自实现该接口，注入循环（`runDeauthLoop`）对后端完全无感知。这是 ESP 协处理器能作为「即插即用新后端」接入而核心逻辑零改动的原因。

---

## 5. ESP 协处理器模式（默认）

### 5.1 原理

```
宿主机 ═══USB 数据线═══> ESP 开发板 ═══2.4/5GHz 射频═══> 目标客户端
      （串口 UART，纯字节流）         （伪装的 deauth 帧）
```

- 宿主机把开发板当作普通串口设备，**宿主机的 WiFi 能力完全不参与**——这是 macOS 唯一可行的注入路径。
- 开发板**不需要连接任何 WiFi**（既不用连目标路由器，也不用开热点）。deauth 是伪造而非连接：帧的 addr2 冒充目标 AP 的 BSSID。
- 全程无需 root / 管理员权限。

### 5.2 硬件要求

同一固件源码（`core/esp/esp.ino`）通过编译期宏自动适配以下板型：

| 开发板 | 注入原语 | 频段 | 支持 |
|:---|:---|:---|:---|
| ESP8266（NodeMCU / Wemos D1 mini 等） | `wifi_send_pkt_freedom` | 2.4GHz（信道 1-14） | ✅ |
| ESP32 经典 / C2 / C3 / S2 / S3 | `esp_wifi_80211_tx` | 2.4GHz（信道 1-14） | ✅ |
| ESP32-C5 | `esp_wifi_80211_tx` | 2.4 + 5GHz（信道 1-14 / 36-165） | ✅ |
| Arduino UNO + WiFi Shield（NINA/WINC） | 无开放注入 API | — | ❌ 编译期 `#error` |

| 项目 | 要求 |
|:---|:---|
| USB 串口芯片 | CH340 / CP2102 / 板载 USB-JTAG（macOS 对 CH340 可能需装驱动） |
| 数据线 | 必须是数据线，纯充电线没有 D+/D- |
| 价格 | ESP8266 约 ¥15-25；ESP32 系列约 ¥20-60 |

频段能力由固件在握手时以**能力位图**上报，主机不猜测板型：5GHz 目标（信道 > 14）在 2.4GHz 芯片上会被逐目标跳过并给出告警。

### 5.3 串口协议

小端定长头帧，双向以魔数区分方向：

```
主机→ESP: [0xA5][cmd][len_lo][len_hi][payload]
ESP→主机: [0x5A][cmd][len_lo][len_hi][payload]
```

| 方向 | cmd | payload | 说明 |
|:---|:---|:---|:---|
| 主机→ESP | `0x00` | 无 | PING 握手；打开串口会复位板子，boot 期间命令必丢，需重试至收到 PONG |
| 主机→ESP | `0x01` | 无 | 请求扫描（含隐藏 SSID） |
| 主机→ESP | `0x02` | 信道(1) + 802.11 帧 | 注入；帧已剥 radiotap |
| ESP→主机 | `0x00` | 协议版本(1) + 能力位图(1) | PONG；boot 完成时也会主动上报一次 |
| ESP→主机 | `0x01` | bssid(6)+channel(1)+rssi(1)+ssidLen(1)+ssid | 扫描条目，逐条回传 |
| ESP→主机 | `0x02` | 无 | 扫描结束 |
| ESP→主机 | `0x04` | 出错命令(1)+错误码(1) | 错误 |

能力位图（PONG 第 2 字节）：

| bit | 含义 |
|:---|:---|
| 0 | 支持 5GHz 注入（当前仅 ESP32-C5） |
| 1-7 | 保留，固定为 0 |

向后兼容：旧固件 PONG 只回 1 字节版本号，主机按「无扩展能力」（仅 2.4GHz）处理，不会误判为损坏。

设计取舍：

- **先握手再干活**——打开串口触发板子复位，boot 需 1-2 秒；主机以 500ms 节奏重发 PING，收到 PONG（协议版本 1）才发扫描命令，冷启动/热启动时序通吃。
- **噪声重同步**——ESP 芯片上电以非工作波特率输出启动日志（ESP8266 为 74880），在 115200 下呈现为随机字节；解析器逐字节丢弃直至帧头 `0x5A`，残缺帧保留待下一段拼齐。
- **注入不回 ACK**——每条确认都占串口带宽（115200 baud ≈ 11KB/s），持续注入场景下丢确认比丢帧更伤帧率。
- **信道随帧携带**——`SetChannel` 在 Go 侧仅缓存，多目标轮发时无需额外串口往返。
- **payload 上限 512 字节**——固件侧超长直接拒绝，防缓冲区溢出。

### 5.4 固件烧录

固件源码：[core/esp/esp.ino](../../core/esp/esp.ino)（目录结构已符合 Arduino 规范：文件夹名 `esp` 与文件名 `esp.ino` 一致）

1. 安装 Arduino IDE 或 arduino-cli，添加对应开发板支持：ESP8266 用 `esp8266:esp8266`，ESP32 系列用 `esp32:esp32`。
2. 用 Arduino IDE 直接打开 `core/esp/esp.ino`。
3. 开发板选择对应型号（ESP8266 如 `NodeMCU 1.0`，ESP32 如 `ESP32C5 Dev Module`），上传。
4. 插入电脑，确认串口出现：
   - macOS：`ls /dev/cu.usbserial-*` 或 `/dev/cu.wchusbserial-*`
   - Linux：`ls /dev/ttyUSB*`（用户需在 `dialout` 组）
   - Windows：设备管理器查看 `COMx`

### 5.5 烧录排错

**编译内存报表解读**：编译成功后 IDE 会输出分段占用，以下为正常范围（以 ESP8266 实测为例；ESP32 分段名称不同但判读方法一致——编译器未报 `overflow` 即正常）：

| 段 | 实测占用 | 判定 | 说明 |
|:---|:---|:---|:---|
| RAM | 35%（28700/80192） | 健康 | 大头是 core 的 WiFi 驱动缓冲区（BSS 26KB），固件自身仅 512B 接收缓冲 |
| IRAM | 91%（59747/65536） | 正常 | 32KB 被 flash 指令缓存强制保留，其余为 core 中断代码的固定开销 |
| Flash | 22%（239316/1048576） | 充裕 | 余量约 800KB |

判定标准：编译器未对任何段报 `overflow` 错误即正常。IRAM 91% 是**每个** ESP8266 sketch 的基线水位，不是本固件的问题。

**上传超时（`Failed to connect: Timed out waiting for packet header`）**：

ESP 芯片必须在复位瞬间拉低 GPIO0（BOOT）才能进入 UART 下载模式。开发板的自动复位电路（DTR/RTS）在 macOS + CH340 组合下经常失灵，esptool 同步不到 bootloader 即超时。按成功率排序：

1. **手动进下载模式**（首选）：按住 `FLASH`（或 `BOOT`）按钮不放 → 点按一下 `RST` → 松开 `FLASH` → 立即点上传。看到 `Writing at 0x00000000...` 即成功。
2. **降低上传波特率**：`工具` → `Upload Speed` → `115200`。默认的 460800/921600 在部分 CH340 与线材组合下不稳定。
3. **检查串口占用**：`lsof /dev/cu.usbserial-XXXX`，关闭占用进程（如 Arduino 串口监视器）。
4. **切换复位方式**：`工具` → `Reset Method` → NodeMCU/Wemos 板选 `nodemcu`，通用板选 `ck`。

**`找到无效库 ... no headers files (.h) found`**：

与固件无关。`~/Documents/Arduino/libraries/` 下存在不符合库结构的文件夹（例如误放的板级核心仓库），IDE 每次编译都会警告。将其移出 `libraries/` 目录即可消除，例如：

```bash
mv ~/Documents/Arduino/libraries/<误放目录> ~/Documents/
```

### 5.6 使用

```bash
# 列出全部串口设备（确认板子被识别、取端口名）
wifisec serial

# 自动探测唯一 USB 串口
wifisec deauth gunner

# 多个串口设备时手动指定
wifisec deauth <BSID> /dev/cu.usbserial-1410
```

`wifisec serial` 输出示例（USB 设备置顶并给出 VID:PID，CH340 为 `1A86:7523`）：

```
端口                             类型  VID:PID    产品           序列号
───────────────────────────────────────────────────────────────────────
/dev/cu.usbserial-1120           USB   1A86:7523  USB2.0-Serial  -
/dev/cu.Bluetooth-Incoming-Port  系统  -          -              -
```

协处理器会先以自身射频扫描周边网络（2.4GHz 芯片只回 2.4GHz 结果，ESP32-C5 同时回 5GHz），顺便绕过了 macOS 对未连接网络 BSSID 的脱敏；锁定目标后进入注入循环。

### 5.7 LED 状态指示

固件驱动板载 LED（`LED_BUILTIN`；ESP8266 的 NodeMCU/Wemos 为 GPIO2 低电平点亮，多数 ESP32 开发板为高电平点亮，固件按芯片自动选择电平），不看终端也能判断固件状态：

| LED 表现 | 状态 |
|:---|:---|
| 上电快闪三下 | 固件启动完成（随后主动上报 PONG） |
| 每 0.5 秒规律闪烁（心跳） | 固件存活，串口待命 |
| 常亮（约 2-3 秒） | 正在扫描周边网络 |
| 急促无规律闪烁 | 正在注入 deauth 帧 |
| 常灭 | 未上电、固件未烧录或串口命令从未到达 |

心跳用 `millis()` 非阻塞实现，不拖慢串口状态机；注入闪烁由每帧翻转产生，帧率越高闪得越快。

---

## 6. Linux 原生注入路径

### 6.1 技术栈

| 环节 | 实现 |
|:---|:---|
| monitor 接口 | `iw phy <phy> interface add <mon> type monitor`（试 `wifimon0..9` 跳过占用名） |
| 启用接口 | `ip link set <mon> up` |
| 信道切换 | `iw dev <mon> set channel <ch>` |
| 帧注入 | `AF_PACKET`(17) + `SOCK_RAW`(3) + `ETH_P_ALL`(0x0003) 原始套接字 |
| 清理 | 退出时 `iw dev <mon> del`（仅删除本进程创建的接口） |

### 6.2 执行要求

```bash
sudo wifisec deauth <SSID>            # 按 SSID（同名多 AP 全打，轮流切信道）
sudo wifisec deauth <BSID> # 按 BSSID（精确锁定）
sudo wifisec deauth <SSID> wlan1      # 指定接口（缺省取第一块无线网卡）
```

- 需要 root 或 `CAP_NET_RAW`。
- 网卡驱动必须支持 monitor 模式（`iw phy` 输出中 `Supported interface modes` 含 `monitor`）。
- 若接口当前处于 managed 模式且已连接，启动时会警告「进入 monitor 模式将断开当前 Wi-Fi 连接」。
- 接口本身已是 monitor 模式时直接复用，退出时不删除。

### 6.3 Termux（Android）

与 Linux 同一路径（`inject_android.go` 使用 `android` 构建标签），额外要求：

1. 设备已 root（`su` / `tsu` 可用）。
2. `pkg install root-repo && pkg install iw`。
3. 芯片固件支持 monitor：Broadcom/Cypress 老芯片需 nexmon 补丁；Qualcomm 视机型而定；最稳妥方案为 Kali NetHunter。

交叉编译：`CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build -o wifisec-android ./cmd`

---

## 7. Windows Npcap 注入路径

| 环节 | 实现 |
|:---|:---|
| 帧注入 | 动态加载 Npcap 的 `wpcap.dll`（`syscall.NewLazyDLL`，无 cgo） |
| monitor 模式 | Npcap 自带 `WlanHelper.exe` 切换网卡为 `rfmon` |
| 权限 | 管理员终端 |

前置条件：

1. 安装 [Npcap](https://npcap.com/)，安装时**必须勾选** `Support raw 802.11 traffic (and monitor mode) for wireless adapters`。
2. 网卡驱动支持 monitor（多数笔记本内置网卡**不支持**，USB 外置网卡如 Alfa 系列支持较好）。
3. 以管理员身份运行终端。

```powershell
wifisec.exe deauth <SSID>
wifisec.exe deauth <BSID> "WLAN"
```

> 该路径目前通过交叉编译验证（`GOOS=windows` 构建通过），真机注入行为依赖具体网卡驱动，实测反馈欢迎。

---

## 8. 使用方法

### 8.1 命令格式

```
wifisec deauth <ssid|bssid> [iface|串口]
```

| 参数 | 必填 | 说明 |
|:---|:---|:---|
| `ssid\|bssid` | 是 | 目标网络。含冒号的合法 MAC 自动识别为 BSSID，否则按 SSID 精确匹配 |
| `iface\|串口` | 否 | ESP 模式为串口名（缺省自动枚举唯一 USB 串口）；Linux 模式为接口名（缺省取第一块无线网卡） |

### 8.2 运行示例

```
$ wifisec deauth <SSID>
[INFO] 通过 /dev/cu.usbserial-1410 扫描周边 2.4GHz 网络…
[INFO] 开始 deauth 攻击：接口 /dev/cu.usbserial-1410 · 目标 2 个 · 间隔 200ms
[WARN] 仅用于授权测试，请确保目标网络为你所有或已获书面许可
^C
已发送 1340 帧 · 目标 2 个 · 运行 2m14s
```

### 8.3 同名 SSID 多 AP 策略

按 SSID 匹配时，若扫到多个同名单元（如双频路由的 2.4G/5G 或 mesh 组网），**每个 AP 都是目标**：注入循环每轮按各自信道轮流发送，所有单元同时受影响。

---

## 9. 执行流程与生命周期

```
START
  ↓
EMBEDDED_MODE? ──true──→ deauthESP（串口路径，无权限要求）
  ↓ false
平台分发（linux/android / windows / darwin）
  ↓
参数解析（BSSID 或 SSID 判定）
  ↓
扫描锁定目标（ESP 射频扫描 / iw scan / Npcap 枚举）
  ↓
按目标预生成 34 字节帧（避免循环内重复构造）
  ↓
准备注入通道（开串口 / 建 monitor 接口+原始套接字 / 加载 wpcap.dll）
  ↓
┌─ 注入循环 ─────────────────────────┐
│  每个目标: 切信道 → 写帧 → sent++   │
│  轮间隔 200ms                       │
│  单目标失败仅警告跳过，不中断整体      │
└────────────────────────────────────┘
  ↓ SIGINT / SIGTERM（Ctrl-C）
打印统计（已发送帧数 · 目标数 · 运行时长）
  ↓
清理（关串口 / 删自建 monitor 接口 / 关句柄）
  ↓
EXIT
```

**信号处理细节**：`cmd/main.go` 注册的全局信号处理器会无条件 `os.Exit(0)`，deauth 路径先执行 `signal.Reset(SIGINT, SIGTERM)` 再 `signal.NotifyContext` 接管——否则清理代码（删除 monitor 接口）永远不会执行。

---

## 10. 配置项

| 配置 | 位置 | 默认值 | 说明 |
|:---|:---|:---|:---|
| `EMBEDDED_MODE` | [constant.go](../../internal/constants/constant.go#L8-L10) | `true` | 是否默认走 ESP 串口协处理器路径 |
| 发送间隔 | deauther.go `sendInterval` | `200ms` | 每轮向所有目标发完后的固定间隔 |
| 串口波特率 | esp.go `baudRate` | `115200` | 必须与固件 `Serial.begin` 一致 |
| 扫描读超时 | esp.go `scanReadTimeout` | `15s` | 覆盖 ESP 完整扫描（约 2-3s）+ 串口回传 |
| monitor 命令超时 | linux/monitor.go `monitorTimeout` | `10s` | 单条 `iw`/`ip` 命令超时 |
| 固件 payload 上限 | esp.ino `rxBuf` | `512B` | 超长帧直接拒绝 |

---

## 11. 错误排查

| 错误信息 | 原因 | 解决 |
|:---|:---|:---|
| `未发现 USB 串口设备` | ESP 未插入或驱动未装 | 检查数据线（须为数据线非充电线）；CH340 芯片装驱动 |
| `发现多个 USB 串口设备` | 插了多个串口设备 | 把端口名作为第二参数传入 |
| `等待固件响应超时` | 固件未烧录或波特率不匹配 | 重新烧录 [core/esp/esp.ino](../../core/esp/esp.ino) |
| `未找到目标 X；当前协处理器仅支持 2.4GHz` | 目标只在 5/6GHz 发射，且固件无双频能力 | 换 ESP32-C5 / Linux / Windows 原生路径，或确认目标有 2.4GHz 信号 |
| `固件协议版本 vX 与本程序支持的 v1 不兼容` | 固件过旧或过新 | 重新烧录最新 [core/esp/esp.ino](../../core/esp/esp.ino) |
| `打开原始套接字需要 root 权限或 CAP_NET_RAW` | Linux 未提权 | `sudo` 运行 |
| `Operation not permitted`（iw 建 monitor） | 同上 | `sudo` 运行 |
| `信道 N 不可用` | 网卡不支持该信道（常见 DFS 雷达信道） | 属正常现象，该目标自动跳过 |
| `macOS 不支持 802.11 帧注入` | 系统无注入 API（`EMBEDDED_MODE=false` 时） | 开启 ESP 模式或换平台；`sudo` 无效 |
| Windows 注入无效果 | 网卡不支持 monitor / 未勾选 raw 802.11 | 重装 Npcap 并勾选项；换支持的网卡 |

---

## 12. 安全边界与法律声明

- 本功能仅用于**授权安全测试**：目标网络必须为你所有，或已获得书面测试许可。启动时程序会输出相应警告。
- 对未授权网络执行 deauth 在多数司法辖区构成违法（干扰无线电通信 / 破坏计算机系统）。
- deauth 只造成**暂时性断连**：停止发送后客户端会自动重连，不窃取凭据、不持久化任何数据。
- 帧构造边界：仅构造标准 deauthentication 管理帧，不实现其他帧类型注入。

---

## 13. FAQ

**Q1：为什么 macOS 上 `sudo` 也不能注入？**
瓶颈不是权限而是平台能力。Apple 从系统框架层未开放 802.11 帧注入——CoreWLAN 只有扫描和关联接口，root 无法让不存在的 API 出现。macOS 的解决方案是 ESP 协处理器模式。

**Q2：ESP 开发板需要连接目标路由器的 WiFi 吗？**
不需要。deauth 是伪造而非连接：帧的 addr2 冒充目标 AP 的 BSSID，目标客户端以为路由器在说「你下线吧」。全程无需密码、无需认证、无需关联。

**Q3：ESP 开发板需要连接我电脑的 WiFi 吗？**
不需要。电脑与开发板之间是 USB 串口线，不是 WiFi。电脑的 WiFi 状态完全无所谓，断网也能用。

**Q4：Docker / 虚拟机里能跑原生注入吗？**
Docker on macOS 的 Linux VM 没有任何无线设备，不可行。VMware/VirtualBox + **USB 网卡直通**可行（内置网卡的射频无法直通）。ESP 模式下虚拟机只要能映射 USB 串口即可。

**Q5：为什么打了没效果？**
按概率排查：① 目标是 WPA3 或启用了 PMF（协议层免疫）；② 协处理器是 2.4GHz 芯片而目标只在 5GHz（换 ESP32-C5 可解）；③ 目标距离过远信号太弱；④ Linux/Windows 网卡实际不支持注入（能进 monitor 不代表能发）。

**Q6：发送速率能调吗？**
修改 [deauther.go](../../internal/functions/deauther.go) 的 `sendInterval`。ESP 路径受 115200 波特率限制（约 280 帧/秒上限），200ms 间隔远未触顶。

**Q7：如何测试 ESP 固件是否工作？**
插上板子后运行 `wifisec deauth 任意名字`：能看到 `[INFO] 协处理器就绪（协议 v1 · 2.4GHz）…` 并返回「未找到目标」错误，说明串口双向通信与固件扫描均正常。
