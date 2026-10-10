# 热点克隆 / Evil Twin（`wifisec clone`）

`wifisec clone` 在指定信道上承载一个**同名同密码的克隆热点**，并可对真实 AP 持续注入广播 deauth（kick），把其客户端「挤」到克隆网络上。这是无线安全评估里的经典 Evil Twin 场景：验证员工/设备在同名网络出现时是否会无感接入，进而评估钓鱼热点与凭证捕获的暴露面。

**两条执行路径自动选择**：插入 ESP 开发板时走协处理器（固件切 AP+STA 双模，克隆 AP 与 kick 帧都由板载射频承载，支持全部平台）；未检测到设备时回落**本机 hostapd 路径**——仅 Linux 可行，且 kick 需要第二块无线网卡。macOS 无公开的 AP hosting API（CoreWLAN 的 IBSS 仅支持 WEP/开放网络）、Windows 的 hostednetwork 已被 Microsoft 废弃、Android 应用层禁止第三方进程承载 AP，这些平台会得到精确的不可行说明，请插 ESP。

固件烧录与串口排错见 [wifi_deauth.md §5.4-§5.5](wifi_deauth.md)；串口发现见 [wifi_serial.md](wifi_serial.md)。

## 获取二进制

```bash
go install github.com/ctkqiang/wifisec/cmd/wifisec@latest
```

其他获取方式（Release 下载、源码编译）见仓库 README。

## 1. 功能定位

`clone` 回答的问题是：**「一个同名热点出现在空中时，客户端会不会把它当成真的」**。它适用于：

- 自有网络的钓鱼暴露面评估——同名 SSID + 同密码的克隆能否吸走设备；
- 已获书面授权的渗透测试——配合监控客户端接入/离开，评估无线准入策略（如 802.1X、按 MAC 准入）是否真的把设备拦在了克隆网络外。

它**不做**凭证捕获：克隆 AP 本身不截获流量、不记录客户端数据。企业级 WPA-EAP（eaphammer 的 rogue RADIUS / 证书捕获路线）超出本工具范围——ESP 的 SoftAPI 只支持开放/WEP/PSK，见 §7.3。

## 2. 用法

```bash
wifisec clone <ssid>:<密码> up [nokick] [串口]     # 拉起克隆热点并进入会话
wifisec clone down [串口]                          # 停止固件上的克隆热点
```

| 参数 | 说明 |
|:---|:---|
| `<ssid>:<密码>` | 克隆网络的名称与密码，按**第一个冒号**切分；密码可再含冒号，无需转义。密码留空（`clone 'MyWiFi': up`）即开放网络 |
| `up` | 拉起克隆热点并进入会话循环，Ctrl-C 结束并输出统计 |
| `nokick` | 可选。禁用对真实 AP 的 deauth 驱赶（kick 默认开启） |
| `[串口]` | 可选。缺省自动探测唯一 USB 串口；多板插入时按 `wifisec serial` 输出手动指定 |

示例：

```bash
wifisec clone 'MyWiFi':'same-password' up          # 同名同密码克隆 + kick 真实 AP
wifisec clone 'MyWiFi': up nokick                  # 开放网络克隆，不驱赶客户端
wifisec clone 'MyWiFi':'same-password' up /dev/cu.usbserial-XXXX   # 指定串口
wifisec clone down                                 # 停止克隆热点
```

凭据约束（802.11 与 hostapd 双侧硬性限制）：SSID 1-32 字节，WPA2 密码 8-63 字节；SSID/密码不能包含换行或 NUL 字符（会破坏 hostapd 配置行结构，两类路径统一直接拒绝）。中文 SSID 按字节计——12 个汉字是 36 字节，超限。

## 3. 执行流程

```
[信息] 连接 /dev/cu.usbserial-XXXX，等待固件就绪…
[信息] 协处理器就绪（协议 v1），扫描周边网络定位克隆目标…
[警告] 克隆热点仅用于授权测试；未经许可克隆他人网络并截获流量违反刑法第二百八十五条
[信息]
════════════ 克隆热点已上线 ════════════
  SSID      : MyWiFi
  密码      : same-password
  信道      : 6
  克隆 BSSID: 1a:2b:3c:4d:5e:6f
  真实 AP   : aa:bb:cc:dd:ee:ff（信道 6）
  kick      : 已启用（每 200ms 广播 deauth 驱赶真实 AP 客户端）
  监控      : 客户端接入/离开将实时打印，Ctrl-C 结束会话
═══════════════════════════════════════
[信息] 客户端接入 8c:85:90:xx:xx:xx（在线 1 台）
[信息] 客户端离开 8c:85:90:xx:xx:xx（在线 0 台）
```

| 输出 | 含义 |
|:---|:---|
| `克隆热点已上线` 凭据块 | SoftAP/hostapd 已就绪。SSID/密码/信道/克隆 BSSID 一次给齐，客户端照此接入 |
| `真实 AP : …` | 扫描锁定到的同名网络；无此行表示周边扫不到同名 SSID（信道回落 6，kick 自动禁用） |
| `客户端接入/离开 <MAC>` | 实时设备事件——ESP 路径按 2 秒轮询差分得出，hostapd 路径来自进程日志即时解析 |
| `kick 注入失败` | 单帧发送异常（串口瞬断等），会话继续；连续出现请检查链路 |

Ctrl-C 结束时输出统计块：运行时长、接入/离开计数、峰值在线与累计 kick 帧数。

### 克隆目标如何锁定

启动时先扫描周边网络，在结果中查找同名 SSID 并取 **RSSI 最强**者作为参照：克隆信道跟随它，kick 也指向它（客户端最可能关联信号最好的同名 AP）。周边扫不到同名网络时，信道回落 6、kick 自动禁用并告警——克隆仍会拉起，但没有驱赶效果。

### 串口复用与会话生命周期

克隆与 deauth/brute 共用同一根串口，**同一时刻只能有一个进程持有板子**。kick 与设备状态轮询在同一会话内并发进行（串口层做事务级互斥），因此不需要开第二个进程。宿主机每次打开串口都会复位开发板——克隆 AP 的存活期跟板子供电走，`clone down` 用于会话内优雅收尾（恢复干净 STA 模式）；拔电即停。

## 4. kick 机制

kick 默认开启（`nokick` 关闭），目标是让真实 AP 的客户端因收不到信标/无法通信而掉线，进而搜索网络并连上同名克隆：

- **帧内容**：复用 deauth 的同一套帧构造——广播 deauth（目标地址 `ff:ff:ff:ff:ff:ff`，源地址为真实 AP 的 BSSID）；
- **节奏**：每 200ms 一帧，与 deauth 命令同节奏，持续发送直到 Ctrl-C；
- **信道**：注入器先切到真实 AP 的信道（与克隆信道一致），帧只发在目标信道上。

ESP 路径中克隆 AP（SoftAP）与 kick 注入（STA 自由帧）共用同一块板子的射频，AP+STA 并存时两份工作都落在同一信道上，互不干扰；hostapd 路径中 AP 接口被 hostapd 独占，kick 由**第二块无线网卡**（USB 小网卡即可）创建的 monitor 接口承担，会话结束时自动删除该接口。

## 5. 协议细节（0x05 / 0x06 克隆命令）

`clone` 复用 deauth/brute 的同一根串口与同一份固件，新增两对命令/回复（0x04 保留给错误帧方向，克隆从 0x05 起编）：

| cmd | 方向 | 含义 | payload |
|:---|:---|:---|:---|
| `0x05` | 主机→ESP | 开/停克隆 AP | op(1) + channel(1) + ssidLen(1) + ssid + passLen(1) + password；op 1=up 0=down（down 时其余字段占位） |
| `0x05` | ESP→主机 | 克隆结果 | result(1) + apMAC(6)；down 回复 MAC 全零 |
| `0x06` | 主机→ESP | 状态查询 | 无 |
| `0x06` | ESP→主机 | 在线设备 | count(1) + count×MAC(6) |

固件侧行为（`handleClone` / `handleCloneStatus`）：

1. `op=1`：校验三段式布局与信道合法性 → `WiFi.mode(WIFI_AP_STA)` 切双模 → `softAP(ssid, pass, channel)` 拉起克隆网络（ESP32 放开到 10 站上限，ESP8266 按芯片默认 4 站）→ 回 `result=1` 与 SoftAP 自身 MAC；
2. `op=0`：`softAPdisconnect(true)` + 恢复 STA 模式 → 回 `result=1` 与全零 MAC；
3. 状态查询：ESP8266 遍历 SoftAP 站点链表、ESP32 走 `esp_wifi_ap_get_sta_list`，统一回 count + MAC 列表；
4. 克隆 AP 存活期间板载 LED 常亮（心跳暂停），便于肉眼确认「板子正在当 AP」。

主机侧 `CloneAPUp/CloneAPDown/CloneStatus` 的读取预算为 5 秒——SoftAP 开关是亚秒级调用，状态查询为即时应答。设备接入/离开事件没有固件主动上报机制，由主机按 2 秒节奏轮询差分得出。

> 旧固件不含 `0x05` 命令：收到后回 `REP_ERROR(出错命令, 0xFF)`，主机报「固件不支持克隆命令」——按 README 固件烧录章节重刷最新固件即可。

## 6. hostapd 本机路径（仅 Linux）

未检测到 ESP 时走本机路径，前置条件三件套：**root 权限**、**hostapd 已安装**（`apt install hostapd`）、**至少一块无线网卡**。

执行顺序：选定接口（优先 managed 模式）→ `iw dev scan` 扫描真实网络定位克隆目标 → 生成临时 hostapd 配置（`driver=nl80211`，密码非空即 `wpa=2`/`wpa_passphrase`/`CCMP`，空即开放网络）→ 接口置 DOWN 后拉起 hostapd → 阻塞等待 `AP-ENABLED`（15 秒超时）→ 进入会话。客户端事件来自 hostapd 进程日志的 `AP-STA-CONNECTED/DISCONNECTED` 行，即时推送。

路径局限：

- **NetworkManager 会抢接口**：桌面发行版上 NetworkManager 可能重新托管无线接口与 hostapd 冲突，测试前建议 `systemctl stop NetworkManager`（会话结束后恢复）；
- **kick 需要第二块网卡**：hostapd 独占 AP 接口，没有第二块无线网卡时 kick 自动降级并告警，克隆照常运行；
- **接口 MAC 即克隆 BSSID**：hostapd 拉起 AP 后接口地址就是克隆网络的 BSSID；
- **五 GHz/DFS 信道**：部分驱动在法规域下拒绝在 DFS 信道（52-140）承载 AP，报错请换 1-11 信道目标。

## 7. 局限与边界

### 7.1 客户端行为不可控

同名同密码是吸引客户端的必要条件而非充分条件：部分系统对「见过的 AP 突然消失又出现但 MAC 不同」保持沉默，企业 MDM 可能直接禁用开放/新网络。kick 只能把客户端从真实 AP 踢下来，**不能强迫它连上克隆**——配合 `nokick` 对照测试可以量化 kick 的贡献。

### 7.2 串口复位决定生命周期

宿主机每次 `Open()` 都会复位开发板（DTR/RTS 时序），因此克隆 AP 无法跨进程「接管」：`clone up` 结束（Ctrl-C）后 SoftAP 随进程关闭而消失，`clone down` 是显式清理而非唯一停止方式。需要长期驻留的克隆 AP 应保持会话进程运行。

### 7.3 企业级 WPA-EAP 不可行

eaphammer 的 `--auth wpa-eap --creds`（rogue RADIUS 证书捕获）依赖主机侧跑完整 802.1X/EAP 认证栈，ESP 的 SoftAPI 只支持开放/WEP/PSK，hostapd 路径虽可配置 `wpa_key_mgmt=WPA-EAP` 但需要额外 RADIUS 服务与证书体系，均不在本工具范围内。wifisec 的 clone 定位是**同名热点的接入面验证**，不是凭证捕获框架。

### 7.4 2.4GHz / 5GHz

克隆信道跟随扫描到的真实 AP。ESP8266/ESP32 经典系列射频仅覆盖 2.4GHz，扫描不到 5GHz 网络也就无法克隆它们（固件会以信道回落 6 告警）；ESP32-C5 双频芯片可以克隆 5GHz 目标（信道 36-165）。hostapd 路径跟随网卡自身能力。

## 8. 排错

| 报错/现象 | 原因 | 处理 |
|:---|:---|:---|
| `SSID 超过 32 字节上限` | 中文等多字节字符按字节计超限 | 缩短 SSID |
| `WPA2 密码须为 8-63 字节` | 密码过短/过长 | 调整密码长度；想克隆开放网络请留空冒号后的密码 |
| `固件不支持克隆命令（错误码 255）` | 固件过旧，不含 `0x05` 命令 | 重刷最新 `core/esp/esp.ino` |
| `等待克隆结果超时` | 串口链路中断或固件死机 | 重插板子；观察板载 LED 是否常亮（克隆态） |
| `周边未发现同名网络`（警告） | 目标不在信号范围或已改名 | 用 `wifisec list` 确认目标可见；克隆仍会以信道 6 拉起但 kick 禁用 |
| `本机热点克隆需要 root 权限` | hostapd 路径未用 sudo | `sudo wifisec clone …`，或插 ESP 免 root |
| `未找到 hostapd` | Linux 本机路径缺依赖 | `apt install hostapd`，或插 ESP 走协处理器路径 |
| `等待 hostapd 启动超时` | 网卡不支持 AP 模式 / 信道被法规禁用 / NetworkManager 抢占 | `iw list` 确认 supported interface modes 含 AP；换信道；暂停 NetworkManager |
| `未找到第二块无线网卡`（警告） | hostapd 路径 kick 无可用网卡 | 插一块 USB 无线网卡，或接受 kick 降级 |
| `本机热点克隆仅支持 Linux…` | macOS/Windows/Android 无本机 hosting API | 插 ESP 协处理器走硬件路径 |
| 客户端接入后立刻离开 | 克隆密码与真实 AP 不一致（客户端拒绝重连） | 核对密码；克隆开放网络需确认真实 AP 也是开放网络 |
| LED 常亮但搜不到克隆网络 | 信道与客户端扫描范围不匹配（如克隆在 5GHz） | 换 ESP32-C5 或 2.4GHz 目标 |

串口级排错（找不到板子、端口占用、74880 乱码）与 deauth 完全相同，见 [wifi_serial.md §6](wifi_serial.md) 与 [wifi_deauth.md §5.5](wifi_deauth.md)。

## 9. 法律红线

克隆热点 + kick 是对目标网络**主动发起的干扰行为**，客户端被驱赶到克隆网络后产生的关联行为在多数司法辖区可能构成「非法侵入计算机信息系统」或「非法截获通信」。《中华人民共和国刑法》第二百八十五条、第二百八十六条与《网络安全法》第二十七条同样适用于本功能——**仅限自有网络或已获书面授权的测试环境**。对邻居、公共场所、任何第三方网络使用即越线；截获、存储他人通信内容在任何授权场景下都需要额外的明确授权。
