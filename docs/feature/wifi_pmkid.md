# PMKID 主动获取与 pcap 离线提取（`pmkid` / `extract`）

传统 WPA2 握手破解链路（`deauth` 踢人 → 等客户端重连 → `get_packet` 抓四次握手）有三个绕不开的前提：空域里有真实客户端在线、客户端被踢后肯重连、AP 未启用 802.11w 管理帧保护。任何一条不满足，链路就卡死。

PMKID 把这三个前提全部拆掉：攻击者自己扮演客户端，向 AP 发送 Authentication + Association，AP 若在关联响应或 EAPOL M1 的 RSN IE 中返回 PMKID List，即可拿回一个**不需要任何握手完成**的离线破解素材——无客户端、免踢人、不受 802.11w 影响。

| 命令 | 作用 | 输出 |
|:---|:---|:---|
| `pmkid <ssid\|bssid> [网卡]` | 主动会话：假客户端关联，抽取 PMKID | hashcat 22000 行（`-o` 落盘） |
| `get_packet --pmkid --bssid xx` | PMKID 会话与 pcap 抓包共存 | hash 行 + 抓包证据文件 |
| `extract capture.pcap` | 离线分析 pcap：握手数 / PMKID 有无 / 各帧合法性 | 摘要 + 择优 hash 行 |

## 1. 原理：为什么 PMKID 优于纯握手

802.11i 规定 AP 维护 PMKSA 缓存，缓存条目以 PMKID 索引：

$$\text{PMKID} = \text{HMAC-SHA1}(\text{PMK},\ \text{“PMK Name”} \,\|\, \text{MAC}_{AP} \,\|\, \text{MAC}_{STA})\ \text{截取 128 位}$$

对个人 PSK 网络而言 PMK = PBKDF2(密码, SSID, 4096, 32) 恒定不变，PMKID 随之长期有效——**SSID 与密码不变，PMKID 就不变**，抓到一次可反复离线爆破。

| 维度 | deauth → 握手 | PMKID 主动获取 |
|:---|:---|:---|
| 真实客户端在线 | 必须 | 不需要 |
| 踢人（deauth） | 必须 | 不需要 |
| 802.11w（PMF）保护 | deauth 被挡即卡死 | 不受影响（认证/关联不受管理帧保护） |
| 素材有效期 | 密码变更前有效（随握手刷新） | SSID+密码不变则永久有效 |
| 适用认证 | PSK / SAE 握手均可 | 仅 PSK（Enterprise 的 PMKID 派生路径不同，必须过滤） |
| AP 侧前提 | 无 | AP 在 RSN IE 返回 PMKID（很多消费级默认开，企业级常关） |

两条路互补：`pmkid` 未命中时（`rsn-no-pmkid`）AP 多半只是不在关联阶段携带，此时退回 deauth + 四次握手路径。

## 2. 用法

```bash
# 主动获取（推荐直接用 BSSID 精确锁定）
wifisec pmkid aa:bb:cc:dd:ee:ff -o out.22000
wifisec pmkid 'MyWiFi' wlan0mon --attempts 5

# 会话与抓包共存：hash 行与 pcap 证据一次拿到
wifisec get_packet --pmkid --bssid aa:bb:cc:dd:ee:ff --ssid 'MyWiFi' 60 capture.pcap

# 离线分析已抓取的 pcap（免 root，不碰网卡）
wifisec extract capture.pcap                       # 摘要：完整握手数 / PMKID 有无 / 各帧合法性
wifisec extract capture.pcap --hashcat out.22000   # 择优导出 22000（PMKID 优先，握手对兜底）
wifisec extract capture.pcap --pmkid out.16800     # 旧版 hashcat 16800（仅 PMKID）
wifisec extract capture.pcap --bssid aa:bb:cc:dd:ee:ff --ssid 'MyWiFi' --json
```

| 参数 | 适用命令 | 含义 |
|:---|:---|:---|
| `-o out.22000` | pmkid | hash 行落盘（0600，与口令同级敏感） |
| `--ssid 名称` | pmkid / get_packet / extract | 隐藏网络显式 ESSID（PBKDF2 的 salt）；extract 中兼作候选的 salt 兜底 |
| `--attempts N` | pmkid | 尝试轮次上限；每轮更换随机客户端 MAC |
| `--json` | pmkid / get_packet / extract | 机器可读输出，字段名对齐 hashcat 社区记法 |
| `--bssid MAC` | get_packet / extract | 攻击目标 / 输出过滤（PMKID 与 BSSID 绑定，推荐替代 SSID） |
| `--eapol` | get_packet | 连接态抓包时实时分析握手与 PMKID 候选 |
| `--hashcat out.22000` | extract | 择优 22000 行落盘 |
| `--pmkid out.16800` | extract | 旧版 16800 行落盘（仅 PMKID 候选） |

## 3. 输出示例

```text
23:14:02 [信息] PMKID 会话启动：接口 wlan0mon · 目标 aa:bb:cc:dd:ee:ff（MyWiFi）· 信道 6 · 每轮随机客户端 MAC，Ctrl-C 中止
23:14:02 [警告] 仅用于授权测试，请确保目标网络为你所有或已获书面许可
23:14:05 [信息] PMKID 获取成功（第 1 轮尝试）
  AP aa:bb:cc:dd:ee:ff · 信道 6 · -47 dBm
  PMKID 00112233445566778899aabbccddeeff
  STA   2e:1a:7f:00:93:c4（本次随机客户端 MAC）
  ESSID MyWiFi
  hashcat WPA*01*0011…eeff*aabbccddeeff*2e1a7f0093c4*4d7957694669***01
```

```text
[信息] pcap 分析完成：capture.pcap
  链路 DLT 127 · 共 862 帧 · EAPOL-Key 4 帧
  M1 2 · M2 2 · M3 0 · M4 0 · 完整握手配对 1 · PMKID 候选 1
  覆盖 AP 1 个 · 择优后 1 条 hash 行
  AP aabbccddeeff（MyWiFi · 信道 6）
    PMKID   有（00112233445566778899aabbccddeeff）
    握手    M1M2 ×1
[信息] 22000 行已写入 out.22000（1 行）：hashcat -m 22000 out.22000 字典.txt
```

同一 AP 同时有 PMKID 与完整握手时，`--hashcat` 只写 PMKID 行：它长期有效且不依赖握手时序；JSON 输出保持全量（两种行都给），择优只发生在 22000 文件里。

## 4. 协议细节

### 4.1 会话帧流程

| 步骤 | 动作 | 说明 |
|:---|:---|:---|
| 1 | 切到目标信道 | 由扫描结果成对绑定（BSSID/信道/RSSI），调用方保证 monitor 模式 |
| 2 | 发 Authentication（Open System, seq=1）→ 收 seq=2 | 被拒即 `auth-reject`（可能 MAC 白名单） |
| 3 | 发 Association Request | 源 MAC 每轮随机生成（local bit 置位，避免与真实 STA 冲突），RSN IE 声明 PMKID 能力 |
| 4 | 收 Association Response / EAPOL M1 | 从 RSN IE 的 PMKID List 抽取目标值 |
| 5 | 超时/未命中 | 退回 deauth + 四次握手路径（`get_packet` 抓取） |

### 4.2 RSN IE（元素 0x30）解析

解析器用状态机按字段步进，每步做长度边界检查，malformed IE 直接跳过，绝不 panic：

| 偏移 | 字段 | 校验 |
|:---|:---|:---|
| 0-1 | 元素 ID 0x30 + 长度 | 长度与缓冲区余量一致 |
| 2-3 | version（0x0001） | 非 1 丢弃 |
| 4-7 | group cipher suite | OUI 必须为 00-0F-AC |
| 8-9 + N×4 | pairwise cipher suite count + 列表 | count 与余量一致 |
| .. + N×4 | AKM suite count + 列表 | **必须含 00-0F-AC:02（PSK）或 :06（PSK-SHA256），否则标记 Enterprise/SAE 并拒绝** |
| .. | RSN capabilities（2B） | bit0 pre-auth、bit1 no pair-wise |
| ..（可选） | PMKID count + 16B×N | 为 0 或不存在即无 PMKID |

### 4.3 hashcat 22000 行格式

规格依据：hashcat wiki "Cracking WPA/WPA2"（mode 22000，v6.0.0+）+ hashcat v7.1.2 `docs/hashcat-example-hashes.md` 与 `tools/test_modules/m22000.py`。代码以 `eapol.FormatVersion = "hashcat-v7.1.2"` 常量锁定，未来格式变动以版本开关分流。

| 行型 | 布局（`*` 分隔 9 段，全小写 hex） |
|:---|:---|
| PMKID（01） | `WPA*01*<PMKID>*<MAC_AP>*<MAC_STA>*<ESSID_HEX>***<MP>` |
| EAPOL（02） | `WPA*02*<MIC>*<MAC_AP>*<MAC_STA>*<ESSID_HEX>*<ANONCE>*<EAPOL>*<MP>` |

- EAPOL 字段为完整包体，**偏移 81 的 16 字节 MIC 区必须清零**——hashcat 用 field2 之外的内容重算 MIC 比对，不清零产出永不可解的废 hash
- messagepair（MP）低 4 位：`00`=M1M2、`01`=M1M4 / PMKID 来自 AP、`02`=M2M3、`05`=M3M4；PMKID 行 bit1 置位表示 AKM 为 SHA-256 变体
- ESSID 为空（隐藏 SSID 且未恢复）时**拒绝产出**——空 salt 的 PBKDF2 不是合法 hash，宁缺毋滥
- 16800（已弃用）：`PMKID:MAC_AP:MAC_STA:ESSID_HEX`，仅为旧版 hashcat 兼容保留

## 5. 平台能力矩阵与失败分类

| 平台 | 路径 | 前提 |
|:---|:---|:---|
| Linux / Termux | monitor VIF 上同时开读帧（AF_PACKET）与注入 | root |
| Windows | Npcap 双句柄：读帧走 capture 层（radiotap 视角），注入走 wpcap.dll | 管理员 + Npcap（勾选 raw 802.11） |
| macOS | 不可用：Apple 未开放帧注入 API，返回精确技术说明并建议 `get_packet --eapol` 被动抓握手 | - |
| ESP 协处理器 | 拒绝：串口协议当前仅支持单向注入，PMKID 需要认证/关联的双向交互 | - |

会话失败按分类给出可行动提示：

| 分类 | 含义 | 下一步 |
|:---|:---|:---|
| `no-beacon` | 收不到目标信标 | 确认范围内；部分 USB 网卡 monitor 下收不到帧，重插或换驱动 |
| `no-rsn-ie` | 开放网络或 WEP | 不存在 PMKID，无攻击面 |
| `non-psk` | 802.1X/Enterprise 或 SAE | PMKID 派生路径与 PSK 字典无关，改走其他路径 |
| `rsn-no-pmkid` | AP 未返回 PMKID | 改走 deauth + `get_packet` 四次握手 |
| `auth-reject` | 认证被拒 | 重试已自动换 MAC；持续被拒多半 MAC 白名单 |
| `assoc-reject` | 关联被拒 | 能力集不符或 AP 负载满，稍后重试 |
| `hidden-ssid` | 目标不广播 SSID | 用 `--ssid` 显式提供（PBKDF2 需要它作 salt） |
| `timeout` | 流程中断在中间阶段 | 增大 `--attempts` 或靠近目标重试 |

同名 SSID 多 AP 场景（双频路由器）在目标解析层直接拒绝并列出候选：hash 与 BSSID 一一绑定，只按 SSID 匹配会产出解不开的废 hash，必须用 BSSID 逐个获取。

## 6. 成功率预期与调参

- **实测命中率**：消费级路由（TP-Link、小米、华硕等家用固件）多数默认在关联响应/M1 携带 PMKID，命中率较高；企业级 AP（Aruba/Cisco）与部分新固件默认关闭 PMKSA 缓存外显，`rsn-no-pmkid` 属正常现象而非工具缺陷
- **提升手段**：增大 `--attempts`（每轮换客户端 MAC，部分固件按 STA 缓存策略决定是否携带 PMKID）；锁定信号最好的信道靠近 AP；清空干扰源提高抓帧质量（PMKID 不依赖真实客户端，但空口质量影响帧完整性）
- **纯软件做不到的事**：无法强制 AP 开启 PMK 缓存外显（固件行为）；802.11w 下 deauth 依旧被挡（本路径不依赖 deauth，但握手兜底链路仍受限）；WPA3-SAE 的 PMKID 与 PSK 字典无关，即使抓到也解不开
- **驱动依赖**：monitor 模式（收）、帧注入（发）缺一不可；radiotap 的 RSSI/信道字段精度随驱动而异，未上报时相应字段如实标注

## 7. 如何自测

```bash
# 1. 用自家路由器验证（合法场景）：观察是成功还是 rsn-no-pmkid
wifisec pmkid <你家路由器的BSSID> -o /tmp/selftest.22000

# 2. 已知密码回归：用真实密码所在字典确认 hashcat 命中
hashcat -m 22000 /tmp/selftest.22000 你的字典.txt

# 3. 全链路无硬件自测：fixture 构造 + golden 比对（tests/ 与各包内测试）
go test ./...
```

判定参考：`rsn-no-pmkid` 但 `deauth + get_packet --eapol` 能抓到完整握手 → 该 AP 只是关联阶段不携带 PMKID，走握手路径即可；`non-psk` 提示出现说明目标为企业认证或 WPA3-SAE，PMKID 路线不适用。

## 8. 授权边界

PMKID 会话会向目标 AP 发送真实认证/关联帧，产出的 hash 行与口令同级敏感——落盘文件 0600，用后即删。仅限自有网络与已获书面授权的测试环境使用（见 [SECURITY.md](../../SECURITY.md) 使用授权边界）；对第三方 AP 执行本功能在多数司法辖区构成未授权访问尝试。
