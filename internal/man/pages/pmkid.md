# PMKID(1)

## 名称
pmkid — 主动获取 PMKID：假客户端关联，免踢人产出 hashcat 22000 行

## 用法
    wifisec pmkid <ssid|bssid> [网卡] [-o out.22000] [--ssid 名称] [--attempts N] [--json]

## 描述
纯 Go 实现的主动 PMKID 获取：构造假客户端向目标 AP 发起关联，从
RSN 握手的第一个 EAPOL 帧提取 PMKID，无需踢下真实客户端。帧构造与
解析复用 internal/ieee80211，注入走现有 packet injection 接口。

与 EAPOL 四步握手两条链路互补：超时/未命中自动回落握手抓取逻辑；
同 BSSID 同时存在两者时优先输出 PMKID。

输出统一使用 hashcat v7.1.2 标准的 22000 格式（代码内常量标注依据
版本并预留 formatVersion 开关），16800 仅作兼容输出保留。

## 选项
`-o out.22000`
:   hash 行输出文件；缺省打印到终端。

`--ssid 名称`
:   隐藏 SSID 场景显式指定网络名。隐藏 SSID 会先尝试从 Probe/Assoc
:   Response 恢复，恢复失败明确标记——绝不留空导致 PBKDF2 用空 salt。

`--attempts N`
:   关联尝试次数；重试时更换随机本地管理位 STA MAC，采用 beacon
:   间隔对齐发送与退避策略。

`--json`
:   以 JSON 输出结构化结果，便于脚本串联。

## 注意
多 AP 同名 SSID 场景按 BSSID/信道/RSSI 成对绑定，不会仅按 SSID 匹配
产出无效 hash。AKM 非 PSK（非 00-0F-AC:02）时明确提示 802.1X/
Enterprise 不可用 PMKID 爆破，不静默产出无效 hash。

## 示例
    wifisec pmkid 01:23:45:67:89:ab -o out.22000
    wifisec pmkid 'MyWiFi' en0 --attempts 5 --json

## 另见
get_packet(1), extract(1), docs/feature/wifi_pmkid.md
