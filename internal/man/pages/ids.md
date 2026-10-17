# IDS(1)

## 名称
ids — 无线入侵检测：伪造 AP/KARMA/降级/泛洪/deauth 风暴

## 用法
    wifisec ids [SSID] [网卡] [秒数]

## 描述
无线 IDS 两条检测路径：扫描差分（免 root）发现伪造 AP 与信道异常；
帧级监测（需特权）识别 KARMA 诱饵、降级攻击、管理帧泛洪与 deauth
风暴。

Rogue AP 判定仅在相同频段内对比 BSSID——双频路由器同 SSID 同时工作
在 2.4GHz 与 5GHz 是正常形态，跨频段对比会误报。

## 参数
`[SSID]`
:   锁定单个 SSID 模式：启动时先扫描确认目标可见，不可见直接拒绝
:   运行。锁定后扫描差分与帧风暴检测仅针对该 SSID 及其 BSSID，
:   信道跳频只使用目标所在信道。

`[网卡]`
:   显式指定帧级监测网卡。

`[秒数]`
:   运行时长；缺省持续运行至 Ctrl-C。

## 示例
    wifisec ids
    sudo wifisec ids
    wifisec ids 'MyWiFi'

## 另见
deauth(1), docs/feature/wireless_ids.md
