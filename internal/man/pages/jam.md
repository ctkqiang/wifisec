# JAM(1)

## 名称
jam — deauth+disassoc 双帧全频段干扰器

## 用法
    wifisec jam <ssid|all|bssid> [串口]

## 描述
复用 deauth 的跨平台路由与帧构造逻辑，同时发送 deauth（0xC0）与
disassoc（0xA0）两种帧——仅 1 字节 opcode 差异，共用公共帧构造器。
三种目标模式：按 SSID 匹配、按 BSSID 精确锁定、`jam all` 遍历所有
可见 AP 逐个干扰。

串口写入连续失败时触发熔断：连续 10 帧写失败判定设备掉线，输出
明确结论后干净退出，不会无限刷屏空转。

## 参数
`<ssid|all|bssid>`
:   `all` 全频段打击所有可见 AP；其余同 deauth(1)。

`[串口]`
:   显式指定 ESP 串口；缺省自动探测。

## 示例
    wifisec jam 'MyWiFi'
    wifisec jam all
    wifisec jam 01:23:45:67:89:ab

## 另见
deauth(1), docs/feature/wifi_jam.md
