# DEAUTH(1)

## 名称
deauth — 向目标 AP 持续发送 deauth 帧，断开其全部客户端

## 用法
    wifisec deauth <ssid|bssid> [串口]

## 描述
默认发送广播 deauth（目标地址 ff:ff:ff:ff:ff:ff），间隔 200ms，
无发包总量上限，持续至 Ctrl-C 后输出统计。同名 SSID 存在多个 AP
时，对每个 AP 的信道轮流发送。

跨平台路由：存在 ESP 串口协处理器时走硬件注入；否则 Linux/Android
用 monitor 接口、Windows 用 Npcap + 管理员。macOS 技术层面不可行
（CoreWLAN 无公开注入 API），返回精确技术说明而非含糊失败。

运行 `wifisec list` 选目标时永远不要加 sudo——root 在 GUI 会话之外，
弹不出授权窗，程序会故意跳过 helper。

## 参数
`<ssid|bssid>`
:   目标：按 SSID 匹配同名全部 AP，或按 BSSID 精确锁定一台。

`[串口]`
:   显式指定 ESP 串口；缺省自动探测。串口被占用时会显示占用进程
:   名称与 PID，而非笼统的 "Serial port busy"。

## 示例
    wifisec deauth 'MyWiFi'
    wifisec deauth 01:23:45:67:89:ab
    wifisec deauth 'MyWiFi' /dev/cu.usbserial-0001

## 另见
jam(1), list(1), serial(1), docs/feature/wifi_deauth.md
