# CLONE(1)

## 名称
clone — 热点克隆（Evil Twin）：同名同密码 SoftAP 诱捕客户端

## 用法
    wifisec clone <ssid>:<密码> up [nokick] [串口]
    wifisec clone down [串口]

## 描述
双路径执行：存在 ESP 串口协处理器时走硬件 AP+STA 双模路径（固件需
包含 CMD_CLONE 0x05 / CMD_CLONE_STATUS 0x06 协议，旧固件返回错误码
255）；无设备时自动回落 Linux hostapd 路径（需 root，kick 功能需
第二块无线网卡）。macOS/Windows/Android 无硬件时返回精确技术说明。

默认每 200ms 对目标 AP 发送 deauth 帧驱赶其客户端，`nokick` 关闭。
目标 SSID 扫描取 RSSI 最强的 AP 作为信道与 kick 目标；扫描不到时
回落信道 6 并禁用 kick。

运行期间实时打印客户端接入/离开事件；Ctrl-C 终止时输出统计：运行
时长、接入客户端数、峰值连接数、kick 发送帧数。

## 参数
`<ssid>:<密码>`
:   克隆热点的名称与密码，中间用英文冒号分隔。

`up [nokick]`
:   启动克隆；`nokick` 关闭对真实 AP 的 deauth 驱赶。

`down`
:   停止固件上的克隆热点，恢复 STA 模式。

## 示例
    wifisec clone 'MyWiFi':'same-password' up
    wifisec clone 'MyWiFi':'same-password' up nokick
    wifisec clone down

## 另见
deauth(1), brute(1), docs/feature/wifi_clone.md
