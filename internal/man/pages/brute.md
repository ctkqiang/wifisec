# BRUTE(1)

## 名称
brute — 在线密码字典爆破，命中即停

## 用法
    wifisec brute <ssid|bssid> with-pass: <字典文件> [串口]

## 描述
双路径执行：存在 ESP 串口协处理器时走硬件路径，无设备时自动回落
本机无线网卡（macOS/Linux/Windows）；Android 因系统限制不支持本机
路径。命中正确密码立即停止，输出完整的 SSID、BSSID、命中密码、
尝试次数与总耗时。

启动前请知悉：每次尝试约 2-5 秒（AP 应答延迟）；现代 AP 多次失败
后会限速/锁定 STA；WPA3 SAE 握手对在线爆破不友好。本机路径会导致
当前 WiFi 断开重连，期间本机网络临时不可用。

本机路径使用临时配置，命中后立即清理，不污染已保存的 WiFi 配置。
macOS 路径采用两段式验证：`networksetup -setairportnetwork` 返回 0
仅代表系统受理请求，需轮询确认当前 SSID 与目标一致才算真实命中，
避免错误密码提前停止。

## 参数
`<ssid|bssid>`
:   目标网络。

`with-pass: <字典文件>`
:   字典每行一个密码；`#` 开头为注释，空行自动跳过。

`[串口]`
:   显式指定 ESP 串口；缺省自动探测。

## 示例
    wifisec brute 'MyWiFi' with-pass: pass.txt
    wifisec brute 01:23:45:67:89:ab with-pass: rockyou-top1000.txt

## 另见
clone(1), pmkid(1), docs/feature/wifi_brute_force.md
