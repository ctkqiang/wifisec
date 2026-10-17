# LIST(1)

## 名称
list — 枚举本机无线接口与周边网络

## 用法
    wifisec list

## 描述
列出本机无线接口（驱动/模式/信道）与周边可见 AP（SSID/BSSID/信道/
加密方式/信号强度），是 deauth/jam/brute/clone 选目标的第一步。

macOS 走 CoreWLAN，扫描需要定位授权：发布物必须是 .app bundle 并经
LaunchServices 激活，裸二进制在终端里直接执行时责任进程归属终端
宿主，系统会静默丢弃授权请求——所以 `make build` 产出 .app。

## 注意
运行本命令**永远不要加 sudo**：root 在 GUI 会话之外，弹不出定位
授权窗，程序会故意跳过 helper，导致扫描结果为空。

## 示例
    wifisec list
    ./build/wifisec list

## 另见
deauth(1), docs/feature/wifi_list.md
