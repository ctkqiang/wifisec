# SERIAL(1)

## 名称
serial — 列出 USB 串口设备与 VID:PID（ESP 协处理器入口）

## 用法
    wifisec serial

## 描述
枚举系统可见的 USB 串口设备，标注 VID:PID 与芯片类型
（CH340/CP210x/FTDI 等），用于 deauth/jam/brute/clone 定位 ESP
协处理器串口。

固件在 core/esp/esp.ino，一份源码 `#ifdef` 通吃 ESP8266/ESP32 全系
（C5 双频 36-165 信道）；Arduino+WiFi Shield 编译期 `#error` 拒绝。

## 排错
握手失败按现象分级：收到过字节 → 固件问题（未烧录/烧错/版本过旧）；
无任何字节 → 硬件问题（供电不足/下载模式/线材/hub/端口选错）。
串口被占用时会显示占用进程名称与 PID。

ESP8266 烧录超时：按住 FLASH + 点按 RST 后松开 FLASH 进入下载模式，
上传波特率降至 115200。射频初始化可能因 300mA+ 电流浪涌触发 USB
过流保护掉电，需直连电脑 USB 口并用短线。

## 示例
    wifisec serial

## 另见
deauth(1), brute(1), docs/feature/wifi_serial.md
