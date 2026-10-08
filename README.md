# WifiSec

将 [veerendra2/wifi-deauth-attack](https://github.com/veerendra2/wifi-deauth-attack)（Python）重构为 Go 的无线安全测试工具，采用 Hexagonal Architecture：应用编排不感知底层注入方式，平台能力收敛在 adapter 层。

## 工作方式

支持两条注入路径，按构建与平台自动分发：

| 路径 | 原理 | 平台 | 权限 |
|:---|:---|:---|:---|
| **ESP 协处理器**（默认） | 帧注入在板载 ESP8266/ESP32 射频上完成，宿主机经 USB 串口下发协议帧 | macOS / Linux / Windows / Termux 全平台 | 无需 root |
| Linux 原生 | `iw` 创建 monitor 接口 + `AF_PACKET` 原始套接字 | Linux / Termux(Android) | root 或 `CAP_NET_RAW` |
| Windows 原生 | Npcap 驱动注入 + WlanHelper 切 monitor | Windows | 管理员 + Npcap |
| macOS 原生 | 不可用——Apple 未开放任何公开的 802.11 帧注入 API，报精确技术说明 | macOS | - |

macOS 用户走协处理器路径即可：插一块 ESP8266 开发板（约十元），烧录固件后全部功能免 root 可用。

## 构建与运行

依赖 Go 1.26+，无 CGO 依赖。

```bash
make build   # 编译至 build/wifisec
make list    # 扫描无线接口与周边网络
make test    # 运行测试
make help    # 查看全部 make target
```

macOS 的 `make build` 会产出 `build/wifisec.app` bundle 并建同名符号链接：定位授权（TCC）弹窗只对 LaunchServices 激活的 bundle 呈现，裸二进制的授权请求会被系统静默丢弃；符号链接保留 `./build/wifisec list` 的 CLI 使用习惯。其他平台为单个二进制。

## 命令

```bash
wifisec list                              # 列出无线接口与周边网络
wifisec serial                            # 列出 USB 串口设备（协处理器入口排查）
wifisec deauth <ssid|bssid> [串口]        # 对目标持续发送 deauth 帧，Ctrl-C 停止
wifisec help                              # 用法总览
```

功能文档：

| 命令 | 功能 | 文档 |
| ---- | ---- | ---- |
| `list` | 无线接口枚举与周边网络扫描 | [wifi_list.md](docs/feature/wifi_list.md) |
| `serial` | 串口设备发现与 VID:PID 判读 | [wifi_serial.md](docs/feature/wifi_serial.md) |
| `deauth` | 802.11 deauthentication 帧注入 | [wifi_deauth.md](docs/feature/wifi_deauth.md) |

`deauth` 目标可传 SSID（同名多 AP 全部命中、轮流切信道）或 BSSID（精确锁定）；多串口设备时以第二参数指定端口名，唯一 USB 串口时自动探测。

## 固件烧录

协处理器固件源码：[core/esp/esp.ino](core/esp/esp.ino)，一份源码经编译期条件分支覆盖 ESP8266 / ESP32 全系（仅 ESP32-C5 具备 5GHz 注入能力，主机按固件握手的能力位图自动识别，不猜板型）。

烧录流程（arduino-cli / Arduino IDE 两种方式）、板型晶振陷阱、下载模式按键与 `--no-stub` 兜底等完整排错，见 [wifi_deauth.md §5.4-§5.5](docs/feature/wifi_deauth.md)。

## 测试

测试集中在 [tests/](tests/) 独立 package，仅访问各 package 导出标识符，以表驱动测试覆盖协议编解码、AP 解析去重、MAC 归一化、CLI 校验等关键逻辑：

```bash
make test
```

## 免责声明

本项目仅用于**授权范围内**的无线安全评估与教学实验。请确保目标网络为你所有或已获书面许可；对未授权网络使用属违法行为，后果由使用者自行承担。
