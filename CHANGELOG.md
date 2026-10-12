# 更新日志 (Changelog)

本项目所有值得注意的变更都记录在此文件中，格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。

## [未发布]

### 新增

- **实时嗅探与 ARP 欺骗 MITM（`wifisec sniff`）**：bettercap 风格被动嗅探当前连接网络（Linux AF_PACKET / macOS BPF / Windows Npcap，需 root/管理员），DNS 查询 / HTTP 请求 / TLS SNI 实时标注 + 40 行/秒限速 + 退出输出协议分布；`--spoof` 叠加双向 ARP 毒化（1s 刷新 + who-has 即时应答）与 IP 转发 / ICMP redirect 压制，退出按启动前备份以真实 MAC 重发 5 轮恢复帧完整还原，Windows 欺骗入口明确拒绝、被动嗅探不受影响
- **横向移动通道（`bind` / `shell`）**：被控端 `wifisec bind` 监听 TCP（默认 9485），HMAC-SHA256 挑战应答认证（令牌不落网、抓包重放无效），空令牌自动生成 128 位随机令牌并打印；控制端 `wifisec <ip> bash` 交互 shell、`wifisec <ip> <命令>` 单命令一步执行（IP 开头自动路由），stdout/stderr 实时回传，远端退出码映射本地，命令超时击杀并返回退出码 124
- 跨平台 CI 编译工作流（macOS / Ubuntu / Windows）
- GitHub Release 发布与下载通道
- 中文 PDF 手册与静态文档站

## 2026-10-08

### 新增

- **ESP 协处理器泛化**：PONG 握手携带能力位图，按能力分发，不猜板型
- **串口枚举**：`wifisec serial` 命令，USB 设备置顶并展示 VID:PID
- **deauth 全程播报**：注入进度逐帧播报，消除主机侧长时间静默
- **串口占用诊断**：点名占用进程，握手失败按链路观测分级诊断
- **CLI 改进**：无子命令时默认展示帮助；help 输出全部子命令用法

### 修复

- 修复打开串口锁死下载模式与批量回传帧读取超时
- 修复开串口复位导致的扫描超时（PING/PONG 握手 + 噪声重同步）

### 文档

- 新增 deauth 功能完整技术文档与 ESP8266 烧录排错实战指南
- deauth 命令示例 MAC 地址统一替换为通用占位符（脱敏）

## 2026-10-07

### 新增

- **Linux 平台 802.11 deauth 帧注入**
- **macOS CoreWLAN BSSID 补全**：helper 架构 + 定位授权 + 签名支持
- **平台代码重构**：拆分各平台网络扫描与接口枚举逻辑
- 企业级 WPA2/WPA3 网络安全态势解释与测试用例

### 修复

- 修复 termux 平台变量声明与错误处理问题
- 修复无 GUI 时定位授权弹窗被抑制的问题

## 2026-10-06 及更早

- 项目初始化：Hexagonal Architecture 骨架、802.11 帧构造、法规域合规对照表
