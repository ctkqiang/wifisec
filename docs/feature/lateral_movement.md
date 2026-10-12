# 横向移动（Lateral Movement）：agent / shell

> 拿下一台内网机器后向同网段其他主机扩展的通道：被控端跑 `wifisec agent` 监听 TCP，
> 控制端 `wifisec <ip> bash` 拿交互 shell，或 `wifisec <ip> <命令>` 单命令一步执行。

## 功能定位

横向移动（Client-to-Client / Lateral Movement）是后渗透阶段的扩展动作：
攻击面从「无线层」（deauth/brute/clone）转向「网络层」，在已授权的实验网里
验证一台主机被拿下后同网段横向扩散的实际影响半径。

典型链路：

```
wifisec clone（Evil Twin 拿下客户端）
        │
        ▼
目标机上落地 wifisec agent（wifisec agent --token xxx）
        │
        ▼
wifisec 192.168.1.123 bash --token xxx   ← 本模块：交互 shell / 单命令执行
        │
        ▼
同网段其他主机的横向评估（scan_ports / devices 继续侦察）
```

## 用法

### 被控端（目标机）

```bash
wifisec agent                              # 自动生成随机令牌并打印
wifisec agent --token lab2026              # 指定令牌
wifisec agent --port 7000 --timeout 120    # 自定义端口与单命令超时（秒）
```

启动后监听 TCP（默认 9485），等待控制端接入；Ctrl-C 退出。
令牌也可经环境变量 `WIFISEC_TOKEN` 传递，避免出现在 shell 历史与 `ps` 里。

### 控制端（攻击机）

```bash
wifisec 192.168.1.123 bash --token lab2026   # 交互 shell（IP 开头自动路由）
wifisec 192.168.1.123 whoami --token lab2026 # 单命令一步执行
wifisec shell 192.168.1.123 bash             # 显式子命令等价形式
wifisec shell M2.local id                    # 主机名同样可用（mDNS/hosts）
```

交互会话内：输入命令回车执行，`exit` / `quit` / Ctrl-D 结束；
单命令模式的远端退出码会映射为本地退出码，方便脚本串联。

## 协议细节（WFS1）

```
agent → client : "WFS1" 魔数 + 16 字节随机 nonce
client → agent : 32 字节 HMAC-SHA256(令牌, 魔数+nonce)
agent → client : 1 字节认证状态（0=通过）
client → agent : 帧(命令文本, 上限 4KB)
agent → client : 帧(输出块, 上限 1MB)... 帧(空)=输出结束, 帧(1字节)=退出码
```

- **帧格式**：4 字节大端长度前缀 + 载荷；超限帧在读载荷前直接拒绝，畸形长度无法撑爆内存
- **令牌不落网**：认证走 HMAC 挑战应答，抓包重放无效；nonce 每次连接随机
- **无认证即无服务**：agent 空令牌时自动生成 128 位随机令牌并打印，不存在「裸奔模式」——
  局域网第三方扫到端口也无法白嫖命令执行
- **命令解释**：Unix 经 `/bin/sh -c`、Windows 经 `cmd /C`，管道/重定向等 shell 特性保留
- **实时回传**：stdout/stderr 按管道写入节奏流式回帧，`ping` 这类长命令不必等结束才有输出
- **超时击杀**：单命令默认 60 秒超时（`--timeout` 调整），击杀后回 GNU timeout 惯用的
  退出码 124，控制端可区分「命令自己失败」与「看门狗击杀」

## 授权边界

- **仅限自有网络或已获书面授权的测试环境使用**。在被控机上启动 `wifisec agent`
  即意味着你对该机器有完整的操作授权；对未授权主机部署本模块属于违法行为
- agent 启动时会在终端打印授权边界警告；认证失败（含暴力尝试）会记录对端地址
- 令牌即权限：请走 `WIFISEC_TOKEN` 环境变量传递，不要把令牌写进脚本提交仓库

## 局限

| 局限 | 说明 |
|:---|:---|
| 需要 agent 先落地 | 本模块是「已拿下 → 扩展」通道，不含投递手段；agent 需在目标机上手动启动 |
| 非 PTY | 交互是行级「输入一条 → 回传一条」，无 vim/top 全屏程序支持；这是刻意取舍（避免 raw 模式终端兼容性坑） |
| 端口暴露 | agent 监听端口对同网段可见；HMAC 认证挡住未授权接入，但端口本身无法隐藏 |
| 单命令超时 | 超过 `--timeout` 的命令被击杀；长任务应改用 nohup/后台方式在目标机落地 |

## 排错

| 现象 | 原因 | 处理 |
|:---|:---|:---|
| `令牌认证失败` | 控制端与被控端令牌不一致 | 核对 agent 启动时打印的令牌，或统一 `WIFISEC_TOKEN` |
| `连接 x.x.x.x 失败` | agent 未启动 / 端口不通 / 防火墙拦截 | 目标机确认 agent 在跑；`wifisec scan_ports <ip> 9485` 验证端口 |
| `退出码 124` | 命令超时被击杀 | 调大 `--timeout`，或把长任务改为后台执行 |
| 交互会话卡住无输出 | 命令本身未结束（如前台 ping） | Ctrl-C 断开重连；远端长命令改后台化 |
| Windows 上命令报错 | 路径空格 / 引号转义 | cmd /C 的引号规则与 Unix 不同，复杂命令建议先落地 .bat 再执行 |

## 自测

```bash
go test ./internal/lateral/ ./tests/ -run Lateral -v
go test ./internal/lateral/ ./tests/ -v   # 全量含端到端
```

端到端测试在本机回环完成：真实起 agent 监听、真实走认证与命令执行，
覆盖 stdout/stderr 合并、非零退出码、超时击杀（124）与错误令牌拒绝。
