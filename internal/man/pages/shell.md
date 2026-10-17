# SHELL(1)

## 名称
shell — 横向移动控制端：交互会话或单命令一步执行

## 用法
    wifisec shell <主机> [命令...] [--token 令牌] [--port N]
    wifisec <主机> [命令...] [--token 令牌] [--port N]

## 描述
WFS1 协议控制端，连接 bind(1) 被控端并下发命令。两种调用形态
等价：首参是 IP 时由参数路由自动转入本命令，无需显式输入
shell。

命令词是 `bash` 或 `sh` 时进入交互会话，exit 或 Ctrl-D 退出；
其余命令整句交由远端 /bin/sh -c（Windows cmd /C）解释，管道与
重定向语义保留，stdout/stderr 实时回传。

单命令模式把远端退出码映射成本地退出码，脚本化的横向移动链
才能正确判断每一步成败；远端命令超时（默认 60 秒）返回退出码
124（GNU timeout 惯例）。

令牌解析优先级：命令行 `--token` > 环境变量 `WIFISEC_TOKEN`。
令牌经 argv 会出现在 shell 历史与 ps 输出中，多用户机器建议走
环境变量。

## 选项
`--token 令牌`
:   认证令牌，与被控端启动时打印的一致；缺省读取
:   `WIFISEC_TOKEN`，两者皆无则拒绝连接。

`--port N`
:   被控端监听端口，默认 9485。

## 示例
    wifisec shell 192.168.1.123 bash --token lab2026
    wifisec 192.168.1.123 whoami --token lab2026
    WIFISEC_TOKEN=lab2026 wifisec 192.168.1.123 'uname -a'

## 另见
bind(1), docs/feature/lateral_movement.md
