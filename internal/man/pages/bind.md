# BIND(1)

## 名称
bind — 横向移动被控端：bind shell 监听，等待控制端接入

## 用法
    wifisec bind [--port N] [--token 令牌] [--timeout 秒]

## 描述
WFS1 协议被控端：长度前缀帧 + HMAC-SHA256 挑战应答认证——令牌不上
网线，抓包重放无效。默认监听 TCP 9485。

必须配置认证令牌，无裸奔模式；空令牌时自动生成 128 位随机令牌并
打印到终端。认证失败记录对端地址用于审计。

命令经 /bin/sh -c（Windows cmd /C）解释，stdout/stderr 实时回传。
超时默认 60 秒，超时强制击杀子进程并返回退出码 124（GNU timeout
惯例）。

## 选项
`--port N`
:   监听端口，默认 9485。

`--token 令牌`
:   认证令牌；缺省自动生成随机令牌并打印。

`--timeout 秒`
:   单条命令执行超时，默认 60。

## 示例
    wifisec bind --token lab2026
    wifisec bind --port 9486 --token lab2026

## 另见
shell(1), docs/feature/lateral_movement.md
