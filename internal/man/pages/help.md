# HELP(1)

## 名称
help — 显示用法总览：命令分组、签名、示例与文档入口

## 用法
    wifisec help
    wifisec

## 描述
输出完整用法总览：无线电塔 banner、版本与授权边界、按攻击面
分组的命令表（无线攻击 / 无线防御 / 勘测可视化 / 局域网分析 /
维护）、每类攻击面的最小可运行示例、仓库内深度文档与在线文档
站入口。

裸跑 wifisec（不带任何参数）等价于执行本命令。

输出遵循 Unix usage 惯例直接写 stdout，不带日志时间戳前缀；
管道或重定向时自动剥离 ANSI 颜色序列，落盘与 CI 日志没有转义
残留。设置 `NO_COLOR` 环境变量可强制关闭颜色。

## 示例
    wifisec help
    NO_COLOR=1 wifisec help > usage.txt

## 另见
man(1)
