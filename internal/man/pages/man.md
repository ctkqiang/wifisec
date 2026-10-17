# MAN(1)

## 名称
man — 阅读内置手册页：按主题查看用法、选项与示例

## 用法
    wifisec man
    wifisec man <主题>

## 描述
wifisec 的内置手册系统。页面随二进制内嵌分发，离线可用，与
当前版本严格同步——不存在系统 man 库里陈旧页面的问题。

不带参数时列出全部可用主题及一行简介；带主题时渲染对应手册
页，版式致敬经典 man(1)：页首标题栏、名称/用法/描述/选项/
示例/另见分节、页脚版本与授权边界。

主题名即子命令名（如 deauth、sniff、pmkid），另有总览页
`wifisec` 介绍项目定位与命令分组。

管道或重定向时自动剥离 ANSI 颜色序列；设置 `NO_COLOR` 环境
变量可强制关闭颜色。

## 示例
    wifisec man
    wifisec man sniff
    wifisec man pmkid | less

## 另见
help(1)
