# WIFISEC(1)

## 名称
wifisec — 哪吒网络安全出品的开源 WiFi 安全审计工具

## 用法
    wifisec <命令> [参数]
    wifisec man <命令>
    wifisec help

## 描述
wifisec 把无线攻击、无线防御、勘测可视化、局域网分析四类能力收进
一个纯 Go 二进制：攻击类命令默认走 ESP 串口协处理器（插板全平台免
root），无设备时按平台能力自动回落本机网卡；局域网分析四平台直连，
sniff/get_packet 等帧级能力需 root 或管理员。

全部手册页可用 `wifisec man` 列出，逐命令细节见 `wifisec man <命令>`。

## 命令分组
**无线攻击**
:   list serial deauth jam brute clone pmkid

**无线防御**
:   ids

**勘测可视化**
:   heatmap

**局域网分析**
:   devices sniff scan_ports bind shell get_packet extract

**维护**
:   upgrade help man

## 授权边界
仅限自有网络或已获书面授权的测试环境使用。对第三方网络使用攻击类
命令可能触犯《刑法》第 285/286 条，后果由使用者自负。

## 另见
help(1), docs/llm.txt, 在线文档站 https://www.ctkqiang.xin/wifisec
