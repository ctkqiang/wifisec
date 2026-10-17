# HEATMAP(1)

## 名称
heatmap — 走位勘测：信号热力图 + AP 方位估计 + 风险徽章

## 用法
    wifisec heatmap [SSID] [平面图.txt]

## 描述
纯 TUI 实现的无线热力图（不使用 Web 界面）：在 ASCII 平面图上走位
采样，用 IDW（反距离加权，1/d²）插值生成信号分布，5 级色阶渲染，
同时标注 AP 位置、信道与风险等级（开放/WEP/弱加密）。免 root。

## 按键
`hjkl / 方向键`
:   移动光标

`空格`
:   在当前位置采样

`Tab`
:   切换目标 AP（最多 9 个目标各自独立热力网格）

`x`
:   清除采样点

`s`
:   保存数据

`q`
:   退出

## 示例
    wifisec heatmap 'MyWiFi'
    wifisec heatmap 'MyWiFi' floorplan.txt

## 另见
list(1), docs/feature/wifi_heatmap.md
