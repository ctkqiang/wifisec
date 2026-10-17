# UPGRADE(1)

## 名称
upgrade — 从 GitHub Releases 下载最新版并原地替换当前二进制

## 用法
    wifisec upgrade

## 描述
查询 GitHub Releases API 获取最新 tag 与产物清单，与当前版本
比对；一致则直接报告「已是最新」并退出，否则下载本平台对应
产物并原地替换。

替换策略是两次 rename：先落盘 <exe>.new，再原子换名——同目录
rename 是原子操作，中途断电或中断不会留下半个二进制。旧版本
改名 .old 暂存；Windows 不允许删除运行中的映像，.old 删除失败
属预期，下次升级时自动清理。

经符号链接安装的场景（如 Homebrew）会先解析链接目标，替换落在
真实文件上，不会只换掉链接本身。

## 注意
本命令需要访问 api.github.com 与 GitHub CDN，国内网络偶发慢速，
HTTP 超时设为 15 秒。

go install 安装的二进制对自身目录需有写权限；权限不足时按提示
加 sudo 或改用包管理器安装。

## 示例
    wifisec upgrade

## 另见
help(1)
