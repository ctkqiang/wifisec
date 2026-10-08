# 贡献指南 (Contributing)

感谢你对 wifisec 的关注！本项目接受代码、文档、测试与固件等多方面的贡献。

## 开发环境

- **Go 1.26.1+**（`go.mod` 为准）
- **make**（构建工具）
- 可选：ESP8266/ESP32 开发板 + Arduino IDE（固件开发）

## 构建与测试

```bash
make build     # 编译（macOS 产出 .app bundle）
make run       # 运行（带 race 检测）
make test      # 运行测试
make format    # 格式化代码
make tidy      # 整理依赖
```

## 提交规范

- 提交信息使用**中文**（项目 githooks 强制）
- 遵循 Conventional Commits 格式：
  - `feat(esp): 新增 ... 功能`
  - `fix(serial): 修复 ... 问题`
  - `docs(deauth): 补充 ... 文档`
  - `refactor(core): 重构 ...`
- 一个提交只做一件事

## 提交流程

1. Fork 本仓库并创建功能分支
2. 编写代码与测试（`make test` 全绿）
3. 提交时 githooks 会自动执行预提交检查
4. 发起 Pull Request，填写 PR 模板
5. 维护者审查通过后合并

## 代码风格

- 遵循 Go 官方代码风格（`go fmt`）
- 平台相关代码放在 `internal/platform/<平台>/` 下
- 跨平台能力通过 adapter 层收敛（Hexagonal Architecture）

## 目录结构

```
cmd/                  # 入口
internal/
  functions/          # 业务编排（list/deauth/serial/...）
  platform/           # 平台 adapter（darwin/linux/windows/esp/termux）
  ieee80211/          # 802.11 帧构造
  utilities/          # 通用工具
core/                 # ESP 固件（Arduino）
tests/                # 测试
docs/                 # 文档站与功能文档
```
