# wifisec Git Hooks 规则手册

本目录包含仓库级 Git 钩子，经 `core.hooksPath` 生效，随仓库分发、对所有克隆者一致。
**核心规则：提交信息必须为中文（Conventional Commits 格式）。**

## 安装

```bash
make hooks            # 等价于 git config core.hooksPath .githooks && chmod +x .githooks/*
```

克隆仓库后需手动执行一次（`core.hooksPath` 属于本地配置，git 不随克隆传输）。
CI 场景（无交互、无本地钩子）如需同等级校验，请在流水线中调用
`bash .githooks/commit-msg` 等脚本前先配置 `core.hooksPath`。

## 钩子清单

| 钩子 | 时机 | 行为 |
|---|---|---|
| `commit-msg` | 提交信息落盘时 | 强制中文 + Conventional Commits 格式（见下） |
| `prepare-commit-msg` | 打开编辑器前 | 注入中文格式模板与变更文件清单（`#` 注释自动剔除） |
| `pre-commit` | 暂存后、落盘前 | gofmt / go vet / 空白与冲突标记 / 密钥扫描 / 大文件 / 路径黑名单 |
| `pre-push` | 推送前 | 全量 `go vet ./...` + `go test -count=1 ./...` |

## commit-msg 强制规则

1. 格式 `type(scope)!?: 中文描述`，type 限：
   `feat fix docs style refactor perf test build ci chore revert`
2. **描述必须含至少一个汉字**（仅英文描述一律拒绝）——本仓库铁律
3. 主题 ≤ 72 字符；不以空白或句点结尾；不含 CR 换行
4. 多行提交：主题与正文空一行，正文每行 ≤ 72 字符
5. 禁止 `WIP` / `TODO` / `fixup!` / `squash!` 占位主题
6. 豁免：合并提交、`WIFISEC_NO_VERIFY=1`

示例：

```
feat: 新增 IEEE 802.11 帧解析模块
fix(darwin): 修复无 GUI 时定位授权弹窗被抑制的问题
refactor(termux)!: 重构平台枚举逻辑，破坏旧版 API
```

## pre-commit 检查项

- `git diff --cached --check`：冲突标记（`<<<<<<<` 等）、行尾空白
- 路径黑名单：`.DS_Store` `*.log` `*.pem` `*.key` `*.p12` `*.keystore`
- 体积：单文件 > 1 MiB 拒绝（防误提交二进制产物）
- `gofmt`：检查**索引内 blob**（将要提交的版本），而非工作区
- `go vet`：仅对涉及暂存 Go 文件的包执行，避免无谓全量扫描
- 密钥扫描（仅新增行）：PEM 私钥、AWS `AKIA…`、GCP `AIza…`、
  GitHub `gh…_`、Slack `xox…-`、OpenAI `sk-…`、JWT `eyJ…`
- 豁免：`WIFISEC_NO_VERIFY=1`、无暂存内容

## 跳过机制（按优先级）

1. **`--no-verify`**（git 原生）：单次提交/推送跳过全部本地钩子，紧急情况使用
2. **`WIFISEC_NO_VERIFY=1`**（环境变量）：同一 shell 内多次操作免打扰，
   适用于批量自动化脚本
3. 钩子对以下场景自动放行，无需干预：
   - 合并提交（commit-msg）
   - 无暂存内容（pre-commit）
   - 远端分支删除（pre-push）
   - amend / 已有信息（prepare-commit-msg）

跳过需有充分理由。代码评审者会看到钩子拦截日志与跳过痕迹。

## 开发钩子本身

- 所有钩子共享 `.githooks/lib/common.sh`：颜色、日志、环境探测等公共逻辑
  **禁止**在单个钩子内复制这些函数
- 新增 type 需同步修改：`commit-msg` 的 `TYPES`、本 README、
  `prepare-commit-msg` 模板三处
- 修改钩子后验证：`bash -n .githooks/*` 语法检查 + 在临时仓库跑
  `git -c core.hooksPath=… commit` 全流程
