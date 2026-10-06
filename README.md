# WifiSec

无线安全研究工具集，由 Python 项目 [wifi-deauth-attack](https://github.com/veerendra2/wifi-deauth-attack) 重构为 Go。

## 构建与运行

```bash
make build   # 编译至 build/wifisec
make list    # 扫描无线接口与周边网络
make test    # 运行测试
```

## 功能文档

| 命令 | 功能 | 文档 |
| ---- | ---- | ---- |
| `list` | 无线接口枚举与周边网络扫描 | [wifi_list.md](docs/feature/wifi_list.md) |
