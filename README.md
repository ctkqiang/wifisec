# WifiSec



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
| `deauth` | 802.11 deauthentication 帧注入 | [wifi_deauth.md](docs/feature/wifi_deauth.md) |
