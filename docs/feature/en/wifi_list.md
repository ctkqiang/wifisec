# wifi list — Wireless Interface and Network Scanning

## Overview

The `list` subcommand enumerates wireless interfaces on the current host and scans nearby Wi-Fi networks. Connected and unconnected networks are presented in a single table. The output style aligns with the aircrack-ng suite: the interface view follows airmon-ng, the scan view follows airodump-ng.

The implementation lives in `internal/functions/lists.go`; the command entry point is `functions.WifiList`, dispatched through the command registry in `cmd/main.go`.

## Usage

### Full scan

```bash
make list
```

Equivalent to:

```bash
go run -race cmd/main.go list
```

Prints the wireless interface table first, followed by the nearby network table. Connected networks are pinned to the top; the rest are sorted by signal strength, strongest first.

Sample output:

```
无线接口 · 共 1 个
PHY  接口  索引  类型     状态  MAC 地址           驱动                              芯片组
─────────────────────────────────────────────────────────────────────────────────────────────────────
-    en0   11    managed  UP    9c:3e:53:83:cc:87  com.apple.DriverKit-AppleBCMWLAN  (0x14E4, 0x4378)

 CH 157 ][ Elapsed: 0 s ][ 2026-10-06 20:46:16

无线网络 · 共 12 个
连接    ESSID                  BSSID  PHY       信道  频段  带宽     加密  加密套件  认证  信号     噪声     SNR    MCS  速率
──────────────────────────────────────────────────────────────────────────────────────────────────
已连接  HOME@CelcomFibre_5G    -      802.11ax  157   5GHz  80 MHz   WPA2  -         PSK   -56 dBm  -91 dBm  35 dB  6    648 Mbps
```

### Target lock

```bash
make list TARGET=kelvin172
```

Equivalent to:

```bash
go run -race cmd/main.go list kelvin172
```

Passing an ESSID or BSSID enters lock mode: the interface table is skipped and only matching networks are shown. This mirrors the `--bssid` filter of airodump-ng.

- ESSID: exact match, case-insensitive
- BSSID: colon separators may be omitted; `aabbccddeeff` equals `aa:bb:cc:dd:ee:ff`
- The 2.4 GHz and 5 GHz variants of one ESSID are two distinct BSS entries and both are kept, matching airodump-ng behavior
- On no match the tool reports `未找到目标 …，请传入完整 ESSID 或 BSSID` (target not found, pass a complete ESSID or BSSID)

Lock mode sample output:

```
 CH hop ][ Elapsed: 3 s ][ 2026-10-06 20:42:04

无线网络 · 共 2 个
连接    ESSID      BSSID  PHY                信道  频段  带宽     加密  加密套件  认证  信号     噪声     SNR    MCS  速率
──────────────────────────────────────────────────────────────────────────────────────────────────
未连接  kelvin172  -      802.11b/g/n/ac/ax  5     2GHz  20 MHz   WPA2  -         PSK   -54 dBm  -88 dBm  34 dB  -    -
未连接  kelvin172  -      802.11a/n/ac/ax    40    5GHz  160 MHz  WPA2  -         PSK   -66 dBm  -92 dBm  26 dB  -    -
```

## Output reference

### Status bar

```
 CH 157 ][ Elapsed: 0 s ][ 2026-10-06 20:46:16
```

| Segment | Meaning |
| ---- | ---- |
| `CH n` | Channel of the connected network; `hop` when unconnected, meaning the system hops across channels |
| `Elapsed: n s` | Duration of this scan in seconds |
| Timestamp | Completion time of the scan |

### Wireless interface table

| Column | Meaning |
| ---- | ---- |
| PHY | Physical device index (e.g. `phy0`); not applicable on macOS, shown as `-` |
| 接口 (Interface) | Kernel interface name (`wlan0` / `en0` / `Wi-Fi`) |
| 索引 (Index) | Kernel interface index |
| 类型 (Type) | Operating mode: `managed` / `monitor` |
| 状态 (State) | `UP` / `DOWN`, colored green and red |
| MAC 地址 (MAC) | Hardware address; on macOS the hardware address from networksetup is preferred over the randomized private one |
| 驱动 (Driver) | Kernel driver identifier |
| 芯片组 (Chipset) | Hardware model (PCI ID or netsh description) |

### Wireless network table

| Column | Meaning |
| ---- | ---- |
| 连接 (Connection) | `已连接` connected (green) / `未连接` unconnected (gray) |
| ESSID | Network name |
| BSSID | MAC address of the access point |
| PHY | 802.11 generation (`802.11ax` etc.) |
| 信道 (Channel) | Channel number |
| 频段 (Band) | `2GHz` / `5GHz` |
| 带宽 (Width) | Channel width (MHz) |
| 加密 (Encryption) | `WPA2` / `WPA3` / `WPA` / `WEP` / `OPEN` |
| 加密套件 (Cipher) | `CCMP` / `TKIP` etc. |
| 认证 (Auth) | `PSK` / `802.1X` |
| 信号 (Signal) | Signal strength (dBm), color coded: green ≥ −50, yellow ≥ −70, red below |
| 噪声 (Noise) | Noise floor (dBm) |
| SNR | Signal-to-noise ratio (dB), derived as signal minus noise |
| MCS | Modulation and coding scheme index |
| 速率 (Rate) | Current transfer rate (Mbps) |

Missing fields are rendered as `-`.

## Platform implementation

| Platform | Interface enumeration | Network scan | Notes |
| ---- | ---- | ---- | ---- |
| macOS | `networksetup -listallhardwareports` + `net.Interfaces` | `system_profiler SPAirPortDataType` (text mode, `LC_ALL=C` pinned to English) | Driver resolved via ioreg IORegistry; the JSON output lacks SSIDs, hence text parsing |
| Linux | `/proc/net/wireless` + sysfs + `iw dev <iface> info` | not implemented yet | iw is not called under Termux; interface names fall back to prefix matching |
| Windows | `netsh wlan show interfaces` / `show drivers` | not implemented yet | netsh output is locale-dependent; both Chinese and English keys are handled |
| Android (Termux) | `/proc/net/wireless` | not implemented yet | data is limited without root |

The macOS profiler parser uses relative indentation instead of fixed levels, so layout differences across macOS versions or privilege levels do not cause missed entries. When the same network appears under both "Current Network Information" and "Other Local Wi-Fi Networks", entries are deduplicated by ESSID + channel, keeping the one with the connected marker.

## Platform limitations

macOS does not expose the following data; those cells show `-`:

| Field | Reason |
| ---- | ---- |
| BSSID | not emitted by the profiler |
| Cipher suite | the profiler reports the encryption generation only, not suite details |
| Noise / SNR / MCS / rate of unconnected networks | link quality data is provided for the connected network only |

BSSID and cipher suites will be filled once the Linux (`iw scan`) and Windows (`netsh wlan show networks mode=bssid`) scans are implemented.

With Wi-Fi turned off, the profiler omits all SSIDs and the tool warns `未扫描到无线网络，请确认 Wi-Fi 已开启` (no networks scanned, make sure Wi-Fi is on).

## FAQ

**Why does the PHY column show `-`?**
macOS has no Linux-style `phyN` naming; the column is only populated on Linux.

**Why does the same ESSID appear twice?**
The 2.4 GHz and 5 GHz variants are two distinct BSS of one SSID, listed as separate rows.

**What does `sudo make list` change?**
Some system information may be trimmed without elevated privileges; sudo yields more complete data.

**What do the signal colors mean?**
Green marks strong signals above −50 dBm, yellow marks fair signals between −50 and −70 dBm, red marks weak signals below −70 dBm where link quality becomes unreliable.
