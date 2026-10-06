# wifi list — Drahtlose Schnittstellen und Netzwerk-Scan

## Überblick

Der Unterbefehl `list` enumeriert die drahtlosen Schnittstellen des aktuellen Hosts und scannt nahegelegene WLAN-Netze. Verbundene und nicht verbundene Netze werden in einer gemeinsamen Tabelle dargestellt. Der Ausgabestil orientiert sich an der aircrack-ng-Suite: die Schnittstellenansicht folgt airmon-ng, die Scan-Ansicht folgt airodump-ng.

Die Implementierung liegt in `internal/functions/lists.go`; der Befehlseinstiegspunkt ist `functions.WifiList`, verteilt über die Befehlsregistry in `cmd/main.go`.

## Verwendung

### Vollständiger Scan

```bash
make list
```

Äquivalent zu:

```bash
go run -race cmd/main.go list
```

Gibt zuerst die Tabelle der drahtlosen Schnittstellen aus, danach die Tabelle der Umgebungsnetze. Verbundene Netze stehen oben, der Rest ist nach Signalstärke absteigend sortiert.

Beispielausgabe:

```
无线接口 · 共 1 个
PHY  接口  索引  类型     状态  MAC 地址           驱动                              芯片组
─────────────────────────────────────────────────────────────────────────────────────────────────────
-    en0   11    managed  UP    00:1a:2b:3c:4d:5e  com.apple.DriverKit-AppleBCMWLAN  (0x14E4, 0x4378)

 CH 157 ][ Elapsed: 0 s ][ 2026-10-06 20:46:16

无线网络 · 共 12 个
连接    ESSID            BSSID  PHY       信道  频段  带宽    加密  加密套件  认证  信号         噪声     SNR    MCS  速率
────────────────────────────────────────────────────────────────────────────────────────────────────────
已连接  SkyFiber-5G      -      802.11ax  157   5GHz  80 MHz  WPA2  -         PSK   -56 dBm ▂▄▆  -91 dBm  35 dB  6    648 Mbps
未连接  SkyFiber         -      802.11b/g/n  3  2GHz  20 MHz  WPA2  -         PSK   -53 dBm ▂▄▆  -84 dBm  31 dB  -    -
```

### Zielsperre

```bash
make list TARGET=CafeGuest
```

Äquivalent zu:

```bash
go run -race cmd/main.go list CafeGuest
```

Die Angabe einer ESSID oder BSSID aktiviert den Sperrmodus: Die Schnittstellentabelle wird übersprungen, nur getroffene Ziele werden angezeigt. Dies entspricht dem `--bssid`-Filter von airodump-ng. Beachte: make behandelt Argumente ohne `TARGET=` als Build-Ziele, daher immer `TARGET=` verwenden.

- ESSID: exakte Übereinstimmung, Groß-/Kleinschreibung ignoriert
- BSSID: Doppelpunkt-Trenner dürfen entfallen; `aabbccddeeff` entspricht `aa:bb:cc:dd:ee:ff`
- Die 2,4-GHz- und 5-GHz-Varianten einer ESSID sind zwei getrennte BSS-Einträge und werden beide behalten, wie bei airodump-ng
- Ohne Treffer meldet das Werkzeug `未找到目标 …，请传入完整 ESSID 或 BSSID` (Ziel nicht gefunden, vollständige ESSID oder BSSID angeben)

Beispielausgabe im Sperrmodus:

```
 CH hop ][ Elapsed: 3 s ][ 2026-10-06 20:42:04

无线网络 · 共 2 个
连接    ESSID      BSSID  PHY                信道  频段  带宽     加密  加密套件  认证  信号         噪声     SNR    MCS  速率
──────────────────────────────────────────────────────────────────────────────────────────────────────────
未连接  CafeGuest  -      802.11b/g/n/ac/ax  5     2GHz  20 MHz   WPA2  -         PSK   -54 dBm ▂▄▆  -88 dBm  34 dB  -    -
未连接  CafeGuest  -      802.11a/n/ac/ax    40    5GHz  160 MHz  WPA2  -         PSK   -66 dBm ▂     -92 dBm  26 dB  -    -
```

## Terminal-Autoanpassung

Die Tabellen passen sich der tatsächlichen Terminalbreite an, sodass weder breite Desktop-Terminals noch schmale Termux-Sitzungen horizontal überlaufen:

1. Die Terminalbreite wird über `TIOCGWINSZ` erfragt (Linux / macOS / Termux);
2. Bei unzureichender Breite werden Spalten nach Priorität weggelassen — ein höherer Prioritätswert fällt zuerst, `0` markiert eine Pflichtspalte;
3. Passt es immer noch nicht, wird die ESSID mit abschließendem `…` verkürzt (die einzige schrumpfbare Spalte);
4. In Pipes oder Dateien umgeleitete Ausgabe gilt als breitenunbegrenzt, damit erfasste Daten vollständig bleiben.

Auf einem 64-Spalten-Terminal lässt die Schnittstellentabelle 索引 (Index) und 驱动 (Treiber) weg; die Netzwerktabelle lässt Chiffre, Authentifizierung, Rauschen und MCS weg; bei 52 Spalten folgen Chipset, PHY, Bandbreite und weitere. Wesentliche Informationen (Schnittstellenname, Status, MAC, Verbindungsstatus, ESSID, Kanal, Signal) bleiben stets erhalten.

## Ausgabereferenz

### Statusleiste

```
 CH 157 ][ Elapsed: 0 s ][ 2026-10-06 20:46:16
```

| Segment | Bedeutung |
| ---- | ---- |
| `CH n` | Kanal des verbundenen Netzes; `hop` ohne Verbindung, das System springt kanalübergreifend |
| `Elapsed: n s` | Dauer dieses Scans in Sekunden |
| Zeitstempel | Abschlusszeitpunkt des Scans |

Die gesamte Zeile ist invers (hervorgehoben) dargestellt — die visuelle Signatur von airodump-ng.

### Tabelle der drahtlosen Schnittstellen

| Spalte | Bedeutung | Priorität |
| ---- | ---- | ---- |
| PHY | Physischer Geräteindex (z. B. `phy0`); unter macOS nicht anwendbar, dargestellt als `-` | 3 |
| 接口 (Schnittstelle) | Kernel-Schnittstellenname (`wlan0` / `en0` / `Wi-Fi`) | Pflicht |
| 索引 (Index) | Kernel-Schnittstellenindex | 4 |
| 类型 (Typ) | Betriebsmodus: `managed` / `monitor` | 2 |
| 状态 (Status) | `UP` / `DOWN`, grün bzw. rot eingefärbt | Pflicht |
| MAC 地址 (MAC) | Hardwareadresse; unter macOS wird die Hardwareadresse von networksetup der zufälligen privaten vorgezogen | Pflicht |
| 驱动 (Treiber) | Kernel-Treiberkennung | 5 |
| 芯片组 (Chipset) | Hardwaremodell (PCI-ID oder netsh-Beschreibung) | 4 |

### Tabelle der drahtlosen Netze

| Spalte | Bedeutung | Priorität |
| ---- | ---- | ---- |
| 连接 (Verbindung) | `已连接` verbunden (grün) / `未连接` nicht verbunden (grau) | Pflicht |
| ESSID | Netzwerkname; darf auf schmalen Terminals verkürzt werden | Pflicht (schrumpfbar) |
| BSSID | MAC-Adresse des Zugangspunkts | Pflicht |
| PHY | 802.11-Generation (`802.11ax` usw.) | 4 |
| 信道 (Kanal) | Kanalnummer | Pflicht |
| 频段 (Band) | `2GHz` / `5GHz` | 3 |
| 带宽 (Breite) | Kanalbreite (MHz) | 4 |
| 加密 (Verschlüsselung) | `WPA2` / `WPA3` / `WPA` / `WEP` / `OPEN`; `OPEN` und `WEP` rot, `WPA` gelb, `WPA3` cyan — schwache Verschlüsselung fällt sofort auf | 1 |
| 加密套件 (Chiffre) | `CCMP` / `TKIP` usw. | 5 |
| 认证 (Authentifizierung) | `PSK` / `802.1X` | 5 |
| 信号 (Signal) | Signalstärke (dBm) mit ▂▄▆█-Stärkebalken, farbcodiert: grün ≥ −50, gelb ≥ −70, rot darunter | Pflicht |
| 噪声 (Rauschen) | Rauschuntergrenze (dBm) | 5 |
| SNR | Signal-Rausch-Abstand (dB), abgeleitet als Signal minus Rauschen | 4 |
| MCS | Modulations- und Codierungsschema-Index | 5 |
| 速率 (Rate) | Aktuelle Übertragungsrate (Mbit/s) | 3 |

Fehlende Felder werden als `-` dargestellt.

## Plattformimplementierung

| Plattform | Schnittstellen-Enumeration | Netzwerk-Scan | Hinweise |
| ---- | ---- | ---- | ---- |
| macOS | `networksetup -listallhardwareports` + `net.Interfaces` | `system_profiler SPAirPortDataType` (Textmodus, `LC_ALL=C` auf Englisch fixiert) | Treiber über die ioreg-IORegistry aufgelöst; die JSON-Ausgabe enthält keine SSIDs, daher Textparsing |
| Linux | `/proc/net/wireless` + sysfs + `iw dev <iface> info` | noch nicht implementiert | iw wird unter Termux nicht aufgerufen; Schnittstellennamen fallback über Präfixe |
| Windows | `netsh wlan show interfaces` / `show drivers` | noch nicht implementiert | netsh-Ausgabe ist sprachabhängig; chinesische und englische Schlüssel werden behandelt |
| Android (Termux) | `/proc/net/wireless` | noch nicht implementiert | Daten ohne Root eingeschränkt |

Der macOS-Profiler-Parser arbeitet mit relativer Einrückung statt fester Ebenen, damit Layoutunterschiede zwischen macOS-Versionen oder Berechtigungsstufen keine Einträge verloren gehen lassen. Erscheint dasselbe Netz sowohl unter „Current Network Information" als auch unter „Other Local Wi-Fi Networks", werden die Einträge nach ESSID + Kanal dedupliziert; der Eintrag mit dem Verbunden-Marker bleibt erhalten.

## Plattformgrenzen

macOS stellt folgende Daten nicht bereit; diese Zellen zeigen `-`:

| Feld | Grund |
| ---- | ---- |
| BSSID | wird vom Profiler nicht ausgegeben |
| Chiffre-Suite | der Profiler berichtet nur die Verschlüsselungsgeneration, keine Suite-Details |
| Rauschen / SNR / MCS / Rate nicht verbundener Netze | Verbindungsqualitätsdaten gibt es nur für das verbundene Netz |

BSSID und Chiffre-Suiten werden ergänzt, sobald die Linux- (`iw scan`)- und Windows- (`netsh wlan show networks mode=bssid`)-Scans implementiert sind.

Bei ausgeschaltetem WLAN lässt der Profiler alle SSIDs weg; das Werkzeug warnt mit `未扫描到无线网络，请确认 Wi-Fi 已开启` (keine Netze gescannt, bitte WLAN einschalten).

## FAQ

**Warum zeigt die PHY-Spalte `-`?**
macOS kennt keine Linux-`phyN`-Benennung; die Spalte wird nur unter Linux gefüllt.

**Warum erscheint dieselbe ESSID zweimal?**
Die 2,4-GHz- und 5-GHz-Varianten sind zwei getrennte BSS einer ESSID und werden als eigene Zeilen geführt.

**Was ändert `sudo make list`?**
Einige Systeminformationen können ohne erhöhte Rechte gekürzt sein; sudo liefert vollständigere Daten.

**Was bedeuten die Signal-Farben?**
Grün markiert starke Signale über −50 dBm, gelb mittlere Signale zwischen −50 und −70 dBm, rot schwache Signale unter −70 dBm, bei denen die Verbindungsqualität unzuverlässig wird.

**Warum fehlen auf schmalen Terminals einige Spalten?**
Das ist die Terminal-Autoanpassung: Bei unzureichender Breite werden sekundäre Spalten nach Priorität weggelassen. Keine Daten gehen verloren — vergrößere das Fenster oder leite die Ausgabe in eine Datei um, um die volle Tabelle zu sehen.
