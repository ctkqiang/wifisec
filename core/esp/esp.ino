// wifisec ESP 串口注入固件（ESP8266 / ESP32 全系）
//
// 本文件位于 core/esp/esp.ino，文件夹名 esp 与文件名 esp.ino 一致，
// 符合 Arduino IDE 的 sketch 结构要求，可直接打开编译。
//
// 支持的硬件（USB 连接宿主机即可，板子不需要连接任何 WiFi）：
//   - ESP8266（NodeMCU / Wemos D1 mini 等）：2.4GHz 注入
//   - ESP32 经典 / C2 / C3 / S2 / S3：2.4GHz 注入
//   - ESP32-C5：2.4 + 5GHz 双频注入（乐鑫首款双频芯片）
//   - Arduino UNO + WiFi Shield 不支持：NINA/WINC 模组的固件
//     不开放原始 802.11 帧注入 API，本文件在其上编译会直接 #error。
//
// 协议（小端，与 internal/platform/esp 一一对应）：
//   主机→ESP: [0xA5][cmd][len_lo][len_hi][payload]
//     cmd 0x00 握手：回复 REP_PONG
//     cmd 0x01 扫描：无 payload；逐条回 0x01 条目，结束后回 0x02
//     cmd 0x02 注入：payload = 信道(1) + 802.11 帧（已剥 radiotap，由主机侧处理）
//     cmd 0x03 关联尝试：payload = ssidLen(1) + ssid + passLen(1) + password
//                       回复 0x03 关联结果（1 字节：0=失败 1=成功），随后 WiFi.disconnect
//   ESP→主机: [0x5A][cmd][len_lo][len_hi][payload]
//     0x00 PONG：协议版本(1) + 能力位图(1)，bit0 = 支持 5GHz
//     0x01 扫描条目：bssid(6) + channel(1) + rssi(1,有符号) + ssidLen(1) + ssid
//     0x02 扫描结束：无 payload
//     0x03 关联结果：result(1)，0=密码错误/超时 1=关联成功
//     0x04 错误：出错命令(1) + 错误码(1)
//
// 注入以最高速率进行，不给注入回 ACK——每条 ACK 都会占用串口带宽，
// 拖慢帧率，丢失比确认更重要。

#if defined(ESP8266)
  #include <ESP8266WiFi.h>
  extern "C" {
    #include "user_interface.h"  // wifi_send_pkt_freedom / wifi_set_channel
  }
  // ESP8266 板载 LED 为低电平点亮。
  static const uint8_t LED_ON  = LOW;
  static const uint8_t LED_OFF = HIGH;
#elif defined(ESP32)
  #include <WiFi.h>
  #include "esp_wifi.h"  // esp_wifi_80211_tx / esp_wifi_set_channel
  // ESP32 各板型 LED 电平不统一，多数开发板为高电平点亮。
  static const uint8_t LED_ON  = HIGH;
  static const uint8_t LED_OFF = LOW;
#else
  #error "不支持的板型：本固件仅支持 ESP8266 / ESP32 系列。Arduino + WiFi Shield（NINA/WINC 模组）不开放原始 802.11 帧注入 API，无法实现 deauth。"
#endif

// 少数 ESP32 板型未在 variant 中定义 LED_BUILTIN，退回常见的 GPIO2。
#ifndef LED_BUILTIN
#define LED_BUILTIN 2
#endif

static const uint8_t  FRAME_HEAD_HOST = 0xA5;
static const uint8_t  FRAME_HEAD_ESP  = 0x5A;
static const uint8_t  CMD_PING        = 0x00;  // 握手请求，回复 REP_PONG
static const uint8_t  CMD_SCAN        = 0x01;
static const uint8_t  CMD_INJECT      = 0x02;
static const uint8_t  CMD_ASSOC       = 0x03;  // 尝试关联 AP，payload 含 SSID 与密码
static const uint8_t  REP_PONG        = 0x00;  // payload = 协议版本(1) + 能力位图(1)
static const uint8_t  REP_SCAN_ENTRY  = 0x01;
static const uint8_t  REP_SCAN_DONE   = 0x02;
static const uint8_t  REP_ASSOC_RESULT = 0x03; // payload = result(1)：0 失败 1 成功
static const uint8_t  REP_ERROR       = 0x04;
static const uint8_t  PROTO_VERSION   = 1;

// 能力位图 bit0 = 支持 5GHz 注入。乐鑫全系当前只有 ESP32-C5 是双频，
// 其余芯片（含全部 ESP8266）射频物理上只覆盖 2.4GHz。
#if defined(CONFIG_IDF_TARGET_ESP32C5)
static const uint8_t BOARD_CAPS = 0x01;
#else
static const uint8_t BOARD_CAPS = 0x00;
#endif

// 板载 LED 状态指示：让用户不看串口也能判断固件在干什么。
static const uint8_t  LED_PIN      = LED_BUILTIN;
static const uint32_t HEARTBEAT_MS = 500;  // 空闲心跳翻转间隔
static unsigned long  lastHeartbeat = 0;

// 串口状态机：等帧头 → 读命令与长度 → 收 payload → 执行
static uint8_t  rxState = 0;
static uint8_t  rxCmd = 0;
static uint16_t rxLen = 0;
static uint16_t rxGot = 0;
static uint8_t  rxBuf[512];  // deauth 帧最长 26 字节（去 radiotap），512 已富余

void setup() {
  Serial.begin(115200);
  while (!Serial) {}

  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, LED_OFF);

  // 扫描需要 station 模式；不关联任何 AP，保持游离态。
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();

  // 上电快闪三下：肉眼可辨固件已完成启动。
  for (int k = 0; k < 3; k++) {
    digitalWrite(LED_PIN, LED_ON);  delay(80);
    digitalWrite(LED_PIN, LED_OFF); delay(80);
  }

  // 上电就绪信号：宿主机打开串口会触发板子复位，boot 完成前主机发来的
  // 命令全部丢失；开机主动上报 PONG，让主机据此判断固件已就位。
  sendPong();
}

// 发送一帧回复到主机
static void sendReply(uint8_t cmd, const uint8_t* payload, uint16_t len) {
  Serial.write(FRAME_HEAD_ESP);
  Serial.write(cmd);
  Serial.write((uint8_t)(len & 0xFF));
  Serial.write((uint8_t)(len >> 8));
  if (len > 0) Serial.write(payload, len);
}

// PONG 载荷 = 协议版本 + 能力位图；主机据此决定 5GHz 目标是否可行，
// 而不是靠猜板型。
static void sendPong() {
  uint8_t pong[2] = { PROTO_VERSION, BOARD_CAPS };
  sendReply(REP_PONG, pong, 2);
}

static void sendError(uint8_t cmd, uint8_t errCode) {
  uint8_t payload[2] = { cmd, errCode };
  sendReply(REP_ERROR, payload, 2);
}

// 信道合法性按芯片射频能力判定：2.4GHz 芯片只认 1-14；
// ESP32-C5 额外放行 5GHz 常用 UNII 信道（36-165）。
static bool channelSupported(uint8_t channel) {
  if (channel >= 1 && channel <= 14) return true;
#if defined(CONFIG_IDF_TARGET_ESP32C5)
  if (channel >= 36 && channel <= 165) return true;
#endif
  return false;
}

// 按芯片调用对应的注入原语：ESP8266 用 freedom API，
// ESP32 用 IDF 的 esp_wifi_80211_tx（走 STA 接口、不阻塞）。
static void rawInject(uint8_t channel, const uint8_t* frame, uint16_t len) {
#if defined(ESP8266)
  wifi_set_channel(channel);
  // sys_seq=false：序列号由帧内值决定（主机侧置 0，芯片按自身计数器填充）。
  wifi_send_pkt_freedom((uint8_t*)frame, len, false);
#elif defined(ESP32)
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
  esp_wifi_80211_tx(WIFI_IF_STA, frame, len, false);
#endif
}

// 执行扫描并流式回传；hidden=true 连隐藏 SSID 的 AP 一并列出。
static void handleScan() {
  // 扫描期间 LED 常亮：scanNetworks 是阻塞调用（约 2-3 秒），
  // 常亮正好覆盖整个过程，结束后恢复心跳。
  digitalWrite(LED_PIN, LED_ON);

  int n = WiFi.scanNetworks(false, true);
  if (n < 0) {
    sendError(CMD_SCAN, 1);
    digitalWrite(LED_PIN, LED_OFF);
    return;
  }

  for (int i = 0; i < n; i++) {
    String ssid = WiFi.SSID(i);
    uint8_t* bssid = WiFi.BSSID(i);
    uint8_t ssidLen = ssid.length();
    if (ssidLen > 32) ssidLen = 32;  // SSID 协议上限 32 字节

    uint8_t entry[9 + 32];
    memcpy(entry, bssid, 6);
    entry[6] = (uint8_t)WiFi.channel(i);
    entry[7] = (uint8_t)WiFi.RSSI(i);  // 有符号 dBm 直接截断为单字节
    entry[8] = ssidLen;
    memcpy(entry + 9, ssid.c_str(), ssidLen);

    sendReply(REP_SCAN_ENTRY, entry, 9 + ssidLen);
  }

  WiFi.scanDelete();
  sendReply(REP_SCAN_DONE, NULL, 0);
  digitalWrite(LED_PIN, LED_OFF);  // 扫描结束，恢复心跳
}

// 执行注入：payload[0] 为信道，其后为完整 802.11 帧。
static void handleInject(const uint8_t* payload, uint16_t len) {
  if (len < 2) {
    sendError(CMD_INJECT, 2);
    return;
  }

  uint8_t channel = payload[0];
  if (!channelSupported(channel)) {
    sendError(CMD_INJECT, 3);
    return;
  }

  rawInject(channel, payload + 1, len - 1);

  // 每注入一帧翻转一次 LED：持续注入时呈现急促闪烁，与空闲心跳明显区分。
  digitalWrite(LED_PIN, !digitalRead(LED_PIN));
}

// handleAssoc 尝试用给定 SSID 与密码关联 AP，返回成功/失败后立即断开。
// payload 布局：ssidLen(1) + ssid + passLen(1) + password。
// WiFi.begin 是阻塞调用，现代 AP 在密码错误时通常 3-5 秒后返回 WL_CONNECT_FAILED；
// 这里给 12 秒上限，超时按失败处理，避免主机侧 readFrame 空等到串口超时。
static void handleAssoc(const uint8_t* payload, uint16_t len) {
  if (len < 2) {
    sendError(CMD_ASSOC, 2);
    return;
  }

  uint8_t ssidLen = payload[0];
  if (len < 1 + ssidLen + 1) {
    sendError(CMD_ASSOC, 2);
    return;
  }
  uint8_t passLen = payload[1 + ssidLen];
  if (len < 1 + ssidLen + 1 + passLen) {
    sendError(CMD_ASSOC, 2);
    return;
  }

  // 直接从 payload 切片构造 String，避免缓冲区拷贝。
  String ssid = String((const char*)(payload + 1), ssidLen);
  String pass = String((const char*)(payload + 1 + ssidLen + 1), passLen);

  // 关联期间 LED 常亮：与扫描一致，让用户肉眼可辨固件正忙。
  digitalWrite(LED_PIN, LED_ON);

  WiFi.begin(ssid.c_str(), pass.c_str());

  uint32_t start = millis();
  wl_status_t status;
  while ((status = WiFi.status()) != WL_CONNECTED && millis() - start < 12000) {
    delay(100);
  }

  uint8_t result = (status == WL_CONNECTED) ? 1 : 0;
  sendReply(REP_ASSOC_RESULT, &result, 1);

  // 无论成败都断开：brute force 场景下关联成功也只需知道密码正确，
  // 不需要真正上网；保持连接会占用 STA 资源影响后续扫描/注入。
  WiFi.disconnect();
  digitalWrite(LED_PIN, LED_OFF);
}

void loop() {
  while (Serial.available() > 0) {
    uint8_t b = (uint8_t)Serial.read();

    switch (rxState) {
      case 0:  // 等帧头
        if (b == FRAME_HEAD_HOST) rxState = 1;
        break;
      case 1:  // 命令字
        rxCmd = b;
        rxState = 2;
        break;
      case 2:  // 长度低字节
        rxLen = b;
        rxState = 3;
        break;
      case 3:  // 长度高字节
        rxLen |= ((uint16_t)b) << 8;
        rxGot = 0;
        // 超长直接丢弃，防缓冲区溢出
        if (rxLen > sizeof(rxBuf)) {
          sendError(rxCmd, 4);
          rxState = 0;
        } else {
          rxState = (rxLen > 0) ? 4 : 5;
        }
        break;
      case 4:  // 收 payload
        rxBuf[rxGot++] = b;
        if (rxGot >= rxLen) rxState = 5;
        break;
    }

    if (rxState == 5) {
      if (rxCmd == CMD_PING) sendPong();
      else if (rxCmd == CMD_SCAN) handleScan();
      else if (rxCmd == CMD_INJECT) handleInject(rxBuf, rxLen);
      else if (rxCmd == CMD_ASSOC) handleAssoc(rxBuf, rxLen);
      else sendError(rxCmd, 0xFF);
      rxState = 0;
    }
  }

  // 空闲心跳：每 500ms 翻转一次 LED，表示固件存活、串口待命。
  // 用 millis() 非阻塞实现，不会拖慢串口状态机。
  if (millis() - lastHeartbeat >= HEARTBEAT_MS) {
    lastHeartbeat = millis();
    digitalWrite(LED_PIN, !digitalRead(LED_PIN));
  }
}
