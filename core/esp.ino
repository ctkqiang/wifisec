// wifisec ESP8266 串口注入固件（sketch 文件夹须命名为 wifisec，文件名须为 wifisec.ino，Arduino IDE 才能正确识别单一编译单元）
//
// 硬件：任意 ESP8266 开发板（NodeMCU / Wemos D1 mini 等），USB 连接宿主机。
// 烧录：Arduino IDE 需把本文件放在名为 esp 的文件夹内（sketch 目录与文件名一致），
//       或使用 arduino-cli compile --fqbn esp8266:esp8266:generic。
//
// 协议（小端，与 internal/platform/esp8266 一一对应）：
//   主机→ESP: [0xA5][cmd][len_lo][len_hi][payload]
//     cmd 0x01 扫描：无 payload；逐条回 0x01 条目，结束后回 0x02
//     cmd 0x02 注入：payload = 信道(1) + 802.11 帧（已剥 radiotap，由主机侧处理）
//   ESP→主机: [0x5A][cmd][len_lo][len_hi][payload]
//     0x01 扫描条目：bssid(6) + channel(1) + rssi(1,有符号) + ssidLen(1) + ssid
//     0x02 扫描结束：无 payload
//     0x04 错误：出错命令(1) + 错误码(1)
//
// 注入以最高速率进行，不给注入回 ACK——每条 ACK 都会占用串口带宽，
// 拖慢帧率，丢失比确认更重要。

#include <ESP8266WiFi.h>

extern "C" {
  #include "user_interface.h"  // wifi_send_pkt_freedom / wifi_set_channel
}

static const uint8_t  FRAME_HEAD_HOST = 0xA5;
static const uint8_t  FRAME_HEAD_ESP  = 0x5A;
static const uint8_t  CMD_SCAN        = 0x01;
static const uint8_t  CMD_INJECT      = 0x02;
static const uint8_t  REP_SCAN_ENTRY  = 0x01;
static const uint8_t  REP_SCAN_DONE   = 0x02;
static const uint8_t  REP_ERROR       = 0x04;

// 串口状态机：等帧头 → 读命令与长度 → 收 payload → 执行
static uint8_t  rxState = 0;
static uint8_t  rxCmd = 0;
static uint16_t rxLen = 0;
static uint16_t rxGot = 0;
static uint8_t  rxBuf[512];  // deauth 帧最长 26 字节（去 radiotap），512 已富余

void setup() {
  Serial.begin(115200);
  while (!Serial) {}

  // 扫描需要 station 模式；不关联任何 AP，保持游离态。
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
}

// 发送一帧回复到主机
static void sendReply(uint8_t cmd, const uint8_t* payload, uint16_t len) {
  Serial.write(FRAME_HEAD_ESP);
  Serial.write(cmd);
  Serial.write((uint8_t)(len & 0xFF));
  Serial.write((uint8_t)(len >> 8));
  if (len > 0) Serial.write(payload, len);
}

static void sendError(uint8_t cmd, uint8_t errCode) {
  uint8_t payload[2] = { cmd, errCode };
  sendReply(REP_ERROR, payload, 2);
}

// 执行扫描并流式回传；hidden=true 连隐藏 SSID 的 AP 一并列出。
static void handleScan() {
  int n = WiFi.scanNetworks(false, true);
  if (n < 0) {
    sendError(CMD_SCAN, 1);
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
}

// 执行注入：payload[0] 为信道，其后为完整 802.11 帧。
static void handleInject(const uint8_t* payload, uint16_t len) {
  if (len < 2) {
    sendError(CMD_INJECT, 2);
    return;
  }

  uint8_t channel = payload[0];
  // ESP8266 射频仅覆盖 2.4GHz（信道 1-14），越界直接拒绝。
  if (channel < 1 || channel > 14) {
    sendError(CMD_INJECT, 3);
    return;
  }

  wifi_set_channel(channel);
  // sys_seq=false：序列号由帧内值决定（主机侧置 0，芯片按自身计数器填充）。
  wifi_send_pkt_freedom((uint8_t*)(payload + 1), len - 1, false);
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
      if (rxCmd == CMD_SCAN) handleScan();
      else if (rxCmd == CMD_INJECT) handleInject(rxBuf, rxLen);
      else sendError(rxCmd, 0xFF);
      rxState = 0;
    }
  }
}
