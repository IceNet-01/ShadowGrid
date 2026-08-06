/**
 * ShadowGrid Base Station
 * LoRa RX only → USB serial JSON output
 *
 * - Receives packets from mobile nodes
 * - Validates: magic, protocol version, CRC, node ID
 * - Tracks known nodes (last seen, seq gaps, RSSI history)
 * - Forwards valid packets to server.py as JSON lines on serial
 * - Never transmits on LoRa — keeps airways clear
 */

#include <Arduino.h>
#include <RadioLib.h>
#include <ArduinoJson.h>

// ── Pins (Heltec V3/V4) ──────────────────────────────────────────────────

#define LORA_NSS   8
#define LORA_RST   12
#define LORA_DIO1  14
#define LORA_BUSY  13
#define LORA_SCK   9
#define LORA_MOSI  10
#define LORA_MISO  11
#define VEXT_PIN   36
#define LED_PIN    35

// Must match mobile nodes
#define LORA_FREQ  915.0
#define LORA_BW    125.0
#define LORA_SF    9
#define LORA_CR    7
#define LORA_SYNC  0x34

#define SG_PROTO_VER 1
#define MAX_NODES    8

// ── CRC-16 (CCITT) — must match mobile node ──────────────────────────────

uint16_t crc16(const uint8_t* data, size_t len) {
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)data[i] << 8;
        for (int j = 0; j < 8; j++) {
            if (crc & 0x8000) crc = (crc << 1) ^ 0x1021;
            else crc <<= 1;
        }
    }
    return crc;
}

// ── Node Tracking ─────────────────────────────────────────────────────────

struct NodeInfo {
    char id[7];         // 6 hex chars + null
    uint32_t lastSeq;   // Last sequence number
    uint32_t lastSeen;  // millis() of last valid packet
    uint32_t rxCount;   // Total valid packets received
    uint32_t dropCount; // Detected sequence gaps
    float lastRssi;
    float lastSnr;
    bool known;
};

NodeInfo nodes[MAX_NODES];
uint8_t nodeCount = 0;

NodeInfo* findOrCreateNode(const char* id) {
    // Find existing
    for (int i = 0; i < nodeCount; i++) {
        if (strcmp(nodes[i].id, id) == 0) return &nodes[i];
    }
    // Create new
    if (nodeCount < MAX_NODES) {
        NodeInfo* n = &nodes[nodeCount++];
        strncpy(n->id, id, 6);
        n->id[6] = 0;
        n->lastSeq = 0;
        n->lastSeen = 0;
        n->rxCount = 0;
        n->dropCount = 0;
        n->known = true;
        return n;
    }
    return nullptr;
}

// ── Globals ───────────────────────────────────────────────────────────────

SPIClass loraSPI(HSPI);
SX1262 radio = new Module(LORA_NSS, LORA_DIO1, LORA_RST, LORA_BUSY, loraSPI);

volatile bool rxFlag = false;
uint32_t totalRx = 0;
uint32_t totalBad = 0;

void rxDone() { rxFlag = true; }

// ── Packet Validation ─────────────────────────────────────────────────────

bool validatePacket(const char* buf, size_t len, JsonDocument& doc) {
    // Must be JSON
    DeserializationError err = deserializeJson(doc, buf, len);
    if (err) return false;

    // Must have SG protocol marker
    if (!doc.containsKey("sg") || doc["sg"].as<int>() != SG_PROTO_VER) return false;

    // Must have node ID
    if (!doc.containsKey("id") || strlen(doc["id"].as<const char*>()) != 6) return false;

    // Must have sequence
    if (!doc.containsKey("sq")) return false;

    // Verify CRC if present
    if (doc.containsKey("crc")) {
        String expectedCrc = doc["crc"].as<String>();

        // Recompute: serialize without crc field, compute CRC
        JsonDocument tmp;
        for (JsonPair kv : doc.as<JsonObject>()) {
            if (strcmp(kv.key().c_str(), "crc") != 0) {
                tmp[kv.key()] = kv.value();
            }
        }
        char tmpBuf[256];
        size_t tmpLen = serializeJson(tmp, tmpBuf, sizeof(tmpBuf));
        uint16_t computed = crc16((uint8_t*)tmpBuf, tmpLen);

        char computedHex[5];
        sprintf(computedHex, "%x", computed);

        if (expectedCrc != computedHex) return false;
    }

    return true;
}

// ── Setup ─────────────────────────────────────────────────────────────────

void setup() {
    Serial.begin(115200);
    delay(500);

    pinMode(VEXT_PIN, OUTPUT);
    digitalWrite(VEXT_PIN, LOW);
    pinMode(LED_PIN, OUTPUT);

    loraSPI.begin(LORA_SCK, LORA_MISO, LORA_MOSI, LORA_NSS);
    int state = radio.begin(LORA_FREQ, LORA_BW, LORA_SF, LORA_CR, LORA_SYNC);

    if (state == RADIOLIB_ERR_NONE) {
        radio.setDio1Action(rxDone);
        radio.startReceive();

        // Announce ourselves to server.py
        JsonDocument announce;
        announce["status"] = "ready";
        announce["type"] = "shadowgrid_base";
        announce["freq"] = LORA_FREQ;
        announce["sf"] = LORA_SF;
        announce["bw"] = LORA_BW;
        char buf[128];
        serializeJson(announce, buf, sizeof(buf));
        Serial.println(buf);
    } else {
        Serial.printf("{\"status\":\"error\",\"code\":%d}\n", state);
        while (true) delay(1000);
    }
}

// ── Loop ──────────────────────────────────────────────────────────────────

void loop() {
    if (!rxFlag) {
        delay(1);
        return;
    }
    rxFlag = false;
    digitalWrite(LED_PIN, HIGH);

    uint8_t buf[256];
    int state = radio.readData(buf, 0);
    size_t len = radio.getPacketLength();
    float rssi = radio.getRSSI();
    float snr = radio.getSNR();

    if (state != RADIOLIB_ERR_NONE || len < 10 || buf[0] != '{') {
        totalBad++;
        digitalWrite(LED_PIN, LOW);
        radio.startReceive();
        return;
    }

    // Null-terminate for JSON parsing
    buf[len] = 0;

    // Validate
    JsonDocument doc;
    if (!validatePacket((char*)buf, len, doc)) {
        totalBad++;
        // Report bad packet
        Serial.printf("{\"reject\":true,\"reason\":\"validation\",\"len\":%d,\"rssi\":%.1f}\n", len, rssi);
        digitalWrite(LED_PIN, LOW);
        radio.startReceive();
        return;
    }

    totalRx++;

    // Track node
    const char* nodeId = doc["id"].as<const char*>();
    uint32_t seq = doc["sq"].as<uint32_t>();
    NodeInfo* node = findOrCreateNode(nodeId);

    if (node) {
        // Detect sequence gaps (dropped packets)
        if (node->rxCount > 0 && seq > node->lastSeq + 1) {
            uint32_t dropped = seq - node->lastSeq - 1;
            node->dropCount += dropped;
        }
        node->lastSeq = seq;
        node->lastSeen = millis();
        node->rxCount++;
        node->lastRssi = rssi;
        node->lastSnr = snr;
    }

    // Build output envelope for server.py
    JsonDocument out;
    out["lora"]["rssi"] = rssi;
    out["lora"]["snr"] = snr;
    out["lora"]["len"] = (int)len;
    out["node"]["id"] = nodeId;
    out["node"]["seq"] = seq;
    out["node"]["rx_count"] = node ? node->rxCount : 0;
    out["node"]["drop_count"] = node ? node->dropCount : 0;
    out["data"] = doc;

    char outBuf[512];
    size_t outLen = serializeJson(out, outBuf, sizeof(outBuf));
    Serial.println(outBuf);

    digitalWrite(LED_PIN, LOW);
    radio.startReceive();

    // Periodic stats every 60 seconds
    static uint32_t lastStats = 0;
    if (millis() - lastStats > 60000) {
        lastStats = millis();
        JsonDocument stats;
        stats["stats"]["total_rx"] = totalRx;
        stats["stats"]["total_bad"] = totalBad;
        stats["stats"]["nodes"] = nodeCount;
        stats["stats"]["uptime"] = millis() / 1000;
        JsonArray nodeArr = stats["stats"]["node_list"].to<JsonArray>();
        for (int i = 0; i < nodeCount; i++) {
            JsonObject n = nodeArr.add<JsonObject>();
            n["id"] = nodes[i].id;
            n["rx"] = nodes[i].rxCount;
            n["drops"] = nodes[i].dropCount;
            n["rssi"] = nodes[i].lastRssi;
            n["snr"] = nodes[i].lastSnr;
            n["age_s"] = (millis() - nodes[i].lastSeen) / 1000;
        }
        char sBuf[384];
        serializeJson(stats, sBuf, sizeof(sBuf));
        Serial.println(sBuf);
    }
}
