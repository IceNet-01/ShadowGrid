/**
 * ShadowGrid Mobile Node v2
 * ESP32-S3 + SX1262 + WiFi + BLE
 *
 * - BLE: Reads JBD BMS batteries + scans Victron
 * - LoRa: Fire-and-forget TX with node ID + CRC
 * - WiFi AP: Full standalone dashboard with history
 * - LittleFS: Circular buffer data logging (~7 days)
 */

#include <Arduino.h>
#include <NimBLEDevice.h>
#include <RadioLib.h>
#include <ArduinoJson.h>
#include <WiFi.h>
#include <ESPAsyncWebServer.h>
#include <LittleFS.h>
#include <time.h>
#include <sys/time.h>

// ── Pins ──────────────────────────────────────────────────────────────────
#define GPS_RX 39
#define GPS_TX 38
#define LORA_NSS 8
#define LORA_RST 12
#define LORA_DIO1 14
#define LORA_BUSY 13
#define LORA_SCK 9
#define LORA_MOSI 10
#define LORA_MISO 11
#define VEXT_PIN 36

// ── Config ────────────────────────────────────────────────────────────────
#define WIFI_SSID     "ShadowGrid"
#define WIFI_PASS     "YOUR_WIFI_PASSWORD"
#define LORA_FREQ     915.0
#define LORA_BW       125.0
#define LORA_SF       9
#define LORA_CR       7
#define LORA_SYNC     0x34
#define LORA_POWER    17
#define POLL_INTERVAL 15000
#define LORA_INTERVAL 20000
#define SG_PROTO_VER  1

// History config
#define HISTORY_FILE     "/history.bin"
#define MAX_HISTORY      40320  // 7 days at 15s intervals
#define HISTORY_SAVE_INTERVAL 15000

// ── JBD BMS ───────────────────────────────────────────────────────────────
static const char* JBD_SVC = "0000ff00-0000-1000-8000-00805f9b34fb";
static const char* JBD_RX  = "0000ff01-0000-1000-8000-00805f9b34fb";
static const char* JBD_TX  = "0000ff02-0000-1000-8000-00805f9b34fb";
static const uint8_t CMD_BASIC[] = {0xDD,0xA5,0x03,0x00,0xFF,0xFD,0x77};
static const uint8_t CMD_CELLS[] = {0xDD,0xA5,0x04,0x00,0xFF,0xFC,0x77};

static const char* BATT_ADDRS[] = {"AA:BB:CC:DD:EE:01","AA:BB:CC:DD:EE:02"};
static const char* BATT_NAMES[] = {"FFA9","09D2"};
#define NUM_BATTS 2

// ── Data Structures ───────────────────────────────────────────────────────

struct BatteryData {
    bool online;
    float voltage, current, remain, nominal, temp, cell_delta;
    float cells[4];
    uint8_t soc;
    bool chg_fet, dsg_fet;
    uint32_t last_update;
};

// Compact history record (16 bytes per entry, ~640KB for 7 days)
struct __attribute__((packed)) HistoryRecord {
    uint32_t timestamp;    // uptime seconds
    uint16_t voltage;      // *100 (1333 = 13.33V)
    int16_t  current;      // *100 (499 = 4.99A)
    uint16_t remain;       // *10  (934 = 93.4Ah)
    uint8_t  soc;          // 0-100
    int8_t   temp;         // degrees C (signed)
    uint16_t cellDelta;    // mV
    uint8_t  flags;        // bit0=online, bit1=chgFet, bit2=dsgFet, bit3=batt_idx
};

struct VictronData {
    bool found;
    char name[20];
    uint16_t model_id;
    uint8_t device_type;
    int8_t rssi;
    uint8_t adv_data[32];
    uint8_t adv_len;
};

// ── Globals ───────────────────────────────────────────────────────────────
SPIClass loraSPI(HSPI);
SX1262 radio = new Module(LORA_NSS, LORA_DIO1, LORA_RST, LORA_BUSY, loraSPI);

BatteryData batteries[NUM_BATTS];
VictronData victron[4];
uint8_t victronCount = 0;
AsyncWebServer webServer(80);

static uint8_t bleRxBuf[64];
static uint8_t bleRxLen = 0;
static volatile bool bleRxDone = false;

uint32_t lastPoll = 0, lastLora = 0, lastHistSave = 0;
uint32_t loraSeq = 0;
char nodeId[7];
bool timeValid = false;  // True once we have wall clock time (GPS or manual set)

// GPS
HardwareSerial gpsSerial(1);
bool gpsFixed = false;
float gpsLat = 0, gpsLon = 0;

// History circular buffer in RAM (most recent 600 entries = ~2.5 hours)
#define RAM_HISTORY 600
HistoryRecord ramHistory[RAM_HISTORY];
uint32_t ramHistHead = 0;
uint32_t ramHistCount = 0;

// Disk history tracking
uint32_t diskHistCount = 0;

// ── CRC-16 ────────────────────────────────────────────────────────────────
uint16_t crc16(const uint8_t* data, size_t len) {
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)data[i] << 8;
        for (int j = 0; j < 8; j++)
            crc = (crc & 0x8000) ? (crc << 1) ^ 0x1021 : crc << 1;
    }
    return crc;
}

void generateNodeId() {
    uint8_t mac[6];
    esp_efuse_mac_get_default(mac);
    sprintf(nodeId, "%02X%02X%02X", mac[3], mac[4], mac[5]);
}

// ── History Storage ───────────────────────────────────────────────────────

void initHistory() {
    if (!LittleFS.begin(true)) {
        Serial.println("[FS] LittleFS mount failed");
        return;
    }
    Serial.printf("[FS] LittleFS: %u KB used / %u KB total\n",
        LittleFS.usedBytes() / 1024, LittleFS.totalBytes() / 1024);

    // Count existing records
    if (LittleFS.exists(HISTORY_FILE)) {
        File f = LittleFS.open(HISTORY_FILE, "r");
        diskHistCount = f.size() / sizeof(HistoryRecord);
        f.close();
        Serial.printf("[FS] %u history records on disk\n", diskHistCount);
    }
}

void saveHistoryRecord(int battIdx) {
    if (!batteries[battIdx].online) return;

    HistoryRecord rec;
    rec.timestamp = millis() / 1000;
    rec.voltage = (uint16_t)(batteries[battIdx].voltage * 100);
    rec.current = (int16_t)(batteries[battIdx].current * 100);
    rec.remain = (uint16_t)(batteries[battIdx].remain * 10);
    rec.soc = batteries[battIdx].soc;
    rec.temp = (int8_t)batteries[battIdx].temp;
    rec.cellDelta = (uint16_t)batteries[battIdx].cell_delta;
    rec.flags = (batteries[battIdx].online ? 1 : 0)
              | (batteries[battIdx].chg_fet ? 2 : 0)
              | (batteries[battIdx].dsg_fet ? 4 : 0)
              | (battIdx << 3);

    // Save to RAM ring buffer
    ramHistory[ramHistHead % RAM_HISTORY] = rec;
    ramHistHead++;
    if (ramHistCount < RAM_HISTORY) ramHistCount++;

    // Save to disk (append, with rotation)
    File f = LittleFS.open(HISTORY_FILE, "a", true);
    if (f) {
        f.write((uint8_t*)&rec, sizeof(rec));
        diskHistCount++;
        f.close();

        // Rotate if too large (keep last MAX_HISTORY records)
        if (diskHistCount > MAX_HISTORY + 1000) {
            // Read last MAX_HISTORY records, rewrite file
            File rf = LittleFS.open(HISTORY_FILE, "r");
            size_t skip = (diskHistCount - MAX_HISTORY) * sizeof(HistoryRecord);
            rf.seek(skip);
            File wf = LittleFS.open("/history_new.bin", "w");
            uint8_t buf[512];
            while (rf.available()) {
                size_t n = rf.read(buf, sizeof(buf));
                wf.write(buf, n);
            }
            rf.close();
            wf.close();
            LittleFS.remove(HISTORY_FILE);
            LittleFS.rename("/history_new.bin", HISTORY_FILE);
            diskHistCount = MAX_HISTORY;
            Serial.println("[FS] History rotated");
        }
    }
}

// ── Time ──────────────────────────────────────────────────────────────

uint32_t getUnixTime() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    // If time is before 2025, it hasn't been set
    if (tv.tv_sec < 1735689600) return 0;
    return (uint32_t)tv.tv_sec;
}

void setUnixTime(uint32_t epoch) {
    struct timeval tv = { .tv_sec = (time_t)epoch, .tv_usec = 0 };
    settimeofday(&tv, NULL);
    timeValid = true;
}

// ── GPS NMEA Parser (minimal — just $GNRMC for time + position) ──────

char nmeaBuf[128];
uint8_t nmeaIdx = 0;

void parseGPRMC(const char* sentence) {
    // $GNRMC,HHMMSS.ss,A,lat,N,lon,E,speed,course,DDMMYY,...
    char fields[15][20];
    int fi = 0;
    const char* p = sentence;
    while (*p && fi < 15) {
        const char* comma = strchr(p, ',');
        if (!comma) comma = p + strlen(p);
        size_t len = min((size_t)(comma - p), (size_t)19);
        memcpy(fields[fi], p, len);
        fields[fi][len] = 0;
        fi++;
        p = *comma ? comma + 1 : comma;
    }

    if (fi < 10) return;
    if (fields[2][0] != 'A') { gpsFixed = false; return; } // No fix

    gpsFixed = true;

    // Parse time: HHMMSS.ss
    int hh = (fields[1][0]-'0')*10 + (fields[1][1]-'0');
    int mm = (fields[1][2]-'0')*10 + (fields[1][3]-'0');
    int ss = (fields[1][4]-'0')*10 + (fields[1][5]-'0');

    // Parse date: DDMMYY
    int dd = (fields[9][0]-'0')*10 + (fields[9][1]-'0');
    int mo = (fields[9][2]-'0')*10 + (fields[9][3]-'0');
    int yr = (fields[9][4]-'0')*10 + (fields[9][5]-'0') + 2000;

    // Convert to unix timestamp
    struct tm t = {};
    t.tm_year = yr - 1900;
    t.tm_mon = mo - 1;
    t.tm_mday = dd;
    t.tm_hour = hh;
    t.tm_min = mm;
    t.tm_sec = ss;
    // Set timezone to UTC for mktime
    setenv("TZ", "UTC0", 1);
    tzset();
    time_t epoch = mktime(&t);

    setUnixTime((uint32_t)epoch);

    // Parse lat/lon
    if (strlen(fields[3]) > 0) {
        float raw = atof(fields[3]);
        int deg = (int)(raw / 100);
        gpsLat = deg + (raw - deg * 100) / 60.0;
        if (fields[4][0] == 'S') gpsLat = -gpsLat;
    }
    if (strlen(fields[5]) > 0) {
        float raw = atof(fields[5]);
        int deg = (int)(raw / 100);
        gpsLon = deg + (raw - deg * 100) / 60.0;
        if (fields[6][0] == 'W') gpsLon = -gpsLon;
    }
}

void processGPS() {
    while (gpsSerial.available()) {
        char c = gpsSerial.read();
        if (c == '$') nmeaIdx = 0;
        if (nmeaIdx < sizeof(nmeaBuf) - 1) nmeaBuf[nmeaIdx++] = c;
        if (c == '\n') {
            nmeaBuf[nmeaIdx] = 0;
            if (strncmp(nmeaBuf, "$GNRMC", 6) == 0 || strncmp(nmeaBuf, "$GPRMC", 6) == 0) {
                parseGPRMC(nmeaBuf);
            }
            nmeaIdx = 0;
        }
    }
}

// ── BLE ───────────────────────────────────────────────────────────────────

void notifyCallback(NimBLERemoteCharacteristic* pChar, uint8_t* data, size_t len, bool isNotify) {
    if (bleRxLen + len <= sizeof(bleRxBuf)) {
        memcpy(bleRxBuf + bleRxLen, data, len);
        bleRxLen += len;
    }
    if (bleRxLen >= 4 && bleRxBuf[bleRxLen - 1] == 0x77) bleRxDone = true;
}

bool readBattery(int idx) {
    std::string addrStr(BATT_ADDRS[idx]);
    NimBLEAddress addr(addrStr, 0);
    NimBLEClient* client = NimBLEDevice::createClient();

    if (!client->connect(addr, false)) {
        NimBLEDevice::deleteClient(client);
        batteries[idx].online = false;
        return false;
    }

    NimBLERemoteService* svc = client->getService(JBD_SVC);
    if (!svc) { client->disconnect(); NimBLEDevice::deleteClient(client); batteries[idx].online = false; return false; }

    NimBLERemoteCharacteristic* rx = svc->getCharacteristic(JBD_RX);
    NimBLERemoteCharacteristic* tx = svc->getCharacteristic(JBD_TX);
    if (!rx || !tx) { client->disconnect(); NimBLEDevice::deleteClient(client); batteries[idx].online = false; return false; }

    rx->subscribe(true, notifyCallback);

    // Basic info
    bleRxLen = 0; bleRxDone = false;
    tx->writeValue(CMD_BASIC, sizeof(CMD_BASIC), false);
    uint32_t t0 = millis();
    while (!bleRxDone && millis() - t0 < 5000) delay(10);

    if (bleRxDone && bleRxLen >= 23) {
        uint8_t* d = bleRxBuf + 4;
        batteries[idx].online = true;
        batteries[idx].voltage = ((d[0]<<8)|d[1]) * 0.01f;
        batteries[idx].current = ((int16_t)((d[2]<<8)|d[3])) * 0.01f;
        batteries[idx].remain = ((d[4]<<8)|d[5]) * 0.01f;
        batteries[idx].nominal = ((d[6]<<8)|d[7]) * 0.01f;
        batteries[idx].soc = d[19];
        batteries[idx].chg_fet = d[20] & 0x01;
        batteries[idx].dsg_fet = d[20] & 0x02;
        if (d[22] > 0 && bleRxLen > 28)
            batteries[idx].temp = (((d[23]<<8)|d[24]) - 2731) / 10.0f;
    } else {
        client->disconnect(); NimBLEDevice::deleteClient(client); batteries[idx].online = false; return false;
    }

    // Cell voltages
    bleRxLen = 0; bleRxDone = false;
    tx->writeValue(CMD_CELLS, sizeof(CMD_CELLS), false);
    t0 = millis();
    while (!bleRxDone && millis() - t0 < 5000) delay(10);

    if (bleRxDone && bleRxLen >= 12) {
        uint8_t* cd = bleRxBuf + 4;
        float minV = 9999, maxV = 0;
        for (int i = 0; i < 4 && (i*2+1) < (bleRxLen-7); i++) {
            batteries[idx].cells[i] = ((cd[i*2]<<8)|cd[i*2+1]) / 1000.0f;
            if (batteries[idx].cells[i] < minV) minV = batteries[idx].cells[i];
            if (batteries[idx].cells[i] > maxV) maxV = batteries[idx].cells[i];
        }
        batteries[idx].cell_delta = (maxV - minV) * 1000.0f;
    }

    batteries[idx].last_update = millis();
    rx->unsubscribe();
    client->disconnect();
    NimBLEDevice::deleteClient(client);
    return true;
}

// ── Victron Scanner ───────────────────────────────────────────────────────

class VictronScanCB : public NimBLEScanCallbacks {
    void onResult(const NimBLEAdvertisedDevice* dev) override {
        if (!dev->haveManufacturerData()) return;
        std::string mfg = dev->getManufacturerData();
        if (mfg.size() < 2) return;
        uint16_t mfgId = (uint8_t)mfg[0] | ((uint8_t)mfg[1] << 8);
        if (mfgId != 0x02E1 || victronCount >= 4) return;
        VictronData& v = victron[victronCount];
        v.found = true;
        strncpy(v.name, dev->getName().c_str(), sizeof(v.name)-1);
        v.rssi = dev->getRSSI();
        const uint8_t* data = (const uint8_t*)mfg.data() + 2;
        size_t dataLen = mfg.size() - 2;
        if (dataLen >= 5) { v.model_id = data[1]|(data[2]<<8); v.device_type = data[4]; }
        v.adv_len = min((size_t)32, dataLen);
        memcpy(v.adv_data, data, v.adv_len);
        victronCount++;
    }
};

void scanVictron() {
    victronCount = 0;
    NimBLEScan* scan = NimBLEDevice::getScan();
    scan->setScanCallbacks(new VictronScanCB(), false);
    scan->setActiveScan(false);
    scan->setInterval(100); scan->setWindow(99);
    scan->start(5, false);
    scan->clearResults();
}

// ── LoRa TX ───────────────────────────────────────────────────────────────

void sendLoRaPacket() {
    JsonDocument doc;
    doc["sg"] = SG_PROTO_VER;
    doc["id"] = nodeId;
    doc["sq"] = loraSeq++;
    doc["up"] = millis() / 1000;

    // Unix timestamp (0 if not set)
    uint32_t ts = getUnixTime();
    if (ts > 0) doc["ts"] = ts;

    // GPS if available
    if (gpsFixed) {
        doc["lat"] = serialized(String(gpsLat, 5));
        doc["lon"] = serialized(String(gpsLon, 5));
    }

    JsonArray batts = doc["b"].to<JsonArray>();
    for (int i = 0; i < NUM_BATTS; i++) {
        if (!batteries[i].online) continue;
        JsonObject b = batts.add<JsonObject>();
        b["n"] = BATT_NAMES[i];
        b["v"] = serialized(String(batteries[i].voltage, 2));
        b["i"] = serialized(String(batteries[i].current, 2));
        b["s"] = batteries[i].soc;
        b["r"] = serialized(String(batteries[i].remain, 1));
        b["t"] = serialized(String(batteries[i].temp, 1));
        b["d"] = (int)batteries[i].cell_delta;
        // Age of this reading in seconds (so server knows freshness)
        b["age"] = (millis() - batteries[i].last_update) / 1000;
        JsonArray c = b["c"].to<JsonArray>();
        for (int j = 0; j < 4; j++) c.add(serialized(String(batteries[i].cells[j], 3)));
    }

    if (victronCount > 0) {
        JsonArray vArr = doc["v"].to<JsonArray>();
        for (int i = 0; i < victronCount; i++) {
            JsonObject vObj = vArr.add<JsonObject>();
            vObj["n"] = victron[i].name;
            vObj["dt"] = victron[i].device_type;
            vObj["m"] = victron[i].model_id;
            vObj["r"] = victron[i].rssi;
            char hex[65];
            for (int j = 0; j < victron[i].adv_len && j < 32; j++) sprintf(hex+j*2, "%02x", victron[i].adv_data[j]);
            hex[victron[i].adv_len*2] = 0;
            vObj["d"] = hex;
        }
    }

    char buf[256];
    size_t len = serializeJson(doc, buf, sizeof(buf));
    uint16_t crcVal = crc16((uint8_t*)buf, len);
    doc["crc"] = String(crcVal, HEX);
    len = serializeJson(doc, buf, sizeof(buf));

    radio.transmit((uint8_t*)buf, len);
    Serial.printf("[LoRa] TX #%lu %db crc:%04X\n", loraSeq-1, len, crcVal);
}

// ── Web Dashboard ─────────────────────────────────────────────────────────

// Full ShadowGrid standalone dashboard - served from PROGMEM
const char DASHBOARD[] PROGMEM = R"rawhtml(
<!DOCTYPE html>
<html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ShadowGrid Mobile</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chartjs-adapter-date-fns@3/dist/chartjs-adapter-date-fns.bundle.min.js"></script>
<style>
:root{--bg:#0f1117;--s1:#1a1d27;--s2:#232734;--bdr:#2d3244;--tx:#e4e6f0;--tx2:#8b8fa3;--acc:#4f8cff;--grn:#34d399;--red:#f87171;--amb:#fbbf24;--cya:#22d3ee}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Cascadia Code',monospace;background:var(--bg);color:var(--tx);min-height:100vh}
.hdr{background:var(--s1);border-bottom:1px solid var(--bdr);padding:12px 16px;display:flex;align-items:center;justify-content:space-between}
.hdr h1{font-size:15px;font-weight:700;letter-spacing:2px;color:var(--acc)}
.hdr .nfo{font-size:10px;color:var(--tx2)}
.tabs{display:flex;background:var(--s1);border-bottom:1px solid var(--bdr);padding:0 12px;overflow-x:auto;scrollbar-width:none}
.tabs::-webkit-scrollbar{display:none}
.tab{padding:10px 14px;font-size:12px;font-weight:500;color:var(--tx2);cursor:pointer;border-bottom:2px solid transparent;white-space:nowrap;flex-shrink:0}
.tab:hover{color:var(--tx)}.tab.a{color:var(--acc);border-bottom-color:var(--acc)}
.tc{display:none;padding:16px}.tc.a{display:block}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(90px,1fr));gap:8px;margin-bottom:16px}
.st{background:var(--s1);border:1px solid var(--bdr);border-radius:8px;padding:10px 8px;text-align:center}
.st .v{font-size:20px;font-weight:800}.st .l{font-size:8px;color:var(--tx2);text-transform:uppercase;letter-spacing:1px;margin-top:2px}
.st .u{font-size:10px;color:var(--tx2);font-weight:400}
.card{background:var(--s1);border:1px solid var(--bdr);border-radius:10px;overflow:hidden;margin-bottom:12px}
.card-h{display:flex;align-items:center;justify-content:space-between;padding:12px 16px;background:var(--s2);border-bottom:1px solid var(--bdr)}
.card-h .nm{font-size:13px;font-weight:600}
.badge{font-size:10px;padding:2px 8px;border-radius:10px;font-weight:600}
.badge.on{background:rgba(52,211,153,.15);color:var(--grn)}.badge.off{background:rgba(248,113,113,.15);color:var(--red)}
.soc-sec{display:flex;align-items:center;padding:16px;gap:16px}
.soc-r{position:relative;width:80px;height:80px;flex-shrink:0}
.soc-r svg{transform:rotate(-90deg)}.soc-r .bg{fill:none;stroke:var(--s2);stroke-width:7}
.soc-r .fg{fill:none;stroke-width:7;stroke-linecap:round;transition:all 1s}
.soc-r .st{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:20px;font-weight:800}
.det{flex:1;display:grid;grid-template-columns:1fr 1fr;gap:6px}
.det .di{font-size:11px}.det .dl{color:var(--tx2);font-size:9px}.det .dv{font-weight:600;font-size:14px}
.ds{padding:0 16px 12px}
.sec-t{font-size:9px;text-transform:uppercase;letter-spacing:1.5px;color:var(--tx2);padding:10px 0 6px;border-top:1px solid var(--bdr)}
.dr{display:flex;justify-content:space-between;padding:4px 0;font-size:12px}
.dr .dk{color:var(--tx2)}.dr .dv{font-weight:500}
.good{color:var(--grn)}.warn{color:var(--amb)}.bad{color:var(--red)}
.cb{display:flex;gap:4px;height:50px;padding:6px 0;align-items:flex-end}
.cbw{flex:1;display:flex;flex-direction:column;align-items:center;height:100%}
.cbr{flex:1;width:100%;background:var(--s2);border-radius:3px;position:relative;overflow:hidden}
.cbf{position:absolute;bottom:0;width:100%;border-radius:3px;transition:height 1s}
.cbl{font-size:8px;color:var(--tx2);margin-top:3px}.cbv{font-size:9px;font-weight:700;margin-bottom:3px}
.socbar{height:14px;background:var(--bg);border-radius:7px;overflow:hidden;position:relative;border:1px solid var(--bdr)}
.socfill{height:100%;border-radius:6px;background:linear-gradient(90deg,var(--red),var(--amb) 30%,var(--grn) 70%,var(--cya));transition:width 1s}
.soctxt{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:800;color:#fff;text-shadow:0 1px 2px rgba(0,0,0,.5)}
.chwrap{position:relative;height:200px;background:var(--s1);border:1px solid var(--bdr);border-radius:10px;padding:12px;margin-bottom:12px}
.chwrap h3{font-size:10px;color:var(--tx2);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px}
.chbox{height:160px}
html,body{overflow-x:hidden;max-width:100vw}
@media(max-width:600px){.soc-sec{flex-wrap:wrap}.stats{grid-template-columns:repeat(2,1fr)}}
</style></head><body>
<div class="hdr"><h1>SHADOWGRID</h1><div class="nfo" id="nfo">--</div></div>
<div class="tabs">
<div class="tab a" data-t="live">Live</div>
<div class="tab" data-t="hist">History</div>
<div class="tab" data-t="info">Info</div>
</div>

<div class="tc a" id="t-live">
<div class="stats" id="sts"></div>
<div id="batts"></div>
</div>

<div class="tc" id="t-hist">
<div class="chwrap"><h3>SOC %</h3><div class="chbox"><canvas id="chSOC"></canvas></div></div>
<div class="chwrap"><h3>Voltage</h3><div class="chbox"><canvas id="chV"></canvas></div></div>
<div class="chwrap"><h3>Current</h3><div class="chbox"><canvas id="chI"></canvas></div></div>
<div class="chwrap"><h3>Temperature</h3><div class="chbox"><canvas id="chT"></canvas></div></div>
</div>

<div class="tc" id="t-info">
<div class="card"><div class="card-h"><span class="nm">Node Info</span></div>
<div class="ds" style="padding-top:12px">
<div class="dr"><span class="dk">Node ID</span><span class="dv" id="iId">--</span></div>
<div class="dr"><span class="dk">Uptime</span><span class="dv" id="iUp">--</span></div>
<div class="dr"><span class="dk">LoRa Packets TX</span><span class="dv" id="iSq">--</span></div>
<div class="dr"><span class="dk">History Records</span><span class="dv" id="iHist">--</span></div>
<div class="dr"><span class="dk">WiFi Clients</span><span class="dv" id="iWifi">--</span></div>
<div class="dr"><span class="dk">Free Heap</span><span class="dv" id="iHeap">--</span></div>
<div class="dr"><span class="dk">FS Used</span><span class="dv" id="iFs">--</span></div>
</div></div>
</div>

<script>
document.querySelectorAll('.tab').forEach(t=>{t.addEventListener('click',()=>{
document.querySelectorAll('.tab').forEach(x=>x.classList.remove('a'));
document.querySelectorAll('.tc').forEach(x=>x.classList.remove('a'));
t.classList.add('a');document.getElementById('t-'+t.dataset.t).classList.add('a');
if(t.dataset.t==='hist')loadHist();
})});

function sc(s){return s>=60?'var(--grn)':s>=25?'var(--amb)':'var(--red)'}
function scHex(s){return s>=60?'#34d399':s>=25?'#fbbf24':'#f87171'}

function renderBatt(b){
const c=2*Math.PI*34,o=c-(c*b.s/100),col=sc(b.s);
let cells='';
if(b.c&&b.c.length){cells=b.c.map((v,i)=>{
const p=Math.min(100,Math.max(0,(v-2.8)/(3.65-2.8)*100));
return`<div class="cbw"><div class="cbv">${v.toFixed(3)}</div><div class="cbr"><div class="cbf" style="height:${p}%;background:${sc(b.s)}"></div></div><div class="cbl">C${i+1}</div></div>`}).join('');}
return`<div class="card"><div class="card-h"><span class="nm">${b.n}</span><span class="badge on">ONLINE</span></div>
<div class="soc-sec"><div class="soc-r"><svg width="80" height="80" viewBox="0 0 80 80"><circle class="bg" cx="40" cy="40" r="34"/><circle class="fg" cx="40" cy="40" r="34" stroke="${col}" stroke-dasharray="${c}" stroke-dashoffset="${o}"/></svg><div class="st" style="color:${col}">${b.s}%</div></div>
<div class="det"><div class="di"><div class="dl">Voltage</div><div class="dv">${b.v.toFixed(2)} V</div></div>
<div class="di"><div class="dl">Current</div><div class="dv">${b.i>0?'+':''}${b.i.toFixed(2)} A</div></div>
<div class="di"><div class="dl">Power</div><div class="dv">${(b.v*b.i).toFixed(0)} W</div></div>
<div class="di"><div class="dl">Temp</div><div class="dv">${b.t.toFixed(1)} C</div></div></div></div>
<div class="ds"><div class="sec-t">Cells</div><div class="cb">${cells}</div>
<div class="dr"><span class="dk">Delta</span><span class="dv ${b.d<=10?'good':b.d<=30?'warn':'bad'}">${b.d} mV</span></div>
<div class="sec-t">Capacity</div>
<div class="socbar"><div class="socfill" style="width:${b.s}%"></div><div class="soctxt">${b.r.toFixed(0)} / ${(b.nom||280).toFixed(0)} Ah</div></div>
</div></div>`}

async function update(){
try{const r=await fetch('/api');const d=await r.json();
document.getElementById('nfo').textContent='NODE '+d.id+' \u2022 #'+d.sq+' \u2022 '+fmtUp(d.up);
let tI=0,tR=0,tN=0,aV=0,n=0;
d.b.forEach(b=>{tI+=b.i;tR+=b.r;tN+=b.nom||280;aV+=b.v;n++});
if(n)aV/=n;const soc=tN>0?(tR/tN*100):0;
document.getElementById('sts').innerHTML=`
<div class="st"><div class="v" style="color:${sc(soc)}">${soc.toFixed(0)}<span class="u">%</span></div><div class="l">SOC</div></div>
<div class="st"><div class="v">${aV.toFixed(1)}<span class="u">V</span></div><div class="l">Voltage</div></div>
<div class="st"><div class="v">${tI.toFixed(1)}<span class="u">A</span></div><div class="l">Current</div></div>
<div class="st"><div class="v">${(aV*tI).toFixed(0)}<span class="u">W</span></div><div class="l">Power</div></div>`;
document.getElementById('batts').innerHTML=d.b.map(renderBatt).join('');
document.getElementById('iId').textContent=d.id;
document.getElementById('iUp').textContent=fmtUp(d.up);
document.getElementById('iSq').textContent=d.sq;
document.getElementById('iHist').textContent=d.hist||'--';
document.getElementById('iWifi').textContent=d.wifi||'--';
document.getElementById('iHeap').textContent=d.heap?((d.heap/1024).toFixed(0)+' KB'):'--';
document.getElementById('iFs').textContent=d.fs||'--';
}catch(e){}}

function fmtUp(s){const h=Math.floor(s/3600),m=Math.floor((s%3600)/60);return h>0?h+'h '+m+'m':m+'m '+(s%60)+'s'}

const chCfg={responsive:true,maintainAspectRatio:false,animation:{duration:300},
plugins:{legend:{labels:{color:'#8b8fa3',font:{size:9}}}},
scales:{x:{type:'time',grid:{color:'rgba(45,50,68,.4)'},ticks:{color:'#8b8fa3',font:{size:8},maxTicksLimit:6}},
y:{grid:{color:'rgba(45,50,68,.4)'},ticks:{color:'#8b8fa3',font:{size:9}}}}};

let charts={};
function initCharts(){
['chSOC','chV','chI','chT'].forEach(id=>{
charts[id]=new Chart(document.getElementById(id),{type:'line',data:{datasets:[]},options:structuredClone(chCfg)})});
}

async function loadHist(){
try{const r=await fetch('/api/history');const d=await r.json();
const byBatt={};d.forEach(r=>{const k=r.flags&8?'09D2':'FFA9';if(!byBatt[k])byBatt[k]=[];byBatt[k].push(r)});
const colors={'FFA9':{l:'#4f8cff',f:'rgba(79,140,255,.1)'},'09D2':{l:'#34d399',f:'rgba(52,211,153,.1)'}};
function upd(id,field){
charts[id].data.datasets=Object.keys(byBatt).map(k=>({label:k,data:byBatt[k].map(r=>({x:new Date(r.ts*1000),y:r[field]})),
borderColor:colors[k].l,backgroundColor:colors[k].f,fill:true,tension:.3,pointRadius:0,borderWidth:1.5}));
charts[id].update('none')}
upd('chSOC','soc');upd('chV','voltage');upd('chI','current');upd('chT','temp');
}catch(e){console.error(e)}}

initCharts();update();setInterval(update,10000);
</script></body></html>
)rawhtml";

void setupWebServer() {
    webServer.on("/", HTTP_GET, [](AsyncWebServerRequest* req) {
        req->send(200, "text/html", DASHBOARD);
    });

    webServer.on("/api", HTTP_GET, [](AsyncWebServerRequest* req) {
        JsonDocument doc;
        doc["id"] = nodeId;
        doc["sq"] = loraSeq;
        doc["up"] = millis() / 1000;
        doc["hist"] = diskHistCount;
        doc["wifi"] = WiFi.softAPgetStationNum();
        doc["heap"] = ESP.getFreeHeap();
        doc["fs"] = String(LittleFS.usedBytes()/1024) + "/" + String(LittleFS.totalBytes()/1024) + " KB";
        doc["time"] = getUnixTime();
        doc["timeValid"] = timeValid;
        doc["gps"] = gpsFixed;
        if (gpsFixed) { doc["lat"] = gpsLat; doc["lon"] = gpsLon; }

        JsonArray batts = doc["b"].to<JsonArray>();
        for (int i = 0; i < NUM_BATTS; i++) {
            if (!batteries[i].online) continue;
            JsonObject b = batts.add<JsonObject>();
            b["n"] = BATT_NAMES[i];
            b["v"] = batteries[i].voltage;
            b["i"] = batteries[i].current;
            b["s"] = batteries[i].soc;
            b["r"] = batteries[i].remain;
            b["nom"] = batteries[i].nominal;
            b["t"] = batteries[i].temp;
            b["d"] = (int)batteries[i].cell_delta;
            b["chg"] = batteries[i].chg_fet;
            b["dsg"] = batteries[i].dsg_fet;
            JsonArray c = b["c"].to<JsonArray>();
            for (int j = 0; j < 4; j++) c.add(batteries[i].cells[j]);
        }

        char buf[768];
        size_t len = serializeJson(doc, buf, sizeof(buf));
        req->send(200, "application/json", buf);
    });

    webServer.on("/api/history", HTTP_GET, [](AsyncWebServerRequest* req) {
        // Serve last N records from RAM buffer as JSON
        uint32_t count = min(ramHistCount, (uint32_t)RAM_HISTORY);
        // Optional ?n= parameter to limit
        if (req->hasParam("n")) {
            uint32_t n = req->getParam("n")->value().toInt();
            if (n > 0 && n < count) count = n;
        }

        String json = "[";
        uint32_t start = (ramHistHead >= count) ? ramHistHead - count : 0;
        for (uint32_t i = start; i < ramHistHead; i++) {
            HistoryRecord& r = ramHistory[i % RAM_HISTORY];
            if (i > start) json += ",";
            json += "{\"ts\":" + String(r.timestamp);
            json += ",\"voltage\":" + String(r.voltage / 100.0, 2);
            json += ",\"current\":" + String(r.current / 100.0, 2);
            json += ",\"remain\":" + String(r.remain / 10.0, 1);
            json += ",\"soc\":" + String(r.soc);
            json += ",\"temp\":" + String(r.temp);
            json += ",\"delta\":" + String(r.cellDelta);
            json += ",\"flags\":" + String(r.flags) + "}";
        }
        json += "]";
        req->send(200, "application/json", json);
    });

    // Time set API — phone pushes unix timestamp
    webServer.on("/api/time", HTTP_GET, [](AsyncWebServerRequest* req) {
        if (req->hasParam("set")) {
            uint32_t epoch = req->getParam("set")->value().toInt();
            if (epoch > 1735689600) {  // After 2025
                setUnixTime(epoch);
                req->send(200, "application/json", "{\"status\":\"ok\",\"time\":" + String(epoch) + "}");
                Serial.printf("[Time] Set to %u via API\n", epoch);
                return;
            }
        }
        JsonDocument doc;
        doc["time"] = getUnixTime();
        doc["valid"] = timeValid;
        doc["gps"] = gpsFixed;
        doc["source"] = gpsFixed ? "gps" : (timeValid ? "manual" : "none");
        char buf[128];
        serializeJson(doc, buf, sizeof(buf));
        req->send(200, "application/json", buf);
    });

    webServer.begin();
}

// ── Setup ─────────────────────────────────────────────────────────────────

void setup() {
    Serial.begin(115200);
    delay(1000);
    generateNodeId();
    Serial.printf("\n[ShadowGrid Mobile] Node: %s\n", nodeId);

    pinMode(VEXT_PIN, OUTPUT);
    digitalWrite(VEXT_PIN, LOW);

    initHistory();

    // GPS on Serial1 (Heltec V4: RX=39, TX=38)
    gpsSerial.begin(9600, SERIAL_8N1, GPS_RX, GPS_TX);
    Serial.println("[GPS] Listening on Serial1");

    NimBLEDevice::init("SG");
    NimBLEDevice::setPower(9);

    loraSPI.begin(LORA_SCK, LORA_MISO, LORA_MOSI, LORA_NSS);
    int st = radio.begin(LORA_FREQ, LORA_BW, LORA_SF, LORA_CR, LORA_SYNC, LORA_POWER);
    Serial.printf("[LoRa] %s\n", st == RADIOLIB_ERR_NONE ? "TX-only @ 915MHz" : "FAIL");

    WiFi.mode(WIFI_AP);
    WiFi.softAP(WIFI_SSID, WIFI_PASS);
    setupWebServer();

    Serial.printf("[WiFi] %s @ %s (pw:%s)\n", WIFI_SSID, WiFi.softAPIP().toString().c_str(), WIFI_PASS);
    Serial.printf("[Ready] BLE:%d | LoRa:q%ds | FS:%uKB\n",
        NUM_BATTS, LORA_INTERVAL/1000, LittleFS.totalBytes()/1024);
}

// ── Loop ──────────────────────────────────────────────────────────────────

void loop() {
    uint32_t now = millis();

    if (now - lastPoll >= POLL_INTERVAL || lastPoll == 0) {
        lastPoll = now;
        for (int i = 0; i < NUM_BATTS; i++) {
            bool ok = readBattery(i);
            if (ok) {
                Serial.printf("[BLE] %s: %.2fV %+.2fA %d%%\n",
                    BATT_NAMES[i], batteries[i].voltage, batteries[i].current, batteries[i].soc);
                saveHistoryRecord(i);
            } else {
                Serial.printf("[BLE] %s: offline\n", BATT_NAMES[i]);
            }
        }
        scanVictron();
        if (victronCount) Serial.printf("[BLE] %d Victron\n", victronCount);
    }

    if (now - lastLora >= LORA_INTERVAL || lastLora == 0) {
        lastLora = now;
        sendLoRaPacket();
    }

    // Process GPS data
    processGPS();

    delay(100);
}
