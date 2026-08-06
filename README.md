<p align="center">
  <h1 align="center">ShadowGrid</h1>
  <p align="center">
    <strong>Monitor every battery you own from one dashboard.</strong><br>
    <em>LFP packs &bull; EcoFlow power stations &bull; Victron solar &bull; LoRa mesh &bull; BLE intelligence</em>
  </p>
</p>

<p align="center">
  <a href="#installation">Install</a> &bull;
  <a href="#what-it-does">Features</a> &bull;
  <a href="#supported-hardware">Hardware</a> &bull;
  <a href="#ecoflow-integration">EcoFlow</a> &bull;
  <a href="#esp32-lora-mesh">LoRa Mesh</a> &bull;
  <a href="#api-reference">API</a>
</p>

---

## What is ShadowGrid?

ShadowGrid is an open-source power monitoring system that talks to your batteries over Bluetooth Low Energy. It reverse-engineers proprietary protocols so you can see **all** your battery data in one place — without vendor apps, without cloud accounts, without subscriptions.

Point it at any supported battery and it pulls voltage, current, SOC, cell voltages, temperatures, charge cycles, and more. For EcoFlow devices, it goes further: per-port power draw, inverter status, solar input, and remote control of AC/USB/DC outputs.

Everything runs locally on a Linux box (Raspberry Pi, mini PC, laptop). No cloud required.

---

## What It Does

### Real-Time Battery Monitoring

Connect any mix of batteries and ShadowGrid reads them all in a round-robin cycle:

- **Cell-level data** — individual cell voltages, min/max delta, balance status
- **Pack-level data** — total voltage, current, power, SOC, remaining capacity
- **Thermal monitoring** — cell temps, MOSFET temps, ambient
- **Protection status** — OVP, UVP, OCP, short circuit, FET state
- **Lifetime stats** — charge cycles, state of health, design vs actual capacity

### EcoFlow Deep Integration

Full reverse-engineered BLE protocol for EcoFlow Delta 2 (and compatible models):

- **ECDH encrypted authentication** — no cloud dependency after initial setup
- **Multi-pack support** — reads both internal and extra battery simultaneously
- **Per-port power** — see exactly how much each USB-A, USB-C, QC, and 12V port draws
- **Inverter telemetry** — AC input/output voltage, current, frequency
- **Solar MPPT** — PV input voltage, current, power from connected panels
- **Remote control** — toggle AC/USB/DC outputs, set charge limits, adjust AC charge speed
- **System data** — fan speed, charge state, remaining time, min/max SOC limits

### Animated Energy Flow

A live SVG diagram shows power flowing through your system:

- Glowing particles animate along flow paths — amber for charging, cyan for discharging
- Every battery renders with a real-time SOC bar, voltage, and current
- Sources (grid, solar, chargers) and loads (AC, USB, DC) appear automatically
- Layout adapts dynamically — add a battery and it appears in the flow

### Victron & Cerbo GX Integration

ShadowGrid reads Victron gear through **two complementary paths**, and merges them
into one picture:

- **Direct BLE Instant Readout** — encrypted Victron advertisements decoded locally
  (AES-128-CTR), no cloud: MPPT solar chargers, Blue Smart AC chargers, Orion DC-DC
  converters, SmartShunt. Add a device's encryption key and it appears automatically.
- **Cerbo GX over Modbus TCP** — the wired source of truth for anything on the GX:
  SmartShunt (net battery current/SOC), VE.Direct MPPTs, and the system aggregate.

This dual approach matters because a Victron GX can only see devices wired to it
(VE.Direct/VE.Can/VE.Bus) — it **cannot** ingest Bluetooth-only chargers like the
Blue Smart IP22 or Orion DC-DC. ShadowGrid reads both worlds, so it's the only place
the **complete** system appears.

- **System Architecture panel** — a live, bus-centric power-flow diagram that mirrors
  a real common-busbar install: charge sources feed the DC bus, the shunt in the
  negative leg reads net battery current, and loads draw from the bus. Foreign/unkeyed
  Victron beacons are filtered out so it reflects *your* system.
- **Auto-discovering Victron history** — one chart per device per data point, driven
  entirely by the logged data, so new Victron gear (or a new metric on existing gear)
  shows up on its own with no code changes.

### BLE Device Scanner

Passive Bluetooth scanning identifies battery BMS devices nearby:

- **12+ protocols recognized** — JBD, JK-BMS, Daly, EcoFlow, Victron, Renogy, PACE, Seplos, TianPower, and more
- **Protocol fingerprinting** — identifies devices by BLE service UUIDs, manufacturer data, and name patterns
- **Persistent history** — every device ever seen is logged with timestamps, signal strength, and protocol
- **Spreadsheet view** — sortable table of all discovered devices

### LoRa Mesh Network

For batteries that aren't near your server — like in an RV, shed, or boat:

- **Mobile Node** (Heltec ESP32-S3 + SX1262) sits near remote batteries
  - Reads BMS over BLE, transmits data over LoRa at 915 MHz
  - Creates its own WiFi AP with a standalone dashboard
  - Stores 7 days of history on-board via LittleFS
  - GPS timestamps when available
  
- **Base Station** plugs into your server via USB
  - LoRa RX only — never transmits, keeps airways clear
  - Validates packets with CRC-16, tracks sequence gaps
  - Per-node statistics: RSSI, SNR, packet loss, last seen

### BMS Password Manager

Change factory passwords on JBD BMS batteries to secure them against unauthorized access:

- **Per-device passwords** — each battery tracked independently
- **Change with verification** — enters factory mode with old password, sets new, verifies it works
- **Full audit trail** — every password change attempt logged (timestamp, old/new, success/fail)
- **Reset to default** — one-click return to factory password `0x5678`
- **Export** — download all devices and passwords as TXT, CSV, or JSON
- **Print** — formatted printable password sheet

### Security

Optional but real security for the dashboard:

- **Password authentication** — PBKDF2-SHA256 hashed (600K iterations, salted), signed session cookies
- **HTTPS / SSL** — self-signed certificate (RSA-2048, valid 10 years), toggle from Settings
- **Login page** — dark-theme, matches dashboard aesthetic
- **All optional** — disabled by default, enable from Settings or during install

### Service Key System

> [!CAUTION]
> Modifying battery protection thresholds (over-voltage, under-voltage, over-current) can cause **fire, explosion, or permanent battery damage** if set incorrectly. These operations are locked behind a service key.

Dangerous BMS operations are gated behind a service key system — similar to Dell Unity or other enterprise service consoles:

- **Safe operations** — always available (reading data, changing passwords, normal controls)
- **Warning zone** — values outside recommended ranges are flagged with a safety warning and require a service key to proceed
- **Blocked zone** — values far outside safe limits are **refused entirely** and cannot be overridden
- **Service keys** are unique per installation — generated from your Installation ID by ShadowGrid maintainers
- **How to get a key**: go to Settings → Service Mode → note your Installation ID → contact ShadowGrid support
- **Keys are permanent** — once activated, stored locally, never expires

### Auto-Backup

Automatically detects external storage and keeps backup copies of critical data:

- **Storage detection** — scans for USB drives, SD cards, NFS/CIFS mounts
- **What's backed up** — device registry, BMS passwords, password history, auth settings, Victron keys, full database
- **Hourly auto-backup** — to all detected storage devices
- **Manual backup** — one-click from Settings tab
- **Versioned** — keeps last 10 timestamped backups, auto-prunes older ones
- **Optional encryption** — AES-256-CBC with passphrase
- **Restore** — API endpoint to restore from any backup file

### Dashboard

Dark-mode responsive web UI with 9 tabs:

| Tab | What's There |
|-----|-------------|
| **Overview** | System SOC gauge, power stats, compact battery panels, scanner summary |
| **Batteries** | Detailed card per battery — SOC ring, cell bars, FET status, protection |
| **Energy Flow** | Animated SVG flow diagram with glowing particles |
| **EcoFlow** | Full EcoFlow dashboard — both packs, all ports, inverter, MPPT, controls |
| **Victron** | Victron SmartSolar, Orion, Blue Smart data |
| **Scanner** | Live BLE device discovery + historical spreadsheet view |
| **History** | Chart.js time-series graphs for voltage, SOC, current, temperature |
| **Logs** | Filterable event log — severity, time range, per-device |
| **Settings** | Device manager, BMS passwords, auto-backup, security, Victron keys |

---

## Supported Hardware

### Batteries & BMS

| Device | Protocol | What You Get |
|--------|----------|-------------|
| **JBD / Xiaoxiang BMS** | BLE GATT | Voltage, current, SOC, 4-16 cell voltages, temps, FET control, protection, cycles. Used by: Eco Worthy, Ampere Time, Redodo, SOK, LiTime, Power Queen, CHINS, Lossigy, Weize |
| **EcoFlow Delta 2 / Pro** | BLE ECDH+AES | Everything — SOC, voltage, current, per-port power, inverter, solar, fan, charge limits, remote control. Supports extra battery pack |
| **JK-BMS** | BLE GATT | Voltage, current, SOC, cells, balance, protection |
| **Daly BMS** | BLE GATT | Voltage, current, SOC, cells, temps |
| **Victron SmartSolar / BlueSolar MPPT** | BLE encrypted **or** Cerbo Modbus | Solar yield, PV voltage/power, battery voltage/current, charge state |
| **Victron Blue Smart IP22** | BLE encrypted | AC charger: battery voltage/current, state, temperature |
| **Victron Orion DC-DC** | BLE encrypted | Input/output voltage, state (BLE Instant Readout carries no current for this model) |
| **Victron SmartShunt** | Cerbo Modbus TCP | Net battery voltage/current/power, SOC, temperature |
| **Victron Cerbo GX** | Modbus TCP | System hub — SmartShunt + MPPTs + system aggregate |
| **Renogy BMS** | BLE GATT | Voltage, current, SOC, cells, temps |
| **PACE / Seplos / TianPower** | BLE GATT | Basic monitoring |

### Other Hardware

| Component | Purpose |
|-----------|---------|
| **Heltec WiFi LoRa 32 V3/V4** | ESP32-S3 + SX1262 for LoRa mesh nodes |
| **Any BLE 4.0+ USB adapter** | Bluetooth scanning and connections |
| **RTL-SDR dongle** (optional) | Smart meter RF reading via rtlamr |

---

## Installation

### One-Line Install

```bash
git clone https://github.com/IceNet-01/ShadowGrid.git
cd ShadowGrid
./install.sh
```

The installer handles everything:
1. Installs system packages (BlueZ, D-Bus, Python)
2. Installs Python dependencies (Flask, bleak, pycryptodome, ecdsa)
3. Configures Bluetooth permissions (user groups, sudoers)
4. Scans for nearby batteries and auto-registers them
5. Walks through EcoFlow setup (if detected) — just enter your email + password
6. Initializes the database
7. Installs and starts the systemd service

### Manual Install

```bash
# Dependencies
sudo apt install python3 python3-pip bluetooth bluez dbus
pip3 install flask flask-cors bleak pycryptodome ecdsa dbus-next pyserial

# Run
python3 server.py
# Open http://localhost:5050

# Add devices from the Settings tab
```

---

## EcoFlow Integration

ShadowGrid is one of the few tools that can talk to EcoFlow devices locally over BLE — no cloud, no app, no subscription.

### Why does it need my EcoFlow email and password?

EcoFlow encrypts all Bluetooth communication with their devices. To prove you own the device, the BLE authentication requires a **user ID** — a numeric identifier tied to your EcoFlow account. There is no way to get this ID from the device itself; it only exists on EcoFlow's servers.

**Here's exactly what happens:**

1. During setup, ShadowGrid sends your email + password to EcoFlow's official login API (`api.ecoflow.com/auth/login`) — the same endpoint their own app uses
2. EcoFlow's server responds with your numeric user ID (e.g., `YOUR_ECOFLOW_USER_ID`)
3. ShadowGrid saves **only the user ID** to its local device database. Your email and password are **immediately purged** — `unset` from the shell, `del` + `gc.collect()` in Python, and the login runs in an isolated subprocess that terminates after extracting the ID
4. The user ID is permanent — it's stored in `shadowgrid.db` and persists across reboots, reinstalls, and updates. You never need to log in again
5. From that point on, ShadowGrid authenticates to your EcoFlow device using only the user ID + the device's serial number, both over local Bluetooth — **no internet connection required**

**What's stored vs what's not:**

| Data | Stored? | Where |
|------|---------|-------|
| User ID | Yes, permanently | `shadowgrid.db` → `devices` table |
| Device serial | Yes, permanently | `shadowgrid.db` → `devices` table |
| BLE MAC address | Yes, permanently | `shadowgrid.db` → `devices` table |
| Email | **No** — used once, purged | Never written to disk |
| Password | **No** — used once, purged | Never written to disk |
| API tokens | **No** — never saved | Discarded with the subprocess |

### Can I use it fully offline after setup?

**Yes, completely.** After the one-time setup, ShadowGrid never contacts EcoFlow's servers again. All communication is local Bluetooth:

- Reading battery data — local BLE, no internet
- Sending commands (toggle AC, USB, etc.) — local BLE, no internet
- Viewing the dashboard — local HTTP on your network
- Historical data — local SQLite database on disk

You can disconnect from the internet permanently. Unplug your router. Go off-grid. ShadowGrid doesn't care — it talks directly to your EcoFlow over Bluetooth using the saved user ID.

### Your User ID is permanent — save it

After the one-time login, the installer displays your user ID in a box and tells you to save it. **Write it down, put it in a password manager, tattoo it on your arm** — this ID is the only thing you need to connect to any EcoFlow device, forever.

Your user ID:
- Is tied to your **EcoFlow account**, not to any specific device
- **Never changes** (unless you create a brand new EcoFlow account)
- Works on **every EcoFlow device you own** — Delta 2, River, Delta Pro, extras
- Works on **brand new devices that have never connected to the internet** — the device doesn't need to be registered, cloud-activated, or paired with the app first
- Can be re-entered manually if you ever reinstall ShadowGrid — no login needed

The BLE authentication is a local math operation: `MD5(your_user_id + device_serial_number)`. The device checks this hash locally — it never phones home. A brand new EcoFlow straight out of the box will accept your user ID over BLE without ever seeing the internet.

### How the BLE authentication works

EcoFlow uses ECDH key exchange (Elliptic Curve Diffie-Hellman) to encrypt BLE communication. ShadowGrid implements the full handshake:

1. **Discovery** — finds your EcoFlow by its `0xB5B5` manufacturer advertisement
2. **Key exchange** — generates an ECDH keypair (SECP160r1), exchanges public keys with the device, derives a shared AES-CBC session key
3. **Authentication** — sends MD5 hash of your user ID + device serial number
4. **Data stream** — decrypts heartbeat packets from all 5 subsystems (PD, BMS, EMS, INV, MPPT)
5. **Commands** — encrypts and sends control packets back over the same session

### Setup

The installer automates all of this. Or manually:

1. Run a BLE scan — your Delta 2 appears as `R33-XXXX`
2. Enter your EcoFlow email + password when prompted (used once, never stored)
3. The installer extracts your user ID and registers the device
4. ShadowGrid connects over BLE, authenticates locally, and starts reading data

### What You Can Control

| Command | What It Does |
|---------|-------------|
| AC Output | Toggle the 120V AC inverter on/off |
| USB Ports | Toggle all USB-A output ports |
| 12V DC | Toggle the car/DC output port |
| Max Charge SOC | Set upper charge limit (50-100%) |
| Min Discharge SOC | Set lower discharge cutoff (0-30%) |
| AC Charge Speed | Set AC charging power limit (100-1200W) |
| Energy Backup | Enable UPS mode with SOC threshold |

---

## ESP32 LoRa Mesh

### Flash Tool

```bash
./flash.sh              # Interactive — choose mobile or base
./flash.sh mobile       # Flash mobile node, auto-detect port
./flash.sh base /dev/ttyACM0
```

The flasher installs PlatformIO if needed, detects your ESP32, builds, flashes, and verifies boot output.

### Mobile Node

The mobile node is a self-contained battery monitor:

- **BLE** — reads JBD BMS batteries and scans for Victron devices
- **LoRa** — fire-and-forget TX at 915 MHz with CRC-16 integrity
- **WiFi AP** — creates `ShadowGrid` hotspot with a standalone dashboard
- **Storage** — LittleFS circular buffer stores ~7 days of readings
- **GPS** — syncs time from GPS (Heltec V4) or via web API from your phone

Connect to the `ShadowGrid` WiFi and open `http://192.168.4.1` for live data, history charts, and node info — no server needed.

### Base Station

Plugs into your server via USB. Receives LoRa packets and forwards them as JSON:

```json
{"lora":{"rssi":-85,"snr":8.5},"node":{"id":"A7495C","seq":42,"rx_count":100,"drop_count":2},"data":{...}}
```

Tracks per-node statistics, detects sequence gaps (dropped packets), and reports RSSI/SNR trends.

---

## Architecture

```
┌─────────────┐     BLE      ┌──────────────┐     HTTP     ┌─────────────┐
│  JBD BMS    │◄────────────►│              │◄────────────►│  Dashboard  │
│  batteries  │              │   server.py  │              │  (browser)  │
└─────────────┘              │              │              └─────────────┘
                             │  - Device DB │
┌─────────────┐     BLE      │  - BLE poller│
│  EcoFlow    │◄────────────►│  - Scanner   │
│  Delta 2    │  (ECDH auth) │  - Alerts    │
└─────────────┘              │  - History   │
                             │  - Flask API │
┌─────────────┐     BLE      │              │     LoRa     ┌─────────────┐
│  Victron    │◄────────────►│              │◄────────────►│  ESP32 Node │
│  devices    │  (AES-CTR)   └──────────────┘    915MHz    │  (mobile)   │
└─────────────┘                    │                       └─────────────┘
                                   │ SQLite
                             ┌──────────────┐
                             │ shadowgrid.db│
                             │  - readings  │
                             │  - devices   │
                             │  - ecoflow   │
                             │  - scanner   │
                             │  - alerts    │
                             │  - energy    │
                             └──────────────┘
```

---

## Project Structure

```
server.py               Main server — BLE poller, device registry, auth, REST API
ecoflow_reader.py       EcoFlow BLE — ECDH auth, packet codec, device commands
scan_bms.py             Standalone JBD BMS scanner and reader
victron_reader.py       Victron BLE Instant Readout decoder
ble_scanner.py          Passive BLE battery device scanner
bms_database.json       Protocol signature database (12 BMS types)
backup.py               Auto-backup to external storage (USB, NAS, SD)
lora_bridge.py          LoRa base station serial bridge
alerts.py               Battery alert rules and notifications
meter_reader.py         Smart meter RF reader (RTL-SDR + rtlamr)
static/
  index.html            Complete dashboard UI (single-file SPA)
  login.html            Authentication login page
firmware/
  remote/               ESP32 mobile node — BLE + LoRa TX + WiFi AP + LittleFS
  base/                 ESP32 base station — LoRa RX + serial forwarding
install.sh              One-command installer with guided setup
flash.sh                ESP32 firmware flasher (PlatformIO)
config.example.env      Configuration template
shadowgrid.service      systemd unit file
```

---

## API Reference

All endpoints return JSON.

### Device Management
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/devices` | `GET` | List all registered devices with live status |
| `/api/devices` | `POST` | Register a new device |
| `/api/devices/<addr>` | `PATCH` | Update label, enable/disable |
| `/api/devices/<addr>` | `DELETE` | Remove a device |
| `/api/devices/discover` | `POST` | BLE scan for nearby battery devices |

### Live Data
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/live` | `GET` | Current readings from all batteries |
| `/api/ecoflow` | `GET` | Full EcoFlow data — packs, ports, inverter, MPPT |
| `/api/victron/live` | `GET` | Victron device data |
| `/api/lora/live` | `GET` | LoRa bridge status and node tracking |
| `/api/scanner` | `GET` | BLE scanner results and stats |

### History
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/history` | `GET` | Battery readings over time |
| `/api/history/summary` | `GET` | Min/max/avg stats per battery |
| `/api/ecoflow/history` | `GET` | EcoFlow time-series data |
| `/api/energy/history` | `GET` | Energy flow snapshots |
| `/api/scanner/history` | `GET` | All-time device discovery log |

### Control
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/ecoflow/command` | `POST` | Send command to EcoFlow (AC, USB, DC, limits) |
| `/api/scanner/test` | `POST` | Probe a registered device |

### BMS Passwords
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/bms/password` | `GET` | Current password for each BMS device |
| `/api/bms/password/change` | `POST` | Change a BMS factory password |
| `/api/bms/password/history` | `GET` | Full password change audit trail |
| `/api/bms/password/export` | `GET` | Export passwords as TXT, CSV, or JSON |

### Security
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/auth/status` | `GET` | Auth and SSL status (public) |
| `/api/auth/password` | `POST` | Set/change password, enable/disable auth, toggle SSL |
| `/login` | `GET/POST` | Login page and authentication |
| `/logout` | `GET` | Clear session |

### Backup
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/backup/status` | `GET` | Backup status and detected storage |
| `/api/backup/run` | `POST` | Trigger manual backup to all storage |
| `/api/backup/restore` | `POST` | Restore from a backup file |

---

## Acknowledgments

- EcoFlow BLE protocol — [rabits/ha-ef-ble](https://github.com/rabits/ha-ef-ble) (Apache 2.0) and [rabits/ef-ble-reverse](https://github.com/rabits/ef-ble-reverse)
- Victron BLE decryption — [victron-ble](https://github.com/keshavdv/victron-ble)
- JBD / Xiaoxiang BMS protocol — open-source community documentation

## Legal

### Reverse Engineering & Interoperability

The EcoFlow BLE integration in this project reverse-engineers proprietary Bluetooth protocols for the purpose of **interoperability** — enabling purchased devices to work with independently created software. This is protected under:

- **17 U.S.C. 1201(f) — DMCA Interoperability Exception**: Reverse engineering is permitted for the purpose of achieving interoperability between independently created programs and other programs. ShadowGrid enables EcoFlow devices to interoperate with a user's own monitoring system.

- **Chamberlain Group v. Skylink Technologies (Fed. Cir. 2004)**: Established that circumventing access controls on a device you own, where there is no nexus to copyright infringement, does not violate the DMCA. Monitoring your own battery data does not infringe any copyrighted work.

- **Van Buren v. United States (Supreme Court, 2021)**: Narrowed the Computer Fraud and Abuse Act, holding that accessing a system you are authorized to use — even in ways not intended by the manufacturer — does not constitute unauthorized access.

This project accesses only devices that the user owns and has authenticated to with their own credentials. No proprietary code, firmware, or copyrighted material from EcoFlow is included in this repository. The BLE protocol implementation is based on publicly available community research ([ha-ef-ble](https://github.com/rabits/ha-ef-ble), [ef-ble-reverse](https://github.com/rabits/ef-ble-reverse)).

### Right to Repair

Battery monitoring is a safety function. Users have a legitimate interest in monitoring the state of charge, cell health, temperature, and protection status of lithium batteries they own — independent of any manufacturer's app or cloud service. This project supports the right to repair and maintain purchased equipment.

### Battery Safety

> [!WARNING]
> Lithium batteries can be dangerous if misconfigured. Incorrect protection settings can cause **thermal runaway, fire, or explosion**.

ShadowGrid provides tools that can modify BMS protection thresholds, toggle charge/discharge FETs, and change factory passwords. To prevent accidental damage:

- **Three-tier safety system**: safe values pass through, warning-zone values require a service key, extreme values are blocked entirely
- **Service key required** for any operation outside manufacturer-recommended ranges
- **Blocked operations cannot be overridden** — even with a service key, values far outside safe limits are refused

These software guardrails are **not a substitute** for understanding your battery chemistry and specifications. The creators of ShadowGrid are not liable for any damage, injury, or loss resulting from battery misconfiguration. **Use at your own risk.**

### User Responsibility

This software is provided for **authorized use on devices you own**. The creators and contributors of ShadowGrid accept no responsibility or liability for misuse of this software, including but not limited to: accessing devices without authorization, violating applicable laws, causing damage to equipment, or any other use beyond monitoring and managing your own purchased hardware. By using this software, you agree that you are solely responsible for ensuring your use complies with all applicable local, state, federal, and international laws. Any consequences of misuse — legal, financial, or otherwise — are the sole responsibility of the user.

---

## License

[MIT](LICENSE) &mdash; see [DISCLAIMER.md](DISCLAIMER.md) for usage guidelines.

## Acknowledgments

- EcoFlow BLE protocol based on research by [rabits/ha-ef-ble](https://github.com/rabits/ha-ef-ble) (Home Assistant EcoFlow BLE integration)
- BLE protocol research from [rabits/ef-ble-reverse](https://github.com/rabits/ef-ble-reverse)
- JBD/Xiaoxiang BMS protocol documentation from the open-source community
