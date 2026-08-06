#!/usr/bin/env python3
"""
ShadowGrid Server
Flask backend that reads Eco Worthy batteries via BLE and serves data as JSON.
Logs readings to SQLite for historical graphs.
"""

import asyncio
import hashlib
import json
import os
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, request as flask_request, send_from_directory, session, redirect, url_for
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from bleak import BleakClient, BleakScanner

from victron_reader import VictronScanner, VictronKeyStore
from ecoflow_reader import EcoFlowBLE
from ble_scanner import BLEBatteryScanner, scanner_thread
from meter_reader import MeterReader, MeterConfig, detect_rtlsdr, init_meter_db, get_latest_reading, get_power_estimate
from alerts import init_alerts_db, check_battery_alerts, check_victron_alerts, get_alerts, acknowledge_alert, get_alert_counts
from lora_bridge import LoraBridge
from backup import find_storage_devices, backup_to_path, restore_from_file, auto_backup_thread, get_backup_status
import cerbo_reader
import zima_power


def _json_body():
    """Request JSON as a dict, tolerating null/list/scalar bodies (-> {}).
    Prevents 500s when a client sends Content-Type: application/json with a
    body that parses to something other than an object."""
    d = flask_request.get_json(silent=True)
    return d if isinstance(d, dict) else {}


def _arg_int(name, default):
    """Query-string integer with a safe fallback on missing/non-numeric input."""
    try:
        return int(flask_request.args.get(name, default))
    except (TypeError, ValueError):
        return default


def _num(value, default, cast=float):
    """Coerce a JSON-body value to int/float with a safe fallback."""
    try:
        return cast(value)
    except (TypeError, ValueError):
        return default


def _load_config_env():
    """Load KEY=VALUE lines from an optional config.env next to this file into
    os.environ (without overriding values already set in the real environment).
    Lets a deployment configure FLASK_HOST/FLASK_PORT/CERBO_HOST/etc. without a
    systemd EnvironmentFile. Missing file / bad lines are ignored silently."""
    cfg = Path(__file__).parent / "config.env"
    if not cfg.exists():
        return
    try:
        for line in cfg.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key, val = key.strip(), val.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = val
    except Exception:
        pass


# ── Config ──────────────────────────────────────────────────────────────────

BMS_POLL_INTERVAL = 10     # seconds between JBD/JK live reads (fast path: 0x03+0x04 only)
BMS_CONFIG_INTERVAL = 300  # seconds between full EEPROM/config reads (slow path); cached between
ECOFLOW_POLL_INTERVAL = 120  # seconds between EcoFlow reads (ECDH is slow)
DB_PATH = Path(__file__).parent / "shadowgrid.db"
STATIC_DIR = Path(__file__).parent / "static"

# ── JBD BLE Protocol ───────────────────────────────────────────────────────

JBD_RX = "0000ff01-0000-1000-8000-00805f9b34fb"
JBD_TX = "0000ff02-0000-1000-8000-00805f9b34fb"
DEFAULT_BMS_PASSWORD = 0x5678

# ── Service Key System ─────────────────────────────────────────────────────
# Dangerous operations (modifying protection thresholds, disabling FETs,
# overriding safety blocks) require a service key. Keys are generated from
# a master secret + the device serial/MAC, so each installation gets a
# unique key that can only be issued by someone who knows the master secret.

SERVICE_MASTER_SECRET = "CHANGE_ME_SET_YOUR_OWN_SERVICE_SECRET"  # Published — the security is in the HMAC


def generate_service_key(device_identifier: str) -> str:
    """Generate a service key for a specific device/installation.
    This would be run by a ShadowGrid maintainer to issue a key to a user."""
    import hmac
    raw = hmac.new(
        SERVICE_MASTER_SECRET.encode(),
        device_identifier.encode(),
        hashlib.sha256
    ).hexdigest()
    # Return first 12 chars uppercase for readability
    return raw[:12].upper()


def verify_service_key(device_identifier: str, key: str) -> bool:
    """Verify a service key is valid for this device."""
    expected = generate_service_key(device_identifier)
    return key.upper() == expected


def get_installation_id() -> str:
    """Get a unique identifier for this installation."""
    try:
        with open("/etc/machine-id") as f:
            return f.read().strip()[:16]
    except Exception:
        return "unknown"


# ── Safety Guardrails ──────────────────────────────────────────────────────
# Safe operating ranges for LiFePO4 cells (most common chemistry)
# Values outside these ranges trigger warnings or are blocked

SAFETY_LIMITS = {
    "cell_ovp": {"min": 3400, "max": 3700, "unit": "mV", "name": "Cell Over-Voltage Protection",
                 "danger": "Setting above 3.65V risks swelling, venting, or thermal runaway"},
    "cell_uvp": {"min": 2000, "max": 2900, "unit": "mV", "name": "Cell Under-Voltage Protection",
                 "danger": "Setting below 2.5V causes irreversible cell damage and capacity loss"},
    "cell_ovp_rel": {"min": 3200, "max": 3600, "unit": "mV", "name": "Cell OVP Release"},
    "cell_uvp_rel": {"min": 2200, "max": 3000, "unit": "mV", "name": "Cell UVP Release"},
    "pack_ovp": {"min": 1360, "max": 1480, "unit": "10mV", "name": "Pack Over-Voltage Protection",
                 "danger": "Pack OVP too high can allow cell overcharge"},
    "pack_uvp": {"min": 800, "max": 1160, "unit": "10mV", "name": "Pack Under-Voltage Protection",
                 "danger": "Pack UVP too low risks deep discharge damage"},
    "chg_oc": {"min": 1000, "max": 30000, "unit": "10mA", "name": "Charge Over-Current",
               "danger": "Excessive charge current can cause overheating and fire"},
    "dsg_oc": {"min": 1000, "max": 50000, "unit": "10mA", "name": "Discharge Over-Current",
               "danger": "Excessive discharge current can cause overheating and fire"},
}


def validate_bms_setting(register: int, value: int) -> dict:
    """Check if a BMS config value is within safe limits.
    Returns {safe: bool, warning: str, blocked: bool}"""
    # Verified JBD EEPROM map (docs/jbd-register-map.md): cell V at 0x24-0x27,
    # pack V at 0x20-0x23, over-current at 0x28-0x29. (The old map pointed cell/
    # pack-voltage names at temperature registers — a dangerous write mismatch.)
    reg_names = {
        0x24: "cell_ovp", 0x25: "cell_ovp_rel", 0x26: "cell_uvp", 0x27: "cell_uvp_rel",
        0x20: "pack_ovp", 0x22: "pack_uvp", 0x28: "chg_oc", 0x29: "dsg_oc",
    }
    key = reg_names.get(register)
    if not key or key not in SAFETY_LIMITS:
        return {"safe": True, "warning": "", "blocked": False}

    limits = SAFETY_LIMITS[key]
    if value < limits["min"] or value > limits["max"]:
        danger = limits.get("danger", f"Value outside safe range ({limits['min']}-{limits['max']} {limits['unit']})")
        # Block extreme values that are clearly dangerous
        extreme_low = limits["min"] * 0.7
        extreme_high = limits["max"] * 1.3
        blocked = value < extreme_low or value > extreme_high
        return {
            "safe": False,
            "warning": f"WARNING: {limits['name']} value {value} {limits['unit']} is outside safe range "
                       f"({limits['min']}-{limits['max']} {limits['unit']}). {danger}",
            "blocked": blocked,
        }
    return {"safe": True, "warning": "", "blocked": False}


def make_read_cmd(reg):
    checksum = (~reg & 0xFFFF) + 1
    return bytes([0xDD, 0xA5, reg, 0x00, (checksum >> 8) & 0xFF, checksum & 0xFF, 0x77])


def make_write_cmd(reg, data: bytes):
    """Build a JBD write command: DD 5A reg len data... checksum 77"""
    length = len(data)
    payload = bytes([length]) + data
    s = sum(payload) & 0xFFFF
    checksum = (~s & 0xFFFF) + 1
    return bytes([0xDD, 0x5A, reg]) + payload + bytes([(checksum >> 8) & 0xFF, checksum & 0xFF, 0x77])


def make_factory_enter(password: int):
    """Build the factory mode enter command with a specific password."""
    pw_bytes = password.to_bytes(2, 'big')
    return make_write_cmd(0x00, pw_bytes)


def make_factory_exit():
    return make_write_cmd(0x01, bytes([0x00, 0x00]))


def parse_date(raw):
    return f"{2000 + ((raw >> 9) & 0x7F)}-{(raw >> 5) & 0x0F:02d}-{raw & 0x1F:02d}"


# ── BLE Reader ─────────────────────────────────────────────────────────────

async def ble_send(client, response, event, cmd):
    response.clear()
    event.clear()
    await client.write_gatt_char(JBD_TX, cmd)
    await asyncio.wait_for(event.wait(), timeout=5)
    return bytes(response)


def parse_jbd_frame(raw):
    """Validate a JBD response frame and return its data payload, or None.

    Frame: DD <reg-echo> <status> <length> <data...> <chk-hi> <chk-lo> 77.
    Rejects bad start/stop, non-zero status (0x80 = e.g. not in factory mode),
    length/size mismatch, or checksum mismatch. Checksum = two's-complement of
    (status + length + sum(data)), big-endian (verified vs jbdtool / ESPHome)."""
    if len(raw) < 7 or raw[0] != 0xDD or raw[-1] != 0x77:
        return None
    status, length = raw[2], raw[3]
    if status != 0x00 or 4 + length + 3 != len(raw):
        return None
    data = raw[4:4 + length]
    chk = (raw[4 + length] << 8) | raw[4 + length + 1]
    if chk != ((0x10000 - (status + length + sum(data))) & 0xFFFF):
        return None
    return data


# Per-address cache of the static EEPROM/config block (OVP thresholds, capacity,
# shunt, manufacturer strings, bal_start_v…). Populated by full (slow-path) reads
# and reused by fast reads so we don't re-read ~30 unchanging registers every poll.
bms_config_cache = {}


async def read_battery(addr, label, full=False):
    """Read one battery. full=True does the slow-path EEPROM/config + manufacturer
    block and refreshes the per-address cache; full=False (fast path) reads only the
    live 0x03/0x04 frames and merges the cached static config. Returns dict."""
    for attempt in range(2):
        try:
            async with BleakClient(addr, timeout=10) as client:
                response = bytearray()
                event = asyncio.Event()

                def on_notify(sender, data):
                    response.extend(data)
                    if len(response) >= 4 and response[-1] == 0x77:
                        event.set()

                await client.start_notify(JBD_RX, on_notify)
                info = {"label": label, "addr": addr, "online": True}

                # 0x03 Basic Info
                raw = await ble_send(client, response, event, make_read_cmd(0x03))
                vd = parse_jbd_frame(raw)
                info["frame_ok"] = vd is not None
                d = vd if vd is not None else raw[4:-3]
                info["voltage"] = round(((d[0] << 8) | d[1]) * 0.01, 2)
                raw_i = (d[2] << 8) | d[3]
                info["current"] = round((raw_i - 65536 if raw_i > 32767 else raw_i) * 0.01, 2)
                info["remain"] = round(((d[4] << 8) | d[5]) * 0.01, 1)
                info["nominal"] = round(((d[6] << 8) | d[7]) * 0.01, 0)
                info["cycles"] = (d[8] << 8) | d[9]
                info["prod_date"] = parse_date((d[10] << 8) | d[11])

                # Balance status bitmask (bytes 12-15). NOTE: on these Ecoworthy
                # JBD packs the mask is reported INVERTED vs physical reality —
                # the set bits flag the low/reference cells, not the cells being
                # bled. The corrected (complemented + voltage-guarded) balancing
                # list is computed further down, once cell voltages and the
                # balance-start threshold are available. Raw mask kept for
                # diagnostics. See docs/jbd-register-map.md.
                bal_lo = (d[12] << 8) | d[13]  # raw: cells 1-16
                bal_hi = (d[14] << 8) | d[15]  # raw: cells 17-32
                bal_full = bal_lo | (bal_hi << 16)
                info["balance_status"] = bal_full

                prot = (d[16] << 8) | d[17]
                prot_names = {
                    0: "Cell OVP", 1: "Cell UVP", 2: "Pack OVP", 3: "Pack UVP",
                    4: "Chg OT", 5: "Chg UT", 6: "Dsg OT", 7: "Dsg UT",
                    8: "Chg OC", 9: "Dsg OC", 10: "Short Circuit", 11: "IC Error", 12: "FET Lock"
                }
                info["protection"] = [prot_names[i] for i in range(16) if prot & (1 << i)] or ["Clear"]
                info["fw"] = f"v{d[18] >> 4}.{d[18] & 0x0F}"
                info["soc"] = d[19]
                info["chg_fet"] = bool(d[20] & 1)
                info["dsg_fet"] = bool(d[20] & 2)
                info["cell_count"] = d[21]
                info["temps"] = []
                for i in range(d[22]):
                    idx = 23 + i * 2
                    if idx + 1 < len(d):
                        raw_t = (d[idx] << 8) | d[idx + 1]
                        info["temps"].append(round((raw_t - 2731) / 10.0, 1))

                # 0x04 Cell Voltages
                raw = await ble_send(client, response, event, make_read_cmd(0x04))
                vc = parse_jbd_frame(raw)
                cd = vc if vc is not None else raw[4:-3]
                info["cells"] = [round(((cd[i] << 8) | cd[i + 1]) / 1000.0, 3) for i in range(0, len(cd), 2)]
                if info["cells"]:
                    info["cell_delta"] = round((max(info["cells"]) - min(info["cells"])) * 1000, 0)

                # Everything read up to here (0x03 + 0x04) is live data. The
                # block below is static EEPROM/config + manufacturer strings —
                # only read on a full (slow-path) poll and cached per address.
                live_keys = set(info.keys())

                if full:
                    # ── SLOW PATH: static config, read every BMS_CONFIG_INTERVAL ──
                    # 0x05 Hardware Version
                    raw = await ble_send(client, response, event, make_read_cmd(0x05))
                    info["hw_ver"] = raw[4:-3].decode("ascii", errors="replace")

                    # Config / EEPROM registers (require factory mode). Register map
                    # + units verified 2026-08-04 against jbdtool, ESPHome, bms-tools,
                    # and the official JBD protocol PDF — see docs/jbd-register-map.md.
                    # (The previous map was shifted 8 registers, swapping the temp and
                    # voltage blocks, so thresholds decoded to impossible values.)
                    bms_pw = get_bms_password(addr)
                    await ble_send(client, response, event, make_factory_enter(bms_pw))

                    def _s16(v):
                        return v - 65536 if v > 32767 else v

                    # reg -> (field, kind); kind selects the scaling applied below.
                    config_regs = {
                        0x10: ("design_cap", "cap"),    0x11: ("cycle_cap", "cap"),
                        0x12: ("full_chg_v", "mv"),     0x13: ("eod_v", "mv"),
                        0x14: ("dsg_rate", "raw"),      0x17: ("cycles_cfg", "raw"),
                        0x18: ("chg_ot", "temp"),       0x19: ("chg_ot_rel", "temp"),
                        0x1A: ("chg_ut", "temp"),       0x1B: ("chg_ut_rel", "temp"),
                        0x1C: ("dsg_ot", "temp"),       0x1D: ("dsg_ot_rel", "temp"),
                        0x1E: ("dsg_ut", "temp"),       0x1F: ("dsg_ut_rel", "temp"),
                        0x20: ("pack_ovp", "packv"),    0x21: ("pack_ovp_rel", "packv"),
                        0x22: ("pack_uvp", "packv"),    0x23: ("pack_uvp_rel", "packv"),
                        0x24: ("cell_ovp", "mv"),       0x25: ("cell_ovp_rel", "mv"),
                        0x26: ("cell_uvp", "mv"),       0x27: ("cell_uvp_rel", "mv"),
                        0x28: ("chg_oc", "curr"),       0x29: ("dsg_oc", "curr"),
                        0x2A: ("bal_start_v", "cellv"), 0x2B: ("bal_delta", "mv"),
                        0x2C: ("shunt_res", "shunt"),
                    }
                    config_ok = True
                    for reg, (field, kind) in config_regs.items():
                        try:
                            raw = await ble_send(client, response, event, make_read_cmd(reg))
                            p = parse_jbd_frame(raw)
                            if p is None:
                                config_ok = False
                                p = raw[4:-3]  # fall back; the corrected map still decodes it
                            val = (p[0] << 8) | p[1] if len(p) >= 2 else 0
                            if kind == "cap":            # 10 mAh -> Ah
                                info[field] = round(val * 0.01, 0)
                            elif kind == "mv":           # raw millivolts (cell-level)
                                info[field] = val
                            elif kind == "cellv":        # 1 mV -> V
                                info[field] = round(val / 1000.0, 3)
                            elif kind == "packv":        # 10 mV -> V
                                info[field] = round(val * 0.01, 2)
                            elif kind == "temp":         # 0.1 K -> degC
                                info[field] = val
                                c = round((val - 2731) / 10.0, 1)
                                info[field + "_c"] = c if -60.0 <= c <= 130.0 else None
                            elif kind == "curr":         # s16, 10 mA -> A (magnitude)
                                info[field] = round(abs(_s16(val)) * 0.01, 0)
                            elif kind == "shunt":        # 0.1 mOhm -> mOhm
                                info[field] = round(val * 0.1, 2)
                            else:                        # raw
                                info[field] = val
                        except Exception:
                            pass
                    info["config_frames_ok"] = config_ok

                    # Manufacturer info
                    for reg, key in [(0xA0, "mfg"), (0xA1, "model"), (0xA2, "serial"), (0xAA, "device_serial")]:
                        try:
                            raw = await ble_send(client, response, event, make_read_cmd(reg))
                            info[key] = raw[4:-3].decode("ascii", errors="replace").strip() or "(blank)"
                        except Exception:
                            pass

                    try:
                        response.clear()
                        event.clear()
                        await client.write_gatt_char(JBD_TX, make_factory_exit())
                        await asyncio.sleep(0.2)
                    except Exception:
                        pass

                    # Cache everything the slow path just added (all static) so
                    # fast polls can reuse it without touching the EEPROM.
                    bms_config_cache[addr] = {k: v for k, v in info.items()
                                              if k not in live_keys}
                else:
                    # ── FAST PATH: reuse the last cached static config ──
                    for k, v in bms_config_cache.get(addr, {}).items():
                        info.setdefault(k, v)

                # Balance decode (runs every poll — fast or slow). CORRECTION
                # 2026-08-04 (later): the balance mask is DIRECT, not inverted —
                # the set bits ARE the cells being bled. Re-confirmed live on BOTH
                # packs during a top-of-charge imbalance: FFA9 raw 7 = high trio
                # {1,2,3} (cell 4 low), 09D2 raw 13 = highs {1,3,4} (cell 2 low),
                # stable across many samples. (The earlier "inverted" call was
                # drawn from noisier resting samples during the config-map bug era
                # and is superseded.) We still gate each candidate on being above
                # the pack minimum AND at/above bal_start_v as a sanity guard, so a
                # stray bit on a low cell can never be reported as balancing; the
                # raw==0 case naturally yields no balancing cells.
                cells = info.get("cells") or []
                n = len(cells)
                bled_mask = bal_full & ((1 << n) - 1) if n else 0
                vmin = min(cells) if cells else 0.0
                bal_start = info.get("bal_start_v")  # volts, or None if not cached yet
                info["balancing"] = [
                    bool(bled_mask & (1 << i))
                    and cells[i] > vmin
                    and (bal_start is None or cells[i] >= bal_start)
                    for i in range(n)
                ]
                info["balancing_active"] = any(info["balancing"])
                info["balancing_cells"] = [i + 1 for i in range(n) if info["balancing"][i]]

                await client.stop_notify(JBD_RX)
                info["timestamp"] = datetime.now().isoformat()
                info["power"] = round(info["voltage"] * info["current"], 1)
                return info

        except Exception:
            # Force disconnect via bluetoothctl in case BleakClient left a stale connection
            try:
                import subprocess
                subprocess.run(["bluetoothctl", "disconnect", addr],
                               capture_output=True, timeout=3)
            except Exception:
                pass
            await asyncio.sleep(2)

    return {"label": label, "addr": addr, "online": False, "timestamp": datetime.now().isoformat()}


async def read_ecoflow_device(addr, serial, user_id):
    """Connect to EcoFlow, authenticate, collect data for 10s, disconnect."""
    ef = EcoFlowBLE(addr, serial, user_id)
    try:
        await ef.connect()
        await ef.authenticate()
        await asyncio.sleep(10)
        data = ef.get_latest()
        return data if data and data.get("last_update") else {}
    except Exception as e:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] EcoFlow read error: {e}")
        return {}
    finally:
        try:
            await ef.disconnect()
        except Exception:
            pass


# ── Database ───────────────────────────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS readings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            label TEXT NOT NULL,
            addr TEXT NOT NULL,
            voltage REAL,
            current REAL,
            soc INTEGER,
            remain REAL,
            power REAL,
            temp REAL,
            cell1 REAL, cell2 REAL, cell3 REAL, cell4 REAL,
            cell_delta REAL,
            chg_fet INTEGER,
            dsg_fet INTEGER,
            protection TEXT
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_readings_ts ON readings(timestamp)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_readings_label ON readings(label)
    """)
    conn.commit()
    conn.close()


def log_reading(data):
    if not data.get("online"):
        return
    conn = sqlite3.connect(str(DB_PATH))
    cells = data.get("cells", [])
    conn.execute(
        """INSERT INTO readings
           (timestamp, label, addr, voltage, current, soc, remain, power, temp,
            cell1, cell2, cell3, cell4, cell_delta, chg_fet, dsg_fet, protection)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            data["timestamp"], data["label"], data["addr"],
            data.get("voltage"), data.get("current"), data.get("soc"),
            data.get("remain"), data.get("power"),
            data["temps"][0] if data.get("temps") else None,
            cells[0] if len(cells) > 0 else None,
            cells[1] if len(cells) > 1 else None,
            cells[2] if len(cells) > 2 else None,
            cells[3] if len(cells) > 3 else None,
            data.get("cell_delta"),
            1 if data.get("chg_fet") else 0,
            1 if data.get("dsg_fet") else 0,
            json.dumps(data.get("protection", [])),
        ),
    )
    conn.commit()
    conn.close()


# ── Victron DB ─────────────────────────────────────────────────────────────

def init_energy_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS energy_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            solar_w REAL DEFAULT 0,
            grid_w REAL DEFAULT 0,
            battery_w REAL DEFAULT 0,
            load_w REAL DEFAULT 0,
            soc REAL,
            independence REAL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_energy_ts ON energy_log(timestamp)")
    conn.commit()
    conn.close()


def log_energy_snapshot(solar_w=0, grid_w=0, battery_w=0, load_w=0, soc=None):
    """Log an energy snapshot and calculate independence score."""
    total_supply = solar_w + grid_w
    independence = (solar_w / total_supply * 100) if total_supply > 0 else 100.0
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute(
        "INSERT INTO energy_log (timestamp, solar_w, grid_w, battery_w, load_w, soc, independence) VALUES (?,?,?,?,?,?,?)",
        (datetime.now().isoformat(), solar_w, grid_w, battery_w, load_w, soc, independence),
    )
    conn.commit()
    conn.close()
    return independence


def get_independence_stats(hours=24):
    """Get independence score stats for a time period."""
    since = (datetime.now() - timedelta(hours=hours)).isoformat()
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        """SELECT
              COUNT(*) as samples,
              AVG(independence) as avg_independence,
              MIN(independence) as min_independence,
              MAX(independence) as max_independence,
              SUM(solar_w) / COUNT(*) * ? / 3600 as solar_kwh,
              SUM(grid_w) / COUNT(*) * ? / 3600 as grid_kwh,
              SUM(load_w) / COUNT(*) * ? / 3600 as load_kwh,
              AVG(solar_w) as avg_solar_w,
              AVG(grid_w) as avg_grid_w,
              AVG(load_w) as avg_load_w,
              AVG(battery_w) as avg_battery_w
           FROM energy_log WHERE timestamp > ?""",
        (BMS_POLL_INTERVAL, BMS_POLL_INTERVAL, BMS_POLL_INTERVAL, since),
    ).fetchone()
    conn.close()
    if row and row["samples"] > 0:
        return dict(row)
    return {"samples": 0, "avg_independence": 0}


def init_victron_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS victron_readings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            addr TEXT NOT NULL,
            name TEXT,
            device_type TEXT,
            model_name TEXT,
            data TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_victron_ts ON victron_readings(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_victron_addr ON victron_readings(addr)")
    conn.commit()
    conn.close()


def log_victron_reading(device_data):
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute(
        "INSERT INTO victron_readings (timestamp, addr, name, device_type, model_name, data) VALUES (?, ?, ?, ?, ?, ?)",
        (
            device_data.get("timestamp", datetime.now().isoformat()),
            device_data.get("addr", ""),
            device_data.get("name", ""),
            device_data.get("device_type", ""),
            device_data.get("model_name", ""),
            json.dumps(device_data),
        ),
    )
    conn.commit()
    conn.close()


# ── Cerbo GX (Modbus TCP) Database ─────────────────────────────────────────
# Wired ingestion of the Victron Cerbo's SmartShunt. Independent of all BLE
# pollers — see cerbo_reader.py.

def init_cerbo_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cerbo_readings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source TEXT,
            voltage REAL,
            current REAL,
            power REAL,
            soc REAL,
            temp REAL,
            aux_voltage REAL,
            data TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cerbo_ts ON cerbo_readings(timestamp)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cerbo_solar_readings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            unit INTEGER,
            name TEXT,
            state TEXT,
            battery_voltage REAL,
            battery_current REAL,
            pv_voltage REAL,
            pv_power REAL,
            yield_today REAL,
            yield_total REAL,
            data TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cerbo_solar_ts ON cerbo_solar_readings(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cerbo_solar_unit ON cerbo_solar_readings(unit)")
    conn.commit()
    conn.close()


def log_cerbo_solar_reading(c):
    if not c.get("online"):
        return
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute(
        """INSERT INTO cerbo_solar_readings
           (timestamp, unit, name, state, battery_voltage, battery_current,
            pv_voltage, pv_power, yield_today, yield_total, data)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (
            c.get("timestamp", datetime.now().isoformat()),
            c.get("unit"), c.get("name"), c.get("state"),
            c.get("battery_voltage"), c.get("battery_current"),
            c.get("pv_voltage"), c.get("pv_power"),
            c.get("yield_today"), c.get("yield_total"),
            json.dumps(c),
        ),
    )
    conn.commit()
    conn.close()


def log_cerbo_reading(d):
    if not d.get("online"):
        return
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute(
        """INSERT INTO cerbo_readings
           (timestamp, source, voltage, current, power, soc, temp, aux_voltage, data)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (
            d.get("timestamp", datetime.now().isoformat()),
            d.get("source", "cerbo_modbus"),
            d.get("voltage"), d.get("current"), d.get("power"),
            d.get("soc"), d.get("temp"), d.get("aux_voltage"),
            json.dumps(d),
        ),
    )
    conn.commit()
    conn.close()


def cerbo_poll_loop():
    """Poll the Cerbo SmartShunt over Modbus TCP. Fully isolated from BLE."""
    interval = int(os.environ.get("CERBO_POLL_INTERVAL", "15"))
    while True:
        try:
            d = cerbo_reader.poll()
            with data_lock:
                latest_cerbo["online"] = d.get("online", False)
                latest_cerbo["updated"] = d.get("timestamp")
                latest_cerbo["data"] = d
            if d.get("online"):
                log_cerbo_reading(d)
        except Exception:
            pass
        # Solar MPPT chargers on the same Cerbo (separate Modbus reads).
        try:
            chargers = cerbo_reader.poll_solar()
            with data_lock:
                latest_cerbo_solar["chargers"] = chargers
                latest_cerbo_solar["online"] = any(c.get("online") for c in chargers)
                latest_cerbo_solar["updated"] = datetime.now().isoformat()
            for c in chargers:
                log_cerbo_solar_reading(c)
        except Exception:
            pass
        time.sleep(interval)


# ── Host (Zima) self-power monitoring + power-mode control ──────────────────

POWER_MODE_FILE = Path(__file__).parent / "power_mode"
AUTO_LOW_SOC = int(os.environ.get("POWER_AUTO_LOW_SOC", "40"))  # eco below this SOC in auto mode


def init_power_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS power_readings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            watts REAL,
            governor TEXT,
            mode TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_power_ts ON power_readings(timestamp)")
    conn.commit()
    conn.close()


def log_power_reading(watts, governor, mode):
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute(
        "INSERT INTO power_readings (timestamp, watts, governor, mode) VALUES (?,?,?,?)",
        (datetime.now().isoformat(), watts, governor, mode),
    )
    conn.commit()
    conn.close()


def read_power_mode():
    try:
        m = POWER_MODE_FILE.read_text().strip()
        return m if m in (set(zima_power.MODES) | {"auto"}) else "balanced"
    except Exception:
        return "balanced"


def write_power_mode(mode):
    try:
        POWER_MODE_FILE.write_text(mode)
    except Exception:
        pass


def _current_min_soc():
    socs = [b.get("soc") for b in latest_data.get("batteries", [])
            if b.get("online") and b.get("device_type") != "ecoflow" and b.get("soc") is not None]
    return min(socs) if socs else None


def power_poll_loop():
    """Monitor host power via RAPL and enforce the selected power mode.
    Defaults to 'balanced' (schedutil = the box's normal behaviour)."""
    interval = int(os.environ.get("POWER_POLL_INTERVAL", "10"))
    # apply the persisted mode at startup (balanced is a no-op vs default)
    startup_mode = read_power_mode()
    if startup_mode in zima_power.MODES:
        zima_power.set_mode(startup_mode)
    zima_power.read_power()  # prime the energy counter
    while True:
        try:
            watts = zima_power.read_power()
            mode = read_power_mode()
            gov = zima_power.get_governor()
            # auto: pick governor from battery SOC (only writes on change)
            if mode == "auto":
                soc = _current_min_soc()
                target = "eco" if (soc is not None and soc < AUTO_LOW_SOC) else "balanced"
                if zima_power.MODES.get(target) != gov:
                    zima_power.set_mode(target)
                    gov = zima_power.get_governor()
            with data_lock:
                latest_power["watts"] = watts
                latest_power["mode"] = mode
                latest_power["governor"] = gov
                latest_power["updated"] = datetime.now().isoformat()
            if watts is not None:
                log_power_reading(watts, gov, mode)
        except Exception:
            pass
        time.sleep(interval)


# ── BMS Password Database ──────────────────────────────────────────────────

def init_bms_password_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS bms_passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            address TEXT NOT NULL,
            label TEXT,
            old_password TEXT NOT NULL,
            new_password TEXT NOT NULL,
            success INTEGER DEFAULT 0
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_bmspw_addr ON bms_passwords(address)")
    # Current password per device
    conn.execute("""
        CREATE TABLE IF NOT EXISTS bms_current_password (
            address TEXT PRIMARY KEY,
            password INTEGER NOT NULL DEFAULT 22136
        )
    """)
    conn.commit()
    conn.close()


def get_bms_password(address: str) -> int:
    """Get the current password for a BMS device. Default 0x5678 = 22136."""
    conn = sqlite3.connect(str(DB_PATH))
    row = conn.execute("SELECT password FROM bms_current_password WHERE address=?", (address,)).fetchone()
    conn.close()
    return row[0] if row else 0x5678


def set_bms_password(address: str, password: int):
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("INSERT OR REPLACE INTO bms_current_password (address, password) VALUES (?, ?)",
                 (address, password))
    conn.commit()
    conn.close()


async def change_bms_password(addr: str, label: str, old_pw: int, new_pw: int) -> dict:
    """Connect to a JBD BMS and change its factory password.
    Returns {'success': True/False, 'message': str}"""
    try:
        async with BleakClient(addr, timeout=10) as client:
            response = bytearray()
            event = asyncio.Event()

            def on_notify(sender, data):
                response.extend(data)
                if len(response) >= 4 and response[-1] == 0x77:
                    event.set()

            await client.start_notify(JBD_RX, on_notify)

            # Step 1: Enter factory mode with old password
            response.clear(); event.clear()
            await client.write_gatt_char(JBD_TX, make_factory_enter(old_pw))
            try:
                await asyncio.wait_for(event.wait(), timeout=5)
            except asyncio.TimeoutError:
                return {"success": False, "message": "No response — old password may be wrong or device out of range"}

            # Check response — 0x00 in status byte means success
            if len(response) >= 4 and response[2] == 0x00:
                pass  # Factory mode entered
            else:
                return {"success": False, "message": f"Factory enter rejected — wrong password? Response: {response.hex()}"}

            # Step 2: Write new password (register 0x00 with new password while in factory mode)
            response.clear(); event.clear()
            await client.write_gatt_char(JBD_TX, make_factory_enter(new_pw))
            try:
                await asyncio.wait_for(event.wait(), timeout=5)
            except asyncio.TimeoutError:
                pass  # Some BMS don't respond to password writes

            # Step 3: Exit factory mode
            response.clear(); event.clear()
            await client.write_gatt_char(JBD_TX, make_factory_exit())
            try:
                await asyncio.wait_for(event.wait(), timeout=3)
            except asyncio.TimeoutError:
                pass

            # Step 4: Verify — try entering factory mode with new password
            response.clear(); event.clear()
            await client.write_gatt_char(JBD_TX, make_factory_enter(new_pw))
            try:
                await asyncio.wait_for(event.wait(), timeout=5)
            except asyncio.TimeoutError:
                return {"success": False, "message": "Verification timeout — password may or may not have changed"}

            if len(response) >= 4 and response[2] == 0x00:
                # Exit factory mode
                await client.write_gatt_char(JBD_TX, make_factory_exit())
                return {"success": True, "message": f"Password changed from 0x{old_pw:04X} to 0x{new_pw:04X}"}
            else:
                return {"success": False, "message": "Verification failed — new password not accepted. Old password may still work."}

    except Exception as e:
        return {"success": False, "message": f"Connection error: {e}"}


# ── EcoFlow Database ───────────────────────────────────────────────────────

def init_ecoflow_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ecoflow_readings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            soc INTEGER,
            voltage REAL,
            current REAL,
            power REAL,
            temp INTEGER,
            cycles INTEGER,
            soh INTEGER,
            pd_in_w INTEGER,
            pd_out_w INTEGER,
            pd_ac_chg_w INTEGER,
            pd_solar_chg_w INTEGER,
            pd_dc_chg_w INTEGER,
            inv_out_w INTEGER,
            mppt_in_w INTEGER,
            ems_fan INTEGER,
            ems_max_soc INTEGER,
            ems_min_dsg_soc INTEGER,
            pack_data TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ecoflow_ts ON ecoflow_readings(timestamp)")
    conn.commit()
    conn.close()


def log_ecoflow_reading(data):
    if not data.get("online"):
        return
    conn = sqlite3.connect(str(DB_PATH))
    packs_json = json.dumps(data.get("packs", []))
    conn.execute(
        """INSERT INTO ecoflow_readings
           (timestamp, soc, voltage, current, power, temp, cycles, soh,
            pd_in_w, pd_out_w, pd_ac_chg_w, pd_solar_chg_w, pd_dc_chg_w,
            inv_out_w, mppt_in_w, ems_fan, ems_max_soc, ems_min_dsg_soc, pack_data)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            data.get("timestamp", datetime.now().isoformat()),
            data.get("soc", 0), data.get("voltage", 0), data.get("current", 0),
            data.get("power", 0), data.get("temps", [0])[0],
            data.get("cycles", 0), data.get("soh", 0),
            data.get("pd_in_w", 0), data.get("pd_out_w", 0),
            data.get("pd_ac_chg_w", 0), data.get("pd_solar_chg_w", 0),
            data.get("pd_dc_chg_w", 0),
            data.get("inv_out_w", 0), data.get("mppt_in_w", 0),
            data.get("ems_fan", 0), data.get("ems_max_soc", 100),
            data.get("ems_min_dsg_soc", 0), packs_json,
        ),
    )
    conn.commit()
    conn.close()


# ── Scanner Database ──────────────────────────────────────────────────────

def init_scanner_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scanner_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            address TEXT NOT NULL,
            name TEXT,
            rssi INTEGER,
            protocol TEXT,
            protocol_name TEXT,
            auth_type TEXT,
            vulnerable INTEGER DEFAULT 0,
            vuln_detail TEXT,
            vuln_severity TEXT,
            default_password TEXT,
            serial TEXT,
            brands TEXT,
            tested INTEGER DEFAULT 0,
            test_result TEXT,
            mfg_data TEXT,
            extra TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scanner_ts ON scanner_log(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scanner_addr ON scanner_log(address)")
    # Unique devices summary table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scanner_devices (
            address TEXT PRIMARY KEY,
            name TEXT,
            protocol TEXT,
            protocol_name TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            seen_count INTEGER DEFAULT 1,
            best_rssi INTEGER,
            auth_type TEXT,
            vulnerable INTEGER DEFAULT 0,
            vuln_detail TEXT,
            vuln_severity TEXT,
            default_password TEXT,
            serial TEXT,
            brands TEXT,
            tested INTEGER DEFAULT 0,
            test_result TEXT
        )
    """)
    conn.commit()
    conn.close()


def log_scanner_results(devices: list):
    """Log all scanner results — update summary table and append to log."""
    if not devices:
        return
    conn = sqlite3.connect(str(DB_PATH))
    now = datetime.now().isoformat()

    for dev in devices:
        # Append to raw log
        conn.execute(
            """INSERT INTO scanner_log
               (timestamp, address, name, rssi, protocol, protocol_name,
                auth_type, vulnerable, vuln_detail, vuln_severity,
                default_password, serial, brands, tested, test_result, mfg_data, extra)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                now, dev["address"], dev["name"], dev["rssi"],
                dev["protocol"], dev["protocol_name"],
                dev["auth_type"], int(dev["vulnerable"]),
                dev["vuln_detail"], dev.get("vuln_severity", ""),
                dev.get("default_password", ""), dev.get("serial", ""),
                json.dumps(dev.get("brands", [])),
                int(dev["tested"]), dev.get("test_result", ""),
                dev.get("mfg_data", ""), json.dumps(dev.get("extra", {})),
            ),
        )

        # Upsert summary
        conn.execute(
            """INSERT INTO scanner_devices
               (address, name, protocol, protocol_name, first_seen, last_seen,
                seen_count, best_rssi, auth_type, vulnerable, vuln_detail,
                vuln_severity, default_password, serial, brands, tested, test_result)
               VALUES (?,?,?,?,?,?,1,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(address) DO UPDATE SET
                 name=excluded.name, last_seen=excluded.last_seen,
                 seen_count=seen_count+1,
                 best_rssi=MAX(best_rssi, excluded.best_rssi),
                 tested=MAX(tested, excluded.tested),
                 test_result=COALESCE(NULLIF(excluded.test_result,''), test_result)""",
            (
                dev["address"], dev["name"], dev["protocol"],
                dev["protocol_name"], now, now,
                dev["rssi"], dev["auth_type"],
                int(dev["vulnerable"]), dev["vuln_detail"],
                dev.get("vuln_severity", ""),
                dev.get("default_password", ""), dev.get("serial", ""),
                json.dumps(dev.get("brands", [])),
                int(dev["tested"]), dev.get("test_result", ""),
            ),
        )

    conn.commit()
    conn.close()


# ── Background Poller ──────────────────────────────────────────────────────

# Hard ceiling on a single battery read. bleak's connect/notify/write/disconnect
# call into BlueZ over D-Bus; a wedged adapter can leave one of those D-Bus method
# calls hanging with no reply (only ble_send's event.wait was guarded). Without an
# overall deadline that freezes the whole poller thread indefinitely (observed
# 2026-08-05: loop parked ~11h, latest_data frozen, graphs empty). asyncio.wait_for
# cancels a hung read so the loop always makes progress; the offline result then
# lets the BLE watchdog bounce the stack.
BLE_READ_DEADLINE = int(os.environ.get("BLE_READ_DEADLINE", "45"))

# Monotonic timestamp of the last completed poll cycle. The BLE watchdog uses this
# as a liveness heartbeat: a hung loop keeps stale online=True data (invisible to
# the per-pack-offline check), so freshness is the only signal that catches it.
_last_poll_ts = 0.0

latest_data = {"batteries": [], "updated": None}
latest_victron = {"devices": {}, "updated": None}
latest_energy = {"independence": 0, "solar_w": 0, "grid_w": 0, "battery_w": 0, "load_w": 0}
latest_meter = {"available": False, "reading": None, "power": None}
latest_cerbo = {"online": False, "updated": None, "data": None}
latest_cerbo_solar = {"online": False, "updated": None, "chargers": []}
latest_power = {"watts": None, "mode": "balanced", "governor": None, "updated": None}
data_lock = threading.Lock()

# Meter reader (starts if RTL-SDR detected)
meter_reader = None

# LoRa bridge (starts if base unit detected)
lora_bridge = LoraBridge()
latest_lora = {"connected": False, "data": None, "lora_stats": None}

ble_scanner = BLEBatteryScanner()

victron_key_store = VictronKeyStore(str(Path(__file__).parent / "victron_keys.json"))
victron_scanner = VictronScanner(victron_key_store)

ecoflow_latest = {}


# ── Device Registry ────────────────────────────────────────────────────────

def init_installations_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""CREATE TABLE IF NOT EXISTS installations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        location TEXT,
        description TEXT,
        icon TEXT DEFAULT 'battery',
        created TEXT NOT NULL
    )""")
    conn.commit()
    conn.close()


def init_devices_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            address TEXT UNIQUE NOT NULL,
            label TEXT NOT NULL,
            device_type TEXT NOT NULL,
            protocol TEXT,
            enabled INTEGER DEFAULT 1,
            config TEXT DEFAULT '{}',
            group_name TEXT DEFAULT '',
            added TEXT NOT NULL
        )
    """)
    # No device seeding. Devices are registered at runtime via BLE scan or the
    # Settings -> Device Manager UI (POST /api/devices, /api/devices/discover),
    # so a fresh install starts empty instead of with someone else's hardware.
    conn.commit()
    conn.close()


def load_devices() -> dict:
    """Load all enabled devices from the registry, grouped by type."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM devices WHERE enabled = 1").fetchall()
    conn.close()
    result = {"jbd_bms": [], "ecoflow": [], "victron": []}
    for r in rows:
        d = dict(r)
        d["config"] = json.loads(d.get("config", "{}"))
        dtype = d["device_type"]
        if dtype not in result:
            result[dtype] = []
        result[dtype].append(d)
    return result


def ecoflow_to_battery(data: dict, label: str = "EcoFlow_Delta2", addr: str = "") -> dict:
    """Convert EcoFlow reader data to the standard battery dict format with all fields."""
    voltage = data.get("bms_voltage", 0)
    current = data.get("bms_current", 0)
    soc = data.get("ems_soc", data.get("pd_soc", 0))

    # Sum capacity across all packs (main + extras)
    remain_cap = data.get("bms_remain_cap", 0)
    full_cap = data.get("bms_full_cap", 0)
    for i in [1, 2]:
        remain_cap += data.get(f"bms{i}_remain_cap", 0)
        full_cap += data.get(f"bms{i}_full_cap", 0)
    remain_ah = remain_cap / 1000.0 if remain_cap > 0 else 0
    full_ah = full_cap / 1000.0 if full_cap > 0 else 0

    # Build extra battery pack info if present
    packs = []
    for i in [0, 1, 2]:
        prefix = "bms" if i == 0 else f"bms{i}"
        if f"{prefix}_soc" in data:
            packs.append({
                "num": i,
                "label": "Main" if i == 0 else f"Extra {i}",
                "soc": data.get(f"{prefix}_soc", 0),
                "voltage": data.get(f"{prefix}_voltage", 0),
                "current": data.get(f"{prefix}_current", 0),
                "temp": data.get(f"{prefix}_temp", 0),
                "cycles": data.get(f"{prefix}_cycles", 0),
                "soh": data.get(f"{prefix}_soh", 0),
                "remain_cap": data.get(f"{prefix}_remain_cap", 0),
                "full_cap": data.get(f"{prefix}_full_cap", 0),
                "max_cell_v": data.get(f"{prefix}_max_cell_v", 0),
                "min_cell_v": data.get(f"{prefix}_min_cell_v", 0),
                "cell_delta": data.get(f"{prefix}_cell_delta", 0),
                "max_cell_temp": data.get(f"{prefix}_max_cell_temp", 0),
                "max_mos_temp": data.get(f"{prefix}_max_mos_temp", 0),
                "err_code": data.get(f"{prefix}_err", 0),
                "input_w": data.get(f"{prefix}_input_w", 0),
                "output_w": data.get(f"{prefix}_output_w", 0),
            })

    return {
        "label": label,
        "addr": addr,
        "online": True,
        "voltage": voltage,
        "current": current,
        "power": round(voltage * current, 1),
        "soc": soc,
        "remain": remain_ah,
        "nominal": full_ah,
        "temps": [data.get("bms_temp", 0)],
        "cells": [],
        "cell_delta": data.get("bms_cell_delta", 0),
        "cycles": data.get("bms_cycles", 0),
        "soh": data.get("bms_soh", 0),
        "chg_fet": data.get("ems_chg_state", 0) > 0,
        "dsg_fet": True,
        "protection": [],
        "source": "ble",
        "device_type": "ecoflow",
        # PD
        "pd_soc": data.get("pd_soc", 0),
        "pd_in_w": data.get("pd_in_w", 0),
        "pd_out_w": data.get("pd_out_w", 0),
        "pd_remain_min": data.get("pd_remain_min", 0),
        "pd_usb1_w": data.get("pd_usb1_w", 0),
        "pd_usb2_w": data.get("pd_usb2_w", 0),
        "pd_qc1_w": data.get("pd_qc1_w", 0),
        "pd_qc2_w": data.get("pd_qc2_w", 0),
        "pd_typec1_w": data.get("pd_typec1_w", 0),
        "pd_typec2_w": data.get("pd_typec2_w", 0),
        "pd_car_w": data.get("pd_car_w", 0),
        "pd_dc_out": data.get("pd_dc_out", 0),
        "pd_dc_chg_w": data.get("pd_dc_chg_w", 0),
        "pd_solar_chg_w": data.get("pd_solar_chg_w", 0),
        "pd_ac_chg_w": data.get("pd_ac_chg_w", 0),
        "pd_ac_dsg_w": data.get("pd_ac_dsg_w", 0),
        # EMS
        "ems_soc": data.get("ems_soc", 0),
        "ems_fan": data.get("ems_fan", 0),
        "ems_max_soc": data.get("ems_max_soc", 100),
        "ems_min_dsg_soc": data.get("ems_min_dsg_soc", 0),
        "ems_chg_state": data.get("ems_chg_state", 0),
        "ems_chg_remain_s": data.get("ems_chg_remain_s", 0),
        "ems_dsg_remain_s": data.get("ems_dsg_remain_s", 0),
        # INV
        "inv_in_w": data.get("inv_in_w", 0),
        "inv_out_w": data.get("inv_out_w", 0),
        "inv_out_v": data.get("inv_out_v", 0),
        "inv_ac_in_v": data.get("inv_ac_in_v", 0),
        "inv_ac_enabled": data.get("inv_ac_enabled", 0),
        # MPPT
        "mppt_in_w": data.get("mppt_in_w", 0),
        "mppt_in_v": data.get("mppt_in_v", 0),
        "mppt_out_w": data.get("mppt_out_w", 0),
        "mppt_temp": data.get("mppt_temp", 0),
        "mppt_car_w": data.get("mppt_car_w", 0),
        # Battery packs
        "packs": packs,
        "timestamp": datetime.now().isoformat(),
    }


def poller_loop():
    """Single poller thread with separate BMS and EcoFlow intervals.
    BMS batteries poll every 30s, EcoFlow every 2 min, never overlapping."""
    global ecoflow_latest, _last_poll_ts
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    poll_count = 0
    last_ecoflow = 0  # timestamp of last EcoFlow poll
    last_bms_full = 0  # timestamp of last full (config) BMS read
    last_victron = 0
    last_weather = 0
    last_sync = 0

    while True:
        poll_count += 1
        now = time.time()
        ts = datetime.now().strftime('%H:%M:%S')
        bms_results = []
        ef_results = []

        # Load current device list from registry
        devices = load_devices()

        # ── BMS batteries: live data every cycle; full config every BMS_CONFIG_INTERVAL ──
        do_full = (now - last_bms_full >= BMS_CONFIG_INTERVAL)
        for dev in devices.get("jbd_bms", []):
            addr, label = dev["address"], dev["label"]
            try:
                data = loop.run_until_complete(
                    asyncio.wait_for(read_battery(addr, label, full=do_full),
                                     timeout=BLE_READ_DEADLINE))
                data["group_name"] = dev.get("group_name", "")
                bms_results.append(data)
                status = f"{data['soc']}%" if data.get("online") else "offline"
                print(f"[{ts}] {label}: {status}{' [full]' if do_full else ''}")
            except Exception as e:
                print(f"[{ts}] {label}: error {e}")
                bms_results.append({"label": label, "addr": addr, "online": False,
                                    "timestamp": datetime.now().isoformat()})
        # Only mark the config as freshly read if a pack actually responded;
        # a full attempt that hit an all-offline blip retries next cycle.
        if do_full and any(r.get("online") for r in bms_results):
            last_bms_full = now

        # ── EcoFlow (every ECOFLOW_POLL_INTERVAL, offset after BMS) ──
        if now - last_ecoflow >= ECOFLOW_POLL_INTERVAL:
            for dev in devices.get("ecoflow", []):
                cfg = dev.get("config", {})
                addr = dev["address"]
                serial = cfg.get("serial", "")
                user_id = cfg.get("user_id", "")
                label = dev["label"]
                if not serial or not user_id:
                    continue
                try:
                    ef_data = loop.run_until_complete(read_ecoflow_device(addr, serial, user_id))
                    if ef_data:
                        ecoflow_latest = ef_data
                        ef_results.append(ecoflow_to_battery(ef_data, label, addr))
                        print(f"[{ts}] {label}: {ef_data.get('ems_soc', '?')}%")
                except Exception as e:
                    print(f"[{ts}] {label}: error {e}")
            last_ecoflow = now

        # Use cached EcoFlow data between polls
        if not ef_results and ecoflow_latest and ecoflow_latest.get("last_update"):
            age = now - ecoflow_latest["last_update"]
            if age < ECOFLOW_POLL_INTERVAL * 2:
                devices_ef = devices.get("ecoflow", [])
                for dev in devices_ef:
                    ef_results.append(ecoflow_to_battery(ecoflow_latest, dev["label"], dev["address"]))

        # Combine results
        results = bms_results + ef_results

        # Update shared state
        with data_lock:
            latest_data["batteries"] = results
            latest_data["updated"] = datetime.now().isoformat()
        # Liveness heartbeat for the BLE watchdog (set every cycle, online or not).
        _last_poll_ts = time.monotonic()

        # Log and alert
        for r in results:
            try:
                if r.get("device_type") == "ecoflow":
                    log_ecoflow_reading(r)
                elif r.get("online"):
                    log_reading(r)
                check_battery_alerts(r)
                if r.get("online"):
                    thresholds = get_thresholds()
                    soc = r.get("soc", 100)
                    temps = r.get("temps", [])
                    max_temp = max(temps) if temps else 0
                    if soc <= thresholds.get("low_soc", 15):
                        send_notification(f"LOW BATTERY: {r.get('label')}", f"SOC at {soc}% — critical level", "high")
                    if max_temp >= thresholds.get("high_temp", 45):
                        send_notification(f"HIGH TEMP: {r.get('label')}", f"Temperature {max_temp}C — danger", "high")
            except Exception:
                pass

        online = len([r for r in results if r.get("online")])
        print(f"[{ts}] Poll #{poll_count}: {online}/{len(results)} online")

        # Evaluate rules + tracking
        try: evaluate_loadshed_rules()
        except Exception: pass
        try: log_energy_usage()
        except Exception: pass
        try: check_generator()
        except Exception: pass
        for r in results:
            try:
                if r.get("online") and r.get("device_type") != "ecoflow" and r.get("balancing"):
                    track_balance_changes(r)
            except Exception: pass

        # ── Victron scan (every 60s) ──
        if now - last_victron >= 60:
            try:
                vdevices = loop.run_until_complete(victron_scanner.scan(duration=8))
                with data_lock:
                    # Some devices (e.g. the Blue Smart charger) interleave the
                    # decodable Instant Readout frame with non-readout records, so
                    # a single 8s window may catch only an undecodable frame. Keep
                    # the last good decode instead of clobbering it with a
                    # data-less sighting; refresh rssi/timestamp from the new one.
                    prev = latest_victron.get("devices", {})
                    for addr, dev in vdevices.items():
                        old = prev.get(addr)
                        if old and old.get("data") and not dev.get("data"):
                            old["rssi"] = dev.get("rssi", old.get("rssi"))
                            old["timestamp"] = dev.get("timestamp", old.get("timestamp"))
                            vdevices[addr] = old
                    latest_victron["devices"] = vdevices
                    latest_victron["updated"] = datetime.now().isoformat()
                for d in vdevices.values():
                    log_victron_reading(d)
                    check_victron_alerts(d)
            except Exception: pass
            last_victron = now

        # ── Energy snapshot ──
        try:
            solar_w = grid_w = battery_w = 0
            soc = None
            for d in latest_victron.get("devices", {}).values():
                dd = d.get("data", {})
                if dd.get("device_type") == "Solar Charger":
                    solar_w += dd.get("pv_power", 0) or 0
                elif dd.get("device_type") == "AC Charger":
                    grid_w += (dd.get("battery_voltage", 0) or 0) * (dd.get("battery_current", 0) or 0)
            # Cerbo-connected MPPTs (Modbus, not BLE) also feed PV.
            for c in latest_cerbo_solar.get("chargers", []):
                if c.get("online"):
                    solar_w += c.get("pv_power", 0) or 0
            for b in latest_data.get("batteries", []):
                if b.get("online"):
                    battery_w += b.get("power", 0) or 0
                    if soc is None: soc = b.get("soc")
            if battery_w > 0 and solar_w == 0 and grid_w == 0:
                grid_w = battery_w
            load_w = max(0, solar_w - battery_w) if solar_w > 0 else 0
            independence = log_energy_snapshot(solar_w, grid_w, battery_w, load_w, soc)
            with data_lock:
                latest_energy.update({"independence": round(independence, 1), "solar_w": solar_w,
                    "grid_w": grid_w, "battery_w": battery_w, "load_w": load_w})
        except Exception: pass

        # ── Remote sync (every 5 min) ──
        if now - last_sync >= 300:
            try: sync_remote_sites()
            except Exception: pass
            last_sync = now

        # ── Weather (every 5 min) ──
        if now - last_weather >= 300:
            try: fetch_weather()
            except Exception: pass
            last_weather = now

        time.sleep(BMS_POLL_INTERVAL)


# ── Auth System ────────────────────────────────────────────────────────────

def init_auth_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS auth (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)
    # Generate secret key if not exists
    row = conn.execute("SELECT value FROM auth WHERE key='secret_key'").fetchone()
    if not row:
        conn.execute("INSERT INTO auth (key, value) VALUES ('secret_key', ?)",
                     (secrets.token_hex(32),))
    # Default: auth disabled
    row = conn.execute("SELECT value FROM auth WHERE key='auth_enabled'").fetchone()
    if not row:
        conn.execute("INSERT INTO auth (key, value) VALUES ('auth_enabled', '0')")
    row = conn.execute("SELECT value FROM auth WHERE key='ssl_enabled'").fetchone()
    if not row:
        conn.execute("INSERT INTO auth (key, value) VALUES ('ssl_enabled', '0')")
    conn.commit()
    conn.close()


def get_auth_setting(key: str) -> str:
    conn = sqlite3.connect(str(DB_PATH))
    row = conn.execute("SELECT value FROM auth WHERE key=?", (key,)).fetchone()
    conn.close()
    return row[0] if row else ""


def set_auth_setting(key: str, value: str):
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("INSERT OR REPLACE INTO auth (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()


def set_password(password: str):
    """Hash and store a password. Never stores plaintext."""
    pw_hash = generate_password_hash(password, method='pbkdf2:sha256:600000')
    set_auth_setting('password_hash', pw_hash)
    set_auth_setting('auth_enabled', '1')


def verify_password(password: str) -> bool:
    pw_hash = get_auth_setting('password_hash')
    if not pw_hash:
        return False
    return check_password_hash(pw_hash, password)


def auth_required(f):
    """Decorator — blocks unauthenticated requests when auth is enabled."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if get_auth_setting('auth_enabled') != '1':
            return f(*args, **kwargs)
        if session.get('authenticated'):
            return f(*args, **kwargs)
        if flask_request.is_json:
            return jsonify({"error": "Authentication required"}), 401
        return redirect('/login')
    return decorated


def generate_ssl_cert(cert_path: str, key_path: str):
    """Generate a self-signed SSL certificate (valid 10 years)."""
    import subprocess
    subprocess.run([
        'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
        '-keyout', key_path, '-out', cert_path,
        '-days', '3650', '-nodes',
        '-subj', '/CN=shadowgrid/O=ShadowGrid/C=US'
    ], capture_output=True)


# ── Flask App ──────────────────────────────────────────────────────────────

app = Flask(__name__, static_folder=str(STATIC_DIR))
CORS(app, supports_credentials=True)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)


@app.before_request
def check_auth():
    """Global auth gate — protects all routes except login and static."""
    if get_auth_setting('auth_enabled') != '1':
        return  # Auth disabled, allow everything
    # Exempt paths
    path = flask_request.path
    if path in ('/login', '/logout', '/api/auth/status') or path.startswith('/static'):
        return
    if not session.get('authenticated'):
        if flask_request.is_json or path.startswith('/api/'):
            return jsonify({"error": "Authentication required"}), 401
        return redirect('/login')


@app.route("/login", methods=["GET", "POST"])
def login():
    if flask_request.method == "GET":
        if get_auth_setting('auth_enabled') != '1':
            return redirect('/')
        return send_from_directory(str(STATIC_DIR), "login.html")

    # POST — verify password
    data = _json_body() if flask_request.is_json else {}
    password = data.get("password") or flask_request.form.get("password", "")

    if verify_password(password):
        session['authenticated'] = True
        session.permanent = True
        return jsonify({"status": "ok"}) if flask_request.is_json else redirect('/')
    else:
        if flask_request.is_json:
            return jsonify({"error": "Invalid password"}), 401
        return redirect('/login?error=1')


@app.route("/logout")
def logout():
    session.clear()
    return redirect('/login')


@app.route("/")
def index():
    resp = send_from_directory(str(STATIC_DIR), "index.html")
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    resp.headers['Pragma'] = 'no-cache'
    return resp


@app.route("/api/auth/status")
def api_auth_status():
    """Public endpoint — tells the frontend if auth is enabled."""
    return jsonify({
        "auth_enabled": get_auth_setting('auth_enabled') == '1',
        "authenticated": bool(session.get('authenticated')),
        "ssl_enabled": get_auth_setting('ssl_enabled') == '1',
    })


@app.route("/api/auth/password", methods=["POST"])
def api_auth_set_password():
    """Change password or enable/disable auth."""
    data = _json_body()
    action = data.get("action")

    if action == "set":
        current = data.get("current", "")
        new_pw = data.get("new", "")
        if not new_pw or len(new_pw) < 6:
            return jsonify({"error": "Password must be at least 6 characters"}), 400
        # If auth is already enabled, verify current password
        if get_auth_setting('auth_enabled') == '1':
            if not verify_password(current):
                return jsonify({"error": "Current password incorrect"}), 401
        set_password(new_pw)
        return jsonify({"status": "ok", "message": "Password set"})

    elif action == "disable":
        current = data.get("current", "")
        if get_auth_setting('auth_enabled') == '1' and not verify_password(current):
            return jsonify({"error": "Password required to disable auth"}), 401
        set_auth_setting('auth_enabled', '0')
        return jsonify({"status": "ok", "message": "Auth disabled"})

    elif action == "enable_ssl":
        cert_path = str(Path(__file__).parent / "cert.pem")
        key_path = str(Path(__file__).parent / "key.pem")
        if not os.path.exists(cert_path):
            generate_ssl_cert(cert_path, key_path)
        set_auth_setting('ssl_enabled', '1')
        return jsonify({"status": "ok", "message": "SSL enabled — restart server to apply"})

    elif action == "disable_ssl":
        set_auth_setting('ssl_enabled', '0')
        return jsonify({"status": "ok", "message": "SSL disabled — restart server to apply"})

    return jsonify({"error": "Unknown action"}), 400


@app.route("/api/live")
def api_live():
    with data_lock:
        return jsonify(latest_data)


@app.route("/api/history")
def api_history():
    hours = _arg_int("hours", 24)
    label = flask_request.args.get("label", None)
    since = (datetime.now() - timedelta(hours=hours)).isoformat()

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row

    if label:
        rows = conn.execute(
            "SELECT * FROM readings WHERE timestamp > ? AND label = ? ORDER BY timestamp",
            (since, label),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM readings WHERE timestamp > ? ORDER BY timestamp",
            (since,),
        ).fetchall()
    conn.close()

    return jsonify([dict(r) for r in rows])


@app.route("/api/history/summary")
def api_history_summary():
    hours = _arg_int("hours", 24)
    since = (datetime.now() - timedelta(hours=hours)).isoformat()

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        """SELECT label,
                  COUNT(*) as readings,
                  MIN(voltage) as min_voltage, MAX(voltage) as max_voltage,
                  MIN(soc) as min_soc, MAX(soc) as max_soc,
                  MIN(current) as min_current, MAX(current) as max_current,
                  MIN(temp) as min_temp, MAX(temp) as max_temp,
                  MIN(timestamp) as first_reading, MAX(timestamp) as last_reading
           FROM readings WHERE timestamp > ?
           GROUP BY label""",
        (since,),
    ).fetchall()
    conn.close()

    return jsonify([dict(r) for r in rows])


# ── Victron API ────────────────────────────────────────────────────────────

@app.route("/api/victron/live")
def api_victron_live():
    with data_lock:
        return jsonify(latest_victron)


@app.route("/api/victron/history")
def api_victron_history():
    hours = _arg_int("hours", 24)
    since = (datetime.now() - timedelta(hours=hours)).isoformat()
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM victron_readings WHERE timestamp > ? ORDER BY timestamp",
        (since,),
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/cerbo/live")
def api_cerbo_live():
    with data_lock:
        return jsonify(latest_cerbo)


@app.route("/api/cerbo/history")
def api_cerbo_history():
    hours = _arg_int("hours", 24)
    since = (datetime.now() - timedelta(hours=hours)).isoformat()
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT timestamp, voltage, current, power, soc, temp FROM cerbo_readings WHERE timestamp > ? ORDER BY timestamp",
        (since,),
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/cerbo/solar")
def api_cerbo_solar():
    with data_lock:
        return jsonify(latest_cerbo_solar)


@app.route("/api/cerbo/solar/history")
def api_cerbo_solar_history():
    hours = _arg_int("hours", 24)
    unit = _arg_int("unit", 0)
    since = (datetime.now() - timedelta(hours=hours)).isoformat()
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    if unit:
        rows = conn.execute(
            "SELECT timestamp, unit, name, state, battery_voltage, battery_current, pv_voltage, pv_power, yield_today, yield_total FROM cerbo_solar_readings WHERE timestamp > ? AND unit = ? ORDER BY timestamp",
            (since, unit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT timestamp, unit, name, state, battery_voltage, battery_current, pv_voltage, pv_power, yield_today, yield_total FROM cerbo_solar_readings WHERE timestamp > ? ORDER BY timestamp",
            (since,),
        ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/power/live")
def api_power_live():
    with data_lock:
        return jsonify(latest_power)


@app.route("/api/power/mode", methods=["POST"])
def api_power_mode():
    data = flask_request.get_json(silent=True) or {}
    mode = data.get("mode", "")
    valid = set(zima_power.MODES) | {"auto"}
    if mode not in valid:
        return jsonify({"error": f"invalid mode; use one of {sorted(valid)}"}), 400
    write_power_mode(mode)
    if mode in zima_power.MODES:
        ok, err = zima_power.set_mode(mode)
        if not ok:
            return jsonify({"error": err}), 500
    gov = zima_power.get_governor()
    with data_lock:
        latest_power["mode"] = mode
        latest_power["governor"] = gov
    return jsonify({"status": "ok", "mode": mode, "governor": gov})


@app.route("/api/power/history")
def api_power_history():
    hours = _arg_int("hours", 24)
    since = (datetime.now() - timedelta(hours=hours)).isoformat()
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT timestamp, watts, governor, mode FROM power_readings WHERE timestamp > ? ORDER BY timestamp",
        (since,),
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/victron/keys", methods=["GET", "POST"])
def api_victron_keys():
    if flask_request.method == "POST":
        data = _json_body()
        mac = data.get("mac", "").upper()
        key = data.get("key", "")
        if mac and key and len(key) == 32:
            victron_key_store.set_key(mac, key)
            return jsonify({"status": "ok", "mac": mac})
        return jsonify({"error": "Invalid MAC or key (must be 32 hex chars)"}), 400
    return jsonify(victron_key_store.keys)


# ── Energy API ─────────────────────────────────────────────────────────────

@app.route("/api/energy/live")
def api_energy_live():
    with data_lock:
        return jsonify(latest_energy)


@app.route("/api/energy/independence")
def api_energy_independence():
    hours = _arg_int("hours", 24)
    stats = get_independence_stats(hours)
    return jsonify(stats)


@app.route("/api/energy/history")
def api_energy_history():
    hours = _arg_int("hours", 24)
    since = (datetime.now() - timedelta(hours=hours)).isoformat()
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM energy_log WHERE timestamp > ? ORDER BY timestamp",
        (since,),
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


# ── Meter API ──────────────────────────────────────────────────────────────

@app.route("/api/meter/live")
def api_meter_live():
    with data_lock:
        result = dict(latest_meter)
    # Also check if RTL-SDR is available
    result["rtlsdr_detected"] = detect_rtlsdr()
    if meter_reader:
        result["reading"] = meter_reader.get_latest()
        result["running"] = meter_reader.running
    return jsonify(result)


@app.route("/api/meter/power")
def api_meter_power():
    meter_id = flask_request.args.get("meter_id")
    power = get_power_estimate(meter_id)
    return jsonify(power or {"error": "Not enough readings"})


# ── Alerts API ─────────────────────────────────────────────────────────────

@app.route("/api/alerts")
def api_alerts():
    hours = _arg_int("hours", 24)
    severity = flask_request.args.get("severity")
    unack = flask_request.args.get("unacknowledged") == "true"
    return jsonify(get_alerts(hours, severity, unack))


@app.route("/api/alerts/counts")
def api_alert_counts():
    return jsonify(get_alert_counts())


@app.route("/api/alerts/acknowledge", methods=["POST"])
def api_alert_ack():
    data = _json_body()
    alert_id = data.get("id")
    if alert_id:
        acknowledge_alert(alert_id)
        return jsonify({"status": "ok"})
    return jsonify({"error": "Provide alert id"}), 400


# ── EcoFlow API ────────────────────────────────────────────────────────────

# ── Time Predictions ───────────────────────────────────────────────────────

@app.route("/api/predictions")
def api_predictions():
    """Calculate time-to-empty and time-to-full for all batteries."""
    predictions = []
    with data_lock:
        for b in latest_data.get("batteries", []):
            if not b.get("online"):
                continue
            pred = {"label": b["label"], "soc": b.get("soc", 0)}
            current = b.get("current", 0)
            remain = b.get("remain", 0)
            nominal = b.get("nominal", 0)
            voltage = b.get("voltage", 0)

            if b.get("device_type") == "ecoflow":
                # EcoFlow provides its own estimate
                pred["pd_remain_min"] = b.get("pd_remain_min", 0)
                pred["source"] = "ecoflow"
                power_in = b.get("pd_in_w", 0)
                power_out = b.get("pd_out_w", 0)
                pred["power_in"] = power_in
                pred["power_out"] = power_out
                if power_out > 0 and remain > 0:
                    hours = (remain * voltage) / power_out
                    pred["hours_to_empty"] = round(hours, 1)
                if power_in > 0 and nominal > remain:
                    hours = ((nominal - remain) * voltage) / power_in
                    pred["hours_to_full"] = round(hours, 1)
            else:
                pred["source"] = "calculated"
                if current < -0.1 and remain > 0:
                    hours = remain / abs(current)
                    pred["hours_to_empty"] = round(hours, 1)
                elif current > 0.1 and nominal > 0 and remain < nominal:
                    hours = (nominal - remain) / current
                    pred["hours_to_full"] = round(hours, 1)

            predictions.append(pred)
    return jsonify(predictions)


# ── Data Export ────────────────────────────────────────────────────────────

@app.route("/api/export/readings")
def api_export_readings():
    """Export battery readings as CSV."""
    hours = _arg_int("hours", 24)
    label = flask_request.args.get("label", "")
    since = (datetime.now() - timedelta(hours=hours)).isoformat()

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    if label:
        rows = conn.execute("SELECT * FROM readings WHERE timestamp > ? AND label = ? ORDER BY timestamp",
                            (since, label)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM readings WHERE timestamp > ? ORDER BY timestamp",
                            (since,)).fetchall()
    conn.close()

    lines = ["timestamp,label,voltage,current,soc,remain,power,temp,cell1,cell2,cell3,cell4,cell_delta"]
    for r in rows:
        lines.append(f"{r['timestamp']},{r['label']},{r['voltage']},{r['current']},{r['soc']},"
                     f"{r['remain']},{r['power']},{r['temp']},{r['cell1']},{r['cell2']},"
                     f"{r['cell3']},{r['cell4']},{r['cell_delta']}")

    resp = app.make_response("\n".join(lines))
    resp.headers["Content-Type"] = "text/csv"
    resp.headers["Content-Disposition"] = f"attachment; filename=shadowgrid_readings_{datetime.now().strftime('%Y%m%d')}.csv"
    return resp


@app.route("/api/export/ecoflow")
def api_export_ecoflow():
    """Export EcoFlow readings as CSV."""
    hours = _arg_int("hours", 24)
    since = (datetime.now() - timedelta(hours=hours)).isoformat()

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM ecoflow_readings WHERE timestamp > ? ORDER BY timestamp",
                        (since,)).fetchall()
    conn.close()

    lines = ["timestamp,soc,voltage,current,power,temp,cycles,soh,pd_in_w,pd_out_w,pd_ac_chg_w,pd_solar_chg_w,inv_out_w,mppt_in_w"]
    for r in rows:
        lines.append(",".join(str(r[k] or "") for k in
                     ["timestamp","soc","voltage","current","power","temp","cycles","soh",
                      "pd_in_w","pd_out_w","pd_ac_chg_w","pd_solar_chg_w","inv_out_w","mppt_in_w"]))

    resp = app.make_response("\n".join(lines))
    resp.headers["Content-Type"] = "text/csv"
    resp.headers["Content-Disposition"] = f"attachment; filename=shadowgrid_ecoflow_{datetime.now().strftime('%Y%m%d')}.csv"
    return resp


# ── Capacity Fade Tracking ─────────────────────────────────────────────────

@app.route("/api/capacity/fade")
def api_capacity_fade():
    """Track battery capacity degradation over time."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row

    # Get daily max SOC readings grouped by label to estimate usable capacity trend
    rows = conn.execute("""
        SELECT date(timestamp) as day, label,
               MAX(soc) as max_soc, MIN(soc) as min_soc,
               AVG(voltage) as avg_voltage, COUNT(*) as readings
        FROM readings
        GROUP BY day, label
        ORDER BY day
    """).fetchall()

    # EcoFlow capacity fade
    ef_rows = conn.execute("""
        SELECT date(timestamp) as day,
               AVG(soc) as avg_soc, AVG(voltage) as avg_voltage,
               COUNT(*) as readings
        FROM ecoflow_readings
        GROUP BY day
        ORDER BY day
    """).fetchall()

    conn.close()

    return jsonify({
        "bms": [dict(r) for r in rows],
        "ecoflow": [dict(r) for r in ef_rows],
    })


# ── Alert Thresholds Configuration ─────────────────────────────────────────

DEFAULT_ALERT_THRESHOLDS = {
    "low_soc": 15,
    "warn_soc": 25,
    "high_temp": 45,
    "warn_temp": 40,
    "high_cell_delta": 50,
    "warn_cell_delta": 30,
    "low_voltage_per_cell": 2.8,
    "high_voltage_per_cell": 3.65,
}


def init_thresholds_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""CREATE TABLE IF NOT EXISTS alert_thresholds (
        key TEXT PRIMARY KEY,
        value REAL NOT NULL
    )""")
    # Seed defaults
    for k, v in DEFAULT_ALERT_THRESHOLDS.items():
        conn.execute("INSERT OR IGNORE INTO alert_thresholds (key, value) VALUES (?, ?)", (k, v))
    conn.commit()
    conn.close()


def get_thresholds() -> dict:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM alert_thresholds").fetchall()
    conn.close()
    result = dict(DEFAULT_ALERT_THRESHOLDS)
    for r in rows:
        result[r["key"]] = r["value"]
    return result


@app.route("/api/alerts/thresholds", methods=["GET"])
def api_get_thresholds():
    return jsonify(get_thresholds())


@app.route("/api/alerts/thresholds", methods=["POST"])
def api_set_thresholds():
    data = _json_body()
    conn = sqlite3.connect(str(DB_PATH))
    for k, v in data.items():
        if k in DEFAULT_ALERT_THRESHOLDS:
            conn.execute("INSERT OR REPLACE INTO alert_thresholds (key, value) VALUES (?, ?)",
                         (k, float(v)))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "thresholds": get_thresholds()})


# ── Push Notifications ─────────────────────────────────────────────────────

def init_notifications_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""CREATE TABLE IF NOT EXISTS notification_config (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )""")
    conn.commit()
    conn.close()


def get_notification_config() -> dict:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM notification_config").fetchall()
    conn.close()
    return {r["key"]: r["value"] for r in rows}


def send_notification(title: str, message: str, priority: str = "normal"):
    """Send a push notification via configured provider."""
    config = get_notification_config()
    provider = config.get("provider", "")

    if provider == "ntfy":
        topic = config.get("ntfy_topic", "")
        server = config.get("ntfy_server", "https://ntfy.sh")
        if topic:
            try:
                import requests
                requests.post(f"{server}/{topic}",
                    headers={"Title": title, "Priority": priority},
                    data=message, timeout=5)
            except Exception:
                pass

    elif provider == "webhook":
        url = config.get("webhook_url", "")
        if url:
            try:
                import requests
                requests.post(url, json={"title": title, "message": message,
                    "priority": priority, "timestamp": datetime.now().isoformat()}, timeout=5)
            except Exception:
                pass

    elif provider == "pushover":
        token = config.get("pushover_token", "")
        user = config.get("pushover_user", "")
        if token and user:
            try:
                import requests
                requests.post("https://api.pushover.net/1/messages.json",
                    data={"token": token, "user": user, "title": title,
                          "message": message, "priority": "1" if priority == "high" else "0"},
                    timeout=5)
            except Exception:
                pass


@app.route("/api/notifications/config", methods=["GET"])
def api_notifications_get():
    return jsonify(get_notification_config())


@app.route("/api/notifications/config", methods=["POST"])
def api_notifications_set():
    data = _json_body()
    conn = sqlite3.connect(str(DB_PATH))
    for k, v in data.items():
        conn.execute("INSERT OR REPLACE INTO notification_config (key, value) VALUES (?, ?)", (k, str(v)))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})


@app.route("/api/notifications/test", methods=["POST"])
def api_notifications_test():
    send_notification("ShadowGrid Test", "Notifications are working!", "normal")
    return jsonify({"status": "ok", "message": "Test notification sent"})


# ── Self-Health Monitoring ─────────────────────────────────────────────────

@app.route("/api/health")
def api_self_health():
    """Self-diagnostic: is ShadowGrid itself healthy?"""
    issues = []
    now = datetime.now()

    # Check last update age
    with data_lock:
        updated = latest_data.get("updated")
    if updated:
        age = (now - datetime.fromisoformat(updated)).total_seconds()
        if age > 120:
            issues.append(f"Poller stale: last update {int(age)}s ago (expected <60s)")
    else:
        issues.append("Poller never ran")

    # Check database size
    db_size = DB_PATH.stat().st_size / (1024*1024) if DB_PATH.exists() else 0
    if db_size > 500:
        issues.append(f"Database large: {db_size:.0f} MB")

    # Check BLE adapter
    import subprocess
    try:
        result = subprocess.run(["hciconfig", "hci0"], capture_output=True, text=True, timeout=5)
        if "UP RUNNING" not in result.stdout:
            issues.append("BLE adapter not running")
    except Exception:
        issues.append("Cannot check BLE adapter")

    # Check disk space
    import shutil
    usage = shutil.disk_usage(str(DB_PATH.parent))
    free_pct = usage.free / usage.total * 100
    if free_pct < 5:
        issues.append(f"Low disk space: {free_pct:.1f}% free")

    return jsonify({
        "status": "healthy" if not issues else "degraded",
        "issues": issues,
        "db_size_mb": round(db_size, 1),
        "disk_free_pct": round(free_pct, 1),
        "uptime_s": int((now - datetime.fromisoformat(latest_data.get("updated", now.isoformat()))).total_seconds()) if latest_data.get("updated") else 0,
    })


# ── Load Shedding Rules ────────────────────────────────────────────────────

def init_loadshed_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""CREATE TABLE IF NOT EXISTS loadshed_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        condition_field TEXT NOT NULL,
        condition_op TEXT NOT NULL,
        condition_value REAL NOT NULL,
        action_type TEXT NOT NULL,
        action_target TEXT NOT NULL,
        action_value TEXT NOT NULL,
        enabled INTEGER DEFAULT 1,
        last_triggered TEXT,
        cooldown_min INTEGER DEFAULT 5
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS loadshed_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        rule_name TEXT,
        condition TEXT,
        action TEXT,
        result TEXT
    )""")
    conn.commit()
    conn.close()


def evaluate_loadshed_rules():
    """Check all load shedding rules against current data. Called each poll cycle."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rules = conn.execute("SELECT * FROM loadshed_rules WHERE enabled = 1").fetchall()
    conn.close()

    if not rules:
        return

    with data_lock:
        batts = latest_data.get("batteries", [])
    if not batts:
        return

    now = datetime.now()
    online = [b for b in batts if b.get("online")]

    for _r in rules:
        rule = dict(_r)
        # Check cooldown
        if rule["last_triggered"]:
            last = datetime.fromisoformat(rule["last_triggered"])
            if (now - last).total_seconds() < rule["cooldown_min"] * 60:
                continue

        # Evaluate condition
        field = rule["condition_field"]  # e.g. "avg_soc", "min_soc", "max_temp", "ecoflow_soc"
        op = rule["condition_op"]        # "<", ">", "<=", ">="
        threshold = rule["condition_value"]

        # Calculate the condition value
        actual = None
        if field == "avg_soc" and online:
            actual = sum(b.get("soc", 0) for b in online) / len(online)
        elif field == "min_soc" and online:
            actual = min(b.get("soc", 100) for b in online)
        elif field == "max_temp" and online:
            temps = [t for b in online for t in (b.get("temps") or [0])]
            actual = max(temps) if temps else None
        elif field == "ecoflow_soc":
            ef = next((b for b in batts if b.get("device_type") == "ecoflow" and b.get("online")), None)
            if ef:
                actual = ef.get("soc", 100)
        elif field == "ecoflow_out_w":
            ef = next((b for b in batts if b.get("device_type") == "ecoflow" and b.get("online")), None)
            if ef:
                actual = ef.get("pd_out_w", 0)

        if actual is None:
            continue

        triggered = False
        if op == "<" and actual < threshold: triggered = True
        elif op == ">" and actual > threshold: triggered = True
        elif op == "<=" and actual <= threshold: triggered = True
        elif op == ">=" and actual >= threshold: triggered = True

        if not triggered:
            continue

        # Execute action
        action_type = rule["action_type"]   # "ecoflow_cmd", "notification", "log_only"
        action_target = rule["action_target"]  # e.g. "ac", "usb", "dc12v"
        action_value = rule["action_value"]    # e.g. "0" (off), "1" (on)
        result = "ok"

        if action_type == "ecoflow_cmd":
            # Find EcoFlow device config and send command
            devices = load_devices()
            ef_devs = devices.get("ecoflow", [])
            if ef_devs:
                cfg = ef_devs[0].get("config", {})
                loop = asyncio.new_event_loop()
                try:
                    ef = EcoFlowBLE(ef_devs[0]["address"], cfg.get("serial", ""), cfg.get("user_id", ""))
                    async def do_cmd():
                        await ef.connect()
                        await ef.authenticate()
                        if action_target == "ac": await ef.set_ac_output(bool(int(action_value)))
                        elif action_target == "usb": await ef.set_usb_ports(bool(int(action_value)))
                        elif action_target == "dc12v": await ef.set_dc_12v_port(bool(int(action_value)))
                        await asyncio.sleep(1)
                        await ef.disconnect()
                    loop.run_until_complete(do_cmd())
                    result = f"Sent {action_target}={action_value}"
                except Exception as e:
                    result = f"Failed: {e}"
                finally:
                    loop.close()

        elif action_type == "notification":
            send_notification(
                f"Load Shed: {rule['name']}",
                f"{field} is {actual:.1f} (threshold: {op}{threshold}). Action: {action_target}",
                "high"
            )
            result = "Notification sent"

        # Log and update cooldown
        conn = sqlite3.connect(str(DB_PATH))
        conn.execute("UPDATE loadshed_rules SET last_triggered = ? WHERE id = ?",
                     (now.isoformat(), rule["id"]))
        conn.execute("INSERT INTO loadshed_log (timestamp, rule_name, condition, action, result) VALUES (?,?,?,?,?)",
                     (now.isoformat(), rule["name"], f"{field} {op} {threshold} (actual: {actual:.1f})",
                      f"{action_type}: {action_target}={action_value}", result))
        conn.commit()
        conn.close()

        print(f"[{now.strftime('%H:%M:%S')}] LOADSHED: {rule['name']} — {result}")
        send_notification(f"Load Shed: {rule['name']}", f"{result}", "high")


@app.route("/api/loadshed/rules", methods=["GET"])
def api_loadshed_rules():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM loadshed_rules ORDER BY id").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/loadshed/rules", methods=["POST"])
def api_loadshed_add_rule():
    data = _json_body()
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""INSERT INTO loadshed_rules
        (name, condition_field, condition_op, condition_value, action_type, action_target, action_value, cooldown_min)
        VALUES (?,?,?,?,?,?,?,?)""",
        (data.get("name", ""), data.get("condition_field", ""),
         data.get("condition_op", "<"), _num(data.get("condition_value", 0), 0, float),
         data.get("action_type", "log_only"), data.get("action_target", ""),
         data.get("action_value", ""), _num(data.get("cooldown_min", 5), 5, int)))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})


@app.route("/api/loadshed/rules/<int:rule_id>", methods=["DELETE"])
def api_loadshed_delete_rule(rule_id):
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("DELETE FROM loadshed_rules WHERE id=?", (rule_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})


@app.route("/api/loadshed/rules/<int:rule_id>", methods=["PATCH"])
def api_loadshed_toggle_rule(rule_id):
    data = _json_body()
    conn = sqlite3.connect(str(DB_PATH))
    if "enabled" in data:
        conn.execute("UPDATE loadshed_rules SET enabled=? WHERE id=?", (int(data["enabled"]), rule_id))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})


@app.route("/api/loadshed/log")
def api_loadshed_log():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM loadshed_log ORDER BY timestamp DESC LIMIT 50").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


# ── Multi-Site Sync ────────────────────────────────────────────────────────

def init_sites_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""CREATE TABLE IF NOT EXISTS remote_sites (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        url TEXT UNIQUE NOT NULL,
        enabled INTEGER DEFAULT 1,
        last_sync TEXT,
        last_status TEXT
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS remote_readings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        site_name TEXT NOT NULL,
        label TEXT NOT NULL,
        voltage REAL,
        current REAL,
        soc INTEGER,
        power REAL,
        temp REAL,
        device_type TEXT
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_remote_ts ON remote_readings(timestamp)")
    conn.commit()
    conn.close()


def sync_remote_sites():
    """Pull live data from all remote ShadowGrid instances."""
    import requests
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    sites = conn.execute("SELECT * FROM remote_sites WHERE enabled=1").fetchall()
    conn.close()

    now = datetime.now()
    for site in sites:
        url = site["url"].rstrip("/")
        name = site["name"]
        try:
            r = requests.get(f"{url}/api/live", timeout=10)
            data = r.json()
            batteries = data.get("batteries", [])

            conn = sqlite3.connect(str(DB_PATH))
            for b in batteries:
                if b.get("online"):
                    conn.execute("""INSERT INTO remote_readings
                        (timestamp, site_name, label, voltage, current, soc, power, temp, device_type)
                        VALUES (?,?,?,?,?,?,?,?,?)""",
                        (now.isoformat(), name, b.get("label", ""),
                         b.get("voltage"), b.get("current"), b.get("soc"),
                         b.get("power"), (b.get("temps") or [None])[0],
                         b.get("device_type", "")))
            conn.execute("UPDATE remote_sites SET last_sync=?, last_status=? WHERE id=?",
                         (now.isoformat(), f"{len(batteries)} batteries", site["id"]))
            conn.commit()
            conn.close()
        except Exception as e:
            conn = sqlite3.connect(str(DB_PATH))
            conn.execute("UPDATE remote_sites SET last_sync=?, last_status=? WHERE id=?",
                         (now.isoformat(), f"Error: {str(e)[:50]}", site["id"]))
            conn.commit()
            conn.close()


@app.route("/api/sites", methods=["GET"])
def api_sites():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM remote_sites ORDER BY name").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/sites", methods=["POST"])
def api_sites_add():
    data = _json_body()
    name = data.get("name", "").strip()
    url = data.get("url", "").strip().rstrip("/")
    if not name or not url:
        return jsonify({"error": "Name and URL required"}), 400
    conn = sqlite3.connect(str(DB_PATH))
    try:
        conn.execute("INSERT INTO remote_sites (name, url) VALUES (?,?)", (name, url))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "Site URL already exists"}), 409
    conn.close()
    return jsonify({"status": "ok"})


@app.route("/api/sites/<int:site_id>", methods=["DELETE"])
def api_sites_delete(site_id):
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("DELETE FROM remote_sites WHERE id=?", (site_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})


@app.route("/api/sites/sync", methods=["POST"])
def api_sites_sync():
    sync_remote_sites()
    return jsonify({"status": "ok"})


@app.route("/api/sites/readings")
def api_sites_readings():
    hours = _arg_int("hours", 24)
    since = (datetime.now() - timedelta(hours=hours)).isoformat()
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM remote_readings WHERE timestamp > ? ORDER BY timestamp DESC LIMIT 500",
                        (since,)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


# ── Weather Correlation ────────────────────────────────────────────────────

def init_weather_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""CREATE TABLE IF NOT EXISTS weather_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        temp_c REAL,
        humidity REAL,
        cloud_pct REAL,
        wind_kph REAL,
        condition TEXT,
        solar_w REAL
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS weather_config (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_weather_ts ON weather_log(timestamp)")
    conn.commit()
    conn.close()


def fetch_weather():
    """Fetch current weather and correlate with solar output."""
    import requests
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    config_rows = conn.execute("SELECT * FROM weather_config").fetchall()
    conn.close()
    config = {r["key"]: r["value"] for r in config_rows}

    api_key = config.get("api_key", "")
    location = config.get("location", "")
    if not api_key or not location:
        return None

    try:
        # OpenWeatherMap free API
        r = requests.get(f"https://api.openweathermap.org/data/2.5/weather",
                         params={"q": location, "appid": api_key, "units": "metric"}, timeout=10)
        w = r.json()
        if w.get("cod") != 200:
            return None

        weather = {
            "temp_c": w.get("main", {}).get("temp"),
            "humidity": w.get("main", {}).get("humidity"),
            "cloud_pct": w.get("clouds", {}).get("all", 0),
            "wind_kph": (w.get("wind", {}).get("speed", 0) or 0) * 3.6,
            "condition": w.get("weather", [{}])[0].get("main", ""),
        }

        # Get current solar power from Victron/EcoFlow
        solar_w = 0
        with data_lock:
            for b in latest_data.get("batteries", []):
                if b.get("device_type") == "ecoflow" and b.get("online"):
                    solar_w += b.get("pd_solar_chg_w", 0) or 0
            for d in latest_victron.get("devices", {}).values():
                if d.get("device_type") == "Solar Charger":
                    solar_w += d.get("data", {}).get("pv_power", 0) or 0
        weather["solar_w"] = solar_w

        # Log
        conn = sqlite3.connect(str(DB_PATH))
        conn.execute("""INSERT INTO weather_log
            (timestamp, temp_c, humidity, cloud_pct, wind_kph, condition, solar_w)
            VALUES (?,?,?,?,?,?,?)""",
            (datetime.now().isoformat(), weather["temp_c"], weather["humidity"],
             weather["cloud_pct"], weather["wind_kph"], weather["condition"], solar_w))
        conn.commit()
        conn.close()

        return weather
    except Exception:
        return None


@app.route("/api/weather/current")
def api_weather_current():
    w = fetch_weather()
    if w:
        return jsonify(w)
    return jsonify({"error": "Weather not configured or unavailable. Add API key in Settings."}), 404


@app.route("/api/weather/history")
def api_weather_history():
    hours = _arg_int("hours", 168)
    since = (datetime.now() - timedelta(hours=hours)).isoformat()
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM weather_log WHERE timestamp > ? ORDER BY timestamp", (since,)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/weather/config", methods=["GET"])
def api_weather_config_get():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM weather_config").fetchall()
    conn.close()
    return jsonify({r["key"]: r["value"] for r in rows})


@app.route("/api/weather/config", methods=["POST"])
def api_weather_config_set():
    data = _json_body()
    conn = sqlite3.connect(str(DB_PATH))
    for k, v in data.items():
        conn.execute("INSERT OR REPLACE INTO weather_config (key, value) VALUES (?,?)", (k, str(v)))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})


# ── Charge Controller (Modbus/Serial) ──────────────────────────────────────

def init_chargecontroller_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""CREATE TABLE IF NOT EXISTS chargecontroller_readings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        controller_name TEXT NOT NULL,
        pv_voltage REAL,
        pv_current REAL,
        pv_power REAL,
        battery_voltage REAL,
        battery_current REAL,
        battery_soc INTEGER,
        load_voltage REAL,
        load_current REAL,
        load_power REAL,
        controller_temp REAL,
        battery_temp REAL,
        charge_state TEXT
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cc_ts ON chargecontroller_readings(timestamp)")
    conn.commit()
    conn.close()


def read_epever_controller(port: str, name: str) -> dict:
    """Read data from an Epever/Tracer charge controller via Modbus RTU."""
    try:
        import serial
        ser = serial.Serial(port, 115200, timeout=2)

        # Modbus RTU read holding registers
        # Epever Tracer registers:
        # 0x3100: PV voltage (V * 100)
        # 0x3101: PV current (A * 100)
        # 0x3102: PV power L (W * 100)
        # 0x3104: Battery voltage (V * 100)
        # 0x3105: Battery current (A * 100)
        # 0x3106: Battery power L (W * 100)
        # 0x310C: Load voltage
        # 0x310D: Load current
        # 0x310E: Load power
        # 0x3110: Battery temp
        # 0x3111: Controller temp
        # 0x3201: Charging status

        def modbus_read(addr, reg, count=1):
            """Build Modbus RTU read holding registers request."""
            import struct
            pkt = struct.pack('>BBH H', addr, 0x04, reg, count)
            # CRC16 Modbus
            crc = 0xFFFF
            for b in pkt:
                crc ^= b
                for _ in range(8):
                    crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
            pkt += struct.pack('<H', crc)
            ser.write(pkt)
            resp = ser.read(5 + count * 2)
            if len(resp) >= 5 + count * 2:
                values = []
                for i in range(count):
                    values.append(struct.unpack('>H', resp[3 + i*2:5 + i*2])[0])
                return values[0] if count == 1 else values
            return None

        data = {"name": name, "port": port, "online": True}
        pv_v = modbus_read(1, 0x3100)
        if pv_v is not None: data["pv_voltage"] = pv_v / 100.0
        pv_i = modbus_read(1, 0x3101)
        if pv_i is not None: data["pv_current"] = pv_i / 100.0
        pv_p = modbus_read(1, 0x3102)
        if pv_p is not None: data["pv_power"] = pv_p / 100.0
        bv = modbus_read(1, 0x3104)
        if bv is not None: data["battery_voltage"] = bv / 100.0
        bi = modbus_read(1, 0x3105)
        if bi is not None: data["battery_current"] = bi / 100.0
        lv = modbus_read(1, 0x310C)
        if lv is not None: data["load_voltage"] = lv / 100.0
        li = modbus_read(1, 0x310D)
        if li is not None: data["load_current"] = li / 100.0
        lp = modbus_read(1, 0x310E)
        if lp is not None: data["load_power"] = lp / 100.0
        ct = modbus_read(1, 0x3111)
        if ct is not None: data["controller_temp"] = ct / 100.0
        bt = modbus_read(1, 0x3110)
        if bt is not None: data["battery_temp"] = bt / 100.0

        ser.close()
        return data
    except Exception as e:
        return {"name": name, "port": port, "online": False, "error": str(e)}


@app.route("/api/chargecontroller/read", methods=["POST"])
def api_cc_read():
    """Read a charge controller via Modbus serial."""
    data = _json_body()
    port = data.get("port", "")
    name = data.get("name", "Controller")
    if not port:
        return jsonify({"error": "Serial port required"}), 400
    result = read_epever_controller(port, name)
    return jsonify(result)


@app.route("/api/chargecontroller/ports")
def api_cc_ports():
    """List available serial ports that could be charge controllers."""
    import glob
    ports = sorted(glob.glob("/dev/ttyUSB*") + glob.glob("/dev/ttyACM*") + glob.glob("/dev/ttyS*"))
    return jsonify(ports)


# ── Parasitic Drain Detection ──────────────────────────────────────────────

@app.route("/api/parasitic")
def api_parasitic():
    """Detect parasitic drain — current draw when all loads should be off."""
    results = []
    with data_lock:
        for b in latest_data.get("batteries", []):
            if not b.get("online"):
                continue
            current = b.get("current", 0)
            power = b.get("power", 0)
            # Parasitic drain: small negative current (discharging) when idle
            # Typically < -0.1A is suspicious if no loads are intentionally on
            is_parasitic = -2.0 < current < -0.05
            results.append({
                "label": b.get("label"),
                "current": current,
                "power": round(abs(power), 1),
                "drain_watts": round(abs(power), 1) if is_parasitic else 0,
                "suspicious": is_parasitic,
                "message": f"Drawing {abs(current):.2f}A ({abs(power):.1f}W) with no active loads" if is_parasitic else "Normal",
            })
    return jsonify(results)


@app.route("/api/parasitic/history")
def api_parasitic_history():
    """Look at overnight drain patterns from historical data."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    # Get readings between midnight and 5 AM for the last 7 days
    rows = conn.execute("""
        SELECT date(timestamp) as day, label,
               AVG(current) as avg_current, MIN(current) as min_current,
               AVG(power) as avg_power, COUNT(*) as readings
        FROM readings
        WHERE time(timestamp) BETWEEN '00:00:00' AND '05:00:00'
          AND timestamp > datetime('now', '-7 days')
        GROUP BY day, label
        ORDER BY day DESC
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


# ── Solar Yield Prediction ─────────────────────────────────────────────────

@app.route("/api/solar/predict")
def api_solar_predict():
    """Predict tomorrow's solar yield based on weather forecast + historical data."""
    import requests as req

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row

    # Get weather config
    wx_rows = conn.execute("SELECT * FROM weather_config").fetchall()
    wx_config = {r["key"]: r["value"] for r in wx_rows}

    # Get historical solar data by cloud coverage
    hist = conn.execute("""
        SELECT cloud_pct, AVG(solar_w) as avg_solar, COUNT(*) as samples
        FROM weather_log
        WHERE solar_w > 0
        GROUP BY CAST(cloud_pct/10 AS INT) * 10
        ORDER BY cloud_pct
    """).fetchall()
    conn.close()

    solar_by_clouds = {int(r["cloud_pct"]): r["avg_solar"] for r in hist}

    # Get forecast
    forecast = None
    api_key = wx_config.get("api_key", "")
    location = wx_config.get("location", "")
    if api_key and location:
        try:
            r = req.get("https://api.openweathermap.org/data/2.5/forecast",
                        params={"q": location, "appid": api_key, "units": "metric", "cnt": 8},
                        timeout=10)
            fc = r.json()
            if fc.get("list"):
                forecast = []
                for item in fc["list"]:
                    clouds = item.get("clouds", {}).get("all", 50)
                    # Estimate solar from historical data at this cloud level
                    nearest = min(solar_by_clouds.keys(), key=lambda x: abs(x - clouds)) if solar_by_clouds else 0
                    est_solar = solar_by_clouds.get(nearest, 0)
                    forecast.append({
                        "time": item.get("dt_txt", ""),
                        "clouds": clouds,
                        "temp": item.get("main", {}).get("temp"),
                        "condition": item.get("weather", [{}])[0].get("main", ""),
                        "est_solar_w": round(est_solar, 0),
                    })
        except Exception:
            pass

    # Calculate daily prediction
    total_kwh = 0
    if forecast:
        # Each forecast slot is 3 hours, solar only during daylight (~6am-6pm = 4 slots)
        daylight_slots = [f for f in forecast if "09:" in f["time"] or "12:" in f["time"] or "15:" in f["time"] or "18:" in f["time"]]
        total_kwh = sum(f["est_solar_w"] for f in daylight_slots) * 3 / 1000  # W * 3h / 1000

    # How many hours of runtime at current draw
    hours_of_runtime = 0
    with data_lock:
        total_draw = sum(abs(b.get("power", 0)) for b in latest_data.get("batteries", []) if b.get("online") and b.get("current", 0) < 0)
    if total_draw > 0 and total_kwh > 0:
        hours_of_runtime = total_kwh * 1000 / total_draw

    return jsonify({
        "predicted_kwh": round(total_kwh, 2),
        "forecast": forecast,
        "hours_of_runtime": round(hours_of_runtime, 1) if hours_of_runtime else None,
        "historical_samples": len(solar_by_clouds),
        "message": f"Predicted solar yield: {total_kwh:.2f} kWh" + (f" ({hours_of_runtime:.0f}h of runtime)" if hours_of_runtime else ""),
    })


# ── Energy Budget ──────────────────────────────────────────────────────────

def init_budget_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""CREATE TABLE IF NOT EXISTS energy_budget (
        key TEXT PRIMARY KEY,
        value REAL NOT NULL
    )""")
    conn.execute("INSERT OR IGNORE INTO energy_budget (key, value) VALUES ('daily_kwh', 3.0)")
    conn.execute("""CREATE TABLE IF NOT EXISTS energy_usage_daily (
        date TEXT PRIMARY KEY,
        kwh_used REAL DEFAULT 0,
        kwh_generated REAL DEFAULT 0
    )""")
    conn.commit()
    conn.close()


def log_energy_usage():
    """Track daily energy consumption. Called each poll cycle."""
    today = datetime.now().strftime("%Y-%m-%d")
    with data_lock:
        batts = latest_data.get("batteries", [])
    discharge_w = sum(abs(b.get("power", 0)) for b in batts if b.get("online") and b.get("current", 0) < -0.1)
    charge_w = sum(b.get("power", 0) for b in batts if b.get("online") and b.get("current", 0) > 0.1)

    # Convert to kWh for this interval (POLL_INTERVAL seconds)
    kwh_used = discharge_w * BMS_POLL_INTERVAL / 3600 / 1000
    kwh_gen = charge_w * BMS_POLL_INTERVAL / 3600 / 1000

    if kwh_used > 0 or kwh_gen > 0:
        conn = sqlite3.connect(str(DB_PATH))
        conn.execute("""INSERT INTO energy_usage_daily (date, kwh_used, kwh_generated)
            VALUES (?, ?, ?)
            ON CONFLICT(date) DO UPDATE SET
                kwh_used = kwh_used + excluded.kwh_used,
                kwh_generated = kwh_generated + excluded.kwh_generated""",
            (today, kwh_used, kwh_gen))
        conn.commit()
        conn.close()


@app.route("/api/budget")
def api_budget():
    today = datetime.now().strftime("%Y-%m-%d")
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    budget_row = conn.execute("SELECT value FROM energy_budget WHERE key='daily_kwh'").fetchone()
    usage_row = conn.execute("SELECT * FROM energy_usage_daily WHERE date=?", (today,)).fetchone()
    # Last 7 days
    week = conn.execute("SELECT * FROM energy_usage_daily ORDER BY date DESC LIMIT 7").fetchall()
    conn.close()

    budget = budget_row[0] if budget_row else 3.0
    used = usage_row["kwh_used"] if usage_row else 0
    generated = usage_row["kwh_generated"] if usage_row else 0
    pct = (used / budget * 100) if budget > 0 else 0

    return jsonify({
        "daily_budget_kwh": budget,
        "used_today_kwh": round(used, 3),
        "generated_today_kwh": round(generated, 3),
        "percent_used": round(pct, 1),
        "remaining_kwh": round(max(0, budget - used), 3),
        "history": [dict(r) for r in week],
    })


@app.route("/api/budget/set", methods=["POST"])
def api_budget_set():
    data = _json_body()
    budget = _num(data.get("daily_kwh", 3.0), 3.0, float)
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("INSERT OR REPLACE INTO energy_budget (key, value) VALUES ('daily_kwh', ?)", (budget,))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "daily_kwh": budget})


# ── Battery Comparison ─────────────────────────────────────────────────────

@app.route("/api/compare")
def api_compare():
    """Side-by-side comparison data for two batteries over time."""
    label1 = flask_request.args.get("b1", "")
    label2 = flask_request.args.get("b2", "")
    hours = _arg_int("hours", 24)
    since = (datetime.now() - timedelta(hours=hours)).isoformat()

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row

    def get_data(label):
        rows = conn.execute(
            "SELECT timestamp, voltage, current, soc, power, temp, cell_delta FROM readings WHERE label=? AND timestamp>? ORDER BY timestamp",
            (label, since)).fetchall()
        return [dict(r) for r in rows]

    data1 = get_data(label1) if label1 else []
    data2 = get_data(label2) if label2 else []

    # Summary stats
    def summarize(data):
        if not data:
            return {}
        socs = [d["soc"] for d in data if d["soc"] is not None]
        volts = [d["voltage"] for d in data if d["voltage"] is not None]
        temps = [d["temp"] for d in data if d["temp"] is not None]
        deltas = [d["cell_delta"] for d in data if d["cell_delta"] is not None]
        return {
            "readings": len(data),
            "soc_range": [min(socs), max(socs)] if socs else [],
            "voltage_range": [round(min(volts), 2), round(max(volts), 2)] if volts else [],
            "avg_temp": round(sum(temps) / len(temps), 1) if temps else None,
            "avg_delta": round(sum(deltas) / len(deltas), 1) if deltas else None,
        }

    conn.close()
    return jsonify({
        "b1": {"label": label1, "data": data1, "summary": summarize(data1)},
        "b2": {"label": label2, "data": data2, "summary": summarize(data2)},
    })


# ── Anomaly Detection ──────────────────────────────────────────────────────

@app.route("/api/anomalies")
def api_anomalies():
    """Detect unusual battery behavior patterns."""
    anomalies = []
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row

    # 1. Persistent cell imbalance (one cell consistently lower for 3+ days)
    cell_data = conn.execute("""
        SELECT label, AVG(cell1) as c1, AVG(cell2) as c2, AVG(cell3) as c3, AVG(cell4) as c4,
               AVG(cell_delta) as avg_delta, COUNT(*) as readings
        FROM readings
        WHERE timestamp > datetime('now', '-3 days')
          AND cell1 > 0 AND cell2 > 0 AND cell3 > 0 AND cell4 > 0
        GROUP BY label
    """).fetchall()

    for row in cell_data:
        if row["avg_delta"] and row["avg_delta"] > 20:
            cells = [row["c1"], row["c2"], row["c3"], row["c4"]]
            lowest = min(cells)
            lowest_idx = cells.index(lowest) + 1
            anomalies.append({
                "type": "cell_imbalance",
                "severity": "warning" if row["avg_delta"] < 40 else "critical",
                "label": row["label"],
                "message": f"Cell {lowest_idx} has been {row['avg_delta']:.0f}mV lower than others for 3+ days",
                "detail": f"Avg cell voltages: {', '.join(f'C{i+1}={c:.3f}V' for i,c in enumerate(cells))}",
            })

    # 2. Unexpected overnight SOC drop (>5% with no load detected)
    overnight = conn.execute("""
        SELECT r.label,
               MAX(CASE WHEN time(r.timestamp) BETWEEN '22:00' AND '23:59' THEN r.soc END) as soc_night,
               MIN(CASE WHEN time(r.timestamp) BETWEEN '05:00' AND '07:00' THEN r.soc END) as soc_morning,
               AVG(CASE WHEN time(r.timestamp) BETWEEN '00:00' AND '05:00' THEN r.current END) as avg_night_current,
               COALESCE(d.group_name, '') as group_name
        FROM readings r
        LEFT JOIN devices d ON r.label = d.label
        WHERE r.timestamp > datetime('now', '-2 days')
        GROUP BY r.label, date(r.timestamp)
    """).fetchall()

    for row in overnight:
        if row["soc_night"] and row["soc_morning"]:
            drop = row["soc_night"] - row["soc_morning"]
            if drop > 5 and (row["avg_night_current"] is None or abs(row["avg_night_current"]) < 1):
                anomalies.append({
                    "type": "overnight_drain",
                    "severity": "warning",
                    "label": row["label"],
                    "message": f"SOC dropped {drop}% overnight with minimal load",
                    "detail": f"Night: {row['soc_night']}% → Morning: {row['soc_morning']}%, avg current: {row['avg_night_current']:.2f}A" if row["avg_night_current"] else "",
                })

    # 3. SOH degradation (cycles increasing, capacity decreasing)
    # Check if any battery has SOH < 90%
    with data_lock:
        for b in latest_data.get("batteries", []):
            if b.get("online") and b.get("soh") and b["soh"] < 90:
                anomalies.append({
                    "type": "soh_degradation",
                    "severity": "warning" if b["soh"] >= 80 else "critical",
                    "label": b.get("label"),
                    "message": f"State of Health at {b['soh']}% — battery degradation detected",
                    "detail": f"Cycles: {b.get('cycles', '?')}, consider replacement below 80%",
                })

    # 4. Temperature anomaly — compare within same installation group only
    # Different installations (truck vs 5th wheel) have different ambient temps
    # Only flag if one device in the SAME group runs significantly hotter
    temp_data = conn.execute("""
        SELECT r.label, AVG(r.temp) as avg_temp, MAX(r.temp) as max_temp, COUNT(*) as readings,
               d.device_type, COALESCE(d.group_name, '') as group_name
        FROM readings r
        LEFT JOIN devices d ON r.label = d.label
        WHERE r.timestamp > datetime('now', '-1 day') AND r.temp > 0
        GROUP BY r.label
    """).fetchall()

    # Group by installation group_name, compare within each group
    install_groups = {}
    for row in temp_data:
        gname = row["group_name"] or "_ungrouped"
        if gname not in install_groups:
            install_groups[gname] = []
        install_groups[gname].append(row)

    for gname, group in install_groups.items():
        if len(group) < 2:
            continue  # Need 2+ devices in same installation to compare
        avg_group = sum(r["avg_temp"] for r in group) / len(group)
        for row in group:
            if row["avg_temp"] > avg_group + 5:
                group_label = gname if gname != "_ungrouped" else "installation"
                anomalies.append({
                    "type": "temp_anomaly",
                    "severity": "warning",
                    "label": row["label"],
                    "message": f"Running {row['avg_temp'] - avg_group:.1f}C hotter than other devices in {group_label}",
                    "detail": f"Avg: {row['avg_temp']:.1f}C vs group avg: {avg_group:.1f}C",
                })

    conn.close()
    return jsonify(anomalies)


# ── Maintenance Schedule ───────────────────────────────────────────────────

def init_maintenance_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""CREATE TABLE IF NOT EXISTS maintenance_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        device_label TEXT NOT NULL,
        task TEXT NOT NULL,
        notes TEXT,
        next_due TEXT
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS maintenance_schedule (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_label TEXT NOT NULL,
        task TEXT NOT NULL,
        interval_days INTEGER NOT NULL,
        last_done TEXT,
        next_due TEXT
    )""")
    conn.commit()
    conn.close()


@app.route("/api/maintenance", methods=["GET"])
def api_maintenance():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    schedule = conn.execute("SELECT * FROM maintenance_schedule ORDER BY next_due").fetchall()
    log = conn.execute("SELECT * FROM maintenance_log ORDER BY timestamp DESC LIMIT 50").fetchall()
    conn.close()

    now = datetime.now()
    items = []
    for s in schedule:
        d = dict(s)
        if d["next_due"]:
            due = datetime.fromisoformat(d["next_due"])
            d["overdue"] = now > due
            d["days_until"] = (due - now).days
        else:
            d["overdue"] = True
            d["days_until"] = -999
        items.append(d)

    return jsonify({"schedule": items, "log": [dict(r) for r in log]})


@app.route("/api/maintenance/schedule", methods=["POST"])
def api_maintenance_add():
    data = _json_body()
    device = data.get("device_label", "")
    task = data.get("task", "")
    interval = _num(data.get("interval_days", 90), 90, int)
    if not device or not task:
        return jsonify({"error": "Device and task required"}), 400

    next_due = (datetime.now() + timedelta(days=interval)).isoformat()
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("INSERT INTO maintenance_schedule (device_label, task, interval_days, next_due) VALUES (?,?,?,?)",
                 (device, task, interval, next_due))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})


@app.route("/api/maintenance/complete", methods=["POST"])
def api_maintenance_complete():
    data = _json_body()
    schedule_id = data.get("id")
    notes = data.get("notes", "")

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    sched = conn.execute("SELECT * FROM maintenance_schedule WHERE id=?", (schedule_id,)).fetchone()
    if not sched:
        conn.close()
        return jsonify({"error": "Schedule not found"}), 404

    now = datetime.now()
    next_due = (now + timedelta(days=sched["interval_days"])).isoformat()

    conn.execute("UPDATE maintenance_schedule SET last_done=?, next_due=? WHERE id=?",
                 (now.isoformat(), next_due, schedule_id))
    conn.execute("INSERT INTO maintenance_log (timestamp, device_label, task, notes, next_due) VALUES (?,?,?,?,?)",
                 (now.isoformat(), sched["device_label"], sched["task"], notes, next_due))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "next_due": next_due})


@app.route("/api/maintenance/schedule/<int:sched_id>", methods=["DELETE"])
def api_maintenance_delete(sched_id):
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("DELETE FROM maintenance_schedule WHERE id=?", (sched_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})


# ── Generator Auto-Start (GPIO) ───────────────────────────────────────────

def init_generator_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""CREATE TABLE IF NOT EXISTS generator_config (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )""")
    conn.execute("INSERT OR IGNORE INTO generator_config (key, value) VALUES ('enabled', '0')")
    conn.execute("INSERT OR IGNORE INTO generator_config (key, value) VALUES ('start_soc', '20')")
    conn.execute("INSERT OR IGNORE INTO generator_config (key, value) VALUES ('stop_soc', '80')")
    conn.execute("INSERT OR IGNORE INTO generator_config (key, value) VALUES ('gpio_pin', '17')")
    conn.execute("""CREATE TABLE IF NOT EXISTS generator_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        action TEXT NOT NULL,
        soc INTEGER,
        reason TEXT
    )""")
    conn.commit()
    conn.close()


def check_generator():
    """Check if generator should start/stop based on SOC thresholds."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    config_rows = conn.execute("SELECT * FROM generator_config").fetchall()
    conn.close()
    config = {r["key"]: r["value"] for r in config_rows}

    if config.get("enabled") != "1":
        return

    start_soc = int(config.get("start_soc", 20))
    stop_soc = int(config.get("stop_soc", 80))
    gpio_pin = int(config.get("gpio_pin", 17))

    # Get average SOC
    with data_lock:
        online = [b for b in latest_data.get("batteries", []) if b.get("online")]
    if not online:
        return

    avg_soc = sum(b.get("soc", 100) for b in online) / len(online)

    # Check current state
    generator_running = config.get("running") == "1"

    if avg_soc <= start_soc and not generator_running:
        # Start generator
        try:
            # Try GPIO (Raspberry Pi)
            with open(f"/sys/class/gpio/gpio{gpio_pin}/value", "w") as f:
                f.write("1")
        except Exception:
            pass
        conn = sqlite3.connect(str(DB_PATH))
        conn.execute("INSERT OR REPLACE INTO generator_config (key, value) VALUES ('running', '1')")
        conn.execute("INSERT INTO generator_log (timestamp, action, soc, reason) VALUES (?,?,?,?)",
                     (datetime.now().isoformat(), "START", int(avg_soc), f"SOC {avg_soc:.0f}% <= {start_soc}%"))
        conn.commit()
        conn.close()
        send_notification("Generator START", f"SOC at {avg_soc:.0f}% — generator started", "high")

    elif avg_soc >= stop_soc and generator_running:
        # Stop generator
        try:
            with open(f"/sys/class/gpio/gpio{gpio_pin}/value", "w") as f:
                f.write("0")
        except Exception:
            pass
        conn = sqlite3.connect(str(DB_PATH))
        conn.execute("INSERT OR REPLACE INTO generator_config (key, value) VALUES ('running', '0')")
        conn.execute("INSERT INTO generator_log (timestamp, action, soc, reason) VALUES (?,?,?,?)",
                     (datetime.now().isoformat(), "STOP", int(avg_soc), f"SOC {avg_soc:.0f}% >= {stop_soc}%"))
        conn.commit()
        conn.close()
        send_notification("Generator STOP", f"SOC at {avg_soc:.0f}% — generator stopped", "normal")


@app.route("/api/generator/config", methods=["GET"])
def api_generator_config():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM generator_config").fetchall()
    conn.close()
    return jsonify({r["key"]: r["value"] for r in rows})


@app.route("/api/generator/config", methods=["POST"])
def api_generator_config_set():
    data = _json_body()
    conn = sqlite3.connect(str(DB_PATH))
    for k, v in data.items():
        conn.execute("INSERT OR REPLACE INTO generator_config (key, value) VALUES (?,?)", (k, str(v)))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})


@app.route("/api/generator/log")
def api_generator_log():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM generator_log ORDER BY timestamp DESC LIMIT 50").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


# ── Installation Management API ────────────────────────────────────────────

@app.route("/api/installations", methods=["GET"])
def api_installations():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    installs = conn.execute("SELECT * FROM installations ORDER BY name").fetchall()
    result = []
    for inst in installs:
        d = dict(inst)
        # Count devices in this installation
        devs = conn.execute("SELECT COUNT(*) as cnt FROM devices WHERE group_name=?", (d["name"],)).fetchone()
        d["device_count"] = devs["cnt"] if devs else 0
        # Get live status summary
        online = 0
        total_soc = 0
        count = 0
        with data_lock:
            for b in latest_data.get("batteries", []):
                if b.get("group_name") == d["name"] or (not b.get("group_name") and d["name"] == "_default"):
                    count += 1
                    if b.get("online"):
                        online += 1
                        total_soc += b.get("soc", 0)
        d["online"] = online
        d["total_devices"] = count
        d["avg_soc"] = round(total_soc / online, 0) if online else None
        result.append(d)
    conn.close()
    return jsonify(result)


@app.route("/api/installations", methods=["POST"])
def api_installations_add():
    data = _json_body()
    name = data.get("name", "").strip()
    if not name:
        return jsonify({"error": "Installation name required"}), 400
    conn = sqlite3.connect(str(DB_PATH))
    try:
        conn.execute("INSERT INTO installations (name, location, description, icon, created) VALUES (?,?,?,?,?)",
                     (name, data.get("location", ""), data.get("description", ""),
                      data.get("icon", "battery"), datetime.now().isoformat()))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "Installation name already exists"}), 409
    conn.close()
    return jsonify({"status": "ok"})


@app.route("/api/installations/<int:inst_id>", methods=["DELETE"])
def api_installations_delete(inst_id):
    conn = sqlite3.connect(str(DB_PATH))
    # Get name before deleting
    row = conn.execute("SELECT name FROM installations WHERE id=?", (inst_id,)).fetchone()
    if row:
        # Unassign devices from this installation
        conn.execute("UPDATE devices SET group_name='' WHERE group_name=?", (row[0],))
    conn.execute("DELETE FROM installations WHERE id=?", (inst_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})


@app.route("/api/installations/<int:inst_id>", methods=["PATCH"])
def api_installations_update(inst_id):
    data = _json_body()
    conn = sqlite3.connect(str(DB_PATH))
    old_name = conn.execute("SELECT name FROM installations WHERE id=?", (inst_id,)).fetchone()
    for field in ["name", "location", "description", "icon"]:
        if field in data:
            conn.execute(f"UPDATE installations SET {field}=? WHERE id=?", (data[field], inst_id))
    # If name changed, update all devices referencing the old name
    if "name" in data and old_name and old_name[0] != data["name"]:
        conn.execute("UPDATE devices SET group_name=? WHERE group_name=?", (data["name"], old_name[0]))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})


@app.route("/api/installations/assign", methods=["POST"])
def api_installations_assign():
    """Assign a device to an installation."""
    data = _json_body()
    address = data.get("address", "")
    installation = data.get("installation", "")
    if not address:
        return jsonify({"error": "Device address required"}), 400
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("UPDATE devices SET group_name=? WHERE address=?", (installation, address))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})


# ── Balance Tracking ───────────────────────────────────────────────────────

def init_balance_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""CREATE TABLE IF NOT EXISTS balance_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        label TEXT NOT NULL,
        cell_num INTEGER NOT NULL,
        event TEXT NOT NULL,
        cell_voltage REAL,
        cell_delta REAL
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_bal_ts ON balance_log(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_bal_label ON balance_log(label)")
    conn.execute("""CREATE TABLE IF NOT EXISTS balance_snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        label TEXT NOT NULL,
        cell_delta REAL,
        balancing_active INTEGER,
        balancing_cells TEXT,
        cell_voltages TEXT
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_balsnap_ts ON balance_snapshots(timestamp)")
    conn.commit()
    conn.close()


# Track previous balance state per battery to detect transitions
_prev_balance_state = {}


def track_balance_changes(battery_data: dict):
    """Compare current balance state to previous, log start/stop events."""
    label = battery_data.get("label", "")
    balancing = battery_data.get("balancing", [])
    cells = battery_data.get("cells", [])
    delta = battery_data.get("cell_delta", 0)

    if not label or not balancing:
        return

    prev = _prev_balance_state.get(label, [])
    now = datetime.now().isoformat()
    conn = sqlite3.connect(str(DB_PATH))

    # Detect per-cell transitions
    for i, is_bal in enumerate(balancing):
        was_bal = prev[i] if i < len(prev) else False
        cell_v = cells[i] if i < len(cells) else None

        if is_bal and not was_bal:
            conn.execute("INSERT INTO balance_log (timestamp, label, cell_num, event, cell_voltage, cell_delta) VALUES (?,?,?,?,?,?)",
                         (now, label, i + 1, "START", cell_v, delta))
        elif not is_bal and was_bal:
            conn.execute("INSERT INTO balance_log (timestamp, label, cell_num, event, cell_voltage, cell_delta) VALUES (?,?,?,?,?,?)",
                         (now, label, i + 1, "STOP", cell_v, delta))

    # Save snapshot for convergence tracking (every reading while balancing is active)
    if any(balancing):
        bal_cells = [i + 1 for i, b in enumerate(balancing) if b]
        conn.execute("INSERT INTO balance_snapshots (timestamp, label, cell_delta, balancing_active, balancing_cells, cell_voltages) VALUES (?,?,?,?,?,?)",
                     (now, label, delta, 1, json.dumps(bal_cells), json.dumps(cells)))

    conn.commit()
    conn.close()
    _prev_balance_state[label] = list(balancing)


@app.route("/api/balance/status")
def api_balance_status():
    """Current balance status for all batteries."""
    results = []
    with data_lock:
        for b in latest_data.get("batteries", []):
            if not b.get("online") or b.get("device_type") == "ecoflow":
                continue
            results.append({
                "label": b.get("label"),
                "balancing_active": b.get("balancing_active", False),
                "balancing_cells": b.get("balancing_cells", []),
                "cell_delta": b.get("cell_delta", 0),
                "cells": b.get("cells", []),
                "balance_status": b.get("balance_status", 0),
            })
    return jsonify(results)


@app.route("/api/balance/log")
def api_balance_log():
    """Balance event log — when cells started/stopped balancing."""
    label = flask_request.args.get("label", "")
    hours = _arg_int("hours", 168)
    since = (datetime.now() - timedelta(hours=hours)).isoformat()
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    if label:
        rows = conn.execute("SELECT * FROM balance_log WHERE label=? AND timestamp>? ORDER BY timestamp DESC LIMIT 200",
                            (label, since)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM balance_log WHERE timestamp>? ORDER BY timestamp DESC LIMIT 200",
                            (since,)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/balance/convergence")
def api_balance_convergence():
    """Cell delta convergence data over time — for charting balance effectiveness."""
    label = flask_request.args.get("label", "")
    hours = _arg_int("hours", 168)
    since = (datetime.now() - timedelta(hours=hours)).isoformat()
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    if label:
        rows = conn.execute("SELECT * FROM balance_snapshots WHERE label=? AND timestamp>? ORDER BY timestamp",
                            (label, since)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM balance_snapshots WHERE timestamp>? ORDER BY timestamp",
                            (since,)).fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["balancing_cells"] = json.loads(d.get("balancing_cells", "[]"))
        d["cell_voltages"] = json.loads(d.get("cell_voltages", "[]"))
        result.append(d)
    return jsonify(result)


@app.route("/api/balance/predict")
def api_balance_predict():
    """Predict when cells will be balanced based on current convergence rate."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row

    # Get recent delta history — use Python datetime to avoid SQLite timezone issues
    since = (datetime.now() - timedelta(hours=6)).isoformat()
    rows = conn.execute("""
        SELECT label, timestamp, cell_delta
        FROM readings
        WHERE cell_delta > 0 AND timestamp > ?
        ORDER BY timestamp
    """, (since,)).fetchall()
    conn.close()

    # Group by battery
    by_label = {}
    for r in rows:
        if r["label"] not in by_label:
            by_label[r["label"]] = []
        by_label[r["label"]].append({"ts": r["timestamp"], "delta": r["cell_delta"]})

    predictions = []
    for label, points in by_label.items():
        if len(points) < 20:
            predictions.append({"label": label, "message": "Not enough data yet", "points": []})
            continue

        # Linear regression over ALL data points for robust trend
        first_dt = datetime.fromisoformat(points[0]["ts"])
        xs = []  # hours since first reading
        ys = []  # delta values
        for p in points:
            dt = datetime.fromisoformat(p["ts"])
            xs.append((dt - first_dt).total_seconds() / 3600)
            ys.append(p["delta"])

        n = len(xs)
        sum_x = sum(xs)
        sum_y = sum(ys)
        sum_xy = sum(x * y for x, y in zip(xs, ys))
        sum_x2 = sum(x * x for x in xs)

        denom = n * sum_x2 - sum_x * sum_x
        if abs(denom) < 0.001:
            predictions.append({"label": label, "message": "Not enough variation", "points": []})
            continue

        slope = (n * sum_xy - sum_x * sum_y) / denom  # mV per hour
        intercept = (sum_y - slope * sum_x) / n
        rate_mv_per_hour = slope
        current_delta = points[-1]["delta"]
        total_hours = xs[-1]

        # Predict future from regression line
        future_points = []
        target_delta = 5  # mV — considered "balanced"
        now = datetime.now()
        now_x = total_hours  # current position on the regression line

        if rate_mv_per_hour >= -0.01:
            # Not improving
            hours_to_balance = None
            balance_date = None
            if rate_mv_per_hour > 0.1:
                message = f"Delta increasing at {rate_mv_per_hour:+.1f} mV/hr — balancing not effective"
            else:
                message = f"Delta stable at {current_delta:.0f}mV — balancing holding steady"
            # Project forward 48h max, clamped
            for h in range(0, 49, 1):
                projected = intercept + slope * (now_x + h)
                projected = max(0, min(projected, current_delta * 2))  # clamp
                future_points.append({
                    "timestamp": (now + timedelta(hours=h)).isoformat(),
                    "delta": round(projected, 1),
                })
        else:
            # Improving — calculate when regression line hits target
            # solve: intercept + slope * x = target_delta
            target_x = (target_delta - intercept) / slope if slope != 0 else now_x
            hours_to_balance = max(0, target_x - now_x)
            balance_date = (now + timedelta(hours=hours_to_balance)).isoformat()

            if hours_to_balance < 24:
                message = f"Estimated balanced in {hours_to_balance:.0f} hours ({rate_mv_per_hour:.1f} mV/hr)"
            else:
                message = f"Estimated balanced in {hours_to_balance/24:.1f} days ({rate_mv_per_hour:.1f} mV/hr)"

            # Generate prediction points — hourly until balanced + 12h buffer
            max_hours = min(int(hours_to_balance) + 12, 336)
            step = max(1, max_hours // 100)  # limit to ~100 points
            for h in range(0, max_hours, step):
                projected = intercept + slope * (now_x + h)
                projected = max(target_delta, projected)
                future_points.append({
                    "timestamp": (now + timedelta(hours=h)).isoformat(),
                    "delta": round(projected, 1),
                })

        predictions.append({
            "label": label,
            "current_delta": current_delta,
            "rate_mv_per_hour": round(rate_mv_per_hour, 2),
            "hours_to_balance": round(hours_to_balance, 1) if hours_to_balance else None,
            "balance_date": balance_date,
            "message": message,
            "points": future_points,
        })

    return jsonify(predictions)


@app.route("/api/balance/summary")
def api_balance_summary():
    """Summary: total balance time per cell, convergence rate, effectiveness."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row

    # Count events per cell per battery
    events = conn.execute("""
        SELECT label, cell_num, event, COUNT(*) as count,
               MIN(timestamp) as first_seen, MAX(timestamp) as last_seen
        FROM balance_log
        GROUP BY label, cell_num, event
        ORDER BY label, cell_num
    """).fetchall()

    # Get convergence trend — delta at start vs now
    trends = conn.execute("""
        SELECT label,
               (SELECT cell_delta FROM balance_snapshots s2 WHERE s2.label = s1.label ORDER BY timestamp ASC LIMIT 1) as first_delta,
               (SELECT cell_delta FROM balance_snapshots s3 WHERE s3.label = s1.label ORDER BY timestamp DESC LIMIT 1) as latest_delta,
               COUNT(*) as snapshots,
               MIN(timestamp) as first_snapshot,
               MAX(timestamp) as last_snapshot
        FROM balance_snapshots s1
        GROUP BY label
    """).fetchall()

    conn.close()
    return jsonify({
        "events": [dict(r) for r in events],
        "trends": [dict(r) for r in trends],
    })


# ── Device Management API ──────────────────────────────────────────────────

@app.route("/api/devices")
def api_devices():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM devices ORDER BY device_type, label").fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["config"] = json.loads(d.get("config", "{}"))
        # Add online status from latest poll data
        with data_lock:
            for b in latest_data.get("batteries", []):
                if b.get("addr") == d["address"]:
                    d["online"] = b.get("online", False)
                    d["soc"] = b.get("soc")
                    break
            else:
                d["online"] = False
                d["soc"] = None
        result.append(d)
    return jsonify(result)


@app.route("/api/devices", methods=["POST"])
def api_devices_add():
    data = _json_body()
    addr = data.get("address", "").strip().upper()
    label = data.get("label", "").strip()
    dtype = data.get("device_type", "jbd_bms")
    protocol = data.get("protocol", dtype)
    config = data.get("config", {})

    if not addr or not label:
        return jsonify({"error": "Address and label required"}), 400

    conn = sqlite3.connect(str(DB_PATH))
    try:
        conn.execute(
            "INSERT INTO devices (address, label, device_type, protocol, config, added) VALUES (?,?,?,?,?,?)",
            (addr, label, dtype, protocol, json.dumps(config), datetime.now().isoformat()))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "Device with this address already exists"}), 409
    conn.close()
    return jsonify({"status": "ok", "address": addr, "label": label})


@app.route("/api/devices/<address>", methods=["DELETE"])
def api_devices_delete(address):
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("DELETE FROM devices WHERE address = ?", (address,))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})


@app.route("/api/devices/<address>", methods=["PATCH"])
def api_devices_update(address):
    data = _json_body()
    conn = sqlite3.connect(str(DB_PATH))
    if "enabled" in data:
        conn.execute("UPDATE devices SET enabled = ? WHERE address = ?",
                     (int(data["enabled"]), address))
    if "label" in data:
        conn.execute("UPDATE devices SET label = ? WHERE address = ?",
                     (data["label"], address))
    if "group_name" in data:
        conn.execute("UPDATE devices SET group_name = ? WHERE address = ?",
                     (data["group_name"], address))
    if "config" in data:
        conn.execute("UPDATE devices SET config = ? WHERE address = ?",
                     (json.dumps(data["config"]), address))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})


@app.route("/api/devices/discover", methods=["POST"])
def api_devices_discover():
    """Run a quick BLE scan and return discovered BMS devices."""
    import asyncio as _asyncio
    loop = _asyncio.new_event_loop()
    try:
        devices = loop.run_until_complete(BleakScanner.discover(timeout=8, return_adv=True))
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        loop.close()

    found = []
    for addr, (dev, adv) in devices.items():
        name = adv.local_name or dev.name or ""
        sig = ble_scanner.identify_device(addr, name, adv)
        if sig:
            mfg = adv.manufacturer_data or {}
            extra = {}
            serial = ""
            if sig["id"] == "ecoflow" and 0xB5B5 in mfg:
                ef_info = ble_scanner.parse_ecoflow_adv(mfg)
                serial = ef_info.get("serial", "")
                extra = ef_info
            found.append({
                "address": addr, "name": name, "rssi": adv.rssi,
                "protocol": sig["id"], "protocol_name": sig["name"],
                "serial": serial, "extra": extra,
            })
    return jsonify(sorted(found, key=lambda x: x["rssi"], reverse=True))


@app.route("/api/ecoflow/history")
def api_ecoflow_history():
    hours = _arg_int("hours", 24)
    since = (datetime.now() - timedelta(hours=hours)).isoformat()
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM ecoflow_readings WHERE timestamp > ? ORDER BY timestamp",
        (since,),
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/scanner/history")
def api_scanner_history():
    """All unique devices ever seen by the scanner."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM scanner_devices ORDER BY last_seen DESC"
    ).fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["brands"] = json.loads(d.get("brands", "[]"))
        result.append(d)
    return jsonify(result)


@app.route("/api/scanner/log")
def api_scanner_log():
    """Raw scanner log entries."""
    hours = _arg_int("hours", 24)
    since = (datetime.now() - timedelta(hours=hours)).isoformat()
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM scanner_log WHERE timestamp > ? ORDER BY timestamp DESC LIMIT 500",
        (since,),
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/ecoflow")
def api_ecoflow():
    """Full EcoFlow data including all packs and subsystems."""
    with data_lock:
        for b in latest_data.get("batteries", []):
            if b.get("device_type") == "ecoflow":
                return jsonify(b)
    return jsonify({"online": False})


@app.route("/api/ecoflow/command", methods=["POST"])
def api_ecoflow_command():
    """Send a command to the EcoFlow Delta 2 (connect, auth, send, disconnect)."""
    data = _json_body()
    cmd = data.get("command")
    val = data.get("value")

    async def run_cmd():
        # Get EcoFlow config from device registry
        devices = load_devices()
        ef_devs = devices.get("ecoflow", [])
        if not ef_devs:
            return {"error": "No EcoFlow device registered"}
        cfg = ef_devs[0].get("config", {})
        ef = EcoFlowBLE(ef_devs[0]["address"], cfg.get("serial", ""), cfg.get("user_id", ""))
        try:
            await ef.connect()
            await ef.authenticate()
            if cmd == "usb": await ef.set_usb_ports(bool(val))
            elif cmd == "dc12v": await ef.set_dc_12v_port(bool(val))
            elif cmd == "ac": await ef.set_ac_output(bool(val))
            elif cmd == "max_charge_soc": await ef.set_max_charge_soc(int(val))
            elif cmd == "min_discharge_soc": await ef.set_min_discharge_soc(int(val))
            elif cmd == "ac_charge_speed": await ef.set_ac_charging_speed(int(val))
            elif cmd == "backup":
                await ef.set_energy_backup(bool(data.get("enabled", True)), _num(data.get("soc", 50), 50, int))
            elif cmd == "grid_bypass": await ef.set_grid_bypass(bool(val))
            else: return {"error": f"Unknown command: {cmd}"}
            await asyncio.sleep(1)
            return {"status": "ok", "command": cmd, "value": val}
        except Exception as e:
            return {"error": str(e)}
        finally:
            await ef.disconnect()

    loop = asyncio.new_event_loop()
    try:
        result = loop.run_until_complete(run_cmd())
        status_code = 400 if "error" in result else 200
        return jsonify(result), status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        loop.close()


# ── BMS Password API ──────────────────────────────────────────────────────

@app.route("/api/bms/password", methods=["GET"])
def api_bms_passwords():
    """Get current passwords for all BMS devices."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT d.address, d.label, COALESCE(p.password, 22136) as password
        FROM devices d LEFT JOIN bms_current_password p ON d.address = p.address
        WHERE d.device_type = 'jbd_bms' AND d.enabled = 1
    """).fetchall()
    conn.close()
    return jsonify([{"address": r["address"], "label": r["label"],
                     "password": f"0x{r['password']:04X}", "password_int": r["password"],
                     "is_default": r["password"] == 0x5678} for r in rows])


PASSWORD_CHANGE_COOLDOWN_DAYS = 7


@app.route("/api/bms/password/change", methods=["POST"])
def api_bms_password_change():
    """Change a BMS factory password.
    Security gates:
    1. Device must be in your registry (you own it)
    2. Must provide a live reading proof (current voltage) to verify you're monitoring it
    3. 7-day cooldown per device after each change
    """
    data = _json_body()
    addr = data.get("address", "")
    new_pw_str = data.get("new_password", "").strip()
    voltage_proof = data.get("voltage_proof")  # Must match live reading

    if not addr:
        return jsonify({"error": "Address required"}), 400
    if not new_pw_str:
        return jsonify({"error": "New password required"}), 400

    # ── Gate 1: Device must be registered (you own it) ──
    conn = sqlite3.connect(str(DB_PATH))
    row = conn.execute("SELECT label FROM devices WHERE address=?", (addr,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "Device not in your registry. Add it in Settings first to prove ownership."}), 403
    label = row[0]

    # ── Gate 2: Cooldown check (7 days between changes per device) ──
    last_change = conn.execute(
        "SELECT timestamp FROM bms_passwords WHERE address=? AND success=1 ORDER BY timestamp DESC LIMIT 1",
        (addr,)).fetchone()
    conn.close()

    if last_change:
        last_dt = datetime.fromisoformat(last_change[0])
        cooldown_end = last_dt + timedelta(days=PASSWORD_CHANGE_COOLDOWN_DAYS)
        if datetime.now() < cooldown_end:
            remaining = cooldown_end - datetime.now()
            days_left = remaining.days
            hours_left = remaining.seconds // 3600
            return jsonify({
                "error": f"Cooldown active — password was changed {PASSWORD_CHANGE_COOLDOWN_DAYS} days ago. "
                         f"Next change available in {days_left}d {hours_left}h.",
                "cooldown": True,
                "cooldown_ends": cooldown_end.isoformat(),
            }), 429

    # ── Gate 3: Live reading proof (must know current voltage) ──
    # Get the most recent live reading for this battery
    live_voltage = None
    with data_lock:
        for b in latest_data.get("batteries", []):
            if b.get("addr") == addr and b.get("online"):
                live_voltage = b.get("voltage")
                break

    if live_voltage is None:
        return jsonify({
            "error": "Cannot verify ownership — battery must be online and readable. "
                     "Wait for the next poll cycle and try again.",
            "needs_proof": True,
        }), 400

    if voltage_proof is None:
        return jsonify({
            "error": "Ownership verification required",
            "needs_proof": True,
            "message": "To change the password, enter the battery's current voltage "
                       "(displayed on the dashboard) to prove you are actively monitoring this device.",
        }), 400

    try:
        proof = float(voltage_proof)
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid voltage value"}), 400

    # Allow 0.5V tolerance
    if abs(proof - live_voltage) > 0.5:
        return jsonify({
            "error": "Voltage doesn't match — the value you entered doesn't match the battery's current reading. "
                     "Check the dashboard for the actual voltage.",
            "needs_proof": True,
        }), 403

    # ── All gates passed — proceed with password change ──
    # Parse password
    try:
        if new_pw_str.startswith("0x") or new_pw_str.startswith("0X"):
            new_pw = int(new_pw_str, 16)
        else:
            new_pw = int(new_pw_str)
    except ValueError:
        return jsonify({"error": "Invalid password format — use 0xNNNN hex or decimal"}), 400

    if new_pw < 0 or new_pw > 0xFFFF:
        return jsonify({"error": "Password must be 0x0000-0xFFFF (0-65535)"}), 400

    old_pw = get_bms_password(addr)

    # Run the change
    loop = asyncio.new_event_loop()
    try:
        result = loop.run_until_complete(change_bms_password(addr, label, old_pw, new_pw))
    finally:
        loop.close()

    # Log the attempt (always, regardless of success)
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute(
        "INSERT INTO bms_passwords (timestamp, address, label, old_password, new_password, success) VALUES (?,?,?,?,?,?)",
        (datetime.now().isoformat(), addr, label,
         f"0x{old_pw:04X}", f"0x{new_pw:04X}", int(result["success"])))
    conn.commit()
    conn.close()

    # Update current password on success
    if result["success"]:
        set_bms_password(addr, new_pw)

    return jsonify(result), 200 if result["success"] else 500


@app.route("/api/bms/password/history")
def api_bms_password_history():
    """Full history of every password change attempt."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    addr = flask_request.args.get("address")
    if addr:
        rows = conn.execute("SELECT * FROM bms_passwords WHERE address=? ORDER BY timestamp DESC", (addr,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM bms_passwords ORDER BY timestamp DESC LIMIT 100").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/bms/config/write", methods=["POST"])
def api_bms_config_write():
    """Write a config register to a JBD BMS — with safety validation."""
    data = _json_body()
    addr = data.get("address", "")
    register = data.get("register", 0)
    value = data.get("value", 0)
    force = data.get("force", False)

    if not addr:
        return jsonify({"error": "Address required"}), 400

    # Safety check
    check = validate_bms_setting(register, value)
    if check["blocked"]:
        return jsonify({
            "error": "BLOCKED — value is dangerously outside safe limits",
            "warning": check["warning"],
            "blocked": True,
        }), 400

    if not check["safe"] and not force:
        return jsonify({
            "error": "Safety warning — requires service key to override",
            "warning": check["warning"],
            "safe": False,
            "blocked": False,
            "requires_service_key": True,
            "installation_id": get_installation_id(),
        }), 400

    if not check["safe"] and force:
        # Verify service key
        service_key = data.get("service_key", "")
        install_id = get_installation_id()
        if not verify_service_key(install_id, service_key):
            return jsonify({
                "error": "Invalid service key — contact ShadowGrid support for a key",
                "installation_id": install_id,
                "hint": "Provide your installation ID to receive a service key",
            }), 403

    # Write the register
    async def do_write():
        pw = get_bms_password(addr)
        try:
            async with BleakClient(addr, timeout=10) as client:
                response = bytearray()
                event = asyncio.Event()
                def on_notify(sender, d):
                    response.extend(d)
                    if len(response) >= 4 and response[-1] == 0x77: event.set()
                await client.start_notify(JBD_RX, on_notify)
                await ble_send(client, response, event, make_factory_enter(pw))
                val_bytes = value.to_bytes(2, 'big')
                await ble_send(client, response, event, make_write_cmd(register, val_bytes))
                await client.write_gatt_char(JBD_TX, make_factory_exit())
                return {"success": True, "register": f"0x{register:02X}", "value": value,
                        "warning": check["warning"] if not check["safe"] else ""}
        except Exception as e:
            return {"success": False, "error": str(e)}

    loop = asyncio.new_event_loop()
    try:
        result = loop.run_until_complete(do_write())
        return jsonify(result), 200 if result["success"] else 500
    finally:
        loop.close()


@app.route("/api/bms/safety/check", methods=["POST"])
def api_bms_safety_check():
    """Check if a proposed BMS config change is safe."""
    data = _json_body()
    register = data.get("register", 0)
    value = data.get("value", 0)
    check = validate_bms_setting(register, value)
    check["limits"] = SAFETY_LIMITS.get({
        0x18: "cell_ovp", 0x19: "cell_ovp_rel", 0x1A: "cell_uvp", 0x1B: "cell_uvp_rel",
        0x1C: "pack_ovp", 0x1D: "pack_uvp", 0x28: "chg_oc", 0x29: "dsg_oc",
    }.get(register, ""), {})
    return jsonify(check)


@app.route("/api/service/info")
def api_service_info():
    """Show installation ID — user provides this to get a service key."""
    install_id = get_installation_id()
    return jsonify({
        "installation_id": install_id,
        "message": "Provide this Installation ID to ShadowGrid support to receive a service key for advanced operations.",
    })


@app.route("/api/service/verify", methods=["POST"])
def api_service_verify():
    """Verify a service key is valid."""
    data = _json_body()
    key = data.get("key", "")
    install_id = get_installation_id()
    valid = verify_service_key(install_id, key)
    if valid:
        # Store it in the auth table so they don't have to enter it every time
        set_auth_setting("service_key", key.upper())
        set_auth_setting("service_key_activated", datetime.now().isoformat())
    return jsonify({"valid": valid, "installation_id": install_id})


@app.route("/api/bms/password/export")
def api_bms_password_export():
    """Export all devices and passwords as downloadable file."""
    fmt = flask_request.args.get("format", "json")
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row

    # Current passwords
    devices = conn.execute("""
        SELECT d.address, d.label, d.device_type, d.protocol,
               COALESCE(p.password, 22136) as password,
               d.added
        FROM devices d LEFT JOIN bms_current_password p ON d.address = p.address
        ORDER BY d.device_type, d.label
    """).fetchall()

    # Full history
    history = conn.execute(
        "SELECT * FROM bms_passwords ORDER BY timestamp DESC"
    ).fetchall()
    conn.close()

    if fmt == "csv":
        lines = ["Address,Label,Type,Password (hex),Password (dec),Is Default,Added"]
        for d in devices:
            pw = d["password"]
            lines.append(f'{d["address"]},{d["label"]},{d["device_type"]},0x{pw:04X},{pw},{"YES" if pw==0x5678 else "NO"},{d["added"]}')
        lines.append("")
        lines.append("--- Password Change History ---")
        lines.append("Timestamp,Address,Label,Old Password,New Password,Success")
        for h in history:
            lines.append(f'{h["timestamp"]},{h["address"]},{h["label"]},{h["old_password"]},{h["new_password"]},{"YES" if h["success"] else "NO"}')
        resp = app.make_response("\n".join(lines))
        resp.headers["Content-Type"] = "text/csv"
        resp.headers["Content-Disposition"] = f"attachment; filename=shadowgrid_passwords_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        return resp

    elif fmt == "text":
        lines = [
            "=" * 60,
            "  SHADOWGRID — Battery Passwords",
            f"  Exported: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "=" * 60, "",
            "CURRENT PASSWORDS", "-" * 40,
        ]
        for d in devices:
            pw = d["password"]
            default = " (DEFAULT)" if pw == 0x5678 else ""
            lines.append(f"  {d['label']:<25s} 0x{pw:04X}  ({pw}){default}")
            lines.append(f"    Address: {d['address']}  Type: {d['device_type']}")
            lines.append("")
        lines.append("PASSWORD CHANGE HISTORY")
        lines.append("-" * 40)
        if not history:
            lines.append("  No changes recorded")
        for h in history:
            ok = "OK" if h["success"] else "FAIL"
            lines.append(f"  [{ok}] {h['timestamp']}  {h['label']}")
            lines.append(f"         {h['old_password']} -> {h['new_password']}")
        lines.append("")
        lines.append("=" * 60)
        resp = app.make_response("\n".join(lines))
        resp.headers["Content-Type"] = "text/plain"
        resp.headers["Content-Disposition"] = f"attachment; filename=shadowgrid_passwords_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        return resp

    else:
        return jsonify({
            "exported": datetime.now().isoformat(),
            "devices": [{"address": d["address"], "label": d["label"],
                         "device_type": d["device_type"],
                         "password_hex": f"0x{d['password']:04X}",
                         "password_int": d["password"],
                         "is_default": d["password"] == 0x5678,
                         "added": d["added"]} for d in devices],
            "history": [dict(h) for h in history],
        })


# ── Backup API ─────────────────────────────────────────────────────────────

@app.route("/api/backup/status")
def api_backup_status():
    status = get_backup_status()
    status["storage"] = find_storage_devices()
    return jsonify(status)


@app.route("/api/backup/run", methods=["POST"])
def api_backup_run():
    data = _json_body() or {}
    target = data.get("path", "")
    passphrase = data.get("passphrase", "")

    if target:
        result = backup_to_path(target, passphrase)
        return jsonify(result), 200 if result["success"] else 500

    # Backup to all available storage
    targets = find_storage_devices()
    if not targets:
        # Create default local backup dir
        default = str(Path.home() / "ShadowGrid-Backups")
        os.makedirs(default, exist_ok=True)
        targets = [{"path": default}]

    results = []
    for t in targets:
        results.append(backup_to_path(t["path"], passphrase))
    return jsonify({"results": results})


@app.route("/api/backup/restore", methods=["POST"])
def api_backup_restore():
    data = _json_body()
    filepath = data.get("path", "")
    passphrase = data.get("passphrase", "")
    if not filepath:
        return jsonify({"error": "Backup file path required"}), 400
    result = restore_from_file(filepath, passphrase)
    return jsonify(result), 200 if result["success"] else 500


# ── BLE Scanner API ────────────────────────────────────────────────────────

@app.route("/api/scanner")
def api_scanner():
    return jsonify({"stats": ble_scanner.get_stats(), "devices": ble_scanner.get_devices()})


@app.route("/api/scanner/test", methods=["POST"])
def api_scanner_test():
    """Probe a discovered device — only allowed for devices in your registry."""
    data = _json_body()
    addr = data.get("address")
    if not addr:
        return jsonify({"error": "No address provided"}), 400
    # Get owned device addresses from registry
    owned = set()
    conn = sqlite3.connect(str(DB_PATH))
    for row in conn.execute("SELECT address FROM devices").fetchall():
        owned.add(row[0])
    conn.close()
    loop = asyncio.new_event_loop()
    try:
        result = loop.run_until_complete(ble_scanner.test_device(addr, owned_addrs=owned))
        return jsonify({"address": addr, "result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        loop.close()


# ── LoRa API ───────────────────────────────────────────────────────────────

@app.route("/api/lora/live")
def api_lora_live():
    with data_lock:
        result = dict(latest_lora)
    result["data"] = lora_bridge.get_latest()
    return jsonify(result)


@app.route("/api/meter/config", methods=["GET", "POST"])
def api_meter_config():
    config = MeterConfig()
    if flask_request.method == "POST":
        data = _json_body()
        if data.get("meter_id"):
            config.set_meter_id(str(data["meter_id"]))
            return jsonify({"status": "ok", "meter_ids": config.meter_ids})
        return jsonify({"error": "Provide meter_id"}), 400
    return jsonify({"meter_ids": config.meter_ids, "msg_types": config.msg_types})


# ── BLE watchdog ─────────────────────────────────────────────────────────────
# Auto-recovers a wedged JBD BLE stack (stale half-open GATT connection jams the
# single-client slot -> ALL packs read offline, poller can't self-recover). See
# docs/ble-watchdog.md. Graduated + self-limiting; only acts when reads already
# fail, and never restarts this service (it would kill the watchdog).
WATCHDOG_ENABLED  = os.environ.get("BLE_WATCHDOG", "1") != "0"
WATCHDOG_INTERVAL = int(os.environ.get("BLE_WATCHDOG_INTERVAL", "20"))
WATCHDOG_STALE    = int(os.environ.get("BLE_WATCHDOG_STALE", "90"))
WATCHDOG_COOLDOWN = int(os.environ.get("BLE_WATCHDOG_COOLDOWN", "60"))
WATCHDOG_REALERT  = int(os.environ.get("BLE_WATCHDOG_REALERT", "1800"))
# Poll-loop liveness ceiling. If poller_loop() hasn't completed a cycle in this
# many seconds the loop is HUNG (not a BLE wedge) — stale data still reads
# online=True, so the per-pack check below can't see it, and a BLE bounce won't
# free a thread parked in a dead D-Bus await. Only a process restart clears it;
# systemd brings the service (and this watchdog) back. Set well above the worst-
# case cycle (2 packs x BLE_READ_DEADLINE + victron/weather/sync).
WATCHDOG_LOOP_STALE = int(os.environ.get("BLE_WATCHDOG_LOOP_STALE", "300"))
_SUDO_PW = os.environ.get("SUDO_PW", "")


def _sudo(args, timeout=25):
    """Run a privileged command via `sudo -S` using SUDO_PW. Returns (ok, output)."""
    try:
        p = subprocess.run(["sudo", "-S", "-p", ""] + args, input=_SUDO_PW + "\n",
                           capture_output=True, text=True, timeout=timeout)
        return p.returncode == 0, (p.stdout + p.stderr).strip()
    except Exception as e:
        return False, str(e)


def _jbd_pack_state():
    """(any_online, [pack addrs], n_packs) for JBD/BMS packs from live data."""
    with data_lock:
        bats = list(latest_data.get("batteries", []))
    packs = [b for b in bats if b.get("device_type") != "ecoflow"]
    any_online = any(b.get("online") for b in packs)
    addrs = [b.get("addr") for b in packs if b.get("addr")]
    return any_online, addrs, len(packs)


def _watchdog_step(st, any_online, now):
    """Pure state machine. st = {'down_since','attempts','last_action'}.
    Returns one of: 'idle','recovered','wait','disconnect','bounce'. No side effects."""
    if any_online:
        was_down = st["down_since"] is not None
        st["down_since"] = None
        st["attempts"] = 0
        return "recovered" if was_down else "idle"
    if st["down_since"] is None:
        st["down_since"] = now
        return "wait"
    if now - st["down_since"] < WATCHDOG_STALE:
        return "wait"
    interval = WATCHDOG_COOLDOWN if st["attempts"] < 3 else WATCHDOG_REALERT
    if now - st["last_action"] < interval:
        return "wait"
    st["attempts"] += 1
    st["last_action"] = now
    return "disconnect" if st["attempts"] == 1 else "bounce"


def ble_watchdog_loop():
    """Detect a wedged BLE stack (all JBD packs offline > STALE) and auto-recover
    with graduated escalation. Never touches the read path in normal operation."""
    if not WATCHDOG_ENABLED:
        print("[watchdog] BLE watchdog disabled")
        return
    st = {"down_since": None, "attempts": 0, "last_action": 0.0, "last_loop_restart": 0.0}
    print(f"[watchdog] BLE watchdog started (stale={WATCHDOG_STALE}s, interval={WATCHDOG_INTERVAL}s, "
          f"loop_stale={WATCHDOG_LOOP_STALE}s)")
    while True:
        time.sleep(WATCHDOG_INTERVAL)
        try:
            # ── Poll-loop liveness (catches a HUNG loop with stale online=True data,
            #    which the per-pack-offline check below cannot see) ──
            now = time.time()
            loop_age = (time.monotonic() - _last_poll_ts) if _last_poll_ts else 0.0
            if _last_poll_ts and loop_age > WATCHDOG_LOOP_STALE:
                if now - st["last_loop_restart"] > WATCHDOG_REALERT:
                    st["last_loop_restart"] = now
                    print(f"[watchdog] poll loop stale {loop_age:.0f}s (>{WATCHDOG_LOOP_STALE}s) "
                          f"-> restarting shadowgrid (loop hung, BLE bounce won't help)")
                    send_notification("Poll loop hung",
                                      f"No poll cycle in {loop_age:.0f}s — restarting ShadowGrid", "high")
                    _sudo(["systemctl", "restart", "shadowgrid"])
                continue  # service is going down; nothing else to do this tick

            any_online, addrs, npacks = _jbd_pack_state()
            if npacks == 0:
                continue  # no JBD packs registered -> nothing to guard
            prev_attempts = st["attempts"]
            act = _watchdog_step(st, any_online, now)
            if act == "recovered":
                if prev_attempts > 0:
                    print("[watchdog] BLE recovered after auto-recovery")
                    send_notification("BLE recovered", "JBD polling restored by watchdog", "normal")
            elif act == "disconnect":
                print(f"[watchdog] L{st['attempts']}: packs offline >{WATCHDOG_STALE}s -> disconnecting stale GATT {addrs}")
                for a in addrs:
                    _sudo(["bluetoothctl", "disconnect", a])
            elif act == "bounce":
                print(f"[watchdog] L{st['attempts']}: still offline -> restart bluetooth + bounce hci0")
                _sudo(["systemctl", "restart", "bluetooth"])
                _sudo(["hciconfig", "hci0", "down"])
                _sudo(["hciconfig", "hci0", "up"])
                if st["attempts"] == 2:
                    send_notification("BLE watchdog", "Bouncing BLE stack to recover JBD polling", "high")
                elif st["attempts"] > 3:
                    send_notification("BLE recovery failing",
                                      "Auto-recovery not restoring JBD polling — check dongle/packs", "high")
        except Exception as e:
            print(f"[watchdog] error: {e}")


# ── Main ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    _load_config_env()
    init_db()
    init_victron_db()
    init_energy_db()
    init_meter_db()
    init_alerts_db()
    init_installations_db()
    init_devices_db()
    init_ecoflow_db()
    init_scanner_db()
    init_bms_password_db()
    init_thresholds_db()
    init_notifications_db()
    init_loadshed_db()
    init_sites_db()
    init_weather_db()
    init_chargecontroller_db()
    init_budget_db()
    init_maintenance_db()
    init_generator_db()
    init_balance_db()
    init_cerbo_db()
    init_power_db()
    init_auth_db()
    app.secret_key = get_auth_setting('secret_key')
    print("ShadowGrid starting...")
    if get_auth_setting('auth_enabled') == '1':
        print("Authentication: ENABLED")
    else:
        print("Authentication: disabled (open access)")
    print(f"Database: {DB_PATH}")
    print(f"Polling: BMS every {BMS_POLL_INTERVAL}s, EcoFlow every {ECOFLOW_POLL_INTERVAL}s")

    poller = threading.Thread(target=poller_loop, daemon=True)
    poller.start()

    # Start BLE battery scanner
    ble_scanner._log_callback = log_scanner_results
    scan_thread = threading.Thread(target=scanner_thread, args=(ble_scanner, 600), daemon=True)  # 10 min
    scan_thread.start()
    print("BLE battery scanner started (scanning mode, 10 min interval)")

    # Start auto-backup
    backup_thread = threading.Thread(target=auto_backup_thread, daemon=True)
    backup_thread.start()
    print("Auto-backup enabled (hourly to detected storage)")

    # Start Cerbo GX Modbus TCP poller (wired Victron SmartShunt; isolated from BLE)
    cerbo_thread = threading.Thread(target=cerbo_poll_loop, daemon=True)
    cerbo_thread.start()
    print(f"Cerbo GX poller started (Modbus TCP {cerbo_reader.CERBO_HOST}:{cerbo_reader.CERBO_PORT} shunt unit {cerbo_reader.SHUNT_UNIT}, solar {cerbo_reader.SOLAR_UNITS})")

    # Start host self-power monitor + power-mode enforcer (RAPL + CPU governor)
    power_thread = threading.Thread(target=power_poll_loop, daemon=True)
    power_thread.start()
    print(f"Host power monitor started (mode: {read_power_mode()})")

    # Start BLE watchdog (auto-recovers a wedged JBD BLE stack; see docs/ble-watchdog.md)
    watchdog_thread = threading.Thread(target=ble_watchdog_loop, daemon=True)
    watchdog_thread.start()

    # Start LoRa bridge if base unit is detected
    if lora_bridge.find_base_unit():
        def on_lora_data(data):
            with data_lock:
                latest_lora["connected"] = True
                latest_lora["data"] = data
                latest_lora["lora_stats"] = data.get("lora")

                # Merge LoRa battery data only if direct BLE missed that battery
                ble_labels = {b.get("label") for b in latest_data.get("batteries", []) if b.get("online")}
                for name, bdata in data.get("batteries", {}).items():
                    full_label = f"BATT_{name}"
                    if full_label not in ble_labels:
                        # BLE didn't reach this battery — use LoRa data
                        bdata["source"] = "lora"
                        # Inject into batteries list
                        existing = [b for b in latest_data.get("batteries", []) if b.get("label") == full_label]
                        if existing:
                            existing[0].update(bdata)
                        else:
                            latest_data.setdefault("batteries", []).append(bdata)
        lora_bridge.on_data(on_lora_data)
        if lora_bridge.start_background():
            print("LoRa bridge connected — receiving remote data")
        else:
            print("LoRa bridge failed to start")
    else:
        print("No LoRa base unit detected — bridge disabled")

    # Start meter reader if RTL-SDR is detected
    if detect_rtlsdr():
        print("RTL-SDR detected — starting meter reader")
        meter_reader = MeterReader()
        if meter_reader.start_background():
            def on_meter(reading):
                power = get_power_estimate(reading["meter_id"])
                if power:
                    with data_lock:
                        latest_meter["reading"] = reading
                        latest_meter["power"] = power
                        latest_meter["available"] = True
            meter_reader.on_reading(on_meter)
        else:
            print("Meter reader failed to start (rtlamr may need installing)")
    else:
        print("No RTL-SDR detected — meter reader disabled (plug in dongle to enable)")

    ssl_ctx = None
    protocol = "http"
    if get_auth_setting('ssl_enabled') == '1':
        cert_path = str(Path(__file__).parent / "cert.pem")
        key_path = str(Path(__file__).parent / "key.pem")
        if os.path.exists(cert_path) and os.path.exists(key_path):
            ssl_ctx = (cert_path, key_path)
            protocol = "https"
            print("SSL: ENABLED (self-signed)")
        else:
            print("SSL: cert/key missing — generating...")
            generate_ssl_cert(cert_path, key_path)
            ssl_ctx = (cert_path, key_path)
            protocol = "https"

    host = os.environ.get("FLASK_HOST", "0.0.0.0")
    try:
        port = int(os.environ.get("FLASK_PORT", "5050"))
    except (TypeError, ValueError):
        port = 5050
    print(f"Web UI: {protocol}://localhost:{port}")
    app.run(host=host, port=port, debug=False, ssl_context=ssl_ctx)
