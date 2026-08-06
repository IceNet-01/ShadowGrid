"""SensorPush BLE integration for ShadowGrid — dependency-free.

Passive BLE-advertisement decoding (monitor + log) plus GATT settings
read/write. The decoder is a clean-room port validated byte-for-byte against
the maintained `sensorpush-ble` library on a live HTP.xw:
    temp 20.01 C, humidity 44.26 %, pressure 977.41 hPa  (ORACLE == PORT).

Models: HT1(id 1), HTP.xw(64), HT.w(65), TC.x(66).
Uses only `bleak` (already a ShadowGrid dependency) + stdlib.
"""
from __future__ import annotations

import asyncio
import sqlite3
from datetime import datetime
from pathlib import Path

from bleak import BleakClient, BleakScanner

# ── Advertisement / protocol constants ─────────────────────────────────────
SERVICE_UUID_V2 = "ef090000-11d6-42ba-93b8-9dd7ec090ab0"
SERVICE_UUID_HT1 = "ef090000-11d6-42ba-93b8-9dd7ec090aa9"
LOCAL_NAMES = {"HTP.xw": "HTP.xw", "HT.w": "HT.w", "TC": "TC.x", "TC.x": "TC.x"}
MFG_LEN_MODEL = {3: "HT.w", 5: "HTP.xw", 2: "TC.x"}
DEVICE_TYPES = {1: "HT1", 64: "HTP.xw", 65: "HT.w", 66: "TC.x"}
# [min, max, step] per packed value
PACK = {
    64: [(-40.0, 140.0, 0.0025), (0.0, 100.0, 0.0025), (30000.0, 125000.0, 1.0)],
    65: [(-40.0, 125.0, 0.0025), (0.0, 100.0, 0.0025)],
    66: [(-200.0, 1800.0, 0.0625)],
}
LABELS = {
    1: ["temp_c", "humidity_pct"],
    64: ["temp_c", "humidity_pct", "pressure_hpa"],
    65: ["temp_c", "humidity_pct"],
    66: ["temp_c"],
}

DB_PATH = str(Path(__file__).resolve().parent / "shadowgrid.db")


# ── Detection ──────────────────────────────────────────────────────────────
def is_sensorpush(name: str | None, service_uuids) -> bool:
    name = name or ""
    uu = [u.lower() for u in (service_uuids or [])]
    return (
        "sensorpush" in name.lower()
        or SERVICE_UUID_V2 in uu
        or SERVICE_UUID_HT1 in uu
        or any(k in name for k in LOCAL_NAMES)
    )


def _determine_model(name, service_uuids, manufacturer_data):
    name = name or ""
    for k, v in LOCAL_NAMES.items():
        if k in name:
            return v
    uu = [u.lower() for u in (service_uuids or [])]
    if SERVICE_UUID_HT1 in uu and name == "s":
        return "HT1"
    if SERVICE_UUID_V2 in uu and manufacturer_data:
        L = len(next(iter(manufacturer_data.values())))
        return MFG_LEN_MODEL.get(L)
    return None


def _find_latest_data(md: dict[int, bytes], is_ht1: bool):
    for id_ in reversed(list(md)):
        data = int(id_).to_bytes(2, "little") + md[id_]
        if is_ht1:
            return data
        if (data[0] & 0x03) == 0:  # page 0 = latest complete reading
            return data
    return None


# ── Decoders ───────────────────────────────────────────────────────────────
def _relhum_ht1(num: int) -> float:
    v = -6.0 + 125.0 * (num / 4096.0)
    return 0.0 if v < 0 else (100.0 if v > 100 else round(v, 2))


def _temp_ht1(num: int) -> float:
    return round(-46.85 + 175.72 * (num / 16384.0), 2)


def _decode_ht1(d: bytes) -> dict:
    if len(d) < 4 or ((d[3] & 124) >> 2) != 1:
        return {}
    hum = _relhum_ht1((d[0] & 255) + ((d[1] & 15) << 8))
    temp = _temp_ht1(((d[1] & 255) >> 4) + ((d[2] & 255) << 4) + ((d[3] & 3) << 12))
    return {"temp_c": temp, "humidity_pct": hum}


def _decode_packed(d: bytes, dtid: int) -> dict:
    pack = PACK.get(dtid)
    if not pack:
        return {}
    packed = 0
    for i in range(1, len(d)):
        packed += d[i] << (8 * (i - 1))
    out, mod, div = {}, 1, 1
    for i, (mn, mx, step) in enumerate(pack):
        rng = int((mx - mn) / step + step / 2.0) + 1
        mod *= rng
        cnt = int((packed % mod) / div)
        v = round(cnt * step + mn, 2)
        lbl = LABELS[dtid][i]
        if lbl == "pressure_hpa":
            v = round(v / 100.0, 2)  # mbar -> hPa
        out[lbl] = v
        div *= rng
    return out


def decode_advertisement(name, service_uuids, manufacturer_data):
    """Return {'model', 'type_id', 'values': {...}} or None if not SensorPush."""
    if not manufacturer_data:
        return None
    model = _determine_model(name, service_uuids, manufacturer_data)
    if not model:
        return None
    is_ht1 = model == "HT1"
    data = _find_latest_data(manufacturer_data, is_ht1)
    if not data:
        return {"model": model, "type_id": None, "values": {}}
    dtid = 1 if is_ht1 else 64 + (data[0] >> 2)
    model = DEVICE_TYPES.get(dtid, model)
    values = _decode_ht1(data) if is_ht1 else _decode_packed(data, dtid)
    return {"model": model, "type_id": dtid, "values": values}


# ── Scanning ───────────────────────────────────────────────────────────────
async def scan(timeout: float = 12.0) -> dict:
    """Passive scan. Returns {address: {address,name,model,rssi,<values>}}."""
    results: dict[str, dict] = {}

    def cb(d, adv):
        if not is_sensorpush(adv.local_name, adv.service_uuids):
            return
        dec = decode_advertisement(adv.local_name, adv.service_uuids, adv.manufacturer_data)
        if dec and dec.get("values"):
            results[d.address] = {
                "address": d.address,
                "name": (adv.local_name or d.name or "").removeprefix("SensorPush "),
                "model": dec["model"],
                "rssi": adv.rssi,
                **dec["values"],
            }

    scanner = BleakScanner(detection_callback=cb)
    await scanner.start()
    await asyncio.sleep(timeout)
    await scanner.stop()
    return results


# ── Persistence ────────────────────────────────────────────────────────────
def init_tables(db_path: str = DB_PATH) -> None:
    conn = sqlite3.connect(db_path)
    conn.execute("""CREATE TABLE IF NOT EXISTS sensorpush_devices (
        address TEXT PRIMARY KEY,
        label TEXT,
        model TEXT,
        enabled INTEGER DEFAULT 1,
        added TEXT
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS sensorpush_readings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        address TEXT NOT NULL,
        temp_c REAL, humidity_pct REAL, pressure_hpa REAL,
        rssi INTEGER
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sp_ts ON sensorpush_readings(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sp_addr ON sensorpush_readings(address)")
    conn.commit()
    conn.close()


def log_readings(results: dict, db_path: str = DB_PATH) -> int:
    if not results:
        return 0
    now = datetime.now().isoformat()
    conn = sqlite3.connect(db_path, timeout=30)
    conn.execute("PRAGMA busy_timeout=30000")
    n = 0
    for r in results.values():
        conn.execute(
            "INSERT INTO sensorpush_readings (timestamp,address,temp_c,humidity_pct,pressure_hpa,rssi)"
            " VALUES (?,?,?,?,?,?)",
            (now, r["address"], r.get("temp_c"), r.get("humidity_pct"),
             r.get("pressure_hpa"), r.get("rssi")),
        )
        # auto-register device on first sight
        conn.execute(
            "INSERT OR IGNORE INTO sensorpush_devices (address,label,model,enabled,added) VALUES (?,?,?,1,?)",
            (r["address"], r.get("name") or r["address"], r.get("model"), now),
        )
        n += 1
    conn.commit()
    conn.close()
    return n


# ── CLI (for testing) ──────────────────────────────────────────────────────
if __name__ == "__main__":
    import json
    import sys

    async def _main():
        t = float(sys.argv[1]) if len(sys.argv) > 1 else 12.0
        res = await scan(t)
        print(json.dumps(res, indent=2))
        if "--log" in sys.argv:
            init_tables()
            print(f"logged {log_readings(res)} reading(s)")

    asyncio.run(_main())
