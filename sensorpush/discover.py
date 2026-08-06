#!/usr/bin/env python3
"""Discover + validate a SensorPush sensor.

Runs in the isolated venv (has the real sensorpush_ble as an oracle).
Compares the maintained parser's decode against our dependency-free port,
then enumerates GATT to assess what settings are editable.
"""
import asyncio
from types import SimpleNamespace

from bleak import BleakScanner, BleakClient
from sensorpush_ble.parser import (
    _find_latest_data, decode_values, determine_device_type,
    SENSORPUSH_SERVICE_UUID_V2, SENSORPUSH_SERVICE_UUID_HT1,
)

# ---- our dependency-free port (this is what ships in ShadowGrid) ----
PACK = {64: [[-40.0, 140.0, 0.0025], [0.0, 100.0, 0.0025], [30000.0, 125000.0, 1.0]],
        65: [[-40.0, 125.0, 0.0025], [0.0, 100.0, 0.0025]],
        66: [[-200.0, 1800.0, 0.0625]]}
LABELS = {64: ["temp_c", "humidity_pct", "pressure_hpa"],
          65: ["temp_c", "humidity_pct"], 66: ["temp_c"]}

def port_decode(data: bytes, dtid: int) -> dict:
    pack = PACK.get(dtid)
    if not pack:
        return {}
    packed = 0
    for i in range(1, len(data)):
        packed += data[i] << (8 * (i - 1))
    out, mod, div = {}, 1, 1
    for i, (mn, mx, step) in enumerate(pack):
        rng = int((mx - mn) / step + step / 2.0) + 1
        mod *= rng
        cnt = int((packed % mod) / div)
        v = round(cnt * step + mn, 2)
        lbl = LABELS[dtid][i]
        if lbl == "pressure_hpa":
            v = v / 100.0
        out[lbl] = v
        div *= rng
    return out

def try_text(b: bytes) -> str:
    try:
        t = b.decode("utf-8")
        return repr(t) if t.isprintable() and t else ""
    except Exception:
        return ""

found = {}
def cb(d, adv):
    name = (adv.local_name or "")
    uuids = [u.lower() for u in (adv.service_uuids or [])]
    if ("sensorpush" in name.lower() or "htp" in name.lower() or "ht.w" in name.lower()
            or SENSORPUSH_SERVICE_UUID_V2 in uuids or SENSORPUSH_SERVICE_UUID_HT1 in uuids):
        found[d.address] = (d, adv)

async def main():
    print("scanning 15s for SensorPush...")
    s = BleakScanner(detection_callback=cb)
    await s.start(); await asyncio.sleep(15); await s.stop()
    if not found:
        print("NO SensorPush device found"); return

    for addr, (d, adv) in found.items():
        name = adv.local_name or d.name or ""
        md = adv.manufacturer_data or {}
        uuids = list(adv.service_uuids or [])
        print("=" * 64)
        print(f"address : {addr}")
        print(f"name    : {name!r}   rssi: {adv.rssi} dBm")
        print(f"uuids   : {uuids}")
        print(f"mfgdata : {{ {', '.join(f'{hex(k)}: {v.hex()}' for k,v in md.items())} }}")
        shim = SimpleNamespace(name=name, service_uuids=uuids, manufacturer_data=md, address=addr)
        dtype = determine_device_type(shim, md)
        print(f"model   : {dtype}")
        data = _find_latest_data(md, dtype == "HT1") if (md and dtype) else None
        if data:
            dtid = 1 if dtype == "HT1" else 64 + (data[0] >> 2)
            oracle = {str(k): v for k, v in decode_values(data, dtid).items()}
            print(f"type_id : {dtid}")
            print(f"ORACLE  : {oracle}")
            print(f"PORT    : {port_decode(data, dtid)}   <-- must match oracle values")

    addr = next(iter(found))
    print("=" * 64)
    print(f"GATT enumerate: {addr}")
    try:
        async with BleakClient(addr, timeout=25) as c:
            for svc in c.services:
                print(f" service {svc.uuid}")
                for ch in svc.characteristics:
                    props = ",".join(ch.properties)
                    val = ""
                    if "read" in ch.properties:
                        try:
                            b = await c.read_gatt_char(ch)
                            val = f" = {b.hex()} {try_text(b)}"
                        except Exception as e:
                            val = f" (read err: {type(e).__name__})"
                    print(f"    {ch.uuid}  [{props}]{val}")
    except Exception as e:
        print(f"GATT connect failed: {type(e).__name__}: {e}")

asyncio.run(main())
