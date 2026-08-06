#!/usr/bin/env python3
"""
ShadowGrid Victron Reader
Reads Victron devices via BLE Instant Readout and Cerbo GX MQTT/Modbus TCP.

Supports: SmartSolar MPPT, Cerbo GX, Orion-Tr Smart DC-DC, Blue Smart IP22
"""

import asyncio
import json
import re
import struct
import time
from datetime import datetime
from bleak import BleakScanner

# ── Victron BLE Constants ──────────────────────────────────────────────────

VICTRON_MFG_ID = 0x02E1

DEVICE_TYPES = {
    0x01: "Solar Charger",
    0x02: "Battery Monitor",
    0x03: "Inverter",
    0x04: "DC-DC Converter",
    0x05: "SmartLithium",
    0x06: "Inverter RS",
    0x07: "GX Device",
    0x08: "AC Charger",
    0x09: "Smart Battery Protect",
    0x0A: "Lynx Smart BMS",
}

CHARGE_STATES = {
    0: "Off", 2: "Fault", 3: "Bulk", 4: "Absorption", 5: "Float",
    6: "Storage", 7: "Equalize", 9: "Inverting", 11: "Power Supply",
    245: "Starting", 247: "Auto Equalize", 252: "External Control",
}

CHARGER_ERRORS = {
    0: "No error", 1: "Battery temp too high", 2: "Battery voltage too high",
    17: "Overheated", 18: "Over-current", 20: "Max bulk time exceeded",
    26: "Terminal overheated", 27: "Short circuit", 33: "PV over-voltage",
    34: "PV over-current", 35: "PV over-power", 67: "BMS connection lost",
}

# "OFF reason" 32-bit bitmask (Orion DC-DC, Blue Smart, etc.) — why the unit is
# not delivering output. Multiple bits may be set; all-zero means it is running.
OFF_REASONS = {
    0: "No input power", 1: "Switched off (switch)", 2: "Switched off (mode)",
    3: "Remote input", 4: "Protection active", 5: "Paygo", 6: "BMS",
    7: "Engine shutdown", 8: "Analysing input voltage",
}


def decode_off_reason(bits: int) -> str:
    """Human-readable OFF reason(s) from the 32-bit bitmask ('Running' when 0)."""
    if not bits:
        return "Running"
    active = [t for b, t in OFF_REASONS.items() if bits & (1 << b)]
    return ", ".join(active) if active else f"Unknown (0x{bits:08X})"

# Known Victron product IDs (partial list)
PRODUCT_IDS = {
    0xA381: "SmartSolar MPPT 75|10",
    0xA382: "SmartSolar MPPT 75|15",
    0xA383: "SmartSolar MPPT 100|15",
    0xA384: "SmartSolar MPPT 100|20",
    0xA385: "SmartSolar MPPT 100|30",
    0xA386: "SmartSolar MPPT 100|50",
    0xA389: "SmartSolar MPPT 150|35",
    0xA38A: "SmartSolar MPPT 150|45",
    0xA38B: "SmartSolar MPPT 150|60",
    0xA38C: "SmartSolar MPPT 150|70",
    0xA38D: "SmartSolar MPPT 150|85",
    0xA38E: "SmartSolar MPPT 150|100",
    0xA38F: "SmartSolar MPPT 250|60",
    0xA390: "SmartSolar MPPT 250|70",
    0xA391: "SmartSolar MPPT 250|85",
    0xA392: "SmartSolar MPPT 250|100",
    0xA3F0: "SmartSolar MPPT RS 450|100",
    0xA3F1: "SmartSolar MPPT RS 450|200",
    0x2780: "Orion Smart 12V|12V-18A",
    0x2781: "Orion Smart 12V|12V-30A",
    0x2782: "Orion Smart 12V|24V-10A",
    0x2783: "Orion Smart 12V|24V-15A",
    0x2784: "Orion Smart 24V|12V-20A",
    0x2785: "Orion Smart 24V|12V-30A",
    0x2786: "Orion Smart 24V|24V-12A",
    0x2787: "Orion Smart 24V|24V-17A",
    0x2788: "Orion Smart 48V|12V-20A",
    0x2789: "Orion Smart 48V|12V-30A",
    0xA339: "Blue Smart IP22 12|15(1)",
    0xA33A: "Blue Smart IP22 12|15(3)",
    0xA33B: "Blue Smart IP22 12|20(1)",
    0xA33C: "Blue Smart IP22 12|20(3)",
    0xA33D: "Blue Smart IP22 12|30(1)",
    0xA33E: "Blue Smart IP22 12|30(3)",
    0xA33F: "Blue Smart IP22 24|8(1)",
    0xA340: "Blue Smart IP22 24|8(3)",
    0xA341: "Blue Smart IP22 24|12(1)",
    0xA342: "Blue Smart IP22 24|12(3)",
    0xA343: "Blue Smart IP22 24|16(1)",
    0xA344: "Blue Smart IP22 24|16(3)",
    # Live-identified from advertised local name; ids not in the public partial
    # list. 0xA337 = our Blue Smart IP22 24/16 (120 V variant), 0xA3C2 = our
    # isolated Orion Smart 24→12 DC-DC. See [[victron-ble-instant-readout]].
    0xA337: "Blue Smart IP22 24|16",
    0xA3C2: "Orion Smart 24V|12V",
    0xC030: "Cerbo GX",
    0xC031: "Cerbo GX MK2",
}


# ── Encryption Key Store ───────────────────────────────────────────────────

class VictronKeyStore:
    """Manages encryption keys for Victron BLE Instant Readout."""

    def __init__(self, key_file="victron_keys.json"):
        self.key_file = key_file
        self.keys = {}
        self._load()

    def _load(self):
        try:
            with open(self.key_file) as f:
                self.keys = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self.keys = {}

    def save(self):
        with open(self.key_file, "w") as f:
            json.dump(self.keys, f, indent=2)

    def get_key(self, mac: str) -> bytes | None:
        hex_key = self.keys.get(mac.upper())
        if hex_key:
            return bytes.fromhex(hex_key)
        return None

    def set_key(self, mac: str, hex_key: str):
        self.keys[mac.upper()] = hex_key.replace(" ", "").replace(":", "")
        self.save()


# ── BLE Advertisement Decoder ──────────────────────────────────────────────

def decrypt_victron_data(mfg_data: bytes, key: bytes) -> bytes | None:
    """Decrypt Victron BLE Instant Readout advertisement data.

    Manufacturer-data (0x02E1) layout: [0:2] prefix, [2:4] model id, [4] record
    type, [5:7] IV (little-endian), [7] key-check byte (== key[0]), [8:] ciphertext.
    Uses AES-128-CTR with a LITTLE-ENDIAN 128-bit counter seeded from the IV.
    """
    try:
        from Crypto.Cipher import AES
        from Crypto.Util import Counter
    except ImportError:
        from Cryptodome.Cipher import AES
        from Cryptodome.Util import Counter

    if len(mfg_data) < 9:
        return None

    iv = mfg_data[5] | (mfg_data[6] << 8)
    ciphertext = mfg_data[8:]
    if not ciphertext:
        return None
    # AES-CTR is a stream cipher; zero-pad to a whole block so pycryptodome is
    # happy. Extra bytes are ignored by the fixed-field parsers.
    if len(ciphertext) % 16:
        ciphertext += b"\x00" * (16 - len(ciphertext) % 16)

    ctr = Counter.new(128, initial_value=iv, little_endian=True)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    return cipher.decrypt(ciphertext)


class BitReader:
    """LSB-first bit reader for Victron decrypted payloads (fields are bit-packed,
    NOT byte-aligned). Mirrors the reference victron-ble decoder."""

    def __init__(self, data: bytes):
        self._d = data
        self._i = 0

    def read(self, n: int) -> int:
        v = 0
        for k in range(n):
            bi = self._i >> 3
            if bi >= len(self._d):
                break
            v |= ((self._d[bi] >> (self._i & 7)) & 1) << k
            self._i += 1
        return v

    def read_signed(self, n: int) -> int:
        v = self.read(n)
        return v - (1 << n) if v & (1 << (n - 1)) else v


def parse_solar_charger(data: bytes) -> dict:
    """Parse decrypted Solar Charger (0x01) data."""
    r = BitReader(data)
    state = r.read(8)
    error = r.read(8)
    batt_v = r.read_signed(16)          # 0.01 V
    batt_i = r.read_signed(16)          # 0.1 A
    yield_today = r.read(16)            # 10 Wh
    pv_power = r.read(16)               # W
    load_i = r.read(9)                 # 0.1 A

    result = {
        "device_type": "Solar Charger",
        "state": CHARGE_STATES.get(state, f"Unknown ({state})"),
        "state_code": state,
        "error": CHARGER_ERRORS.get(error, f"Unknown ({error})"),
        "error_code": error,
        "battery_voltage": round(batt_v * 0.01, 2) if batt_v != 0x7FFF else None,
        "battery_current": round(batt_i * 0.1, 1) if batt_i != 0x7FFF else None,
        "yield_today": round(yield_today * 0.01, 2) if yield_today != 0xFFFF else None,  # kWh
        "pv_power": pv_power if pv_power != 0xFFFF else None,
        "load_current": round(load_i * 0.1, 1) if load_i != 0x1FF else None,
    }
    if result["battery_voltage"] and result["battery_current"] is not None:
        result["battery_power"] = round(result["battery_voltage"] * result["battery_current"], 1)
    return result


def parse_dc_dc_converter(data: bytes) -> dict:
    """Parse decrypted DC-DC Converter (0x04) data."""
    r = BitReader(data)
    state = r.read(8)
    error = r.read(8)
    input_v = r.read(16)                # 0.01 V
    output_v = r.read_signed(16)        # 0.01 V
    off_reason = r.read(32)

    return {
        "device_type": "DC-DC Converter",
        "state": CHARGE_STATES.get(state, f"Unknown ({state})"),
        "state_code": state,
        "error": CHARGER_ERRORS.get(error, f"Unknown ({error})"),
        "error_code": error,
        "input_voltage": round(input_v * 0.01, 2) if input_v != 0xFFFF else None,
        "output_voltage": round(output_v * 0.01, 2) if output_v != 0x7FFF else None,
        "off_reason": decode_off_reason(off_reason),
        "off_reason_code": off_reason,
    }


def parse_ac_charger(data: bytes) -> dict:
    """Parse decrypted AC Charger (0x08) data."""
    r = BitReader(data)
    state = r.read(8)
    error = r.read(8)
    v1 = r.read(13)                     # 0.01 V
    i1 = r.read(11)                     # 0.1 A
    v2 = r.read(13)
    i2 = r.read(11)
    v3 = r.read(13)
    i3 = r.read(11)
    temp = r.read(7)                   # C, offset 40
    ac_i = r.read(9)                   # 0.1 A

    result = {
        "device_type": "AC Charger",
        "state": CHARGE_STATES.get(state, f"Unknown ({state})"),
        "state_code": state,
        "error": CHARGER_ERRORS.get(error, f"Unknown ({error})"),
        "error_code": error,
        "battery_voltage": round(v1 * 0.01, 2) if v1 != 0x1FFF else None,
        "battery_current": round(i1 * 0.1, 1) if i1 != 0x7FF else None,
        "temperature": (temp - 40) if temp != 0x7F else None,
        "ac_current": round(ac_i * 0.1, 1) if ac_i != 0x1FF else None,
    }
    if v2 != 0x1FFF:
        result["battery_voltage_2"] = round(v2 * 0.01, 2)
        result["battery_current_2"] = round(i2 * 0.1, 1) if i2 != 0x7FF else None
    if v3 != 0x1FFF:
        result["battery_voltage_3"] = round(v3 * 0.01, 2)
        result["battery_current_3"] = round(i3 * 0.1, 1) if i3 != 0x7FF else None
    return result


def parse_battery_monitor(data: bytes) -> dict:
    """Parse decrypted Battery Monitor (0x02) data."""
    r = BitReader(data)
    ttg = r.read(16)                    # minutes
    batt_v = r.read_signed(16)          # 0.01 V
    alarm = r.read(16)
    aux = r.read(16)
    aux_mode = r.read(2)
    cur_u = r.read(22)                  # mA (raw unsigned; 0x3FFFFF = n/a)
    consumed = r.read(20)               # 0.1 Ah
    soc = r.read(10)                   # 0.1 %

    current = None
    if cur_u != 0x3FFFFF:
        current = round((cur_u - (1 << 22) if cur_u & (1 << 21) else cur_u) / 1000.0, 2)

    result = {
        "device_type": "Battery Monitor",
        "time_to_go": ttg if ttg != 0xFFFF else None,
        "battery_voltage": round(batt_v * 0.01, 2) if batt_v != 0x7FFF else None,
        "battery_current": current,
        "soc": round(soc / 10.0, 1) if soc != 0x3FF else None,
        "consumed_ah": round(-consumed / 10.0, 1) if consumed != 0xFFFFF else None,
        "alarm_reason": alarm,
    }
    if aux_mode == 2 and aux != 0xFFFF:          # temperature (Kelvin*100)
        result["temperature"] = round(aux / 100.0 - 273.15, 1)
    elif aux_mode == 0:                          # starter voltage (signed)
        sv = aux - 65536 if aux > 32767 else aux
        result["starter_voltage"] = round(sv / 100.0, 2)
    elif aux_mode == 1:                          # midpoint voltage
        result["midpoint_voltage"] = round(aux / 100.0, 2)
    return result


PARSERS = {
    0x01: parse_solar_charger,
    0x02: parse_battery_monitor,
    0x04: parse_dc_dc_converter,
    0x08: parse_ac_charger,
}


def parse_victron_advertisement(mfg_data: bytes, key: bytes | None = None) -> dict:
    """Parse a Victron BLE manufacturer data advertisement."""
    if len(mfg_data) < 8:
        return {"error": "too short"}

    # Victron devices emit several manufacturer records under the same company
    # id; only the "Product Advertisement" record (record-type byte 0x10) carries
    # the Instant Readout model/type/IV/ciphertext layout. Other records (seen
    # with a leading 0x01/0x02) have a completely different structure — parsing
    # them as Instant Readout yields garbage model ids, a bogus "device type",
    # and a shifting "key-check" byte that is really ciphertext. Reject them here
    # so a stray non-readout frame can never clobber a real decode.
    if mfg_data[0] != 0x10:
        return {"error": f"non-readout record (0x{mfg_data[0]:02X})",
                "record_ignored": True}

    prefix = struct.unpack_from("<H", mfg_data, 0)[0]
    model_id = struct.unpack_from("<H", mfg_data, 2)[0]
    record_type = mfg_data[4]
    nonce = struct.unpack_from("<H", mfg_data, 5)[0]
    key_check = mfg_data[7]

    result = {
        "model_id": f"0x{model_id:04X}",
        "model_name": PRODUCT_IDS.get(model_id, "Unknown"),
        "record_type": record_type,
        "device_type": DEVICE_TYPES.get(record_type, f"Unknown (0x{record_type:02X})"),
        "nonce": nonce,
        "encrypted": True,
    }

    if key:
        # Validate key check byte
        if key[0] != key_check:
            result["error"] = f"Key mismatch (expected 0x{key_check:02X}, got 0x{key[0]:02X})"
            return result

        decrypted = decrypt_victron_data(mfg_data, key)
        if decrypted:
            result["encrypted"] = False
            parser = PARSERS.get(record_type)
            if parser:
                result["data"] = parser(decrypted)
            else:
                result["data"] = {"raw_hex": decrypted.hex()}

    return result


# ── BLE Scanner ────────────────────────────────────────────────────────────

def _clean_local_name(name: str) -> str:
    """Strip the trailing Victron serial (HQxxxxxxxxx) and ellipsis from an
    advertised BLE name so it reads as a model, e.g.
    'BSC IP22 24/16...HQ2616C4YAV' -> 'BSC IP22 24/16'."""
    n = re.sub(r"\s*\.*\s*HQ[0-9A-Z]+\s*$", "", name).strip().rstrip(". ").strip()
    return n or name


class VictronScanner:
    """Scan for Victron devices via BLE Instant Readout."""

    def __init__(self, key_store: VictronKeyStore | None = None):
        self.key_store = key_store or VictronKeyStore()
        self.devices = {}

    async def scan(self, duration: int = 15) -> dict:
        """Scan for Victron BLE advertisements."""
        found = {}

        def callback(device, adv):
            mfg = adv.manufacturer_data
            if VICTRON_MFG_ID not in mfg:
                return

            mfg_data = mfg[VICTRON_MFG_ID]
            addr = device.address.upper()
            name = adv.local_name or device.name or "Victron"
            key = self.key_store.get_key(addr)

            parsed = parse_victron_advertisement(mfg_data, key)
            parsed["addr"] = addr
            parsed["name"] = name
            # Fall back to the device's own advertised name when its model id
            # isn't in our (partial) product table, so cards never read
            # "Unknown". Strips the trailing Victron serial (e.g. "HQ2540K4QHA").
            if parsed.get("model_name") in (None, "Unknown") and name:
                parsed["model_name"] = _clean_local_name(name)
            parsed["rssi"] = adv.rssi
            parsed["timestamp"] = datetime.now().isoformat()
            parsed["has_key"] = key is not None

            # A device emits several manufacturer records; only the Instant
            # Readout one decrypts. Don't let a non-decodable record clobber a
            # good decode captured earlier in this same scan window.
            prev = found.get(addr)
            if prev is not None and prev.get("data") and not parsed.get("data"):
                prev["rssi"] = parsed["rssi"]
                prev["timestamp"] = parsed["timestamp"]
                return

            found[addr] = parsed

        scanner = BleakScanner(detection_callback=callback)
        await scanner.start()
        await asyncio.sleep(duration)
        await scanner.stop()

        self.devices = found
        return found

    async def scan_continuous(self, callback_fn, interval: int = 10):
        """Continuously scan and call callback with results."""
        while True:
            devices = await self.scan(duration=interval)
            if callback_fn:
                callback_fn(devices)
            await asyncio.sleep(1)


# ── Cerbo GX MQTT Client ──────────────────────────────────────────────────

class CerboMQTT:
    """Read Victron data from Cerbo GX via MQTT."""

    # Key topics to subscribe to
    TOPICS = {
        "system_voltage": "system/0/Dc/Battery/Voltage",
        "system_current": "system/0/Dc/Battery/Current",
        "system_soc": "system/0/Dc/Battery/Soc",
        "system_power": "system/0/Dc/Battery/Power",
        "pv_power": "system/0/Dc/Pv/Power",
    }

    SOLAR_TOPICS = {
        "voltage": "Dc/0/Voltage",
        "current": "Dc/0/Current",
        "pv_voltage": "Pv/V",
        "pv_power": "Yield/Power",
        "state": "State",
        "error": "ErrorCode",
        "yield_today": "Yield/User",
    }

    CHARGER_TOPICS = {
        "voltage": "Dc/0/Voltage",
        "current": "Dc/0/Current",
        "state": "State",
        "error": "ErrorCode",
    }

    def __init__(self, host: str, port: int = 1883, portal_id: str = ""):
        self.host = host
        self.port = port
        self.portal_id = portal_id
        self.data = {}
        self._client = None

    async def connect(self):
        """Connect to Cerbo GX MQTT broker."""
        try:
            import paho.mqtt.client as mqtt

            def on_connect(client, userdata, flags, rc):
                if rc == 0:
                    # Subscribe to all Victron topics
                    client.subscribe(f"N/{self.portal_id}/#")
                    # Send keepalive to trigger data publication
                    client.publish(f"R/{self.portal_id}/keepalive", "")

            def on_message(client, userdata, msg):
                try:
                    payload = json.loads(msg.payload)
                    value = payload.get("value", payload)
                    self.data[msg.topic] = value
                except (json.JSONDecodeError, AttributeError):
                    self.data[msg.topic] = msg.payload.decode()

            self._client = mqtt.Client()
            self._client.on_connect = on_connect
            self._client.on_message = on_message
            self._client.connect(self.host, self.port, 60)
            self._client.loop_start()
            return True
        except Exception as e:
            return False

    def get_data(self) -> dict:
        return dict(self.data)

    def disconnect(self):
        if self._client:
            self._client.loop_stop()
            self._client.disconnect()


# ── Main (standalone scan) ─────────────────────────────────────────────────

async def main():
    print("Scanning for Victron BLE devices (15 seconds)...")

    key_store = VictronKeyStore(
        key_file=str(__import__("pathlib").Path(__file__).parent / "victron_keys.json")
    )
    scanner = VictronScanner(key_store)
    devices = await scanner.scan(duration=15)

    if not devices:
        print("\nNo Victron devices found.")
        print("Devices may be out of BLE range or Instant Readout may be disabled.")
        print("\nTo enable: VictronConnect -> Settings -> Instant Readout -> ON")
        return

    print(f"\nFound {len(devices)} Victron device(s):\n")
    for addr, info in devices.items():
        print(f"  {info['name']}")
        print(f"    Address:  {addr}")
        print(f"    Model:    {info['model_name']} ({info['model_id']})")
        print(f"    Type:     {info['device_type']}")
        print(f"    RSSI:     {info['rssi']} dBm")
        print(f"    Has Key:  {info['has_key']}")

        if not info["encrypted"] and "data" in info:
            print(f"    Data:")
            for k, v in info["data"].items():
                if k != "device_type":
                    print(f"      {k}: {v}")
        elif info["encrypted"]:
            print(f"    Status:   Encrypted (add key with victron_keys.json)")
        print()


if __name__ == "__main__":
    asyncio.run(main())
