"""
ShadowGrid BLE Battery Scanner
Continuously scans for BLE battery BMS devices, identifies protocols,
and checks for default credential vulnerabilities.
"""

import asyncio
import json
import time
import threading
import logging
from datetime import datetime
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from bleak import BleakScanner, BleakClient

log = logging.getLogger("ble_scanner")

# ── Load BMS Database ──────────────────────────────────────────────────────

DB_PATH = Path(__file__).parent / "bms_database.json"

def load_bms_db() -> dict:
    try:
        with open(DB_PATH) as f:
            return json.load(f)
    except Exception as e:
        log.error("Failed to load BMS database: %s", e)
        return {"protocols": [], "default_passwords": {}, "scan_targets": {}}

_bms_db = load_bms_db()

def _build_signatures(db: dict) -> list[dict]:
    """Build flat matcher list from the database protocols."""
    sigs = []
    for proto in db.get("protocols", []):
        auth_info = proto.get("auth", {})
        vuln_info = proto.get("vulnerability", {})
        auth_type = auth_info.get("type", "unknown")
        default_pw = auth_info.get("default_password")
        vuln_detail = vuln_info.get("detail", "")
        severity = vuln_info.get("severity", "unknown")

        # Build a sig entry per match rule
        for rule in proto.get("match_rules", []):
            if rule["type"] == "service_uuid":
                sigs.append({
                    "id": proto["id"], "name": proto["name"],
                    "match": "service_uuid", "value": rule["value"],
                    "auth": auth_type, "default_pw": default_pw,
                    "vuln": vuln_detail if severity in ("critical", "high") else "",
                    "severity": severity,
                    "write_uuid": proto.get("ble_write"),
                    "read_uuid": proto.get("ble_notify"),
                    "test_cmd": bytes.fromhex(proto["test_command"]) if proto.get("test_command") else None,
                    "brands": proto.get("brands", []),
                })
            elif rule["type"] == "name_prefix":
                for prefix in rule.get("values", [rule.get("value", "")]):
                    sigs.append({
                        "id": proto["id"], "name": proto["name"],
                        "match": "name_prefix", "value": prefix,
                        "auth": auth_type, "default_pw": default_pw,
                        "vuln": vuln_detail if severity in ("critical", "high") else "",
                        "severity": severity,
                        "brands": proto.get("brands", []),
                    })
            elif rule["type"] == "name_contains":
                for val in rule.get("values", [rule.get("value", "")]):
                    sigs.append({
                        "id": proto["id"], "name": proto["name"],
                        "match": "name_contains", "value": val,
                        "auth": auth_type, "default_pw": default_pw,
                        "vuln": vuln_detail if severity in ("critical", "high") else "",
                        "severity": severity,
                        "brands": proto.get("brands", []),
                    })
            elif rule["type"] == "mfg_id":
                sigs.append({
                    "id": proto["id"], "name": proto["name"],
                    "match": "mfg_id", "value": rule["value"],
                    "auth": auth_type, "default_pw": default_pw,
                    "vuln": vuln_detail if severity in ("critical", "high") else "",
                    "severity": severity,
                    "brands": proto.get("brands", []),
                })
    return sigs

BMS_SIGNATURES = _build_signatures(_bms_db)
log.info("Loaded %d BMS signatures from database (%d protocols)",
         len(BMS_SIGNATURES), len(_bms_db.get("protocols", [])))

# Keep the old static list as fallback if DB is empty
if not BMS_SIGNATURES:
    BMS_SIGNATURES = [
    {
        "id": "jbd",
        "name": "JBD / Xiaoxiang / LLT Power",
        "match": "service_uuid",
        "value": "0000ff00-0000-1000-8000-00805f9b34fb",
        "auth": "none",
        "vuln": "No authentication — anyone in BLE range can read/write",
        "write_uuid": "0000ff02-0000-1000-8000-00805f9b34fb",
        "read_uuid": "0000ff01-0000-1000-8000-00805f9b34fb",
        "test_cmd": bytes([0xDD, 0xA5, 0x03, 0x00, 0xFF, 0xFD, 0x77]),
    },
    {
        "id": "jk",
        "name": "JK-BMS",
        "match": "name_prefix",
        "value": "JK_",
        "alt_value": "JK-",
        "auth": "none",
        "vuln": "No authentication — full read/write access over BLE",
        "service_uuid": "0000ffe0-0000-1000-8000-00805f9b34fb",
    },
    {
        "id": "daly",
        "name": "Daly BMS",
        "match": "name_prefix",
        "value": "DL-",
        "auth": "none",
        "vuln": "No authentication — battery data exposed over BLE",
    },
    {
        "id": "ant",
        "name": "ANT BMS",
        "match": "name_contains",
        "value": "ANT",
        "auth": "none",
        "vuln": "No authentication required",
    },
    {
        "id": "ecoflow",
        "name": "EcoFlow",
        "match": "mfg_id",
        "value": 0xB5B5,
        "auth": "ecdh",
        "vuln_check": True,
    },
    {
        "id": "victron",
        "name": "Victron Energy",
        "match": "mfg_id",
        "value": 0x02E1,
        "auth": "encrypted_adv",
        "vuln": None,  # Encrypted advertisements, not vulnerable
    },
    {
        "id": "renogy",
        "name": "Renogy BMS",
        "match": "name_prefix",
        "value": "BT-TH",
        "auth": "none",
        "vuln": "No authentication — BLE GATT open access",
    },
    {
        "id": "pace",
        "name": "PACE BMS",
        "match": "name_contains",
        "value": "PACE",
        "auth": "none",
        "vuln": "No authentication on GATT services",
    },
    {
        "id": "seplos",
        "name": "Seplos BMS",
        "match": "name_prefix",
        "value": "SP",
        "alt_match": "name_contains",
        "alt_value": "Seplos",
        "auth": "none",
        "vuln": "No authentication — open BLE access",
    },
    {
        "id": "heltec",
        "name": "Heltec / Generic BMS",
        "match": "name_prefix",
        "value": "DP04",
        "auth": "none",
        "vuln": "No authentication — JBD protocol clone, fully open",
    },
    {
        "id": "tian",
        "name": "TianPower BMS",
        "match": "name_contains",
        "value": "Tian",
        "auth": "none",
        "vuln": "No authentication",
    },
    {
        "id": "smart_bms",
        "name": "Smart BMS (Generic)",
        "match": "service_uuid",
        "value": "00010203-0405-0607-0809-0a0b0c0d1912",
        "auth": "none",
        "vuln": "No authentication — generic smart BMS protocol, full access",
    },
]


@dataclass
class ScannedDevice:
    address: str
    name: str
    rssi: int
    protocol: str
    protocol_name: str
    first_seen: float
    last_seen: float
    seen_count: int = 1
    auth_type: str = "unknown"
    vulnerable: bool = False
    vuln_detail: str = ""
    vuln_severity: str = ""
    default_password: str = ""
    tested: bool = False
    test_result: str = ""
    serial: str = ""
    mfg_data: str = ""
    service_uuids: list = field(default_factory=list)
    connectable: bool = False
    brands: list = field(default_factory=list)
    extra: dict = field(default_factory=dict)


class BLEBatteryScanner:
    """Background BLE scanner that identifies battery BMS devices."""

    def __init__(self):
        self.devices: dict[str, ScannedDevice] = {}
        self.scan_count = 0
        self.running = False
        self._lock = threading.Lock()
        self._stop_event = threading.Event()

    def identify_device(self, address, name, adv) -> Optional[dict]:
        """Try to match a BLE advertisement against known BMS signatures."""
        name_lower = (name or "").lower()
        uuids = adv.service_uuids or []
        mfg = adv.manufacturer_data or {}

        for sig in BMS_SIGNATURES:
            matched = False
            match_type = sig["match"]

            if match_type == "service_uuid":
                if sig["value"] in uuids:
                    matched = True
            elif match_type == "name_prefix":
                if name and (name.startswith(sig["value"]) or
                             name.startswith(sig.get("alt_value", "\x00"))):
                    matched = True
            elif match_type == "name_contains":
                if sig["value"].lower() in name_lower:
                    matched = True
            elif match_type == "mfg_id":
                if sig["value"] in mfg:
                    matched = True

            # Check alt match
            if not matched and "alt_match" in sig:
                if sig["alt_match"] == "name_contains":
                    if sig["alt_value"].lower() in name_lower:
                        matched = True

            if matched:
                return sig

        return None

    def parse_ecoflow_adv(self, mfg_data: dict) -> dict:
        """Parse EcoFlow manufacturer data for serial and encrypt type."""
        if 0xB5B5 not in mfg_data:
            return {}
        data = mfg_data[0xB5B5]
        if len(data) < 17:
            return {}
        serial = data[1:17].decode('ascii', errors='replace').rstrip('\x00')
        status = data[17] if len(data) > 17 else 0
        cap = data[22] if len(data) > 22 else 0
        enc_type = (cap & 0b0111000) >> 3
        encrypt = cap & 0b0000001
        return {
            "serial": serial,
            "encrypt_type": enc_type,
            "encrypt": bool(encrypt),
            "active": bool(status & 0x80),
            "vuln": "No encryption (type 0) — data readable without auth" if enc_type == 0
                    else "Simple AES (type 1) — key derivable from serial number" if enc_type == 1
                    else None,
        }

    async def scan_once(self, duration: float = 15):
        """Run one BLE scan cycle."""
        self.scan_count += 1
        now = time.time()

        try:
            devices = await BleakScanner.discover(timeout=duration, return_adv=True)
        except Exception as e:
            log.error("Scan failed: %s", e)
            return

        for addr, (dev, adv) in devices.items():
            name = adv.local_name or dev.name or ""
            sig = self.identify_device(addr, name, adv)
            if sig is None:
                continue

            mfg = adv.manufacturer_data or {}
            mfg_hex = "; ".join(f"0x{k:04X}:{v.hex()}" for k, v in mfg.items()) if mfg else ""

            with self._lock:
                if addr in self.devices:
                    d = self.devices[addr]
                    d.last_seen = now
                    d.seen_count += 1
                    d.rssi = adv.rssi
                    d.name = name or d.name
                else:
                    vuln = sig.get("vuln", "")
                    auth = sig.get("auth", "unknown")

                    # EcoFlow-specific parsing
                    extra = {}
                    serial = ""
                    if sig["id"] == "ecoflow":
                        ef_info = self.parse_ecoflow_adv(mfg)
                        serial = ef_info.get("serial", "")
                        extra = ef_info
                        if ef_info.get("vuln"):
                            vuln = ef_info["vuln"]
                            auth = f"encrypt_type_{ef_info.get('encrypt_type', '?')}"

                    d = ScannedDevice(
                        address=addr,
                        name=name,
                        rssi=adv.rssi,
                        protocol=sig["id"],
                        protocol_name=sig["name"],
                        first_seen=now,
                        last_seen=now,
                        auth_type=auth,
                        vulnerable=bool(vuln),
                        vuln_detail=vuln or "",
                        vuln_severity=sig.get("severity", ""),
                        default_password=sig.get("default_pw") or "",
                        serial=serial,
                        mfg_data=mfg_hex,
                        service_uuids=adv.service_uuids or [],
                        brands=sig.get("brands", []),
                        extra=extra,
                    )
                    self.devices[addr] = d
                    log.info("NEW: %s [%s] %s @ %ddBm %s",
                             name or addr, sig["name"], sig["id"], adv.rssi,
                             f"VULNERABLE: {vuln}" if vuln else "")

    async def test_device(self, addr: str, owned_addrs: set = None) -> str:
        """Device probing disabled in public release for legal compliance.
        To enable, implement your own probe logic for devices you own."""
        return "Probe disabled in public release — see README for details"


    def get_devices(self) -> list[dict]:
        """Get all discovered devices as dicts."""
        with self._lock:
            result = []
            for d in sorted(self.devices.values(), key=lambda x: x.last_seen, reverse=True):
                dd = {
                    "address": d.address,
                    "name": d.name,
                    "rssi": d.rssi,
                    "protocol": d.protocol,
                    "protocol_name": d.protocol_name,
                    "first_seen": datetime.fromtimestamp(d.first_seen).isoformat(),
                    "last_seen": datetime.fromtimestamp(d.last_seen).isoformat(),
                    "age_s": int(time.time() - d.last_seen),
                    "seen_count": d.seen_count,
                    "auth_type": d.auth_type,
                    "vulnerable": d.vulnerable,
                    "vuln_detail": d.vuln_detail,
                    "tested": d.tested,
                    "test_result": d.test_result,
                    "serial": d.serial,
                    "mfg_data": d.mfg_data,
                    "connectable": d.connectable,
                    "vuln_severity": d.vuln_severity,
                    "default_password": d.default_password,
                    "brands": d.brands,
                    "extra": d.extra,
                }
                result.append(dd)
            return result

    def get_stats(self) -> dict:
        """Get scanner statistics."""
        with self._lock:
            total = len(self.devices)
            vuln = sum(1 for d in self.devices.values() if d.vulnerable)
            tested = sum(1 for d in self.devices.values() if d.tested)
            protocols = {}
            for d in self.devices.values():
                protocols[d.protocol_name] = protocols.get(d.protocol_name, 0) + 1
        return {
            "scan_count": self.scan_count,
            "total_devices": total,
            "vulnerable": vuln,
            "tested": tested,
            "protocols": protocols,
            "running": self.running,
        }


def scanner_thread(scanner: BLEBatteryScanner, interval: float = 600, ble_lock=None):
    """Background thread that runs continuous BLE scans."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    scanner.running = True
    scanner._log_callback = None  # Set by server.py

    # Wait for other BLE operations to start first
    scanner._stop_event.wait(60)

    while not scanner._stop_event.is_set():
        try:
            loop.run_until_complete(scanner.scan_once(duration=10))
            # Log results to database after each scan
            if scanner._log_callback:
                scanner._log_callback(scanner.get_devices())
        except Exception as e:
            log.error("Scanner error: %s", e)
        scanner._stop_event.wait(interval)

    scanner.running = False
