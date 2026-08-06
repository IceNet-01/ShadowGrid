#!/usr/bin/env python3
"""
ShadowGrid BMS Scanner
Continuously scans for Eco Worthy / JBD BMS battery packs via BLE.
Detects BATT_xxxx, BWOB_xxxx, ECO_xxxx patterns and JBD UUID 0xFF00.
"""

import asyncio
import sys
from datetime import datetime
from bleak import BleakScanner, BleakClient

# JBD BMS BLE UUIDs
JBD_SERVICE_UUID = "0000ff00-0000-1000-8000-00805f9b34fb"
JBD_RX_CHAR = "0000ff01-0000-1000-8000-00805f9b34fb"  # Notify
JBD_TX_CHAR = "0000ff02-0000-1000-8000-00805f9b34fb"  # Write

# JBD commands
CMD_BASIC_INFO = bytes([0xDD, 0xA5, 0x03, 0x00, 0xFF, 0xFD, 0x77])
CMD_CELL_VOLTAGES = bytes([0xDD, 0xA5, 0x04, 0x00, 0xFF, 0xFC, 0x77])

# Name patterns for Eco Worthy / JBD BMS
BMS_NAME_PATTERNS = ['batt_', 'bwob_', 'eco', 'bms', 'jbd', 'xiaoxiang', 'sp1']

# Known battery addresses
KNOWN_BATTERIES = {
    "AA:BB:CC:DD:EE:01": "BATT_FFA9",
    "AA:BB:CC:DD:EE:02": "BATT_09D2",
}

# JBD factory mode password (default: 0x5678)
ENTER_FACTORY = bytes([0xDD, 0x5A, 0x00, 0x02, 0x56, 0x78, 0xFF, 0x30, 0x77])
EXIT_FACTORY = bytes([0xDD, 0x5A, 0x01, 0x02, 0x00, 0x00, 0xFF, 0xFD, 0x77])

class BMSDevice:
    def __init__(self, address, name, rssi):
        self.address = address
        self.name = name
        self.rssi = rssi
        self.data = bytearray()

    def __repr__(self):
        return f"BMSDevice({self.name}, {self.address}, {self.rssi}dBm)"


def parse_basic_info(data: bytes) -> dict:
    """Parse JBD basic info response (command 0x03)."""
    if len(data) < 23 or data[0] != 0xDD or data[2] != 0x00:
        return {"error": "Invalid response", "raw": data.hex()}

    info = {}
    d = data[4:-3]  # Strip header and checksum/footer

    if len(d) >= 23:
        info["total_voltage"] = ((d[0] << 8) | d[1]) * 0.01  # V
        raw_current = (d[2] << 8) | d[3]
        info["current"] = (raw_current - 65536 if raw_current > 32767 else raw_current) * 0.01  # A
        info["remaining_capacity"] = ((d[4] << 8) | d[5]) * 0.01  # Ah
        info["nominal_capacity"] = ((d[6] << 8) | d[7]) * 0.01  # Ah
        info["cycle_count"] = (d[8] << 8) | d[9]
        info["production_date"] = (d[10] << 8) | d[11]
        info["balance_status"] = (d[12] << 8) | d[13]
        info["balance_status_hi"] = (d[14] << 8) | d[15]
        info["protection_status"] = (d[16] << 8) | d[17]
        info["software_version"] = d[18]
        info["soc"] = d[19]  # %
        info["fet_status"] = d[20]
        info["cell_count"] = d[21]
        info["ntc_count"] = d[22]

        # Parse NTC temperatures
        temps = []
        for i in range(info["ntc_count"]):
            idx = 23 + i * 2
            if idx + 1 < len(d):
                raw_temp = (d[idx] << 8) | d[idx + 1]
                temps.append((raw_temp - 2731) / 10.0)  # Convert to °C
        info["temperatures"] = temps

    return info


def parse_cell_voltages(data: bytes) -> list:
    """Parse JBD cell voltage response (command 0x04)."""
    if len(data) < 7 or data[0] != 0xDD or data[2] != 0x00:
        return []

    d = data[4:-3]
    voltages = []
    for i in range(0, len(d), 2):
        if i + 1 < len(d):
            mv = (d[i] << 8) | d[i + 1]
            voltages.append(mv / 1000.0)
    return voltages


async def read_bms(address: str) -> dict:
    """Connect to a JBD BMS and read battery data."""
    result = {"address": address}

    try:
        async with BleakClient(address, timeout=10) as client:
            response_data = bytearray()
            event = asyncio.Event()

            def notification_handler(sender, data):
                response_data.extend(data)
                if len(response_data) >= 4 and response_data[-1] == 0x77:
                    event.set()

            await client.start_notify(JBD_RX_CHAR, notification_handler)

            # Read basic info
            response_data.clear()
            event.clear()
            await client.write_gatt_char(JBD_TX_CHAR, CMD_BASIC_INFO)
            try:
                await asyncio.wait_for(event.wait(), timeout=5)
                result["basic_info"] = parse_basic_info(bytes(response_data))
            except asyncio.TimeoutError:
                result["basic_info"] = {"error": "Timeout waiting for response"}

            # Read cell voltages
            response_data.clear()
            event.clear()
            await client.write_gatt_char(JBD_TX_CHAR, CMD_CELL_VOLTAGES)
            try:
                await asyncio.wait_for(event.wait(), timeout=5)
                result["cell_voltages"] = parse_cell_voltages(bytes(response_data))
            except asyncio.TimeoutError:
                result["cell_voltages"] = []

            await client.stop_notify(JBD_RX_CHAR)

    except Exception as e:
        result["error"] = str(e)

    return result


def is_bms_device(name: str, uuids: list) -> bool:
    """Check if a device looks like a BMS."""
    if name:
        name_lower = name.lower()
        if any(p in name_lower for p in BMS_NAME_PATTERNS):
            return True
    if uuids:
        if JBD_SERVICE_UUID in [u.lower() for u in uuids]:
            return True
    return False


async def scan_and_read(scan_duration: int = 15, connect: bool = True):
    """Scan for BMS devices and optionally connect to read data."""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Scanning for BMS devices ({scan_duration}s)...")

    devices = await BleakScanner.discover(timeout=scan_duration, return_adv=True)

    bms_devices = []
    print(f"\nFound {len(devices)} total BLE devices:")
    for addr, (device, adv) in sorted(devices.items(), key=lambda x: x[1][1].rssi, reverse=True):
        name = adv.local_name or device.name or "Unknown"
        uuids = adv.service_uuids or []
        is_bms = is_bms_device(name, uuids)
        marker = " <<< BMS" if is_bms else ""
        print(f"  {adv.rssi:4d} dBm | {addr} | {name}{marker}")
        if is_bms:
            bms_devices.append(BMSDevice(addr, name, adv.rssi))

    if not bms_devices:
        print("\nNo BMS devices detected.")
        print("Tips:")
        print("  - Press button on battery pack to wake BLE")
        print("  - Connect a load or charger to wake the BMS")
        print("  - Move BLE dongle closer to the batteries")
        print("  - Run again: python3 scan_bms.py --loop")
        return []

    print(f"\n{'='*60}")
    print(f"Found {len(bms_devices)} BMS device(s)!")
    print(f"{'='*60}")

    if connect:
        for bms in bms_devices:
            print(f"\nConnecting to {bms.name} ({bms.address})...")
            data = await read_bms(bms.address)

            if "error" in data:
                print(f"  Connection error: {data['error']}")
                continue

            info = data.get("basic_info", {})
            if "error" not in info:
                print(f"  Total Voltage:  {info.get('total_voltage', '?')} V")
                print(f"  Current:        {info.get('current', '?')} A")
                print(f"  SOC:            {info.get('soc', '?')}%")
                print(f"  Capacity:       {info.get('remaining_capacity', '?')} / {info.get('nominal_capacity', '?')} Ah")
                print(f"  Cycle Count:    {info.get('cycle_count', '?')}")
                print(f"  Cell Count:     {info.get('cell_count', '?')}")
                print(f"  Temperatures:   {info.get('temperatures', [])}")
                print(f"  FET Status:     {info.get('fet_status', '?')}")
                print(f"  Protection:     {info.get('protection_status', '?')}")
            else:
                print(f"  Parse error: {info['error']}")

            cells = data.get("cell_voltages", [])
            if cells:
                print(f"  Cell Voltages:  {cells}")
                print(f"  Cell Delta:     {(max(cells) - min(cells))*1000:.0f} mV")

    return bms_devices


async def loop_scan(interval: int = 30):
    """Continuously scan for BMS devices."""
    print("Continuous BMS scan mode. Ctrl+C to stop.\n")
    while True:
        try:
            await scan_and_read(scan_duration=10)
            print(f"\nNext scan in {interval}s...\n")
            await asyncio.sleep(interval)
        except KeyboardInterrupt:
            break


if __name__ == "__main__":
    if "--loop" in sys.argv:
        asyncio.run(loop_scan())
    else:
        asyncio.run(scan_and_read())
