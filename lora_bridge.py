#!/usr/bin/env python3
"""
ShadowGrid LoRa Bridge
Reads JSON packets from ESP32 base receiver via USB serial.
Provides data to server.py as an alternative/supplementary data source.
"""

import glob
import json
import serial
import threading
import time
from datetime import datetime, timedelta


class LoraBridge:
    """Reads ShadowGrid LoRa packets from ESP32 base unit via serial."""

    def __init__(self):
        self.port = None
        self.serial = None
        self.running = False
        self.latest_data = {}
        self.latest_lora = {"rssi": None, "snr": None, "last_rx": None}
        self.callbacks = []
        self._lock = threading.Lock()

    def on_data(self, callback):
        self.callbacks.append(callback)

    def find_base_unit(self):
        """Find the ShadowGrid base unit on serial ports."""
        candidates = glob.glob("/dev/ttyACM*") + glob.glob("/dev/ttyUSB*")
        for port in candidates:
            try:
                ser = serial.Serial(port, 115200, timeout=3)
                time.sleep(1)
                # Read for up to 25 seconds (LoRa packets come every ~20s)
                deadline = time.time() + 25
                while time.time() < deadline:
                    if ser.in_waiting:
                        line = ser.readline().decode("utf-8", errors="replace").strip()
                        # Match boot message OR incoming LoRa data packets
                        if "shadowgrid_base" in line or '"node":{' in line or '"lora":{' in line:
                            print(f"[LoRa Bridge] Found base unit on {port}")
                            self.port = port
                            ser.close()
                            return port
                    else:
                        time.sleep(0.1)
                ser.close()
            except (serial.SerialException, OSError):
                continue
        return None

    def connect(self, port=None):
        """Connect to the base unit."""
        if port:
            self.port = port
        elif not self.port:
            self.find_base_unit()

        if not self.port:
            return False

        try:
            self.serial = serial.Serial(self.port, 115200, timeout=1)
            self.running = True
            print(f"[LoRa Bridge] Connected to {self.port}")
            return True
        except serial.SerialException as e:
            print(f"[LoRa Bridge] Connection failed: {e}")
            return False

    def read_loop(self):
        """Read and parse serial data continuously."""
        while self.running and self.serial:
            try:
                if self.serial.in_waiting:
                    line = self.serial.readline().decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    self._process_line(line)
            except serial.SerialException:
                print("[LoRa Bridge] Serial disconnected, reconnecting...")
                time.sleep(5)
                self.connect()
            except Exception as e:
                print(f"[LoRa Bridge] Error: {e}")
                time.sleep(1)

    def _process_line(self, line):
        """Process a JSON line from the base unit."""
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            return

        # Base unit startup message
        if msg.get("status") == "ready":
            print(f"[LoRa Bridge] Base unit ready (freq: {msg.get('freq')}MHz)")
            return

        # LoRa error
        if "lora_error" in msg:
            return

        # Data packet from remote unit
        lora_meta = msg.get("lora", {})
        data = msg.get("data", {})

        if data.get("t") != "sg":
            return  # Not a ShadowGrid packet

        with self._lock:
            self.latest_lora = {
                "rssi": lora_meta.get("rssi"),
                "snr": lora_meta.get("snr"),
                "len": lora_meta.get("len"),
                "last_rx": datetime.now().isoformat(),
            }

            # Parse battery data with timestamps
            pkt_ts = data.get("ts")  # Unix timestamp from mobile node (GPS or manual)
            pkt_up = data.get("up", 0)  # Uptime seconds

            batteries = {}
            for b in data.get("b", []):
                name = b.get("n", "")
                read_age = int(b.get("age", 0))  # How old this BLE read is in seconds

                # Calculate reading timestamp
                if pkt_ts:
                    # Mobile node has wall clock — use it minus read age
                    read_ts = datetime.fromtimestamp(pkt_ts - read_age).isoformat()
                else:
                    # No wall clock — use server time minus read age
                    read_ts = (datetime.now() - timedelta(seconds=read_age)).isoformat()

                batteries[name] = {
                    "label": f"BATT_{name}",
                    "voltage": float(b.get("v", 0)),
                    "current": float(b.get("i", 0)),
                    "soc": int(b.get("s", 0)),
                    "remain": float(b.get("r", 0)),
                    "temp": float(b.get("t", 0)),
                    "cell_delta": int(b.get("d", 0)),
                    "cells": [float(c) for c in b.get("c", [])],
                    "online": True,
                    "source": "lora",
                    "read_age": read_age,
                    "timestamp": read_ts,
                    "node_time": pkt_ts,
                }

            # Parse Victron data
            victron_devices = {}
            for v in data.get("v", []):
                victron_devices[v.get("n", "unknown")] = {
                    "name": v.get("n"),
                    "device_type": v.get("dt"),
                    "model_id": v.get("m"),
                    "rssi": v.get("r"),
                    "adv_hex": v.get("d"),
                    "source": "lora",
                }

            self.latest_data = {
                "batteries": batteries,
                "victron": victron_devices,
                "lora": self.latest_lora,
                "timestamp": datetime.now().isoformat(),
            }

        # Notify callbacks
        for cb in self.callbacks:
            try:
                cb(self.latest_data)
            except Exception:
                pass

        # Track node info from base station
        node_info = msg.get("node", {})
        self.latest_data["node"] = node_info

        print(f"[LoRa] RX node {node_info.get('id','?')}: {len(batteries)} batts, {len(victron_devices)} victron "
              f"(RSSI: {lora_meta.get('rssi')}dBm, SNR: {lora_meta.get('snr')}dB, "
              f"seq #{node_info.get('seq',0)}, drops: {node_info.get('drop_count',0)})")

    def get_latest(self):
        with self._lock:
            return dict(self.latest_data)

    def start_background(self):
        """Start reading in background thread."""
        if not self.connect():
            return False
        thread = threading.Thread(target=self.read_loop, daemon=True)
        thread.start()
        return True

    def stop(self):
        self.running = False
        if self.serial:
            try:
                self.serial.close()
            except Exception:
                pass


# Standalone test
if __name__ == "__main__":
    bridge = LoraBridge()
    port = bridge.find_base_unit()
    if not port:
        print("No base unit found. Listing serial ports:")
        for p in glob.glob("/dev/ttyACM*") + glob.glob("/dev/ttyUSB*"):
            print(f"  {p}")
        print("\nUsage: python3 lora_bridge.py")
        exit(1)

    bridge.on_data(lambda d: print(json.dumps(d, indent=2)))

    if bridge.connect():
        try:
            bridge.read_loop()
        except KeyboardInterrupt:
            bridge.stop()
