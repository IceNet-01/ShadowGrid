#!/usr/bin/env python3
"""
ShadowGrid Meter Reader
Reads utility smart meter data via RTL-SDR + rtlamr.
Supports ERT/SCM/SCM+ protocols used by Nodak Electric and most US co-ops.

Usage:
  Auto-detect:  python3 meter_reader.py
  With meter ID: python3 meter_reader.py --meter-id 12345678
  List meters:  python3 meter_reader.py --discover
"""

import json
import os
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).parent / "shadowgrid.db"
CONFIG_PATH = Path(__file__).parent / "meter_config.json"

# ── Config ─────────────────────────────────────────────────────────────────

class MeterConfig:
    def __init__(self):
        self.meter_ids = []  # Filter to these meter IDs (empty = all)
        self.msg_types = "scm,scm+,idm"
        self.rtlamr_path = None
        self.rtl_tcp_path = "rtl_tcp"
        self.center_freq = 912380000  # 912.38 MHz
        self.sample_rate = 2400000
        self.gain = "auto"
        self._load()

    def _load(self):
        try:
            with open(CONFIG_PATH) as f:
                d = json.load(f)
                self.meter_ids = d.get("meter_ids", [])
                self.msg_types = d.get("msg_types", self.msg_types)
                if d.get("rtlamr_path"):
                    self.rtlamr_path = d["rtlamr_path"]
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    def save(self):
        with open(CONFIG_PATH, "w") as f:
            json.dump({
                "meter_ids": self.meter_ids,
                "msg_types": self.msg_types,
                "rtlamr_path": self.rtlamr_path,
            }, f, indent=2)

    def set_meter_id(self, meter_id):
        if meter_id not in self.meter_ids:
            self.meter_ids.append(meter_id)
            self.save()


# ── Database ───────────────────────────────────────────────────────────────

def init_meter_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS meter_readings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            meter_id TEXT NOT NULL,
            meter_type INTEGER,
            consumption INTEGER,
            msg_type TEXT,
            raw TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_meter_ts ON meter_readings(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_meter_id ON meter_readings(meter_id)")
    conn.commit()
    conn.close()


def log_meter_reading(meter_id, meter_type, consumption, msg_type, raw):
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute(
        "INSERT INTO meter_readings (timestamp, meter_id, meter_type, consumption, msg_type, raw) VALUES (?,?,?,?,?,?)",
        (datetime.now().isoformat(), str(meter_id), meter_type, consumption, msg_type, json.dumps(raw)),
    )
    conn.commit()
    conn.close()


def get_latest_reading(meter_id=None):
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    if meter_id:
        row = conn.execute(
            "SELECT * FROM meter_readings WHERE meter_id=? ORDER BY id DESC LIMIT 1",
            (str(meter_id),)
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT * FROM meter_readings ORDER BY id DESC LIMIT 1"
        ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_power_estimate(meter_id=None):
    """Estimate current power draw from consecutive meter readings."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    if meter_id:
        rows = conn.execute(
            "SELECT * FROM meter_readings WHERE meter_id=? ORDER BY id DESC LIMIT 2",
            (str(meter_id),)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM meter_readings ORDER BY id DESC LIMIT 2"
        ).fetchall()
    conn.close()

    if len(rows) < 2:
        return None

    r1, r2 = rows[0], rows[1]  # r1 is newer
    dt = (datetime.fromisoformat(r1["timestamp"]) - datetime.fromisoformat(r2["timestamp"])).total_seconds()
    if dt <= 0:
        return None

    delta_wh = r1["consumption"] - r2["consumption"]  # Usually in Wh
    power_w = delta_wh / (dt / 3600)  # Convert to watts

    return {
        "power_w": round(power_w, 1),
        "delta_wh": delta_wh,
        "interval_s": round(dt, 1),
        "consumption": r1["consumption"],
        "timestamp": r1["timestamp"],
    }


# ── RTL-SDR Detection ─────────────────────────────────────────────────────

def detect_rtlsdr():
    """Check if an RTL-SDR dongle is connected."""
    try:
        result = subprocess.run(
            ["rtl_test", "-t"],
            capture_output=True, text=True, timeout=5
        )
        return "Found" in result.stderr or "Found" in result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Fallback: check USB devices
    try:
        result = subprocess.run(["lsusb"], capture_output=True, text=True, timeout=5)
        rtl_vendors = ["0bda:2832", "0bda:2838", "0bda:2834"]
        return any(v in result.stdout for v in rtl_vendors)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def find_rtlamr():
    """Find rtlamr binary, install if needed."""
    # Check common locations
    for path in ["/usr/local/bin/rtlamr", "/usr/bin/rtlamr",
                 os.path.expanduser("~/go/bin/rtlamr"),
                 os.path.expanduser("~/.local/bin/rtlamr")]:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path

    # Check PATH
    try:
        result = subprocess.run(["which", "rtlamr"], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.strip()
    except FileNotFoundError:
        pass

    return None


def install_rtlamr():
    """Attempt to install rtlamr."""
    print("rtlamr not found. Attempting to install...")

    # Try downloading pre-built binary
    import platform
    arch = platform.machine()
    if arch == "x86_64":
        arch = "amd64"
    elif arch == "aarch64":
        arch = "arm64"

    url = f"https://github.com/bemasher/rtlamr/releases/latest/download/rtlamr_linux_{arch}"
    dest = os.path.expanduser("~/.local/bin/rtlamr")
    os.makedirs(os.path.dirname(dest), exist_ok=True)

    try:
        subprocess.run(
            ["wget", "-q", "-O", dest, url],
            check=True, timeout=30
        )
        os.chmod(dest, 0o755)
        print(f"Installed rtlamr to {dest}")
        return dest
    except Exception as e:
        print(f"Failed to download rtlamr: {e}")

    # Try Go install
    try:
        go_path = subprocess.run(["which", "go"], capture_output=True, text=True).stdout.strip()
        if go_path:
            subprocess.run(
                ["go", "install", "github.com/bemasher/rtlamr@latest"],
                check=True, timeout=120
            )
            return os.path.expanduser("~/go/bin/rtlamr")
    except Exception:
        pass

    print("Could not install rtlamr. Install Go and run: go install github.com/bemasher/rtlamr@latest")
    return None


# ── RTL-AMR Reader ─────────────────────────────────────────────────────────

class MeterReader:
    """Reads smart meter data via rtl_tcp + rtlamr."""

    def __init__(self, config=None):
        self.config = config or MeterConfig()
        self.rtl_tcp_proc = None
        self.rtlamr_proc = None
        self.running = False
        self.latest = {}
        self.callbacks = []
        self._lock = threading.Lock()

    def on_reading(self, callback):
        self.callbacks.append(callback)

    def _start_rtl_tcp(self):
        """Start rtl_tcp server for rtlamr to connect to."""
        try:
            self.rtl_tcp_proc = subprocess.Popen(
                [self.config.rtl_tcp_path, "-a", "127.0.0.1", "-p", "1234"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(2)  # Wait for rtl_tcp to start
            return True
        except Exception as e:
            print(f"Failed to start rtl_tcp: {e}")
            return False

    def _parse_line(self, line):
        """Parse a JSON line from rtlamr output."""
        try:
            data = json.loads(line)
            msg = data.get("Message", {})
            msg_type = data.get("Type", "unknown")

            meter_id = msg.get("ID") or msg.get("EndpointID") or msg.get("ERTSerialNumber")
            consumption = msg.get("Consumption") or msg.get("LastConsumptionCount")
            meter_type = msg.get("Type") or msg.get("EndpointType")

            if meter_id is None:
                return None

            meter_id = str(meter_id)

            # Filter by configured meter IDs
            if self.config.meter_ids and meter_id not in [str(m) for m in self.config.meter_ids]:
                return None

            reading = {
                "meter_id": meter_id,
                "meter_type": meter_type,
                "consumption": consumption,
                "msg_type": msg_type,
                "timestamp": data.get("Time", datetime.now().isoformat()),
                "raw": msg,
            }

            with self._lock:
                self.latest[meter_id] = reading

            # Log to DB
            log_meter_reading(meter_id, meter_type, consumption, msg_type, msg)

            # Notify callbacks
            for cb in self.callbacks:
                try:
                    cb(reading)
                except Exception:
                    pass

            return reading

        except (json.JSONDecodeError, KeyError, TypeError):
            return None

    def start(self):
        """Start reading meter data."""
        rtlamr_path = self.config.rtlamr_path or find_rtlamr()
        if not rtlamr_path:
            rtlamr_path = install_rtlamr()
        if not rtlamr_path:
            print("ERROR: rtlamr not available")
            return False

        self.config.rtlamr_path = rtlamr_path

        if not self._start_rtl_tcp():
            return False

        # Build rtlamr command
        cmd = [
            rtlamr_path,
            "-format=json",
            f"-msgtype={self.config.msg_types}",
            "-unique=true",
        ]

        if self.config.meter_ids:
            ids = ",".join(str(m) for m in self.config.meter_ids)
            cmd.append(f"-filterid={ids}")

        try:
            self.rtlamr_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
            self.running = True
            print(f"Meter reader started (rtlamr: {rtlamr_path})")
            return True
        except Exception as e:
            print(f"Failed to start rtlamr: {e}")
            self.stop()
            return False

    def read_loop(self):
        """Block and read meter data continuously."""
        if not self.rtlamr_proc:
            return

        try:
            for line in self.rtlamr_proc.stdout:
                if not self.running:
                    break
                line = line.strip()
                if line:
                    reading = self._parse_line(line)
                    if reading:
                        print(f"[METER] {reading['meter_id']}: {reading['consumption']} ({reading['msg_type']})")
        except Exception as e:
            print(f"Meter read error: {e}")
        finally:
            self.running = False

    def start_background(self):
        """Start reading in a background thread."""
        if not self.start():
            return False
        thread = threading.Thread(target=self.read_loop, daemon=True)
        thread.start()
        return True

    def stop(self):
        """Stop all processes."""
        self.running = False
        for proc in [self.rtlamr_proc, self.rtl_tcp_proc]:
            if proc:
                try:
                    proc.terminate()
                    proc.wait(timeout=5)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
        self.rtlamr_proc = None
        self.rtl_tcp_proc = None

    def get_latest(self):
        with self._lock:
            return dict(self.latest)


# ── Main (standalone) ──────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="ShadowGrid Meter Reader")
    parser.add_argument("--meter-id", help="Filter to specific meter ID")
    parser.add_argument("--discover", action="store_true", help="Discover all meters (no filter)")
    parser.add_argument("--set-meter", help="Save meter ID to config")
    args = parser.parse_args()

    init_meter_db()
    config = MeterConfig()

    if args.set_meter:
        config.set_meter_id(args.set_meter)
        print(f"Saved meter ID: {args.set_meter}")
        print(f"Config: {CONFIG_PATH}")
        return

    if not detect_rtlsdr():
        print("No RTL-SDR dongle detected.")
        print("Plug in an RTL-SDR USB dongle and try again.")
        return

    print("RTL-SDR detected!")

    if args.meter_id:
        config.meter_ids = [args.meter_id]
    elif args.discover:
        config.meter_ids = []  # Accept all
        print("Discovery mode — showing ALL meters. Press Ctrl+C to stop.")

    reader = MeterReader(config)

    def on_reading(r):
        power = get_power_estimate(r["meter_id"])
        if power:
            print(f"  Estimated power: {power['power_w']} W")

    reader.on_reading(on_reading)

    if not reader.start():
        return

    try:
        reader.read_loop()
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        reader.stop()

    # Show discovered meters
    latest = reader.get_latest()
    if latest:
        print(f"\nDiscovered {len(latest)} meter(s):")
        for mid, data in latest.items():
            print(f"  ID: {mid}  Type: {data['meter_type']}  Reading: {data['consumption']}")
        print(f"\nTo lock to your meter: python3 meter_reader.py --set-meter YOUR_METER_ID")


if __name__ == "__main__":
    main()
