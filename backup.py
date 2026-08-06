"""
ShadowGrid Auto-Backup
Detects external storage devices and keeps encrypted backup copies
of critical data (passwords, device registry, EcoFlow credentials).
"""

import hashlib
import json
import os
import shutil
import sqlite3
import time
import threading
import logging
from datetime import datetime
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

log = logging.getLogger("backup")

DB_PATH = Path(__file__).parent / "shadowgrid.db"
BACKUP_INTERVAL = 3600  # Check every hour
BACKUP_FILENAME = "shadowgrid_backup.enc"
BACKUP_DB_FILENAME = "shadowgrid_backup.db"
MANIFEST_FILENAME = "shadowgrid_backup.json"


def find_storage_devices() -> list[dict]:
    """Find mounted external storage — USB drives, SD cards, NAS mounts."""
    found = []

    # Check /media and /mnt for mounted volumes
    for base in ["/media", "/mnt"]:
        if not os.path.exists(base):
            continue
        # /media/<user>/<volume> or /mnt/<volume>
        for root, dirs, files in os.walk(base, topdown=True):
            depth = root.replace(base, "").count(os.sep)
            if depth > 2:
                dirs.clear()
                continue
            if os.path.ismount(root) or (depth >= 1 and os.access(root, os.W_OK)):
                try:
                    stat = os.statvfs(root)
                    free_mb = (stat.f_bavail * stat.f_frsize) / (1024 * 1024)
                    total_mb = (stat.f_blocks * stat.f_frsize) / (1024 * 1024)
                    if free_mb > 1:  # At least 1MB free
                        found.append({
                            "path": root,
                            "free_mb": round(free_mb, 1),
                            "total_mb": round(total_mb, 1),
                            "type": "usb/mount",
                        })
                        dirs.clear()  # Don't descend further
                except OSError:
                    pass

    # Check for common NAS/network mount points
    try:
        with open("/proc/mounts") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3:
                    device, mount, fstype = parts[0], parts[1], parts[2]
                    if fstype in ("nfs", "nfs4", "cifs", "smbfs", "fuse.sshfs"):
                        if os.access(mount, os.W_OK):
                            try:
                                stat = os.statvfs(mount)
                                free_mb = (stat.f_bavail * stat.f_frsize) / (1024 * 1024)
                                total_mb = (stat.f_blocks * stat.f_frsize) / (1024 * 1024)
                                found.append({
                                    "path": mount,
                                    "free_mb": round(free_mb, 1),
                                    "total_mb": round(total_mb, 1),
                                    "type": fstype,
                                })
                            except OSError:
                                pass
    except Exception:
        pass

    # Also check home directory for a Backups folder
    home_backup = Path.home() / "ShadowGrid-Backups"
    if home_backup.exists() and os.access(str(home_backup), os.W_OK):
        found.append({
            "path": str(home_backup),
            "free_mb": round(shutil.disk_usage(str(home_backup)).free / (1024*1024), 1),
            "total_mb": round(shutil.disk_usage(str(home_backup)).total / (1024*1024), 1),
            "type": "local",
        })

    return found


def derive_key(passphrase: str) -> bytes:
    """Derive a 256-bit AES key from a passphrase using PBKDF2."""
    # Use a fixed salt derived from the machine ID for consistency
    machine_id = "shadowgrid-default"
    try:
        with open("/etc/machine-id") as f:
            machine_id = f.read().strip()
    except Exception:
        pass
    return hashlib.pbkdf2_hmac('sha256', passphrase.encode(), machine_id.encode(), 100000)


def encrypt_data(data: bytes, key: bytes) -> bytes:
    """AES-256-CBC encrypt with random IV prepended."""
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(data, AES.block_size))


def decrypt_data(encrypted: bytes, key: bytes) -> bytes:
    """AES-256-CBC decrypt (IV is first 16 bytes)."""
    iv = encrypted[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(encrypted[16:]), AES.block_size)


def get_critical_data() -> dict:
    """Extract all critical data that needs backing up."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row

    # Device registry
    devices = [dict(r) for r in conn.execute("SELECT * FROM devices").fetchall()]

    # BMS passwords (current)
    passwords = [dict(r) for r in conn.execute(
        "SELECT * FROM bms_current_password").fetchall()]

    # BMS password history
    pw_history = [dict(r) for r in conn.execute(
        "SELECT * FROM bms_passwords ORDER BY timestamp DESC").fetchall()]

    # Auth settings (secret key, password hash)
    auth = [dict(r) for r in conn.execute("SELECT * FROM auth").fetchall()]

    # Victron keys (if table exists)
    victron_keys = []
    try:
        victron_keys = [dict(r) for r in conn.execute(
            "SELECT * FROM victron_keys").fetchall()]
    except Exception:
        pass

    conn.close()

    # Also grab victron_keys.json if it exists
    vk_file = Path(__file__).parent / "victron_keys.json"
    vk_json = {}
    if vk_file.exists():
        try:
            with open(vk_file) as f:
                vk_json = json.load(f)
        except Exception:
            pass

    return {
        "exported": datetime.now().isoformat(),
        "version": "1.0",
        "devices": devices,
        "bms_passwords": passwords,
        "bms_password_history": pw_history,
        "auth_settings": auth,
        "victron_keys_db": victron_keys,
        "victron_keys_file": vk_json,
    }


def backup_to_path(target_dir: str, passphrase: str = "") -> dict:
    """Run a backup to a specific directory. Returns status dict."""
    try:
        os.makedirs(target_dir, exist_ok=True)
        backup_dir = os.path.join(target_dir, "ShadowGrid-Backup")
        os.makedirs(backup_dir, exist_ok=True)

        data = get_critical_data()
        data_json = json.dumps(data, indent=2).encode()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if passphrase:
            # Encrypted backup
            key = derive_key(passphrase)
            encrypted = encrypt_data(data_json, key)
            backup_file = os.path.join(backup_dir, f"backup_{timestamp}.enc")
            with open(backup_file, "wb") as f:
                f.write(encrypted)
            # Also keep latest as known filename
            latest = os.path.join(backup_dir, BACKUP_FILENAME)
            with open(latest, "wb") as f:
                f.write(encrypted)
        else:
            # Unencrypted JSON backup
            backup_file = os.path.join(backup_dir, f"backup_{timestamp}.json")
            with open(backup_file, "w") as f:
                f.write(data_json.decode())
            latest = os.path.join(backup_dir, MANIFEST_FILENAME)
            with open(latest, "w") as f:
                f.write(data_json.decode())

        # Also copy the raw database
        db_backup = os.path.join(backup_dir, BACKUP_DB_FILENAME)
        shutil.copy2(str(DB_PATH), db_backup)

        # Write manifest
        manifest = {
            "timestamp": datetime.now().isoformat(),
            "backup_file": os.path.basename(backup_file),
            "encrypted": bool(passphrase),
            "db_copy": BACKUP_DB_FILENAME,
            "devices": len(data["devices"]),
            "passwords": len(data["bms_passwords"]),
            "history_entries": len(data["bms_password_history"]),
        }
        with open(os.path.join(backup_dir, "manifest.json"), "w") as f:
            json.dump(manifest, f, indent=2)

        # Prune old backups (keep last 10)
        backups = sorted([f for f in os.listdir(backup_dir)
                         if f.startswith("backup_") and (f.endswith(".enc") or f.endswith(".json"))])
        while len(backups) > 10:
            os.remove(os.path.join(backup_dir, backups.pop(0)))

        log.info("Backup to %s: %d devices, %d passwords", target_dir,
                 len(data["devices"]), len(data["bms_passwords"]))

        return {
            "success": True,
            "path": backup_dir,
            "file": os.path.basename(backup_file),
            "encrypted": bool(passphrase),
            "devices": len(data["devices"]),
            "passwords": len(data["bms_passwords"]),
            "timestamp": manifest["timestamp"],
        }

    except Exception as e:
        log.error("Backup failed to %s: %s", target_dir, e)
        return {"success": False, "error": str(e), "path": target_dir}


def restore_from_file(filepath: str, passphrase: str = "") -> dict:
    """Restore critical data from a backup file."""
    try:
        with open(filepath, "rb") as f:
            raw = f.read()

        if passphrase:
            key = derive_key(passphrase)
            data_json = decrypt_data(raw, key)
        else:
            data_json = raw

        data = json.loads(data_json)

        conn = sqlite3.connect(str(DB_PATH))

        # Restore devices
        for d in data.get("devices", []):
            try:
                conn.execute(
                    "INSERT OR REPLACE INTO devices (address, label, device_type, protocol, enabled, config, added) VALUES (?,?,?,?,?,?,?)",
                    (d["address"], d["label"], d["device_type"], d.get("protocol"),
                     d.get("enabled", 1), d.get("config", "{}"), d.get("added", datetime.now().isoformat())))
            except Exception:
                pass

        # Restore passwords
        for p in data.get("bms_passwords", []):
            try:
                conn.execute("INSERT OR REPLACE INTO bms_current_password (address, password) VALUES (?,?)",
                             (p["address"], p["password"]))
            except Exception:
                pass

        # Restore password history
        for h in data.get("bms_password_history", []):
            try:
                conn.execute(
                    "INSERT OR IGNORE INTO bms_passwords (timestamp, address, label, old_password, new_password, success) VALUES (?,?,?,?,?,?)",
                    (h["timestamp"], h["address"], h.get("label", ""),
                     h["old_password"], h["new_password"], h.get("success", 0)))
            except Exception:
                pass

        conn.commit()
        conn.close()

        return {
            "success": True,
            "devices": len(data.get("devices", [])),
            "passwords": len(data.get("bms_passwords", [])),
            "history": len(data.get("bms_password_history", [])),
        }

    except Exception as e:
        return {"success": False, "error": str(e)}


# Track backup status
_backup_status = {"last_backup": None, "targets": [], "results": []}


def auto_backup_thread(passphrase: str = ""):
    """Background thread that periodically backs up to all available storage."""
    global _backup_status
    while True:
        time.sleep(60)  # Initial delay
        targets = find_storage_devices()
        _backup_status["targets"] = targets

        if targets:
            results = []
            for t in targets:
                result = backup_to_path(t["path"], passphrase)
                results.append(result)
            _backup_status["results"] = results
            _backup_status["last_backup"] = datetime.now().isoformat()

        time.sleep(BACKUP_INTERVAL)


def get_backup_status() -> dict:
    return dict(_backup_status)
