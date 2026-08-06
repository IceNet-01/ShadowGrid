#!/usr/bin/env python3
"""
ShadowGrid Alert System
Monitors battery and system conditions, generates alerts.
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).parent / "shadowgrid.db"

# Alert severity levels
CRITICAL = "critical"
WARNING = "warning"
INFO = "info"

# Alert rules
RULES = {
    "low_soc": {
        "severity": CRITICAL,
        "threshold": 15,
        "message": "{label} SOC critically low: {soc}%",
        "cooldown": 300,
    },
    "warn_soc": {
        "severity": WARNING,
        "threshold": 25,
        "message": "{label} SOC low: {soc}%",
        "cooldown": 600,
    },
    "high_temp": {
        "severity": WARNING,
        "threshold": 45,
        "message": "{label} temperature high: {temp}C",
        "cooldown": 300,
    },
    "cell_imbalance": {
        "severity": WARNING,
        "threshold": 50,  # mV
        "message": "{label} cell imbalance: {delta}mV",
        "cooldown": 600,
    },
    "protection_trip": {
        "severity": CRITICAL,
        "message": "{label} protection tripped: {flags}",
        "cooldown": 60,
    },
    "battery_offline": {
        "severity": WARNING,
        "message": "{label} went offline",
        "cooldown": 300,
    },
    "charger_error": {
        "severity": CRITICAL,
        "message": "{device} charger error: {error}",
        "cooldown": 120,
    },
}


def init_alerts_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            rule TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL,
            source TEXT,
            acknowledged INTEGER DEFAULT 0
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp)")
    conn.commit()
    conn.close()


# Track last alert time per rule+source to implement cooldowns
_last_alert = {}


def fire_alert(rule_name, source="", **kwargs):
    """Fire an alert if cooldown has passed."""
    rule = RULES.get(rule_name)
    if not rule:
        return None

    key = f"{rule_name}:{source}"
    now = datetime.now()

    # Check cooldown
    cooldown = rule.get("cooldown", 60)
    if key in _last_alert:
        elapsed = (now - _last_alert[key]).total_seconds()
        if elapsed < cooldown:
            return None

    _last_alert[key] = now

    message = rule["message"].format(source=source, **kwargs)
    severity = rule["severity"]

    conn = sqlite3.connect(str(DB_PATH))
    conn.execute(
        "INSERT INTO alerts (timestamp, rule, severity, message, source) VALUES (?,?,?,?,?)",
        (now.isoformat(), rule_name, severity, message, source),
    )
    conn.commit()
    conn.close()

    return {"rule": rule_name, "severity": severity, "message": message, "timestamp": now.isoformat()}


def check_battery_alerts(battery_data):
    """Check a battery reading for alert conditions."""
    alerts = []
    if not battery_data.get("online"):
        a = fire_alert("battery_offline", source=battery_data.get("label", ""), label=battery_data.get("label", ""))
        if a:
            alerts.append(a)
        return alerts

    label = battery_data.get("label", "Unknown")
    soc = battery_data.get("soc", 100)
    temps = battery_data.get("temps", [])
    cell_delta = battery_data.get("cell_delta", 0)
    protection = battery_data.get("protection", ["Clear"])

    # SOC alerts
    if soc <= RULES["low_soc"]["threshold"]:
        a = fire_alert("low_soc", source=label, label=label, soc=soc)
        if a:
            alerts.append(a)
    elif soc <= RULES["warn_soc"]["threshold"]:
        a = fire_alert("warn_soc", source=label, label=label, soc=soc)
        if a:
            alerts.append(a)

    # Temperature
    if temps and temps[0] >= RULES["high_temp"]["threshold"]:
        a = fire_alert("high_temp", source=label, label=label, temp=temps[0])
        if a:
            alerts.append(a)

    # Cell imbalance
    if cell_delta and cell_delta >= RULES["cell_imbalance"]["threshold"]:
        a = fire_alert("cell_imbalance", source=label, label=label, delta=cell_delta)
        if a:
            alerts.append(a)

    # Protection trips
    if protection and protection != ["Clear"] and protection != ["None"]:
        flags = ", ".join(protection)
        a = fire_alert("protection_trip", source=label, label=label, flags=flags)
        if a:
            alerts.append(a)

    return alerts


def check_victron_alerts(device_data):
    """Check Victron device for alert conditions."""
    alerts = []
    data = device_data.get("data", {})
    device = device_data.get("model_name", device_data.get("name", "Victron"))

    if data.get("error_code") and data["error_code"] != 0:
        a = fire_alert("charger_error", source=device, device=device, error=data.get("error", "Unknown"))
        if a:
            alerts.append(a)

    return alerts


def get_alerts(hours=24, severity=None, unacknowledged_only=False):
    """Get recent alerts."""
    from datetime import timedelta
    since = (datetime.now() - timedelta(hours=hours)).isoformat()
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row

    query = "SELECT * FROM alerts WHERE timestamp > ?"
    params = [since]

    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if unacknowledged_only:
        query += " AND acknowledged = 0"

    query += " ORDER BY timestamp DESC LIMIT 100"
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def acknowledge_alert(alert_id):
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,))
    conn.commit()
    conn.close()


def get_alert_counts():
    """Get counts of unacknowledged alerts by severity."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT severity, COUNT(*) as count FROM alerts WHERE acknowledged = 0 GROUP BY severity"
    ).fetchall()
    conn.close()
    counts = {CRITICAL: 0, WARNING: 0, INFO: 0}
    for r in rows:
        counts[r["severity"]] = r["count"]
    return counts
