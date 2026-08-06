"""
cerbo_reader.py — Victron Cerbo GX ingestion for ShadowGrid over Modbus TCP.

Reads the Cerbo's SmartShunt (the wired 24V-bank monitor) directly over the
network — no broker, no extra dependencies (raw Modbus TCP, function 3).

This is a SEPARATE, self-contained source. It does NOT touch the battery BLE
pollers (JBD/EcoFlow) or the Victron BLE scanner in any way.

Register map (validated byte-for-byte against the Cerbo's own D-Bus, 2026-08-03):
  SmartShunt 500A/50mV = Modbus unit 226 (com.victronenergy.battery.ttyS7)
    reg 259  /Dc/0/Voltage      uint16  /100   V
    reg 260  /Dc/1/Voltage      uint16  /100   V   (aux/starter input — usually 0)
    reg 261  /Dc/0/Current      int16   /10    A   (+ = charging into bank)
    reg 262  /Dc/0/Temperature  int16   /10    C   (empty on this shunt)
    reg 266  /Soc               uint16  /10    %
  Power is computed V*I (the shunt exposes no dedicated power register here).

Host / port / unit are overridable via env: CERBO_HOST, CERBO_PORT, CERBO_UNIT.
"""

import os
import socket
import struct
import logging
from datetime import datetime

log = logging.getLogger("cerbo")

CERBO_HOST = os.environ.get("CERBO_HOST", "venus.local")
CERBO_PORT = int(os.environ.get("CERBO_PORT", "502"))
SHUNT_UNIT = int(os.environ.get("CERBO_UNIT", "226"))
SHUNT_NAME = "SmartShunt 500A/50mV"

# Solar MPPT chargers reached over the Cerbo's Modbus TCP (com.victronenergy.
# solarcharger register block 771+). Discovered/verified 2026-08-05 against the
# Cerbo's own unitid2di.csv + live probe:
#   unit 224 = DeviceInstance 278 (ttyS6) = SmartSolar MPPT 150/45
#   unit 226 = DeviceInstance 279 (ttyS7) = BlueSolar MPPT 100/50
# NB: unit 226 also serves the SmartShunt (shared device instance 279); the
# battery vs solarcharger register RANGE disambiguates which service answers.
SOLAR_UNITS = os.environ.get(
    "CERBO_SOLAR_UNITS", "224:SmartSolar MPPT 150/45,226:BlueSolar MPPT 100/50")

# Register 775 /State, 788 /ErrorCode, 791 /MppOperationMode enum decodes
# (from the Cerbo's attributes.csv).
_SOLAR_STATE = {0: "Off", 2: "Fault", 3: "Bulk", 4: "Absorption", 5: "Float",
                6: "Storage", 7: "Equalize", 11: "Other (Hub-1)", 252: "Hub-1"}
_SOLAR_ERROR = {0: "No error", 1: "Battery temp too high", 2: "Battery voltage too high",
                17: "Charger temp too high", 18: "Charger over-current",
                20: "Bulk time limit reached", 33: "PV over-voltage",
                34: "Input current too high"}
_MPP_MODE = {0: "Off", 1: "V/I limited", 2: "MPPT active", 255: "N/A"}


def _parse_solar_units(spec):
    out = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        uid, _, name = part.partition(":")
        try:
            out.append((int(uid), name.strip() or f"MPPT unit {uid}"))
        except ValueError:
            continue
    return out


def _s16(x):
    return x - 65536 if x > 32767 else x


def _read_registers(sock, unit, start, qty, txid=1):
    """One Modbus TCP read-holding-registers (function 3). Returns tuple of uint16."""
    req = struct.pack(">HHHBBHH", txid, 0, 6, unit, 3, start, qty)
    sock.sendall(req)
    # MBAP header is 7 bytes; byte 5-6 = length of the rest (unit + PDU)
    hdr = _recv_exact(sock, 7)
    length = struct.unpack(">H", hdr[4:6])[0]
    body = _recv_exact(sock, length - 1)  # length counts the unit-id byte already in hdr[6]
    func = body[0]
    if func & 0x80:
        raise IOError(f"Modbus exception {body[1]} on unit {unit} reg {start}")
    nbytes = body[1]
    return struct.unpack(">%dH" % (nbytes // 2), body[2:2 + nbytes])


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise IOError("connection closed mid-frame")
        buf += chunk
    return buf


def poll(host=None, port=None, unit=None, timeout=5):
    """
    Read the Cerbo SmartShunt. Returns a dict; on any failure returns
    {"online": False, ...} and never raises (safe to call from a poller loop).
    """
    host = host or CERBO_HOST
    port = port or CERBO_PORT
    unit = unit or SHUNT_UNIT
    ts = datetime.now().isoformat()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        try:
            # 259..266 in one read: [0]=V [1]=auxV [2]=I [3]=Temp ... [7]=SOC
            r = _read_registers(sock, unit, 259, 8)
        finally:
            sock.close()
        voltage = round(r[0] / 100.0, 2)
        aux_v = round(r[1] / 100.0, 2)
        current = round(_s16(r[2]) / 10.0, 2)
        temp = round(_s16(r[3]) / 10.0, 1)
        soc = round(r[7] / 10.0, 1)
        power = round(voltage * current, 1)
        return {
            "online": True,
            "timestamp": ts,
            "host": host,
            "unit": unit,
            "name": SHUNT_NAME,
            "source": "cerbo_modbus",
            "voltage": voltage,
            "current": current,
            "power": power,
            "soc": soc,
            "temp": temp if temp != 0 else None,
            "aux_voltage": aux_v if aux_v > 0.5 else None,
        }
    except Exception as e:
        log.warning("Cerbo Modbus poll failed (%s:%s unit %s): %s", host, port, unit, e)
        return {
            "online": False,
            "timestamp": ts,
            "host": host,
            "unit": unit,
            "name": SHUNT_NAME,
            "source": "cerbo_modbus",
            "error": str(e),
        }


def poll_solar(host=None, port=None, timeout=5):
    """
    Read every configured Cerbo solar MPPT (solarcharger register block 771+).
    Returns a list of dicts (one per charger); each is self-contained and never
    raises. A charger that doesn't answer comes back {"online": False, ...}.
    Safe to call from a poller loop alongside poll() — separate Modbus reads.
    """
    host = host or CERBO_HOST
    port = port or CERBO_PORT
    ts = datetime.now().isoformat()
    units = _parse_solar_units(SOLAR_UNITS)
    out = []

    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except Exception as e:
        log.warning("Cerbo solar connect failed (%s:%s): %s", host, port, e)

    for unit, name in units:
        base = {"unit": unit, "name": name, "source": "cerbo_modbus",
                "device_type": "Solar Charger", "timestamp": ts, "host": host}
        if sock is None:
            out.append({**base, "online": False, "error": "no connection"})
            continue
        try:
            # 771..791 in one read: battery V/I/temp, mode, state, PV V/I, …,
            # daily yield/maxpower, error, instantaneous power, total yield, MPP.
            r = _read_registers(sock, unit, 771, 21)
            batt_v = round(r[0] / 100.0, 2)
            batt_i = round(_s16(r[1]) / 10.0, 2)
            temp = round(_s16(r[2]) / 10.0, 1)
            state = r[4]
            pv_v = round(r[5] / 100.0, 2)
            yield_today = round(r[13] / 10.0, 2)
            max_power_today = r[14]
            err = r[17]
            pv_power = round(r[18] / 10.0, 1)
            yield_total = round(r[19] / 10.0, 2)
            mpp = r[20]
            out.append({
                **base,
                "online": True,
                "state": _SOLAR_STATE.get(state, f"Unknown ({state})"),
                "state_code": state,
                "error": _SOLAR_ERROR.get(err, f"Error {err}"),
                "error_code": err,
                "mpp_mode": _MPP_MODE.get(mpp, f"Unknown ({mpp})"),
                "battery_voltage": batt_v,
                "battery_current": batt_i,
                "pv_voltage": pv_v,
                "pv_power": pv_power,
                "yield_today": yield_today,
                "yield_total": yield_total,
                "max_power_today": max_power_today,
                "temperature": temp if temp != 0 else None,
            })
        except Exception as e:
            log.warning("Cerbo solar read failed (unit %s): %s", unit, e)
            out.append({**base, "online": False, "error": str(e)})

    if sock is not None:
        try:
            sock.close()
        except Exception:
            pass
    return out


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    import json
    print(json.dumps({"shunt": poll(), "solar": poll_solar()}, indent=2))
