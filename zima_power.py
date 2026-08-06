"""
zima_power.py — self-power monitoring + CPU power-mode control for ShadowGrid.

Reads the host's own power draw via Intel RAPL and lets the dashboard switch
the CPU governor between power modes. Read/write access to the two sysfs knobs
is granted by shadowgrid-power-perms.service (RAPL energy_uj: group-read,
scaling_governor: group-write for the mesh group). All operations are safe and
degrade to no-ops if the knobs are unavailable.

Modes -> CPU governor:
  eco         -> powersave    (pin low freq, lowest watts)
  balanced    -> schedutil    (default; race-to-idle)
  performance -> performance  (max freq)
  auto        -> chosen by battery SOC at runtime (see server poller)
"""

import os
import glob
import time
import logging

log = logging.getLogger("zimapower")

RAPL_PKG   = "/sys/class/powercap/intel-rapl:0/energy_uj"
RAPL_MAX   = "/sys/class/powercap/intel-rapl:0/max_energy_range_uj"
GOV_GLOB   = "/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor"
GOV_CPU0   = "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"

MODES = {                 # dashboard mode -> governor
    "eco": "powersave",
    "balanced": "schedutil",
    "performance": "performance",
}
GOV_TO_MODE = {v: k for k, v in MODES.items()}

_last = {"e": None, "t": None}


def _read_int(path):
    try:
        with open(path) as f:
            return int(f.read().strip())
    except Exception:
        return None


def read_power():
    """Package watts since the previous call. Returns None on the first call
    or if RAPL is unavailable. Handles the energy counter wrapping."""
    e = _read_int(RAPL_PKG)
    t = time.monotonic()
    watts = None
    if e is not None and _last["e"] is not None and _last["t"] is not None:
        de = e - _last["e"]
        dt = t - _last["t"]
        if de < 0:  # counter wrapped
            mx = _read_int(RAPL_MAX)
            de = de + mx if mx else None
        if de is not None and dt > 0:
            watts = round(de / dt / 1e6, 2)
    _last["e"], _last["t"] = e, t
    return watts


def get_governor():
    try:
        with open(GOV_CPU0) as f:
            return f.read().strip()
    except Exception:
        return None


def get_mode():
    return GOV_TO_MODE.get(get_governor(), "custom")


def set_mode(mode):
    """Apply a power mode by writing the matching governor to every CPU.
    Returns (ok, error). 'auto' is resolved by the caller, not here."""
    gov = MODES.get(mode)
    if gov is None:
        return False, f"unknown mode: {mode}"
    wrote = 0
    err = None
    for p in glob.glob(GOV_GLOB):
        try:
            with open(p, "w") as f:
                f.write(gov)
            wrote += 1
        except Exception as e:
            err = str(e)
    if wrote == 0:
        return False, err or "no cpufreq governor files writable"
    if err:
        log.warning("set_mode(%s): partial (%d cpus, last err: %s)", mode, wrote, err)
    return True, None


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    read_power()
    time.sleep(1)
    print("watts:", read_power(), "| governor:", get_governor(), "| mode:", get_mode())
