# SensorPush Integration — Resume Here

**Status as of 2026-08-01 ~16:42 (before a planned Zima move + reboot).**
Monitor + Log core is BUILT and VERIFIED against the live device. Server API,
dashboard tab, and settings-write are NOT done yet. Pick up at "REMAINING WORK".

---

## ⚠️ FIRST THINGS AFTER REBOOT
1. **Verify batteries came back.** They were stale when this was written
   (BATT_09D2 ~68 min, BATT_FFA9 ~125 min) — same BLE signature as the morning
   incident. The reboot + repositioning should clear it. Check:
   `sqlite3 shadowgrid.db "SELECT label, CAST((julianday('now','localtime')-julianday(MAX(timestamp)))*86400 AS INT) age_s FROM readings WHERE label LIKE 'BATT%' GROUP BY label;"`
   If still stale → it's the USB BLE dongle placement/adapter. See the
   `ble-troubleshooting` memory. **Make sure the dongle is clear of metal** in
   the Zima's new location (metal behind it was the root cause this morning).
2. Confirm services came up: `systemctl is-active shadowgrid bluetooth`
   (both enabled). `/mnt/data01` should auto-mount (fstab `nofail`).

## ⚠️ ENVIRONMENT — DO NOT BREAK
- **ShadowGrid runs on `bleak==2.0.0`** (mesh user-site `~/.local`). The server
  service runs as **mesh** (that's why BLE test scripts must run as mesh, NOT
  sudo/root — root has no bleak).
- **NEVER `pip install sensorpush-ble` into the user/system site** — it drags in
  the HA bluetooth stack and **upgrades bleak to 3.x, which breaks ShadowGrid.**
  The SensorPush lib lives ONLY in the isolated venv:
  `/home/mesh/dev/ShadowGrid/sensorpush/venv` (bleak 3.0.2 + sensorpush-ble 1.9.0)
  — used only as a decode oracle / for GATT dev, never at ShadowGrid runtime.
- The shipping decoder (`sensorpush.py`) is **dependency-free** (bleak + stdlib).

---

## DONE (verified)
- `sensorpush.py` (repo root) — dependency-free module:
  - `decode_advertisement()` — clean-room port, **matches sensorpush-ble
    byte-for-byte** on live HTP.xw (temp/humidity/pressure identical).
  - `scan()` — passive BLE scan → decoded dict.
  - `init_tables()` / `log_readings()` — DB persistence.
  - CLI: `python3 sensorpush.py <secs> --log` (run as mesh; pause poller first
    to free the adapter: `sudo systemctl stop shadowgrid`, then start after).
- DB tables created + populated (1 device, ≥1 reading):
  `sensorpush_devices(address,label,model,enabled,added)`,
  `sensorpush_readings(id,timestamp,address,temp_c,humidity_pct,pressure_hpa,rssi)`.
- `sensorpush/discover.py` — venv script that scans, oracle-vs-port validates,
  and enumerates GATT.

## DEVICE
- **HTP.xw**, name "SensorPush HTP.xw 769", addr **F0:F8:F2:C9:D7:69**, rssi ~-52.
- Config service **`ef090000-11d6-42ba-93b8-9dd7ec090ab0`**; chars `ef0900XX-...-aa9`.
- Live sample decoded: temp ~20 °C, humidity ~44 %, pressure ~977 hPa.

## GATT SETTINGS MAP (from discover.py enumeration)
Writable config chars (values are last-read hex). Meanings are GUESSES pending
read→write→read reverse-engineering — DO NOT blind-write:
- `ef090004` = `3c00` (u16le=60) → likely **sample interval (s)**
- `ef090003` = `05`               → likely a mode/units byte
- `ef090005` = `0808`
- `ef090009` = `8e286e6affff…`    → likely **calibration offsets**
- `ef09000d` = `69d7c9f2f8f0`      → device MAC reversed (READ-ONLY, don't touch)
- `ef090080`=`60090000`, `ef090081`=`89130000`, `ef090082`=`f9039400`, `ef090008`=`0d306e6a`, `ef09000b`=`3700000005000100`, `ef09000c`=`00`, `ef090001`=`f4bb0001`
- read-only: `ef090007`=`a00b1400`, `ef090002`=`0001001e030005`; notify: `ef09000a`
- Leave the TI OAD firmware service `f000ffc0-…` ALONE.

---

## REMAINING WORK (pick up here)
Integration points in `server.py`:
- Background threads start ~L3972–3983 (`poller`, `scanner_thread`, `backup_thread`) — add a `sensorpush_poller_loop` thread here.
- Table init: `init_db()` @ L332 — call `sensorpush.init_tables()` (or inline).
- Routes: `@app.route("/api/...")` style (see `/api/live` L1308, `/api/scanner`, `/api/victron/live`).
- `__main__` L3941, `app.run(...:5050…)` L4049.
Dashboard: `static/index.html` (single-file SPA, tab-based — mirror an existing tab like Victron/Scanner).

**Increment 2 — server API + poller thread:**
- `sensorpush.init_tables()` at startup.
- `sensorpush_poller_loop()` daemon thread: `asyncio.run(scan(12))` every ~90 s,
  `log_readings()`, keep a live cache under `data_lock`.
  ⚠️ Adapter contention: keep scans short + spaced; **re-verify battery
  freshness after enabling** (this adapter is placement-sensitive).
- Endpoints: `/api/sensorpush/live`, `/api/sensorpush/history`,
  `/api/sensorpush/discover` (POST), `/api/sensorpush/settings` (GET/POST).

**Increment 3 — dashboard tab:** live tiles (temp/humidity/pressure/rssi/battery),
history charts (reuse Chart.js), device list.

**Increment 4 — settings read/write (GATT):** read + display all config chars;
expose EDIT only for chars confirmed by careful read→write→read on the device
(start with sample interval `ef090004`); everything else read-only or behind an
"advanced/raw" warning. **Confirm with user before the first real device write.**

## PENDING DECISIONS (ask user on resume)
1. OK to restart shadowgrid to load new endpoints + poller thread (brief blip)?
2. Settings-write scope: safe-subset (recommended) vs full raw editor. Gate the
   first write behind explicit confirmation.

## HISTORY-TIERING NOTE
`sensorpush_readings` is NOT yet in `archive_history.py`'s TELEMETRY_TABLES — add
it there once logging is live so it tiers to USB like the other telemetry.
