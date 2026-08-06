# BLE Watchdog — auto-recovery for wedged JBD polling

Added 2026-08-05 after a stale half-open GATT connection jammed the single-client
JBD slot and took both packs offline until manual recovery. See
[[ble-troubleshooting]] for the failure mode.

## Problem it solves

JBD/Xiaoxiang packs allow ONE BLE (GATT) client at a time. A poll that fails to
tear down cleanly can leave a half-open connection in BlueZ (`hcitool con` shows
it held, no data flowing). That jams the slot → ALL packs read offline and the
poller cannot self-recover. `systemd Restart=on-failure` does NOT help: the
process stays alive (still serving `/api/live`), and even a bare process restart
wouldn't clear a BlueZ-level wedge.

## Design — graduated, decoupled, self-limiting

Two layers:

### Layer 1 — systemd hardening
`StartLimitIntervalSec=300` + `StartLimitBurst=5` so a genuine crash-loop backs
off instead of hammering. (`Restart=on-failure`/`RestartSec=10` already present.)

### Layer 2 — in-process BLE watchdog thread (`ble_watchdog_loop`)
A daemon thread (fits the existing thread pattern) that ONLY acts when reads are
already failing — it never touches the read path in normal operation.

Trigger: **ALL** JBD packs offline continuously for `> STALE` seconds. (If even
one pack is online, BLE works — a single offline pack is RF, not a wedge, so we
do nothing and never disrupt a working radio.)

### Layer 3 — poll-loop liveness (added 2026-08-06)
The per-pack-offline trigger has a blind spot: if the poller **thread itself
hangs** (a bleak call into BlueZ over D-Bus that never returns — `start_notify`,
`write_gatt_char`, connect/disconnect; only `ble_send`'s `event.wait` was
timeout-guarded), then `latest_data` freezes with the last values, which still
read `online=True`. The Layer-2 check sees "online" and does nothing while data
silently stops. This actually happened 2026-08-05 22:41 → the loop parked ~11h,
`/api/live` and the readings table froze, and the History graphs (default 1h
window) went empty.

Two fixes:
1. **Overall read deadline** (`BLE_READ_DEADLINE`, default 45s): `poller_loop`
   wraps `read_battery` in `asyncio.wait_for`, so no single hung D-Bus call can
   freeze the whole loop. A timed-out read marks the pack offline → the loop
   keeps cycling → if it's a real wedge, packs go offline and Layer 2 bounces BLE.
2. **Liveness heartbeat**: `poller_loop` stamps `_last_poll_ts = time.monotonic()`
   every cycle. The watchdog checks `WATCHDOG_LOOP_STALE` (default 300s) FIRST,
   before the pack check. If the loop hasn't cycled in that long it's hung, and a
   BLE bounce won't free a thread parked in a dead await — so the watchdog does a
   **`systemctl restart shadowgrid`** (systemd brings the service + watchdog back;
   this is the one case that restarts the service). Rate-limited to once per
   `REALERT` and alerted via `send_notification`.

Escalation (pure state machine `_watchdog_step`, so it's unit-testable):

| Attempt | Spacing | Action |
|---------|---------|--------|
| 1 | after STALE | **disconnect** the stale GATT connection(s): `bluetoothctl disconnect <mac>` (often frees the slot alone) |
| 2 | +COOLDOWN | **bounce** the stack: `systemctl restart bluetooth` + `hciconfig hci0 down/up` → notify (high) |
| 3 | +COOLDOWN | bounce again (one more try) |
| 4+ | every REALERT | back off: bounce + re-alert "recovery failing, check dongle/packs" |

On recovery (any pack back online after an escalation) → notify "BLE recovered".

Key safety properties:
- **Does NOT restart the shadowgrid service** (in-process; a self-restart would
  kill the watchdog). Disconnect + bluetooth/hci bounce clears the wedge without
  it — the poller opens a fresh GATT session on its next cycle.
- **Backoff + alert**, never an infinite fast loop. If bouncing doesn't help
  (dead dongle, packs physically off), it stops hammering and pages a human via
  the existing `send_notification`.
- **Alerts on every recovery action** → recurring wedges are visible, not masked.
- **Safety is cross-box, not here.** Once the Cerbo failsafe/guardian lands, the
  Cerbo sees the bank via the SmartShunt independent of the Zima's BLE — so this
  watchdog is about restoring DATA/UI, and is allowed to be imperfect. See
  [[cerbo-failsafe-architecture]].

## Config (env vars, all optional)

| Var | Default | Meaning |
|-----|---------|---------|
| `BLE_WATCHDOG` | `1` | set `0` to disable |
| `BLE_WATCHDOG_INTERVAL` | `20` | check cadence (s) |
| `BLE_WATCHDOG_STALE` | `90` | all-packs-offline this long before first action (s) |
| `BLE_WATCHDOG_COOLDOWN` | `60` | wait after an action before escalating (s) |
| `BLE_WATCHDOG_REALERT` | `1800` | retry/re-alert cadence once in backoff (s) |
| `BLE_WATCHDOG_LOOP_STALE` | `300` | poll loop silent this long ⇒ hung ⇒ restart service (s) |
| `BLE_READ_DEADLINE` | `45` | hard ceiling on one `read_battery` (poller_loop) (s) |

## Privilege
Runs privileged BLE ops via `sudo -S` using the `SUDO_PW` env already injected by
the systemd unit (same mechanism the box already relies on). Non-privileged
otherwise.

## Testing
- `_watchdog_step` is a pure function → unit-tested offline with synthetic
  offline/online sequences (no hardware, no induced wedge).
- Live: confirm the thread starts, stays idle while packs are online (no false
  actions), and that `sudo -S` ops succeed.
