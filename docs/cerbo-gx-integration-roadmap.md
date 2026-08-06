# Cerbo GX — Integration Roadmap & Ideas

What ShadowGrid can leverage from the Victron Cerbo GX Mk2, and the protocol
decisions behind it. Compiled 2026-08-04.

**Our setup:** Cerbo GX Mk2 at `192.168.1.100`, **Modbus TCP + SSH enabled**,
SmartShunt on Modbus unit 226. ShadowGrid ingests via `cerbo_reader`. The
`dbus-shadowgrid` bridge already presents the two JBD packs as the Cerbo's
battery service (per-pack temps + a settable temp charge-cutoff). Known gap:
we feed data in but do **not** yet close the loop to actually control charging
(the "DVCC/charger gap").

---

## Protocol decision: Modbus TCP is primary; MQTT is optional/additive

We use **Modbus TCP** and should keep it. It is the correct transport for our
two needs — deterministic reads of specific registers, and (the flagship)
**control writes**. MQTT is not an upgrade; it is a different tool optimized
for push telemetry, and it carries operational baggage we don't want in a
control path.

| Aspect | Modbus TCP (chosen) | MQTT |
|--------|--------------------|------|
| Model | Synchronous request/response | Async publish/subscribe (push on change) |
| Control writes | **Officially documented** (DVCC regs, charger on/off, current limit) | Possible via `W/<portal>/…` topics, less documented/awkward |
| Heartbeat | None (stateless) | **Keepalive every ~55 s** to `R/<portal-id>/keepalive` or broker stops publishing |
| Coupling | Fixed register list + IP | Topics keyed to **VRM Portal ID**; broker swapped dbus-mqtt→dbus-flashmq in Venus 3.20 |
| Dependency | TCP socket only | Running broker + live subscription state |
| Enabled | Manual (we already did it) | On by default |
| Best at | Targeted reads + **control** | Low-latency push of many changing values; publishing computed values back onto the bus |

**Verdict:** stay on Modbus for reads + the control loop. Only add MQTT later
if we specifically want event-driven low-latency telemetry or to publish
ShadowGrid-computed values (e.g. corrected per-cell balancing) back onto the
Cerbo D-Bus. Additive, not a replacement.

---

## Ideas, ranked by value / effort

### 🚩 1. Close the DVCC loop — ShadowGrid as charge controller (FLAGSHIP)
Directly fixes the flagged DVCC/charger gap. Writable DVCC registers over the
Modbus TCP we already have:
- **Reg 2705** — DVCC max charge current (`-1` = no limit, else A)
- **Reg 2710 / 2712** — DVCC max charge voltage / limit managed voltage

Two architectures:
1. **Managed-battery path** — emit CVL/CCL/DCL from our battery service so DVCC
   treats the JBD packs like a CAN-BMS battery and the chargers obey our numbers.
   The "correct" design.
2. **External-controller path** — ShadowGrid writes reg 2705/2710 from live cell
   state: taper charge current when a cell crosses `bal_start` (3.3 V), hard-cut
   (CCL→0) on the decoded low-temp cutoff (no LiFePO4 charging below 0 °C), back
   off near cell OVP. Cell-level protection the chargers can't do alone.

⚠️ Writes to real charge hardware — stage it:
  (a) **read-only register probe** (confirm we can see/target 2705/2710 + current
      DVCC/charger state on this firmware),
  (b) guarded writer with hard clamps + dead-man revert,
  (c) confirm before first live write.

### ⚙️ 2. On-Cerbo automation (Venus OS Large + Node-RED)
Runs on the Cerbo's own CPU → keeps working even if the Zima is off. A
resilience *mirror* of ShadowGrid logic, not a competitor:
- SOC/cell-based load shedding via the 2 built-in GX relays
- Generator auto start/stop (local, survives internet loss) — if a genset exists
- Balance-aware charge tapering as backup to the Modbus path
- Push events back to ShadowGrid via MQTT
Tradeoff: another moving part.

### 📡 3. MQTT push ingest (optional — see protocol decision)
Event-driven, lower-latency telemetry + ability to publish computed values back.
Only worth it if polling cadence becomes limiting. Remember the 55 s keepalive
and Portal-ID coupling.

### 🌡️ 4. Expand sensing (cheap wins)
- Cerbo physical **temp/tank inputs** — fridge/ambient/water-tank sensors,
  surfaced in ShadowGrid alongside the SensorPush work.
- **Relay 2 as temperature-controlled** — battery-bay cooling fan or cold-weather
  heat pad, gated on the NTC temps we now decode correctly.

### ☁️ 5. Remote / cloud (VRM)
- **VRM API personal access token** → pull historical stats/alarms/forecasts into
  ShadowGrid, or set cloud alarm rules (40+ endpoints, e.g. `stats?type=live_feed`).
- Reach the Cerbo remote console over the existing **Tailscale** tailnet — no
  public exposure.

---

## Recommended sequence
1. **Read-only DVCC register probe** over Modbus — zero risk, proves viability of
   the flagship control loop on this firmware.
2. Build the guarded charge-control writer (managed-battery path preferred).
3. Revisit MQTT only if push telemetry / write-back becomes a real need.

## Sources
- Venus OS Large / Node-RED: https://www.victronenergy.com/live/venus-os:large
- node-red-contrib-victron: https://github.com/victronenergy/node-red-contrib-victron
- DVCC via Modbus-TCP (reg 2705/2710): https://communityarchive.victronenergy.com/questions/98261/ccgx-dvcc-how-to-limit-charge-voltage-using-modbus.html
- Set DVCC max charge current by MQTT: https://communityarchive.victronenergy.com/questions/227201/set-dvcc-maximum-charge-current-by-mqtt.html
- MQTT keepalive / topics: https://github.com/victronenergy/dbus-mqtt
- Cerbo generator auto start/stop: https://www.victronenergy.com/media/pg/Cerbo_GX/en/gx---generator-auto-start-stop.html
- DVCC overview: https://www.victronenergy.com/media/pg/Cerbo_GX/en/dvcc---distributed-voltage-and-current-control.html
- VRM API docs: https://vrm-api-docs.victronenergy.com/
