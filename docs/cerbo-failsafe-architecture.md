# Cerbo Failsafe & Inverter-Control Architecture

Status: DESIGN (2026-08-05). Nothing deployed yet. Prepared for panel install +
DVCC enable, but the over-discharge / inverter pieces harden things NOW.

## Governing principle

**The Cerbo is the autonomous safety authority. The Zima/ShadowGrid is an
optimizer layer that is allowed to disappear.** No life-critical function may
depend on the Zima — because the Zima can fail on its own AND the Cerbo may
deliberately kill it by shedding the inverter that powers it.

## The circular dependency (why this matters)

    24V bank ──► Phoenix 24/800 inverter ──► 120V AC ──► Zima (ShadowGrid)
       ▲                                                     │
       │                                          fetches /api/live every 5s
       │                                                     ▼
    MPPTs/charge ◄──── DVCC ◄──── dbus-shadowgrid bridge (on the Cerbo)

The Cerbo's charge brain (bridge) needs the Zima; the Zima needs the Phoenix;
the Cerbo may need to kill the Phoenix. So the protective layer must run on the
Cerbo with only Cerbo-local data (SmartShunt, inverter DC volts), never the Zima.

## Layered failsafe model

| Layer | Runs on | Depends on Zima? | Function |
|-------|---------|------------------|----------|
| **L0** hardware | JBD BMS + Phoenix | NO | JBD FET cutoff (cell OVP/UVP/OT); Phoenix built-in low-DC-voltage shutdown/restart. Ultimate backstops. |
| **L1** Cerbo autonomous | Cerbo | NO | Load-shed guardian (shunt→inverter /Mode); DVCC MaxChargeVoltage ceiling; bridge charge fail-safe. |
| **L2** optimizer | Zima/ShadowGrid | (is the Zima) | Cell-aware charge taper; early/graceful load management; UI/history. Best-effort; degrades cleanly. |

## Verified current state (2026-08-05)

- Bridge on Zima-loss: sets `/Connected=0` and **returns, leaving CVL/CCL/DCL
  STALE** (`dbus-shadowgrid.py` update() ~L214-220). GAP — see fix below.
- DVCC OFF (`Bol=0`); `MaxChargeVoltage=0` (no Cerbo-native ceiling yet).
- Phoenix inverter NOT on the Cerbo (no inverter/vebus service).
- Cerbo has TWO free programmable relays (relay0/relay1) — dry contacts.
- All 3 built-in VE.Direct ports used (shunt ttyS5, MPPT ttyS6, MPPT ttyS7);
  **USB VE.Direct path is FREE** (no ttyUSB in use).
- ShadowGrid systemd unit is `enabled` (auto-starts on boot → black-start OK).
- Node-RED OFF (not required; guardian daemon preferred).

## Phoenix 24/800 (PIN241800510, VE.Direct, 120V) integration

1. Connect Phoenix **VE.Direct → VE.Direct-USB cable → free Cerbo USB port**.
   Appears as `com.victronenergy.inverter.ttyUSB0` and **Modbus unit 239**
   (ttyUSB0 → DeviceInstance 288 per unitid2di.csv).
2. Control: Cerbo sets `/Mode` (1=On, 4=Off, 5=Eco) over VE.Direct — **software
   on/off, no relay needed**. ShadowGrid can also read/toggle via Modbus 239 (L2).
3. Set the Phoenix's own **low-DC-voltage shutdown/restart** via VictronConnect
   (L0 backstop), conservatively (see thresholds).

## L1a — Load-shed guardian daemon (Cerbo-resident, Zima-independent)

Small Python daemon on the Cerbo (same pattern as the bridge). Reads the
**SmartShunt** over local D-Bus (`com.victronenergy.battery.ttyS5` /Dc/0/Voltage,
/Soc) — NOT the Zima. Drives inverter `/Mode`:
- Trigger primarily on **pack voltage under load** (SOC drifts; an 800W load sags
  the pack — voltage+hysteresis is the robust trigger, same basis as the Phoenix
  cutoff). Optional SOC floor as secondary.
- **Wide hysteresis** so it cannot flap and repeatedly reboot the Zima.
- Keeps running after it kills the inverter (and the Zima); restores the inverter
  when the bank recovers → Zima reboots → ShadowGrid auto-starts → bridge resumes.

### Proposed thresholds (8S LiFePO4 — PENDING USER CONFIRM)

| Action | Trigger (pack V under load) | Owner |
|--------|-----------------------------|-------|
| Guardian shed inverter | ~24.4 V (≈3.05 V/cell) | Cerbo daemon |
| Guardian restore inverter | ~25.8 V (≈3.23 V/cell) — wide gap | Cerbo daemon |
| Phoenix hard cutoff (backstop) | ~24.0 V | inverter setting |
| JBD UVP (last resort) | 18.4 V (2.30 V/cell factory) | BMS |

## L1b — Charge-side failsafes (land when DVCC is enabled)

- Set Cerbo-native **`/Settings/SystemSetup/MaxChargeVoltage`** ceiling (e.g.
  28.0 V, or conservative 27.6 V). Independent of the bridge — caps the MPPTs
  even if the bridge dies or feeds garbage. Primary over-charge failsafe.
- **Bridge fail-safe fix:** on Zima-loss (fail>threshold) publish CONSERVATIVE
  charge limits (clamp CVL to a safe floor, CCL→0) instead of stale values —
  but **never cut discharge** (a network blip must not shed the inverter/Zima).

## Black-start recovery sequence (must be automatic)

bank low → guardian sets inverter Off → Zima powers down → sun/charge recovers
bank → guardian sets inverter On → Zima boots → shadowgrid.service auto-starts →
bridge resumes fetching → smart control (L2) returns. Wide hysteresis prevents
oscillation.

## Task checklist

Panel-INDEPENDENT (harden over-discharge now):
- [ ] Phoenix VE.Direct → USB into Cerbo; verify inverter service + Modbus 239.
- [ ] Set Phoenix built-in low-voltage cutoff (VictronConnect).
- [ ] Build + deploy the load-shed guardian daemon on the Cerbo.
- [ ] Fix bridge fail-safe (conservative charge limits on Zima-loss; leave DCL).

Panel-GATED (with DVCC enable):
- [ ] Set Cerbo MaxChargeVoltage ceiling.
- [ ] Deploy phase-2 charge taper (docs/dvcc-charge-taper.py) + enable DVCC.

## Other (non-Phoenix) inverter — remote on/off via Cerbo relay

The second inverter (model TBD) likely has no VE.Direct, so control it via its
hardware remote-on/off jack + a **Cerbo relay** (dry contact) wired across the
on/off contact, ideally through a Y-splitter so the existing manual switch still
works (logical OR). MUST verify the jack type + pinout for that specific model
(manual, or meter the existing switch) before wiring — never short pins blind.
Confirm whether the contact is MAINTAINED (maps to relay held closed) or
MOMENTARY (needs a pulse + is state-ambiguous). TODO: fill in once model known.
