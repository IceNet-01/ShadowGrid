# JBD / Xiaoxiang Smart BMS — Verified Register Map

Reference for ShadowGrid's JBD decoder (`server.py:read_battery`). Verified
2026-08-04 against five independent sources and cross-checked against live raw
reads from our Ecoworthy packs (model `DP04S007L4S200ABUS`).

**Sources:** official JBD "Smart BMS protocol V4" PDF; `jbdtool`
(github.com/sshoecraft/jbdtool); `esphome-jbd-bms` (github.com/syssi); bms-tools
`JBD_REGISTER_MAP.md` (gitlab.com/bms-tools/bms-tools); Hackaday teardown.

> A prior version of the decoder used a map shifted by 8 registers (temperature
> block where the voltage block belongs), so thresholds decoded to impossible
> values (pack OVP "34.81 V", temps "−127 °C"). This is the corrected map.

## Frame format

Request:  `DD  A5(read)/5A(write)  <reg>  <len>  <data...>  <chkHi> <chkLo>  77`
Response: `DD  <reg-echo>  <status>  <len>  <data...>  <chkHi> <chkLo>  77`

- **status**: `0x00` = OK, non-zero (`0x80`) = error (e.g. reading EEPROM without factory mode).
- **checksum** (both directions): `(0x10000 − (fieldsum)) & 0xFFFF`, big-endian.
  - Request `fieldsum = reg + len + Σdata` (action byte 0xA5/0x5A **excluded**).
  - Response `fieldsum = status + len + Σdata` (reg-echo byte **excluded**).

## 0x03 Basic Info (read-only)

| Off | Field | Type | Unit | Formula |
|-----|-------|------|------|---------|
| 0–1 | total voltage | u16 | 10 mV | ×0.01 → V |
| 2–3 | current | **s16** | 10 mA | ×0.01 → A (charge +, discharge −) |
| 4–5 | remaining cap | u16 | 10 mAh | ×0.01 → Ah |
| 6–7 | nominal cap | u16 | 10 mAh | ×0.01 → Ah |
| 8–9 | cycle count | u16 | — | raw |
| 10–11 | mfg date | u16 | packed | day=raw&0x1F, mon=(raw>>5)&0xF, yr=2000+(raw>>9) |
| 12–13 | balance status low | u16 bitmask | — | bit n = cell n+1 (cells 1–16) |
| 14–15 | balance status high | u16 bitmask | — | cells 17–32 |
| 16–17 | protection status | u16 bitmask | — | see bit table |
| 18 | sw version | u8 | — | 0x10 = v1.0 |
| 19 | RSOC | u8 | % | raw |
| 20 | FET status | u8 | — | bit0=charge FET, bit1=discharge FET |
| 21 | # cells | u8 | — | raw |
| 22 | # NTC | u8 | — | raw |
| 23+ | NTC temps (N×u16) | u16 | 0.1 K | (raw−2731)/10 → °C |

**Protection bits:** 0 cell OVP, 1 cell UVP, 2 pack OVP, 3 pack UVP, 4 chg OT,
5 chg UT, 6 dsg OT, 7 dsg UT, 8 chg OC, 9 dsg OC, 10 short-circuit, 11 AFE IC
error, 12 FET-locked.

> ✅ **Resolved (2026-08-04): the balance-status mask is DIRECT** — the set bits
> ARE the cells being bled (the HIGH cells). `read_battery` uses the raw mask
> directly (`bled_mask = bal_full & ((1<<n)-1)`), gated so each candidate must be
> (a) above the pack's minimum cell voltage and (b) at/above `bal_start_v` as a
> sanity guard (a stray bit on a low cell can't be reported; `raw==0` → none).
> ⚠️ This flipped twice: an earlier "inverted / complement" reading was drawn
> from noisy *resting* samples during the config-map bug era and was WRONG.
> Re-confirmed DIRECT on a clean top-of-charge imbalance, stable across many live
> samples on both packs — FFA9 raw `7`={1,2,3} = the high trio (cell 4 low);
> 09D2 raw `13`={1,3,4} = the three highest (cell 2 low, cell 4 high @3.60 V).
> Raw mask retained as `balance_status` for diagnostics.

## 0x04 Cell voltages / 0x05 version

- 0x04: N = len/2 cells, each u16 **1 mV**, big-endian, cell 1 first.
- 0x05: byte0 = string length, then ASCII.

## EEPROM / factory-config registers (require factory mode)

Enter: write `0x00` = `56 78`. Exit: write `0x01` = `00 00` (or `28 28` to also commit).

| Reg | Field | Type | Unit | → engineering |
|-----|-------|------|------|---------------|
| 0x10 | design_cap | u16 | 10 mAh | ×0.01 Ah |
| 0x11 | cycle_cap | u16 | 10 mAh | ×0.01 Ah |
| 0x12 | cap_100 (full-chg V) | u16 | 1 mV | cell V @100% |
| 0x13 | cap_0 (EOD V) | u16 | 1 mV | cell V @0% |
| 0x14 | dsg_rate | u16 | 0.1 % | |
| 0x15 | mfg_date | u16 | packed | |
| 0x16 | serial_num | u16 | — | |
| 0x17 | **cycle_cnt** | u16 | count | (NOT balance-start!) |
| 0x18–0x19 | **chg** over-temp / release | u16 | 0.1 K | (raw−2731)/10 °C |
| 0x1A–0x1B | **chg** under-temp / release | u16 | 0.1 K | |
| 0x1C–0x1D | **dsg** over-temp / release | u16 | 0.1 K | |
| 0x1E–0x1F | **dsg** under-temp / release | u16 | 0.1 K | |
| 0x20–0x21 | **pack** OVP / release | u16 | 10 mV | ×0.01 V |
| 0x22–0x23 | **pack** UVP / release | u16 | 10 mV | ×0.01 V |
| 0x24–0x25 | **cell** OVP / release | u16 | 1 mV | |
| 0x26–0x27 | **cell** UVP / release | u16 | 1 mV | |
| 0x28 | chg over-current | **s16** | 10 mA | ×0.01 A (positive) |
| 0x29 | dsg over-current | **s16** | 10 mA | ×0.01 A (negative; magnitude shown) |
| 0x2A | **bal_start** voltage | s16 | 1 mV | (NOT short-circuit!) |
| 0x2B | bal_window / delta | u16 | 1 mV | |
| 0x2C | **shunt resistance** | u16 | 0.1 mΩ | (NOT balance-delta!) |
| 0x2D | func_config | u16 | bitmask | bit2=balance_en, bit3=chg_balance_en… |
| 0x2E | ntc_config | u16 | bitmask | |
| 0x2F | cell_cnt (config) | u16 | count | |

Short-circuit + secondary OC thresholds are **bit-packed enums** in 0x38/0x39
(not raw values); not currently decoded by ShadowGrid.

## Live validation (our packs, 2026-08-04)

Corrected map applied to captured raw values yields textbook LiFePO4 defaults:
chg OT 65 °C / dsg OT 75 °C / chg UT −7 °C / dsg UT −20 °C; pack OVP 14.6 V,
pack UVP 9.2 V; cell OVP 3.65 V, cell UVP 2.30 V; chg/dsg OC ±220 A;
balance start 3.30 V, window 15 mV; shunt 0.1 mΩ. Both packs identical (same
model/batch) — as expected for factory config.
