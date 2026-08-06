# JBD BMS BLE Protocol Reference

## BLE Service

| UUID | Description |
|---|---|
| `0000ff00-0000-1000-8000-00805f9b34fb` | JBD BMS Service |
| `0000ff01-0000-1000-8000-00805f9b34fb` | RX Characteristic (Notify) — subscribe here for responses |
| `0000ff02-0000-1000-8000-00805f9b34fb` | TX Characteristic (Write Without Response) — send commands here |

## Packet Format

### Read command
```
DD A5 <register> 00 <checksum_hi> <checksum_lo> 77
```

### Write command (requires factory mode)
```
DD 5A <register> <data_len> <data...> <checksum_hi> <checksum_lo> 77
```

### Response
```
DD <register> <status> <data_len> <data...> <checksum_hi> <checksum_lo> 77
```
- Status `0x00` = success
- Status `0x80` = error / unsupported

### Checksum
```
checksum = (~sum_of_data_bytes & 0xFFFF) + 1
```
For read commands, data bytes = just the register byte.
For write commands, data bytes = length byte + all data bytes.

## Authentication

### Enter Factory Mode (unlock config registers)
```
DD 5A 00 02 56 78 FF 30 77
```
Password: `0x5678` (JBD default, works on Eco Worthy batteries)

### Exit Factory Mode
```
DD 5A 01 02 00 00 FF FD 77
```

## Read Registers

### 0x03 — Basic Info (no auth required)
```
Send: DD A5 03 00 FF FD 77
```
Response payload:

| Offset | Length | Field | Unit |
|---|---|---|---|
| 0 | 2 | Total voltage | 10 mV |
| 2 | 2 | Current (signed) | 10 mA |
| 4 | 2 | Remaining capacity | 10 mAh |
| 6 | 2 | Nominal capacity | 10 mAh |
| 8 | 2 | Cycle count | — |
| 10 | 2 | Production date (encoded) | see below |
| 12 | 2 | Balance status (low) | bitmask |
| 14 | 2 | Balance status (high) | bitmask |
| 16 | 2 | Protection status | bitmask |
| 18 | 1 | Software version | high.low nibble |
| 19 | 1 | SOC | % |
| 20 | 1 | FET status | bit0=charge, bit1=discharge |
| 21 | 1 | Cell count | — |
| 22 | 1 | NTC sensor count | — |
| 23+ | 2 each | NTC temperatures | raw (subtract 2731, divide by 10 for C) |

Production date encoding: `year = 2000 + (raw >> 9)`, `month = (raw >> 5) & 0x0F`, `day = raw & 0x1F`

### 0x04 — Cell Voltages (no auth required)
```
Send: DD A5 04 00 FF FC 77
```
Response: 2 bytes per cell, in millivolts (MSB first).

### 0x05 — Hardware Version (no auth required)
```
Send: DD A5 05 00 FF FB 77
```
Response: ASCII string (e.g., `DP04S007L4S200ABUS`).

### Protection Status Bits (register 0x03, offset 16)

| Bit | Flag |
|---|---|
| 0 | Cell Over-Voltage |
| 1 | Cell Under-Voltage |
| 2 | Pack Over-Voltage |
| 3 | Pack Under-Voltage |
| 4 | Charge Over-Temperature |
| 5 | Charge Under-Temperature |
| 6 | Discharge Over-Temperature |
| 7 | Discharge Under-Temperature |
| 8 | Charge Over-Current |
| 9 | Discharge Over-Current |
| 10 | Short Circuit |
| 11 | IC Error |
| 12 | FET Lock |

## Config Registers (require factory mode auth)

| Reg | Name | Unit | Our Value |
|---|---|---|---|
| 0x10 | Design Capacity | 10 mAh | 28000 (280 Ah) |
| 0x11 | Cycle Capacity | 10 mAh | 22400 (224 Ah) |
| 0x12 | Full Charge Voltage | mV | 3550 |
| 0x13 | End of Discharge Voltage | mV | 2800 |
| 0x14 | Discharge Rate | — | 1 |
| 0x15 | Production Date | encoded | 2026-05-25 |
| 0x16 | Serial Config Flags | — | 0 |
| 0x17 | Balance Start Voltage | mV | 0 |
| 0x18 | Cell OVP | mV | 3381 |
| 0x19 | Cell OVP Release | mV | 3281 |
| 0x1A | Cell UVP | mV | 2661 |
| 0x1B | Cell UVP Release | mV | 2711 |
| 0x1C | Pack OVP | 10 mV | 3481 (34.81 V) |
| 0x1D | Pack UVP | 10 mV | 3381 (33.81 V) |
| 0x1E | Pack OVP Release | 10 mV | 2531 (25.31 V) |
| 0x1F | Pack UVP Release | 10 mV | 2631 (26.31 V) |
| 0x20 | Charge Over-Temp | NTC raw | — |
| 0x21 | Charge OT Release | NTC raw | — |
| 0x22 | Discharge Over-Temp | NTC raw | — |
| 0x23 | Discharge OT Release | NTC raw | — |
| 0x24 | Charge Under-Temp | NTC raw | — |
| 0x25 | Charge UT Release | NTC raw | — |
| 0x26 | Discharge Under-Temp | NTC raw | — |
| 0x27 | Discharge UT Release | NTC raw | — |
| 0x28 | Charge Over-Current | 10 mA | 22000 (220 A) |
| 0x29 | Discharge Over-Current | 10 mA | 43536 (435 A) |
| 0x2A | Short Circuit Threshold | raw | 0x0CE4 |
| 0x2B | Short Circuit Delay | raw | 0x000F |
| 0x2C | Balance Delta | mV | 1 |
| 0x2D | LED/UART Config | raw | 0x0007 |
| 0x2E | Cell Count Config | — | 0 (auto) |
| 0x2F | NTC Count Config | — | 0 (auto) |
| 0x30 | Function Config | bitmask | 0x001E |
| 0x31 | NTC Enable | bitmask | 0x001E |
| 0x32 | MFG String Length | — | 0x0D01 |
| 0x33 | Model String Length | — | 0x0CEA |

## Extended Registers (require factory mode auth)

| Reg | Name | Our Value |
|---|---|---|
| 0xA0 | Manufacturer Name | "DGJBD" |
| 0xA1 | Device Model | "DP04S007L4S200ABUS" |
| 0xA2 | Barcode/Serial | (blank) |
| 0xAA | Device Serial | 000000000000000100010000000000000000000100010001 (FFA9) |
| 0xAB | Calibration | 0xE377 (FFA9) / 0xE477 (09D2) |

## GATT Characteristics (non-JBD)

| UUID | Value |
|---|---|
| `00010203-...-0d2b12` | 0x00 (unknown custom service) |
| `00002a50` (PnP ID) | `028a2466820100` — vendor=0x8A24, product=0x6682, version=1 |
