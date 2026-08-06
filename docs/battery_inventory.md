# Battery Inventory

## Pack 1: BATT_FFA9

| Field | Value |
|---|---|
| BLE Address | AA:BB:CC:DD:EE:01 |
| BLE Advertised Name | BATT_FFA9 |
| BMS Full Name | DP04S007L4S200ABUS |
| Manufacturer | DGJBD (Dongguan JBD) |
| Brand | Eco Worthy |
| Chemistry | LiFePO4 |
| Configuration | 4S (12.8V nominal) |
| Design Capacity | 280 Ah |
| Cycle Capacity (80% DOD) | 224 Ah |
| Production Date | 2026-05-25 |
| FW Version | v6.6 |
| Cycle Count | 0 |
| Barcode/Serial | (not programmed) |
| Calibration ID | 0xE377 |
| GATT PnP ID | vendor=0x8A24, product=0x6682, version=1 |
| Device Serial Raw | 000000000000000100010000000000000000000100010001 |

### First Reading (2026-07-28)
- Voltage: 13.33 V
- Current: +4.99 A (charging)
- SOC: 33-34%
- Remaining: 93.0 Ah
- Cell Voltages: 3.335, 3.335, 3.333, 3.335 V
- Cell Delta: 2 mV
- Temperature: 27.1 C

## Pack 2: BATT_09D2

| Field | Value |
|---|---|
| BLE Address | AA:BB:CC:DD:EE:02 |
| BLE Advertised Name | BATT_09D2 |
| BMS Full Name | DP04S007L4S200ABUS |
| Manufacturer | DGJBD (Dongguan JBD) |
| Brand | Eco Worthy |
| Chemistry | LiFePO4 |
| Configuration | 4S (12.8V nominal) |
| Design Capacity | 280 Ah |
| Cycle Capacity (80% DOD) | 224 Ah |
| Production Date | 2026-05-25 |
| FW Version | v6.6 |
| Cycle Count | 0 |
| Barcode/Serial | (not programmed) |
| Calibration ID | 0xE477 |
| GATT PnP ID | vendor=0x8A24, product=0x6682, version=1 |
| Device Serial Raw | 000000000000000100010000000000000000000100000001 |

### First Reading (2026-07-28)
- Voltage: 13.33 V
- Current: +5.26 A (charging)
- SOC: 32%
- Remaining: 89.2 Ah
- Cell Voltages: 3.333, 3.334, 3.333, 3.334 V
- Cell Delta: 1 mV
- Temperature: 27.9 C

## Notes

- Both packs are identical: same model, same production date, same protection config.
- Both are brand new (0 cycles) as of 2026-07-28.
- BMS factory password is the JBD default: `0x5678`.
- Batteries advertise as `DP04S007L4S200ABUS` during service discovery but as `BATT_xxxx` in the Eco Worthy app.
- BLE signal is weak at current dongle position (~-87 to -90 dBm). Connections require retries. Moving dongle closer improves reliability significantly.
- Config registers (0x10-0x33) require entering factory mode before they return data.
