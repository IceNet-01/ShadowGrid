# Legal Disclaimer

## Authorized Use Only

ShadowGrid is designed for monitoring **your own** battery systems and power
equipment. You must only connect to, scan, or interact with devices that you
own or have explicit authorization to access.

## Battery Safety Warning

**DANGER: Lithium batteries can cause fire, explosion, or death if misconfigured.**

ShadowGrid includes tools that can modify BMS protection parameters (over-voltage,
under-voltage, over-current thresholds) and toggle charge/discharge FETs. While
ShadowGrid implements a three-tier safety system (safe / warning / blocked) and
requires a service key for dangerous operations, these software guardrails are
**not a substitute** for understanding your battery chemistry, specifications,
and safe operating limits.

**You are solely responsible for any changes you make to your battery configuration.**
The creators and contributors of ShadowGrid accept no liability whatsoever for
damage, injury, fire, property loss, or death resulting from battery misconfiguration,
whether caused by user error, software defect, or any other reason.

## BLE Scanning

The BLE scanner passively receives Bluetooth Low Energy advertisements that
devices broadcast publicly. Passive scanning is legal in most jurisdictions.
**Do not** use the scanner to actively probe, connect to, or exploit devices
you do not own.

## EcoFlow Integration

The EcoFlow BLE integration uses reverse-engineered protocols for
**interoperability** with your own purchased devices, as permitted under
17 U.S.C. 1201(f) (DMCA interoperability exception). This integration is
for personal, non-commercial use only.

## BMS Vulnerability Information

The BMS protocol database documents publicly known characteristics of battery
management systems. This information is provided for **defensive security
awareness** — to help you understand the security posture of your own devices.
Do not use this information to access devices you do not own.

## No Warranty

This software is provided "as-is" without warranty of any kind, express or
implied. The authors and contributors are not responsible for any damage,
data loss, injury, or legal consequences arising from the use or misuse of
this software. **Use entirely at your own risk.**

## User Responsibility

By using ShadowGrid, you agree that you are solely responsible for:
- Ensuring your use complies with all applicable laws
- Verifying that any configuration changes are safe for your specific hardware
- Any consequences — legal, financial, physical, or otherwise — resulting from your use

The creators of ShadowGrid accept no responsibility for misuse of this software.

## Radio Compliance

LoRa firmware operates in the 915 MHz ISM band under FCC Part 15. Ensure
your hardware module has appropriate regulatory certification for your region.
