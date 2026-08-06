"""
EcoFlow Delta 2 BLE Reader for ShadowGrid
Standalone module that connects to an EcoFlow Delta 2 via BLE,
performs the ECDH key exchange + auth handshake, and reads battery data.

Based on the ha-ef-ble reverse engineering project by rabits.
Protocol: encrypt_type=7 (ECDH + AES-CBC), packet_version=2, xor_payload=True

Uses dbus-next for BLE (bleak 3.x has service discovery bugs on this system).
"""

import asyncio
import hashlib
import os
import struct
import subprocess
import logging
import json
import time
from dataclasses import dataclass
from typing import Optional, Callable

import ecdsa
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ha-ef-ble keydata (EcoFlow session-key table). Load from a persistent
# location — a hardcoded /tmp path gets wiped on reboot and took the whole
# server down (2026-08-01). Import is non-fatal: if keydata is missing, only
# EcoFlow BLE auth is disabled, the rest of ShadowGrid still runs.
import sys
_KEYDATA_DIRS = [
    os.path.join(os.path.expanduser("~"), ".local", "share", "shadowgrid", "eflib"),
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "eflib"),
    "/tmp/ha-ef-ble/custom_components/ef_ble/eflib",
]
for _kd in _KEYDATA_DIRS:
    if os.path.isfile(os.path.join(_kd, "keydata.py")):
        sys.path.insert(0, _kd)
        break
try:
    import keydata
except ImportError:
    keydata = None
    logging.getLogger("ecoflow").warning(
        "EcoFlow keydata module not found; EcoFlow BLE auth disabled. "
        "Place keydata.py in ~/.local/share/shadowgrid/eflib/ to enable."
    )

from dbus_next.aio import MessageBus
from dbus_next import BusType, Variant

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("ecoflow")


# ── CRC ────────────────────────────────────────────────────────────────────

def _build_crc8_table():
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = ((crc << 1) ^ 0x07) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
        table.append(crc)
    return table

def _build_crc16_table():
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
        table.append(crc)
    return table

_CRC8_TABLE = _build_crc8_table()
_CRC16_TABLE = _build_crc16_table()

def crc8(data: bytes) -> int:
    crc = 0
    for b in data:
        crc = _CRC8_TABLE[crc ^ b]
    return crc

def crc16(data: bytes) -> int:
    crc = 0
    for b in data:
        crc = _CRC16_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc


# ── Encryption ─────────────────────────────────────────────────────────────

class Type7Encryption:
    def __init__(self, session_key: bytes, iv: bytes):
        self.session_key = session_key
        self.iv = iv

    def encrypt(self, plaintext: bytes) -> bytes:
        cipher = AES.new(self.session_key, AES.MODE_CBC, self.iv)
        return cipher.encrypt(pad(plaintext, AES.block_size))

    def decrypt(self, ciphertext: bytes) -> bytes:
        aligned = len(ciphertext) - len(ciphertext) % AES.block_size
        if aligned == 0:
            return ciphertext
        cipher = AES.new(self.session_key, AES.MODE_CBC, self.iv)
        decrypted = cipher.decrypt(ciphertext[:aligned])
        try:
            return unpad(decrypted, AES.block_size)
        except ValueError:
            return decrypted


# ── EncPacket (0x5A5A wrapper) ─────────────────────────────────────────────

ENC_PREFIX = b"\x5a\x5a"

def enc_packet_encode(frame_type: int, payload: bytes,
                      enc_key: bytes = None, iv: bytes = None) -> bytes:
    """Build an EncPacket frame"""
    if enc_key and iv:
        engine = AES.new(enc_key, AES.MODE_CBC, iv)
        payload = engine.encrypt(pad(payload, AES.block_size))

    data = ENC_PREFIX + struct.pack("<B", frame_type << 4) + b"\x01"
    data += struct.pack("<H", len(payload) + 2)  # +2 for trailing crc16
    data += payload
    data += struct.pack("<H", crc16(data))
    return data

def enc_packet_decode_simple(data: bytes) -> Optional[bytes]:
    """Parse a simple (unencrypted) EncPacket, return payload"""
    while data:
        start = data.find(ENC_PREFIX)
        if start < 0:
            return None
        data = data[start:]
        if len(data) < 8:
            return None
        header = data[0:6]
        data_end = 6 + struct.unpack("<H", header[4:6])[0]
        if data_end > len(data):
            return None
        payload_data = data[6:data_end - 2]
        payload_crc = data[data_end - 2:data_end]
        if crc16(header + payload_data) != struct.unpack("<H", payload_crc)[0]:
            data = data[2:]
            continue
        return payload_data
    return None

def enc_packet_decode_encrypted(data: bytes, encryption: Type7Encryption) -> list[bytes]:
    """Parse encrypted EncPacket frames, return list of decrypted payloads"""
    payloads = []
    while data:
        start = data.find(ENC_PREFIX)
        if start < 0:
            break
        data = data[start:]
        if len(data) < 8:
            break
        header = data[0:6]
        payload_len = struct.unpack("<H", header[4:6])[0]
        if payload_len > 10000:
            data = data[2:]
            continue
        data_end = 6 + payload_len
        if data_end > len(data):
            break
        payload_data = data[6:data_end - 2]
        payload_crc = data[data_end - 2:data_end]
        if crc16(header + payload_data) != struct.unpack("<H", payload_crc)[0]:
            data = data[2:]
            continue
        data = data[data_end:]
        decrypted = encryption.decrypt(payload_data)
        payloads.append(decrypted)
    return payloads


# ── V2 Packet ──────────────────────────────────────────────────────────────

@dataclass
class Packet:
    src: int
    dst: int
    cmd_set: int
    cmd_id: int
    payload: bytes = b""
    dsrc: int = 1
    ddst: int = 1
    version: int = 2
    seq: bytes = b"\x00\x00\x00\x00"

    def to_bytes(self) -> bytes:
        data = b"\xaa" + struct.pack("<B", self.version)
        data += struct.pack("<H", len(self.payload))
        data += struct.pack("<B", crc8(data))
        data += b"\x0d" + self.seq + b"\x00\x00"
        data += struct.pack("<BB", self.src, self.dst)
        data += struct.pack("<BB", self.cmd_set, self.cmd_id)
        data += self.payload
        data += struct.pack("<H", crc16(data))
        return data

    @staticmethod
    def from_bytes(data: bytes, xor_payload: bool = True) -> Optional["Packet"]:
        if not data or data[0] != 0xAA:
            return None
        version_byte = data[1]
        version = version_byte & 0x0F
        sentinel_format = (version_byte & 0x10) != 0

        if (version == 2 and len(data) < 18) or (version == 3 and len(data) < 20):
            return None
        payload_length = struct.unpack("<H", data[2:4])[0]
        if crc8(data[:4]) != data[4]:
            return None
        seq = data[6:10]
        src = data[12]
        dst = data[13]

        # V2: cmd_set/cmd_id at 14-15, payload at 16
        # V3: dsrc/ddst at 14-15, cmd_set/cmd_id at 16-17, payload at 18
        if version == 2:
            cmd_set, cmd_id = data[14], data[15]
            payload_start = 16
        else:
            cmd_set, cmd_id = data[16], data[17]
            payload_start = 18

        payload = b""
        if payload_length > 0:
            payload = data[payload_start:payload_start + payload_length]
            # XOR decode — Delta 2 always XOR's payload with seq[0]
            if xor_payload and seq[0] != 0:
                payload = bytes(c ^ seq[0] for c in payload)
            # Strip sentinel markers
            if sentinel_format and len(payload) >= 2 and payload[-2:] == b"\xbb\xbb":
                payload = payload[:-2]
        return Packet(src=src, dst=dst, cmd_set=cmd_set, cmd_id=cmd_id,
                      payload=payload, version=version_byte, seq=seq)


# ── Session Key Generation ─────────────────────────────────────────────────

def gen_session_key(seed: bytes, srand: bytes) -> bytes:
    """Generate session key from seed and sRand using keydata table"""
    data_num = [0, 0, 0, 0]
    pos = seed[0] * 0x10 + ((seed[1] - 1) & 0xFF) * 0x100
    data_num[0] = struct.unpack("<Q", keydata.get8bytes(pos))[0]
    pos += 8
    data_num[1] = struct.unpack("<Q", keydata.get8bytes(pos))[0]
    data_num[2] = struct.unpack("<Q", srand[0:8])[0]
    data_num[3] = struct.unpack("<Q", srand[8:16])[0]
    data = b""
    for n in data_num:
        data += struct.pack("<Q", n)
    return hashlib.md5(data).digest()


def get_ecdh_type_size(curve_num: int) -> int:
    match curve_num:
        case 1: return 52
        case 2: return 56
        case 3 | 4: return 64
        case _: return 40


# ── EcoFlow BLE Connection ─────────────────────────────────────────────────

class EcoFlowBLE:
    """Manages BLE connection to EcoFlow Delta 2 via D-Bus"""

    def __init__(self, address: str, serial: str, user_id: str):
        self.address = address
        self.serial = serial
        self.user_id = user_id
        self.dev_path = "/org/bluez/hci0/dev_" + address.replace(":", "_")
        self.bus = None
        self.encryption = None
        self.authenticated = False
        self.data_callback = None
        self._write_char = None
        self._notify_char = None
        self._nprops = None
        self._rx_event = asyncio.Event()
        self._rx_buffer = bytearray()
        self._latest = {}

    async def connect(self):
        """Connect via bluetoothctl + D-Bus"""
        # Trust and connect via bluetoothctl
        subprocess.run(
            ["sudo", "-S", "bluetoothctl", "trust", self.address],
            input=os.environ.get("SUDO_PW", "").encode() + b"\n", capture_output=True
        )
        result = subprocess.run(
            ["sudo", "-S", "bluetoothctl", "connect", self.address],
            input=os.environ.get("SUDO_PW", "").encode() + b"\n", capture_output=True, timeout=15
        )
        output = result.stdout.decode()
        if "Connection successful" not in output:
            raise ConnectionError(f"BLE connect failed: {output}")

        log.info("BLE connected to %s", self.address)
        await asyncio.sleep(2)

        # Open D-Bus
        self.bus = await MessageBus(bus_type=BusType.SYSTEM).connect()

        # Verify connected
        di = await self.bus.introspect("org.bluez", self.dev_path)
        do = self.bus.get_proxy_object("org.bluez", self.dev_path, di)
        dev = do.get_interface("org.bluez.Device1")
        if not await dev.get_connected():
            raise ConnectionError("Device connected then dropped")

        # Resolve GATT paths
        write_path = self.dev_path + "/service0028/char0029"
        notify_path = self.dev_path + "/service0028/char002b"

        # Write char
        wi = await self.bus.introspect("org.bluez", write_path)
        wo = self.bus.get_proxy_object("org.bluez", write_path, wi)
        self._write_char = wo.get_interface("org.bluez.GattCharacteristic1")

        # Notify char
        ni = await self.bus.introspect("org.bluez", notify_path)
        no = self.bus.get_proxy_object("org.bluez", notify_path, ni)
        self._notify_char = no.get_interface("org.bluez.GattCharacteristic1")
        self._nprops = no.get_interface("org.freedesktop.DBus.Properties")

    async def _write(self, data: bytes, response: bool = True):
        """Write to the BLE GATT characteristic"""
        if response:
            await self._write_char.call_write_value(
                data, {"type": Variant("s", "request")}
            )
        else:
            await self._write_char.call_write_value(
                data, {"type": Variant("s", "command")}
            )

    async def _subscribe(self, handler):
        """Subscribe to notifications"""
        self._nprops.on_properties_changed(handler)
        await self._notify_char.call_start_notify()

    async def _unsubscribe(self):
        """Stop notifications"""
        try:
            await self._notify_char.call_stop_notify()
        except Exception:
            pass

    async def _wait_for_response(self, timeout: float = 10.0) -> bytes:
        """Wait for a BLE notification response"""
        self._rx_buffer.clear()
        self._rx_event.clear()
        try:
            await asyncio.wait_for(self._rx_event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            raise TimeoutError("No BLE response")
        return bytes(self._rx_buffer)

    # ── ECDH Key Exchange ──────────────────────────────────────────────────

    async def authenticate(self):
        """Full ECDH handshake + auth flow.
        Uses a single persistent notification handler throughout — never
        unsubscribes between steps to avoid the device dropping the connection."""
        log.info("Starting ECDH key exchange...")

        # Single persistent notification handler — routes to handshake
        # or data processing depending on auth state
        def on_notify(iface, changed, inv):
            if "Value" in changed:
                data = bytes(changed["Value"].value)
                self._rx_buffer.extend(data)
                self._rx_event.set()
                if self.authenticated:
                    self._process_rx_buffer()

        await self._subscribe(on_notify)

        # Step 1: Generate keypair and send public key
        private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP160r1)
        public_key = private_key.get_verifying_key()

        pubkey_payload = b"\x01\x00" + public_key.to_string()
        pubkey_packet = enc_packet_encode(0x00, pubkey_payload)

        # Retry ECDH up to 5 times (BLE responses can be corrupted by adapter contention)
        dev_pub_key = None
        for attempt in range(5):
            self._rx_buffer.clear()
            self._rx_event.clear()
            log.info("Sending public key (attempt %d)", attempt + 1)
            await self._write(pubkey_packet, response=True)

            response = await self._wait_for_response(timeout=10)
            dev_key_data = enc_packet_decode_simple(response)
            if dev_key_data is None or len(dev_key_data) < 3:
                log.warning("Bad pubkey response (%d bytes), retrying...", len(response))
                await asyncio.sleep(1)
                continue

            curve_num = dev_key_data[2]
            ecdh_size = get_ecdh_type_size(curve_num)
            try:
                dev_pub_key = ecdsa.VerifyingKey.from_string(
                    dev_key_data[3:3 + ecdh_size], curve=ecdsa.SECP160r1
                )
                log.info("Received device public key (%d bytes)", len(dev_key_data))
                break
            except Exception as e:
                log.warning("ECDH key parse failed: %s, retrying...", e)
                await asyncio.sleep(2)
                # Flush any stale data
                self._rx_buffer.clear()
                self._rx_event.clear()
                continue

        if dev_pub_key is None:
            raise ConnectionError("Failed to get valid device public key after 5 attempts")

        shared_key = ecdsa.ECDH(
            ecdsa.SECP160r1, private_key, dev_pub_key
        ).generate_sharedsecret_bytes()
        iv = hashlib.md5(shared_key).digest()
        self.encryption = Type7Encryption(shared_key[:16], iv)
        log.info("ECDH shared key derived")

        # Step 2: Request session key info (reuse same handler, just clear buffer)
        self._rx_buffer.clear()
        self._rx_event.clear()

        key_req = enc_packet_encode(0x00, b"\x02")
        log.info("Requesting session key info...")
        await self._write(key_req, response=True)

        response = await self._wait_for_response(timeout=10)

        key_info = enc_packet_decode_simple(response)
        if key_info is None or key_info[0] != 0x02:
            raise ConnectionError(f"Bad key info response: {response[:32].hex()}")

        decrypted_key_info = self.encryption.decrypt(key_info[1:])
        srand = decrypted_key_info[:16]
        seed = decrypted_key_info[16:18]
        session_key = gen_session_key(seed, srand)
        self.encryption = Type7Encryption(session_key, self.encryption.iv)
        log.info("Session key established")

        # Step 3: Send auth status request
        self._rx_buffer.clear()
        self._rx_event.clear()

        auth_status_pkt = Packet(0x21, 0x35, 0x35, 0x89, b"", version=2)
        encoded = enc_packet_encode(
            0x01, auth_status_pkt.to_bytes(),
            enc_key=self.encryption.session_key,
            iv=self.encryption.iv
        )
        log.info("Requesting auth status...")
        await self._write(encoded, response=True)

        response = await self._wait_for_response(timeout=10)
        log.info("Auth status received (%d bytes)", len(response))

        # Step 4: Send authentication (MD5 of user_id + serial)
        self._rx_buffer.clear()
        self._rx_event.clear()

        md5_data = hashlib.md5(
            (self.user_id + self.serial).encode("ASCII")
        ).digest()
        auth_payload = ("".join(f"{c:02X}" for c in md5_data)).encode("ASCII")

        auth_pkt = Packet(0x21, 0x35, 0x35, 0x86, auth_payload, version=2)
        encoded = enc_packet_encode(
            0x01, auth_pkt.to_bytes(),
            enc_key=self.encryption.session_key,
            iv=self.encryption.iv
        )
        log.info("Sending auth credentials...")
        await self._write(encoded, response=False)

        # Wait briefly for auth response, then start processing data
        await asyncio.sleep(3)

        # From this point, incoming data goes through the encrypted data pipeline
        # Swap the handler to process encrypted heartbeat packets
        # (The D-Bus properties_changed signal keeps firing to the same handler)
        self.authenticated = True
        log.info("Authentication complete — listening for data")

    # ── Data Processing ────────────────────────────────────────────────────

    def _process_rx_buffer(self):
        """Process incoming encrypted data from the RX buffer"""
        if not self.encryption:
            return

        data = bytes(self._rx_buffer)
        if not data:
            return

        payloads = enc_packet_decode_encrypted(data, self.encryption)
        if payloads:
            self._rx_buffer.clear()
            for payload in payloads:
                packet = Packet.from_bytes(payload)
                if packet:
                    self._handle_packet(packet)

    def _parse_bms(self, pl: bytes) -> Optional[dict]:
        """Parse a BMS heartbeat payload into a dict. Returns None if sanity check fails."""
        if len(pl) < 30:
            return None
        off = 0
        num = pl[off]; off += 1        # pack number (0=main, 1=ext1, 2=ext2)
        off += 1 + 1                   # type, cellId
        err = struct.unpack_from("<I", pl, off)[0]; off += 4
        off += 4                       # sysVer
        soc = pl[off]; off += 1
        vol = struct.unpack_from("<I", pl, off)[0]; off += 4
        amp = struct.unpack_from("<I", pl, off)[0]; off += 4
        temp = pl[off]; off += 1
        off += 1                       # openBmsIdx
        design_cap = struct.unpack_from("<I", pl, off)[0]; off += 4
        remain_cap = struct.unpack_from("<I", pl, off)[0]; off += 4
        full_cap = struct.unpack_from("<I", pl, off)[0]; off += 4
        cycles = struct.unpack_from("<I", pl, off)[0]; off += 4
        soh = pl[off] if off < len(pl) else 0; off += 1

        # Cell voltages
        max_cell_v = min_cell_v = 0
        max_cell_t = min_cell_t = 0
        max_mos_t = min_mos_t = 0
        if off + 6 <= len(pl):
            max_cell_v = struct.unpack_from("<H", pl, off)[0]; off += 2
            min_cell_v = struct.unpack_from("<H", pl, off)[0]; off += 2
            max_cell_t = pl[off]; off += 1
            min_cell_t = pl[off]; off += 1
        if off + 2 <= len(pl):
            max_mos_t = pl[off]; off += 1
            min_mos_t = pl[off]; off += 1

        # f32_show_soc, input/output watts, remain_time at end
        f32_soc = None
        input_w = output_w = remain_time = 0
        if off + 4 <= len(pl):
            off += 1 + 1  # bms_fault, bq_sys_stat_reg
            off += 4      # tag_chg_amp
        if off + 4 <= len(pl):
            f32_soc = struct.unpack_from("<f", pl, off)[0]; off += 4
        if off + 12 <= len(pl):
            input_w = struct.unpack_from("<I", pl, off)[0]; off += 4
            output_w = struct.unpack_from("<I", pl, off)[0]; off += 4
            remain_time = struct.unpack_from("<I", pl, off)[0]; off += 4

        if amp > 0x7FFFFFFF:
            amp -= 0x100000000

        # Sanity check — log rejections to debug missing packs
        if vol > 100000 or vol < 1000 or abs(amp) > 200000:
            log.warning("BMS sanity REJECT: num=%d vol=%d amp=%d soc=%d", num, vol, amp, soc)
            return None

        return {
            "num": num, "soc": soc, "vol_mv": vol, "amp_ma": amp,
            "voltage": vol / 1000.0, "current": amp / 1000.0,
            "temp": temp, "design_cap": design_cap,
            "remain_cap": remain_cap, "full_cap": full_cap,
            "cycles": cycles, "soh": soh, "err_code": err,
            "max_cell_v": max_cell_v, "min_cell_v": min_cell_v,
            "cell_delta_mv": max_cell_v - min_cell_v if max_cell_v and min_cell_v else 0,
            "max_cell_temp": max_cell_t, "min_cell_temp": min_cell_t,
            "max_mos_temp": max_mos_t, "min_mos_temp": min_mos_t,
            "f32_soc": f32_soc, "input_w": input_w, "output_w": output_w,
            "remain_time": remain_time,
        }

    def _handle_packet(self, pkt: Packet):
        """Process a decoded packet — full Delta 2 struct parsing"""
        pl = pkt.payload

        # ── PD Heartbeat ───────────────────────────────────────────────
        if pkt.src == 0x02 and pkt.cmd_set == 0x20 and pkt.cmd_id == 0x02:
            if len(pl) < 20:
                return
            off = 1 + 4 + 4 + 4 + 1   # model + errCode + sysVer + wifiVer + wifiAutoRcvy = 14
            soc = pl[off]; off += 1
            out_w = struct.unpack_from("<H", pl, off)[0]; off += 2
            in_w = struct.unpack_from("<H", pl, off)[0]; off += 2
            remain = struct.unpack_from("<i", pl, off)[0]; off += 4
            # Per-port power
            beep = pl[off]; off += 1
            dc_out = pl[off]; off += 1
            usb1 = pl[off]; off += 1
            usb2 = pl[off]; off += 1
            qc1 = pl[off]; off += 1
            qc2 = pl[off]; off += 1
            tc1 = pl[off]; off += 1
            tc2 = pl[off]; off += 1
            tc1_temp = pl[off]; off += 1
            tc2_temp = pl[off]; off += 1
            car_state = pl[off]; off += 1
            car_w = pl[off]; off += 1
            car_temp = pl[off]; off += 1

            # Charging power breakdown (further into payload)
            dc_chg = ac_chg = solar_chg = dc_dsg = ac_dsg = 0
            if off + 4 <= len(pl):
                off += 2 + 2 + 1  # standby_min(H) lcd_off_sec(H) lcd_brightness(B)
            if off + 20 <= len(pl):
                dc_chg = struct.unpack_from("<I", pl, off)[0]; off += 4
                solar_chg = struct.unpack_from("<I", pl, off)[0]; off += 4
                ac_chg = struct.unpack_from("<I", pl, off)[0]; off += 4
                dc_dsg = struct.unpack_from("<I", pl, off)[0]; off += 4
                ac_dsg = struct.unpack_from("<I", pl, off)[0]; off += 4

            self._latest.update({
                "pd_soc": soc, "pd_out_w": out_w, "pd_in_w": in_w,
                "pd_remain_min": remain,
                "pd_usb1_w": usb1, "pd_usb2_w": usb2,
                "pd_qc1_w": qc1, "pd_qc2_w": qc2,
                "pd_typec1_w": tc1, "pd_typec2_w": tc2,
                "pd_typec1_temp": tc1_temp, "pd_typec2_temp": tc2_temp,
                "pd_car_w": car_w, "pd_car_state": car_state,
                "pd_car_temp": car_temp, "pd_dc_out": dc_out,
                "pd_dc_chg_w": dc_chg, "pd_solar_chg_w": solar_chg,
                "pd_ac_chg_w": ac_chg, "pd_dc_dsg_w": dc_dsg,
                "pd_ac_dsg_w": ac_dsg,
            })
            log.info("PD: SOC=%d%% IN=%dW OUT=%dW (AC:%d DC:%d Solar:%d) USB:%d+%d TC:%d+%d Car:%d",
                     soc, in_w, out_w, ac_chg, dc_chg, solar_chg,
                     usb1, usb2, tc1, tc2, car_w)

        # ── BMS Heartbeat ──────────────────────────────────────────────
        # Main battery: src=0x03, cmd_set=0x20, cmd_id=0x32
        # Extra battery 1: src=0x06, cmd_set=0x20, cmd_id=0x32
        # Extra battery 2: src=0x07, cmd_set=0x20, cmd_id=0x32 (if exists)
        elif pkt.cmd_set == 0x20 and pkt.cmd_id == 0x32 and pkt.src in (0x03, 0x06, 0x07):
            bms = self._parse_bms(pl)
            if bms is None:
                return

            # Determine pack from source address, not the num field
            # src=0x03 = main, src=0x06 = extra 1, src=0x07 = extra 2
            pack_idx = {0x03: 0, 0x06: 1, 0x07: 2}.get(pkt.src, bms["num"])
            prefix = "bms" if pack_idx == 0 else f"bms{pack_idx}"

            self._latest[f"{prefix}_soc"] = bms["soc"]
            self._latest[f"{prefix}_voltage"] = bms["voltage"]
            self._latest[f"{prefix}_current"] = bms["current"]
            self._latest[f"{prefix}_vol_mv"] = bms["vol_mv"]
            self._latest[f"{prefix}_amp_ma"] = bms["amp_ma"]
            self._latest[f"{prefix}_temp"] = bms["temp"]
            self._latest[f"{prefix}_cycles"] = bms["cycles"]
            self._latest[f"{prefix}_soh"] = bms["soh"]
            self._latest[f"{prefix}_design_cap"] = bms["design_cap"]
            self._latest[f"{prefix}_remain_cap"] = bms["remain_cap"]
            self._latest[f"{prefix}_full_cap"] = bms["full_cap"]
            self._latest[f"{prefix}_max_cell_v"] = bms["max_cell_v"]
            self._latest[f"{prefix}_min_cell_v"] = bms["min_cell_v"]
            self._latest[f"{prefix}_cell_delta"] = bms["cell_delta_mv"]
            self._latest[f"{prefix}_max_cell_temp"] = bms["max_cell_temp"]
            self._latest[f"{prefix}_min_cell_temp"] = bms["min_cell_temp"]
            self._latest[f"{prefix}_max_mos_temp"] = bms["max_mos_temp"]
            self._latest[f"{prefix}_err"] = bms["err_code"]
            self._latest[f"{prefix}_input_w"] = bms["input_w"]
            self._latest[f"{prefix}_output_w"] = bms["output_w"]
            if bms["f32_soc"] is not None:
                self._latest[f"{prefix}_f32_soc"] = round(bms["f32_soc"], 1)

            pack_label = "Main" if pack_idx == 0 else f"Ext{pack_idx}"
            log.info("BMS[%s]: SOC=%d%% V=%.2fV I=%.2fA T=%dC cycles=%d soh=%d%% cells=%d-%dmV",
                     pack_label, bms["soc"], bms["voltage"], bms["current"],
                     bms["temp"], bms["cycles"], bms["soh"],
                     bms["min_cell_v"], bms["max_cell_v"])

        # ── EMS Heartbeat ──────────────────────────────────────────────
        elif pkt.src == 0x03 and pkt.cmd_set == 0x20 and pkt.cmd_id == 0x02:
            if len(pl) < 15:
                return
            off = 0
            chg_state = pl[off]; off += 1
            chg_cmd = pl[off]; off += 1
            dsg_cmd = pl[off]; off += 1
            chg_vol = struct.unpack_from("<I", pl, off)[0]; off += 4
            chg_amp = struct.unpack_from("<I", pl, off)[0]; off += 4
            fan = pl[off]; off += 1
            max_soc = pl[off]; off += 1
            off += 1  # bmsModel
            lcd_soc = pl[off]; off += 1
            ups_flag = pl[off] if off < len(pl) else 0; off += 1
            warn_state = pl[off] if off < len(pl) else 0; off += 1

            chg_remain = dsg_remain = 0
            min_dsg_soc = 0
            if off + 8 <= len(pl):
                chg_remain = struct.unpack_from("<I", pl, off)[0]; off += 4
                dsg_remain = struct.unpack_from("<I", pl, off)[0]; off += 4
            # Skip some fields to get min_dsg_soc
            if off + 1 <= len(pl):
                off += 1  # emsIsNormalFlag
            if off + 4 <= len(pl):
                off += 4  # f32LcdShowSoc
            if off + 3 <= len(pl):
                off += 3  # bmsIsConnt (3 bytes)
            if off + 2 <= len(pl):
                off += 1 + 1  # maxAvailableNum, openBmsIdx
            if off + 8 <= len(pl):
                off += 4 + 4  # paraVolMin, paraVolMax
            if off + 1 <= len(pl):
                min_dsg_soc = pl[off]

            # Parse bmsIsConnt (3 bytes — one per pack slot)
            bms_connt = [0, 0, 0]
            max_avail = 0
            if off + 1 <= len(pl):
                off += 1  # emsIsNormalFlag
            if off + 4 <= len(pl):
                off += 4  # f32LcdShowSoc
            if off + 3 <= len(pl):
                bms_connt = [pl[off], pl[off+1], pl[off+2]]; off += 3
            if off + 1 <= len(pl):
                max_avail = pl[off]

            self._latest.update({
                "ems_soc": lcd_soc, "ems_chg_state": chg_state,
                "ems_fan": fan, "ems_max_soc": max_soc,
                "ems_min_dsg_soc": min_dsg_soc,
                "ems_ups_flag": ups_flag, "ems_warn": warn_state,
                "ems_chg_remain_s": chg_remain,
                "ems_dsg_remain_s": dsg_remain,
                "ems_chg_vol_mv": chg_vol, "ems_chg_amp_ma": chg_amp,
                "ems_bms_connt": bms_connt,
                "ems_max_avail": max_avail,
            })
            log.info("EMS: soc=%d%% chg=%d fan=%d max=%d min=%d packs=%s avail=%d",
                     lcd_soc, chg_state, fan, max_soc, min_dsg_soc, bms_connt, max_avail)

        # ── Inverter Heartbeat ─────────────────────────────────────────
        elif pkt.src == 0x04 and pkt.cmd_set == 0x20 and pkt.cmd_id == 0x02:
            if len(pl) < 20:
                return
            off = 0
            off += 4 + 4  # errCode, sysVer
            charger_type = pl[off]; off += 1
            inv_in_w = struct.unpack_from("<H", pl, off)[0]; off += 2
            inv_out_w = struct.unpack_from("<H", pl, off)[0]; off += 2
            inv_type = pl[off]; off += 1
            inv_out_v = struct.unpack_from("<I", pl, off)[0]; off += 4
            inv_out_a = struct.unpack_from("<I", pl, off)[0]; off += 4
            inv_out_hz = pl[off] if off < len(pl) else 0; off += 1

            ac_in_v = ac_in_a = ac_in_hz = 0
            if off + 9 <= len(pl):
                ac_in_v = struct.unpack_from("<I", pl, off)[0]; off += 4
                ac_in_a = struct.unpack_from("<I", pl, off)[0]; off += 4
                ac_in_hz = pl[off]; off += 1

            ac_enabled = 0
            if off + 3 <= len(pl):
                off += 2 + 4 + 4 + 2  # out_temp, dc_in_vol, dc_in_amp, dc_in_temp
                off += 1  # fan_state
                if off < len(pl):
                    ac_enabled = pl[off]

            self._latest.update({
                "inv_in_w": inv_in_w, "inv_out_w": inv_out_w,
                "inv_out_v": inv_out_v / 1000.0,
                "inv_out_a": inv_out_a / 1000.0,
                "inv_out_hz": inv_out_hz,
                "inv_ac_in_v": ac_in_v / 1000.0,
                "inv_ac_in_a": ac_in_a / 1000.0,
                "inv_ac_in_hz": ac_in_hz,
                "inv_ac_enabled": ac_enabled,
                "inv_charger_type": charger_type,
            })
            log.debug("INV: in=%dW out=%dW ac_out=%.1fV/%.1fA/%dHz ac_in=%.1fV",
                      inv_in_w, inv_out_w, inv_out_v/1000.0, inv_out_a/1000.0,
                      inv_out_hz, ac_in_v/1000.0)

        # ── MPPT Heartbeat ─────────────────────────────────────────────
        elif pkt.src == 0x05 and pkt.cmd_set == 0x20 and pkt.cmd_id == 0x02:
            if len(pl) < 20:
                return
            off = 0
            off += 4 + 4  # fault_code, sw_ver
            mppt_in_v = struct.unpack_from("<I", pl, off)[0]; off += 4
            mppt_in_a = struct.unpack_from("<I", pl, off)[0]; off += 4
            mppt_in_w = struct.unpack_from("<H", pl, off)[0]; off += 2
            mppt_out_v = struct.unpack_from("<I", pl, off)[0]; off += 4
            mppt_out_a = struct.unpack_from("<I", pl, off)[0]; off += 4
            mppt_out_w = struct.unpack_from("<H", pl, off)[0]; off += 2
            mppt_temp = struct.unpack_from("<h", pl, off)[0] if off + 2 <= len(pl) else 0; off += 2

            # 12V car output
            car_out_v = car_out_a = car_out_w = 0
            if off + 14 <= len(pl):
                off += 1 + 1 + 1 + 1  # xt60_type, cfg_chg_type, chg_type, chg_state
                off += 4 + 4 + 2      # dcdc_12v: vol, amp, watts
                car_out_v = struct.unpack_from("<I", pl, off)[0]; off += 4
                car_out_a = struct.unpack_from("<I", pl, off)[0]; off += 4
                car_out_w = struct.unpack_from("<H", pl, off)[0]; off += 2

            self._latest.update({
                "mppt_in_v": mppt_in_v / 1000.0,
                "mppt_in_a": mppt_in_a / 1000.0,
                "mppt_in_w": mppt_in_w,
                "mppt_out_v": mppt_out_v / 1000.0,
                "mppt_out_a": mppt_out_a / 1000.0,
                "mppt_out_w": mppt_out_w,
                "mppt_temp": mppt_temp,
                "mppt_car_v": car_out_v / 1000.0,
                "mppt_car_a": car_out_a / 1000.0,
                "mppt_car_w": car_out_w,
            })
            log.debug("MPPT: in=%.1fV/%.2fA/%dW out=%.1fV/%.2fA/%dW temp=%dC car=%dW",
                      mppt_in_v/1000, mppt_in_a/1000, mppt_in_w,
                      mppt_out_v/1000, mppt_out_a/1000, mppt_out_w,
                      mppt_temp, car_out_w)

        # ── AllKitDetailData (connected accessories info) ───────────────
        elif pkt.src == 0x03 and pkt.cmd_set == 0x03 and pkt.cmd_id == 0x0E:
            if len(pl) > 20:
                # Contains serial numbers of connected packs
                # Format: count(B) then per-kit entries with serial numbers
                try:
                    kit_count = pl[0]
                    off = 1
                    kits = []
                    for i in range(kit_count):
                        if off + 20 > len(pl):
                            break
                        # Each kit: some header bytes + 16-byte serial
                        kit_type = pl[off]; off += 1
                        off += 1  # unknown
                        sn_bytes = pl[off:off+16]; off += 16
                        sn = sn_bytes.decode('ascii', errors='replace').rstrip('\x00')
                        kits.append({"type": kit_type, "serial": sn})
                        off += 2  # skip remaining per-kit data
                    self._latest["kits"] = kits
                    for k in kits:
                        log.info("Kit: type=%d serial=%s", k["type"], k["serial"])
                except Exception as e:
                    log.debug("AllKitDetailData parse error: %s", e)

        # ── Auth response ──────────────────────────────────────────────
        elif pkt.src == 0x35 and pkt.cmd_set == 0x35 and pkt.cmd_id == 0x86:
            if pl.hex() != "03":  # 03 = ack from our replies, don't spam log
                log.info("Auth response: %s", pl.hex())

        else:
            # Log unknown packets from interesting sources
            if pkt.src in (0x02, 0x03, 0x04, 0x05, 0x06, 0x07):
                src_map = {2: "PD", 3: "BMS/EMS", 4: "INV", 5: "MPPT"}
                if "unknown_pkts" not in self._latest:
                    self._latest["unknown_pkts"] = set()
                key = f"{pkt.src}:{pkt.cmd_set}:{pkt.cmd_id}"
                if key not in self._latest["unknown_pkts"]:
                    self._latest["unknown_pkts"].add(key)
                    log.warning("Unknown pkt src=%s set=0x%02x id=0x%02x len=%d: %s",
                                src_map.get(pkt.src, hex(pkt.src)),
                                pkt.cmd_set, pkt.cmd_id, len(pl), pl[:30].hex())
            return  # Don't update timestamp for unknown

        self._latest["last_update"] = time.time()
        if self.data_callback:
            self.data_callback(self._latest.copy())

        # Reply to data heartbeat packets only (not auth responses or our own replies)
        # Only reply to src=0x02-0x07 (device subsystems), skip src=0x35 (auth) and src=0x21 (app/us)
        if (self.authenticated and self.encryption and self._write_char
                and pkt.src in (0x02, 0x03, 0x04, 0x05, 0x06, 0x07)
                and pkt.cmd_set == 0x20):
            asyncio.get_event_loop().create_task(self._reply_packet(pkt))

    async def _reply_packet(self, pkt: Packet):
        """Echo packet back with src/dst swapped — tells the Delta 2 we're listening,
        which makes it send more detailed data (configs, extra battery info, etc.)"""
        try:
            reply = Packet(
                src=pkt.dst,    # swap
                dst=pkt.src,    # swap
                cmd_set=pkt.cmd_set,
                cmd_id=pkt.cmd_id,
                payload=pkt.payload,
                version=pkt.version,
                seq=pkt.seq,
            )
            encoded = enc_packet_encode(
                0x01, reply.to_bytes(),
                enc_key=self.encryption.session_key,
                iv=self.encryption.iv
            )
            await self._write(encoded, response=False)
        except Exception:
            pass  # Non-critical — device will still send basics without replies

    # ── Commands ────────────────────────────────────────────────────────

    async def send_command(self, src, dst, cmd_set, cmd_id, payload=b""):
        """Send an encrypted command packet to the Delta 2"""
        if not self.authenticated or not self.encryption:
            raise ConnectionError("Not authenticated")
        pkt = Packet(src=src, dst=dst, cmd_set=cmd_set, cmd_id=cmd_id,
                     payload=payload, version=2)
        encoded = enc_packet_encode(
            0x01, pkt.to_bytes(),
            enc_key=self.encryption.session_key,
            iv=self.encryption.iv
        )
        await self._write(encoded, response=False)
        log.info("CMD: dst=0x%02x set=0x%02x id=0x%02x payload=%s",
                 dst, cmd_set, cmd_id, payload.hex())

    async def set_usb_ports(self, enabled: bool):
        """Turn USB-A output ports on/off"""
        await self.send_command(0x21, 0x02, 0x20, 0x22, (1 if enabled else 0).to_bytes(1, 'little'))

    async def set_dc_12v_port(self, enabled: bool):
        """Turn 12V car/DC port on/off"""
        await self.send_command(0x21, 0x05, 0x20, 0x51, (1 if enabled else 0).to_bytes(1, 'little'))

    async def set_ac_output(self, enabled: bool):
        """Turn AC inverter output on/off"""
        payload = bytes([1 if enabled else 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
        await self.send_command(0x21, 0x05, 0x20, 0x42, payload)

    async def set_max_charge_soc(self, limit: int):
        """Set maximum charge SOC (30-100%)"""
        limit = max(30, min(100, limit))
        await self.send_command(0x21, 0x03, 0x20, 0x31, limit.to_bytes(1, 'little'))

    async def set_min_discharge_soc(self, limit: int):
        """Set minimum discharge SOC (0-30%)"""
        limit = max(0, min(30, limit))
        await self.send_command(0x21, 0x03, 0x20, 0x33, limit.to_bytes(1, 'little'))

    async def set_ac_charging_speed(self, watts: int):
        """Set AC charging speed limit (100-1200W for Delta 2)"""
        watts = max(100, min(1500, watts))
        payload = watts.to_bytes(2, 'little') + bytes([0xFF])
        await self.send_command(0x21, 0x05, 0x20, 0x45, payload)

    async def set_energy_backup(self, enabled: bool, soc_level: int = 50):
        """Enable/disable energy backup mode with SOC threshold"""
        soc_level = max(5, min(100, soc_level))
        payload = bytes([0x01 if enabled else 0, soc_level, 0x00, 0x00])
        await self.send_command(0x21, 0x02, 0x20, 0x5E, payload)

    async def set_grid_bypass(self, disabled: bool):
        """Disable/enable AC pass-through (grid bypass)"""
        await self.send_command(0x21, 0x02, 0x20, 0x60, (1 if disabled else 0).to_bytes(1, 'little'))

    def get_latest(self) -> dict:
        """Get the latest readings"""
        return self._latest.copy()

    async def run(self, duration: float = 0):
        """Run for a duration (0 = forever)"""
        if duration > 0:
            await asyncio.sleep(duration)
        else:
            while True:
                await asyncio.sleep(1)

    async def disconnect(self):
        """Disconnect"""
        try:
            await self._unsubscribe()
        except Exception:
            pass
        subprocess.run(
            ["sudo", "-S", "bluetoothctl", "disconnect", self.address],
            input=os.environ.get("SUDO_PW", "").encode() + b"\n", capture_output=True
        )
        if self.bus:
            self.bus.disconnect()
        log.info("Disconnected from %s", self.address)


# ── Standalone Test ────────────────────────────────────────────────────────

async def main():
    ADDR = "XX:XX:XX:XX:XX:XX"
    SERIAL = "YOUR_ECOFLOW_SERIAL"
    USER_ID = "YOUR_ECOFLOW_USER_ID"

    ef = EcoFlowBLE(ADDR, SERIAL, USER_ID)

    try:
        await ef.connect()
        await ef.authenticate()
        print("\n[Connected and authenticated — reading data for 60 seconds]\n")

        start = time.time()
        while time.time() - start < 60:
            await asyncio.sleep(1)
            data = ef.get_latest()
            if data and data.get("last_update", 0) > start:
                elapsed = time.time() - start
                if int(elapsed) % 10 == 0:
                    print(f"  [{int(elapsed)}s] Latest: {json.dumps({k:v for k,v in data.items() if k != 'last_update'}, default=str)}")

    except Exception as e:
        log.error("Error: %s", e, exc_info=True)
    finally:
        data = ef.get_latest()
        if data:
            print("\n=== Final readings ===")
            for k, v in sorted(data.items()):
                print(f"  {k}: {v}")
        await ef.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
