#!/bin/bash
#
# ShadowGrid ESP32 Flasher
# One-command tool to build and flash Heltec ESP32-S3 V3/V4 firmware
#
# Usage: ./flash.sh [mobile|base] [port]
#
# Examples:
#   ./flash.sh                  # Interactive — asks what to flash
#   ./flash.sh mobile           # Flash mobile node, auto-detect port
#   ./flash.sh base /dev/ttyACM0  # Flash base station to specific port
#

set -e

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[0;33m'; CYN='\033[0;36m'
BLD='\033[1m'; DIM='\033[2m'; RST='\033[0m'

ok()   { echo -e "  ${GRN}✓${RST} $1"; }
warn() { echo -e "  ${YLW}!${RST} $1"; }
fail() { echo -e "  ${RED}✗${RST} $1"; exit 1; }
ask()  { echo -ne "  ${YLW}?${RST} $1: "; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo -e "${CYN}${BLD}"
echo "  ╔═══════════════════════════════════════╗"
echo "  ║      SHADOWGRID ESP32 FLASHER         ║"
echo "  ║   Heltec WiFi LoRa 32 V3/V4          ║"
echo "  ╚═══════════════════════════════════════╝"
echo -e "${RST}"

# ── Step 1: Check PlatformIO ──────────────────────────────────────────────
if ! command -v pio &>/dev/null; then
    echo -e "  ${DIM}PlatformIO not found — installing...${RST}"
    pip3 install --user --break-system-packages platformio 2>/dev/null || \
    pip3 install platformio 2>/dev/null
    export PATH="$HOME/.local/bin:$PATH"
    if ! command -v pio &>/dev/null; then
        fail "PlatformIO install failed. Install manually: pip3 install platformio"
    fi
    ok "PlatformIO installed"
else
    ok "PlatformIO found: $(pio --version 2>/dev/null | head -1)"
fi

# ── Step 2: Choose firmware ───────────────────────────────────────────────
TARGET="${1:-}"
if [ -z "$TARGET" ]; then
    echo ""
    echo -e "  ${BLD}Which firmware to flash?${RST}"
    echo ""
    echo -e "  ${CYN}1)${RST} ${BLD}Mobile Node${RST} — BLE battery reader + LoRa TX + WiFi AP dashboard"
    echo -e "     ${DIM}Goes near your batteries. Creates WiFi hotspot with standalone UI.${RST}"
    echo -e "     ${DIM}Reads JBD BMS + Victron over BLE, transmits data over LoRa.${RST}"
    echo ""
    echo -e "  ${CYN}2)${RST} ${BLD}Base Station${RST} — LoRa RX + USB serial bridge"
    echo -e "     ${DIM}Plugs into your server. Receives LoRa packets, forwards via USB.${RST}"
    echo -e "     ${DIM}No WiFi, no BLE — just a LoRa-to-serial gateway.${RST}"
    echo ""
    ask "Choose (1 or 2)"
    read -r CHOICE
    case "$CHOICE" in
        1|mobile|m) TARGET="mobile" ;;
        2|base|b)   TARGET="base" ;;
        *) fail "Invalid choice" ;;
    esac
fi

case "$TARGET" in
    mobile|remote|1|m)
        FW_DIR="$SCRIPT_DIR/firmware/remote"
        FW_NAME="Mobile Node"
        ;;
    base|2|b)
        FW_DIR="$SCRIPT_DIR/firmware/base"
        FW_NAME="Base Station"
        ;;
    *)
        fail "Unknown target: $TARGET (use 'mobile' or 'base')"
        ;;
esac

echo -e "\n  Firmware: ${BLD}$FW_NAME${RST} (${DIM}$FW_DIR${RST})"

if [ ! -f "$FW_DIR/platformio.ini" ]; then
    fail "Firmware directory not found: $FW_DIR"
fi

# ── Step 3: Configure WiFi password (mobile only) ─────────────────────────
if [ "$TARGET" = "mobile" ] || [ "$TARGET" = "remote" ]; then
    MAIN_CPP="$FW_DIR/src/main.cpp"
    CURRENT_PW=$(grep '#define WIFI_PASS' "$MAIN_CPP" 2>/dev/null | sed 's/.*"\(.*\)".*/\1/')

    echo ""
    echo -e "  ${BLD}Mobile Node WiFi Configuration${RST}"
    echo -e "  ${DIM}The mobile node creates a WiFi hotspot for its standalone dashboard.${RST}"
    echo -e "  ${DIM}Current SSID: ShadowGrid | Current password: ${CURRENT_PW}${RST}"
    echo ""
    ask "Set new WiFi password? (Enter to keep current, or type new password)"
    read -r NEW_PW

    if [ -n "$NEW_PW" ]; then
        sed -i "s/#define WIFI_PASS.*/#define WIFI_PASS     \"$NEW_PW\"/" "$MAIN_CPP"
        ok "WiFi password set to: $NEW_PW"
    else
        ok "Keeping password: $CURRENT_PW"
    fi
fi

# ── Step 4: Detect port ──────────────────────────────────────────────────
PORT="${2:-}"
if [ -z "$PORT" ]; then
    echo ""
    echo -e "  ${BLD}Detecting ESP32...${RST}"

    # Find all Espressif USB devices
    PORTS=()
    for p in /dev/ttyACM* /dev/ttyUSB*; do
        [ -e "$p" ] || continue
        PORTS+=("$p")
    done

    if [ ${#PORTS[@]} -eq 0 ]; then
        echo ""
        echo -e "  ${RED}No serial ports found.${RST}"
        echo ""
        echo -e "  ${BLD}Troubleshooting:${RST}"
        echo -e "  1. Plug in your Heltec ESP32 via USB-C"
        echo -e "  2. Check: ${DIM}ls /dev/ttyACM* /dev/ttyUSB*${RST}"
        echo -e "  3. If using V4, hold BOOT button while plugging in"
        echo -e "  4. Try: ${DIM}sudo dmesg | tail -10${RST} to see USB detection"
        echo ""
        fail "No ESP32 detected"
    elif [ ${#PORTS[@]} -eq 1 ]; then
        PORT="${PORTS[0]}"
        ok "Found ESP32 on $PORT"
    else
        echo -e "  Multiple serial ports found:"
        for i in "${!PORTS[@]}"; do
            # Try to identify each port
            DESC=""
            if [ -d "/sys/class/tty/$(basename ${PORTS[$i]})/device" ]; then
                PROD=$(cat "/sys/class/tty/$(basename ${PORTS[$i]})/device/../product" 2>/dev/null || echo "")
                DESC=" ($PROD)"
            fi
            echo -e "    ${CYN}$((i+1)))${RST} ${PORTS[$i]}${DIM}${DESC}${RST}"
        done
        ask "Which port?"
        read -r PORT_CHOICE
        PORT="${PORTS[$((PORT_CHOICE-1))]}"
        if [ -z "$PORT" ]; then
            fail "Invalid port choice"
        fi
        ok "Using $PORT"
    fi
fi

# Verify port exists
if [ ! -e "$PORT" ]; then
    fail "Port $PORT does not exist"
fi

# ── Step 5: Build ────────────────────────────────────────────────────────
echo ""
echo -e "  ${BLD}Building firmware...${RST}"
cd "$FW_DIR"

pio run 2>&1 | while read -r line; do
    if echo "$line" | grep -q "SUCCESS"; then
        echo -e "  ${GRN}${BLD}$line${RST}"
    elif echo "$line" | grep -q "FAILED\|Error\|error:"; then
        echo -e "  ${RED}$line${RST}"
    elif echo "$line" | grep -q "RAM:\|Flash:"; then
        echo -e "  ${DIM}$line${RST}"
    fi
done

# Check build succeeded
if [ ! -f ".pio/build/*/firmware.bin" ]; then
    fail "Build failed — check errors above"
fi

BUILD_DIR=$(ls -d .pio/build/*/ 2>/dev/null | head -1)
FW_SIZE=$(stat -c%s "${BUILD_DIR}firmware.bin" 2>/dev/null || echo "?")
ok "Build complete ($(( FW_SIZE / 1024 )) KB)"

# ── Step 6: Flash ────────────────────────────────────────────────────────
echo ""
echo -e "  ${BLD}Flashing to $PORT...${RST}"
echo -e "  ${DIM}(If flash hangs, hold BOOT button on ESP32 during upload)${RST}"
echo ""

pio run -t upload --upload-port "$PORT" 2>&1 | while read -r line; do
    if echo "$line" | grep -q "SUCCESS"; then
        echo -e "  ${GRN}${BLD}$line${RST}"
    elif echo "$line" | grep -q "Writing at\|Wrote"; then
        echo -e "  ${DIM}$line${RST}"
    elif echo "$line" | grep -q "FAILED\|Error\|fatal"; then
        echo -e "  ${RED}$line${RST}"
    fi
done

# ── Step 7: Verify ───────────────────────────────────────────────────────
echo ""
echo -e "  ${DIM}Waiting for ESP32 to reboot...${RST}"
sleep 4

# Try to read boot output
BOOT_OUTPUT=$(timeout 10 python3 -c "
import serial, time
try:
    ser = serial.Serial('$PORT', 115200, timeout=1)
    time.sleep(2)
    ser.dtr = False; time.sleep(0.1); ser.dtr = True; time.sleep(0.1); ser.dtr = False
    time.sleep(1); ser.reset_input_buffer()
    start = time.time()
    lines = []
    while time.time() - start < 6:
        if ser.in_waiting:
            line = ser.readline().decode('utf-8', errors='replace').strip()
            if line: lines.append(line)
        else: time.sleep(0.05)
    ser.close()
    print('\n'.join(lines[:10]))
except Exception as e:
    print(f'Could not read serial: {e}')
" 2>/dev/null || echo "Could not verify (port may have changed)")

if [ -n "$BOOT_OUTPUT" ]; then
    echo -e "  ${DIM}Boot output:${RST}"
    echo "$BOOT_OUTPUT" | while read -r line; do
        echo -e "    ${DIM}$line${RST}"
    done
fi

# ── Done ─────────────────────────────────────────────────────────────────
echo ""
echo -e "${GRN}${BLD}  ╔═══════════════════════════════════════╗"
echo "  ║          FLASH COMPLETE               ║"
echo -e "  ╚═══════════════════════════════════════╝${RST}"
echo ""
echo -e "  Firmware: ${BLD}$FW_NAME${RST}"
echo -e "  Port:     ${DIM}$PORT${RST}"

if [ "$TARGET" = "mobile" ] || [ "$TARGET" = "remote" ]; then
    PW=$(grep '#define WIFI_PASS' "$MAIN_CPP" 2>/dev/null | sed 's/.*"\(.*\)".*/\1/')
    echo ""
    echo -e "  ${BLD}Connect to the mobile node:${RST}"
    echo -e "    WiFi:      ${CYN}ShadowGrid${RST}"
    echo -e "    Password:  ${CYN}${PW}${RST}"
    echo -e "    Dashboard: ${CYN}http://192.168.4.1${RST}"
else
    echo ""
    echo -e "  ${BLD}Base station is listening for LoRa packets.${RST}"
    echo -e "  ${DIM}Connect via USB to your ShadowGrid server.${RST}"
    echo -e "  ${DIM}It will be auto-detected on next server restart.${RST}"
fi
echo ""
