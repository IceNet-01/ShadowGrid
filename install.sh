#!/bin/bash
#
# ShadowGrid Installer & First-Run Setup
# Installs all dependencies, configures permissions, and walks through device setup.
#
# Usage: curl -sSL https://raw.githubusercontent.com/IceNet-01/ShadowGrid/main/install.sh | bash
#    or: ./install.sh
#

set -e

# ── Colors ─────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[0;33m'; CYN='\033[0;36m'
BLD='\033[1m'; DIM='\033[2m'; RST='\033[0m'

banner() {
    echo ""
    echo -e "${CYN}${BLD}"
    echo "  ╔═══════════════════════════════════════╗"
    echo "  ║         SHADOWGRID INSTALLER          ║"
    echo "  ║   Off-Grid Power Monitoring System    ║"
    echo "  ╚═══════════════════════════════════════╝"
    echo -e "${RST}"
}

step() { echo -e "\n${CYN}${BLD}[$1]${RST} $2"; }
ok()   { echo -e "  ${GRN}✓${RST} $1"; }
warn() { echo -e "  ${YLW}!${RST} $1"; }
fail() { echo -e "  ${RED}✗${RST} $1"; }
ask()  { echo -ne "  ${YLW}?${RST} $1: "; }

# Install location. If run from a directory that already has server.py (e.g.
# /opt/shadowgrid), install in place. Otherwise install to /opt/shadowgrid — the
# standard system location this project runs from.
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ ! -f "$INSTALL_DIR/server.py" ]; then
    INSTALL_DIR="/opt/shadowgrid"
    if [ ! -d "$INSTALL_DIR" ]; then
        step "0/7" "Installing to $INSTALL_DIR..."
        sudo mkdir -p "$INSTALL_DIR"
        sudo chown "$(whoami):$(whoami)" "$INSTALL_DIR"
        git clone https://github.com/IceNet-01/ShadowGrid.git "$INSTALL_DIR"
    fi
fi

cd "$INSTALL_DIR"
CONFIG_FILE="$INSTALL_DIR/config.env"

banner

echo -e "${DIM}Install directory: $INSTALL_DIR${RST}"
echo ""

# ── Step 1: System packages ───────────────────────────────────────────────
step "1/7" "Installing system packages..."

if command -v apt-get &>/dev/null; then
    sudo apt-get update -qq
    sudo apt-get install -y -qq \
        python3 python3-pip \
        bluetooth bluez \
        dbus libdbus-1-dev \
        build-essential libssl-dev libffi-dev \
        git 2>/dev/null
    ok "APT packages installed"
elif command -v dnf &>/dev/null; then
    sudo dnf install -y -q \
        python3 python3-pip \
        bluez bluez-tools \
        dbus dbus-devel \
        gcc openssl-devel libffi-devel \
        git 2>/dev/null
    ok "DNF packages installed"
elif command -v pacman &>/dev/null; then
    sudo pacman -Sy --noconfirm \
        python python-pip \
        bluez bluez-utils \
        dbus git base-devel 2>/dev/null
    ok "Pacman packages installed"
else
    warn "Unknown package manager — install manually: python3, pip, bluez, dbus, git"
fi

# ── Step 2: Python packages ───────────────────────────────────────────────
step "2/7" "Installing Python packages..."

PIP_FLAGS="--user --break-system-packages"
# Check if we're in a venv
if [ -n "$VIRTUAL_ENV" ]; then
    PIP_FLAGS=""
fi

pip3 install $PIP_FLAGS -q \
    flask flask-cors \
    bleak dbus-next \
    pycryptodome ecdsa \
    pyserial 2>/dev/null

ok "Python packages installed"

# ── Step 3: System permissions ─────────────────────────────────────────────
step "3/7" "Configuring permissions..."

# Add user to bluetooth and dialout groups
CURRENT_USER=$(whoami)
if ! groups "$CURRENT_USER" | grep -q bluetooth; then
    sudo usermod -aG bluetooth "$CURRENT_USER"
    ok "Added $CURRENT_USER to bluetooth group"
else
    ok "Already in bluetooth group"
fi

if ! groups "$CURRENT_USER" | grep -q dialout; then
    sudo usermod -aG dialout "$CURRENT_USER"
    ok "Added $CURRENT_USER to dialout group"
else
    ok "Already in dialout group"
fi

# Configure passwordless bluetoothctl
SUDOERS_LINE="$CURRENT_USER ALL=(ALL) NOPASSWD: /usr/bin/bluetoothctl"
if ! sudo grep -q "bluetoothctl" /etc/sudoers.d/shadowgrid 2>/dev/null; then
    echo "$SUDOERS_LINE" | sudo tee /etc/sudoers.d/shadowgrid >/dev/null
    sudo chmod 440 /etc/sudoers.d/shadowgrid
    ok "Passwordless bluetoothctl configured"
else
    ok "Sudoers already configured"
fi

# Ensure bluetooth service is running
sudo systemctl enable bluetooth --now 2>/dev/null
ok "Bluetooth service enabled"

# ── Step 4: First-run configuration ───────────────────────────────────────
step "4/7" "Device configuration..."

if [ -f "$CONFIG_FILE" ]; then
    echo -e "  ${DIM}Existing config found at $CONFIG_FILE${RST}"
    ask "Reconfigure? (y/N)"
    read -r RECONFIG
    if [ "$RECONFIG" != "y" ] && [ "$RECONFIG" != "Y" ]; then
        ok "Keeping existing config"
        SKIP_CONFIG=true
    fi
fi

if [ "$SKIP_CONFIG" != "true" ]; then
    echo ""
    echo -e "  ${BLD}Device Setup${RST}"
    echo -e "  ${DIM}ShadowGrid can monitor multiple battery types.${RST}"
    echo -e "  ${DIM}You can also add devices later from the web UI Settings tab.${RST}"
    echo ""

    # ── Scan for BLE devices ──
    ask "Scan for nearby BLE battery devices now? (Y/n)"
    read -r DO_SCAN
    if [ "$DO_SCAN" != "n" ] && [ "$DO_SCAN" != "N" ]; then
        echo -e "  ${DIM}Scanning for 10 seconds...${RST}"
        python3 -c "
import asyncio
from bleak import BleakScanner

async def scan():
    devices = await BleakScanner.discover(timeout=10, return_adv=True)
    found = []
    for addr, (dev, adv) in sorted(devices.items(), key=lambda x: x[1][1].rssi, reverse=True):
        name = adv.local_name or dev.name or ''
        mfg = adv.manufacturer_data or {}
        uuids = adv.service_uuids or []

        dtype = None
        # JBD BMS
        if '0000ff00-0000-1000-8000-00805f9b34fb' in uuids:
            dtype = 'JBD BMS'
        elif '00010203-0405-0607-0809-0a0b0c0d1912' in uuids:
            dtype = 'Smart BMS (JBD compatible)'
        # EcoFlow
        elif 0xB5B5 in mfg:
            data = mfg[0xB5B5]
            sn = data[1:17].decode('ascii', errors='replace') if len(data) > 16 else ''
            dtype = f'EcoFlow (SN: {sn})'
        # Victron
        elif 0x02E1 in mfg:
            dtype = 'Victron Energy'
        # JK-BMS
        elif name.startswith('JK_') or name.startswith('JK-'):
            dtype = 'JK-BMS'
        elif '0000ffe0-0000-1000-8000-00805f9b34fb' in uuids:
            dtype = 'JK-BMS'
        # Daly
        elif name.startswith('DL-'):
            dtype = 'Daly BMS'
        # Renogy
        elif name.startswith('BT-TH'):
            dtype = 'Renogy BMS'

        if dtype:
            found.append((addr, name, adv.rssi, dtype))

    if not found:
        print('  No battery BMS devices found nearby.')
        print('  Make sure your batteries are powered on and BLE is enabled.')
        return

    print(f'  Found {len(found)} battery device(s):')
    print()
    for i, (addr, name, rssi, dtype) in enumerate(found, 1):
        print(f'    {i}. {name or addr}')
        print(f'       Address: {addr}  |  RSSI: {rssi} dBm  |  Type: {dtype}')
        print()

asyncio.run(scan())
" 2>/dev/null || warn "BLE scan failed — you may need to log out and back in for group changes to take effect"
    fi

    echo ""
    echo -e "  ${BLD}You can add these devices from the Settings tab after starting ShadowGrid.${RST}"
    echo ""

    # ── Auto-detect and register all found devices ──
    echo ""
    echo -e "  ${BLD}Auto-registering discovered devices...${RST}"

    EF_ADDR="" EF_SERIAL="" EF_USER_ID=""

    python3 << 'SCANEOF' 2>/dev/null
import asyncio, sqlite3, json, sys, os
from datetime import datetime
from bleak import BleakScanner

DB = os.environ.get("SG_DB", "shadowgrid.db")

async def scan_and_register():
    devices = await BleakScanner.discover(timeout=10, return_adv=True)
    conn = sqlite3.connect(DB)
    conn.execute("""CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT, address TEXT UNIQUE NOT NULL,
        label TEXT NOT NULL, device_type TEXT NOT NULL, protocol TEXT,
        enabled INTEGER DEFAULT 1, config TEXT DEFAULT '{}', added TEXT NOT NULL)""")

    added = 0
    ecoflows = []
    for addr, (dev, adv) in sorted(devices.items(), key=lambda x: x[1][1].rssi, reverse=True):
        name = adv.local_name or dev.name or ""
        mfg = adv.manufacturer_data or {}
        uuids = adv.service_uuids or []
        dtype = proto = label = None
        config = {}

        if "0000ff00-0000-1000-8000-00805f9b34fb" in uuids:
            dtype, proto = "jbd_bms", "jbd"
            label = name or f"BMS_{addr[-5:].replace(':','')}"
        elif "00010203-0405-0607-0809-0a0b0c0d1912" in uuids:
            dtype, proto = "jbd_bms", "jbd"
            label = name or f"SmartBMS_{addr[-5:].replace(':','')}"
        elif 0xB5B5 in mfg:
            data = mfg[0xB5B5]
            sn = data[1:17].decode("ascii", errors="replace").rstrip("\x00") if len(data) > 16 else ""
            dtype, proto = "ecoflow", "ecoflow_delta2"
            label = f"EcoFlow_{sn[-4:]}" if sn else f"EcoFlow_{addr[-5:].replace(':','')}"
            config = {"serial": sn, "user_id": ""}
            ecoflows.append({"addr": addr, "serial": sn, "label": label})
        elif name.startswith("JK_") or name.startswith("JK-"):
            dtype, proto = "jk_bms", "jk"
            label = name
        elif name.startswith("DL-"):
            dtype, proto = "daly_bms", "daly"
            label = name
        elif name.startswith("BT-TH"):
            dtype, proto = "renogy_bms", "renogy"
            label = name

        if dtype:
            try:
                conn.execute("INSERT INTO devices (address,label,device_type,protocol,config,added) VALUES (?,?,?,?,?,?)",
                    (addr, label, dtype, proto, json.dumps(config), datetime.now().isoformat()))
                added += 1
                print(f"  + {label} ({dtype}) @ {addr}")
            except sqlite3.IntegrityError:
                print(f"  = {label} already registered")

    conn.commit()
    conn.close()

    if added == 0:
        print("  No new devices to register")

    # Output EcoFlow info for the shell
    if ecoflows:
        ef = ecoflows[0]
        with open("/tmp/sg_ecoflow_info", "w") as f:
            f.write(f"{ef['addr']}\n{ef['serial']}\n{ef['label']}\n")

asyncio.run(scan_and_register())
SCANEOF

    ok "Device scan complete"

    # ── EcoFlow auto-setup ──
    if [ -f /tmp/sg_ecoflow_info ]; then
        EF_ADDR=$(sed -n '1p' /tmp/sg_ecoflow_info)
        EF_SERIAL=$(sed -n '2p' /tmp/sg_ecoflow_info)
        EF_LABEL=$(sed -n '3p' /tmp/sg_ecoflow_info)
        rm -f /tmp/sg_ecoflow_info

        echo ""
        echo -e "  ${CYN}${BLD}EcoFlow detected: $EF_LABEL${RST}"
        echo -e "  ${DIM}Address: $EF_ADDR | Serial: $EF_SERIAL${RST}"
        echo ""
        echo -e "  ${DIM}To read data from your EcoFlow over BLE, we need your EcoFlow${RST}"
        echo -e "  ${DIM}account user ID. We'll log in once to get it, then never again.${RST}"
        echo ""
        ask "EcoFlow account email (or Enter to skip)"
        read -r EF_EMAIL

        if [ -n "$EF_EMAIL" ]; then
            ask "Password (hidden)"
            read -rs EF_PASS
            echo ""

            echo -e "  ${DIM}Logging into EcoFlow API to extract user ID...${RST}"
            echo -e "  ${DIM}(credentials are used for this one request only)${RST}"

            # Run login in isolated Python process — credentials exist only in this subprocess
            EF_USER_ID=$(python3 -c "
import requests, base64, sys, gc

email, password = sys.argv[1], sys.argv[2]
pw_b64 = base64.b64encode(password.encode()).decode()
user_id = None

for host in ['api.ecoflow.com','api-a.ecoflow.com','api-e.ecoflow.com']:
    try:
        r = requests.post(f'https://{host}/auth/login', json={
            'scene':'IOT_APP','appVersion':'1.0.0','password':pw_b64,
            'oauth':{'bundleId':'com.ef.EcoFlow'},'userType':'ECOFLOW',
            'email':email}, timeout=10)
        d = r.json()
        if d.get('code')=='0':
            user_id = d['data']['user']['userId']
            break
    except: pass

# Purge credentials from memory before printing result
del email, password, pw_b64
gc.collect()

if user_id:
    print(user_id)
    sys.exit(0)
sys.exit(1)
" "$EF_EMAIL" "$EF_PASS" 2>/dev/null)
            LOGIN_OK=$?

            # Purge credentials from shell variables immediately
            unset EF_PASS
            unset EF_EMAIL

            if [ $LOGIN_OK -eq 0 ] && [ -n "$EF_USER_ID" ]; then
                ok "Credentials purged from memory"

                # Save user ID to device registry (permanent — survives reboots)
                python3 -c "
import sqlite3, json
conn = sqlite3.connect('$INSTALL_DIR/shadowgrid.db')
row = conn.execute('SELECT config FROM devices WHERE address=?', ('$EF_ADDR',)).fetchone()
if row:
    cfg = json.loads(row[0])
    cfg['user_id'] = '$EF_USER_ID'
    conn.execute('UPDATE devices SET config=? WHERE address=?', (json.dumps(cfg), '$EF_ADDR'))
    conn.commit()
conn.close()
" 2>/dev/null
                ok "EcoFlow fully configured — all future connections are local BLE only"
                echo ""
                echo -e "  ${BLD}╔══════════════════════════════════════════════════╗${RST}"
                echo -e "  ${BLD}║  YOUR ECOFLOW USER ID (save this somewhere!)    ║${RST}"
                echo -e "  ${BLD}║                                                  ║${RST}"
                echo -e "  ${BLD}║  ${CYN}${EF_USER_ID}${RST}${BLD}              ║${RST}"
                echo -e "  ${BLD}║                                                  ║${RST}"
                echo -e "  ${BLD}║${RST}${DIM}  This ID is permanent. It works on ALL your     ${RST}${BLD}║${RST}"
                echo -e "  ${BLD}║${RST}${DIM}  EcoFlow devices — even brand new ones that     ${RST}${BLD}║${RST}"
                echo -e "  ${BLD}║${RST}${DIM}  have never connected to the internet.          ${RST}${BLD}║${RST}"
                echo -e "  ${BLD}║${RST}${DIM}  You will never need to log in again.           ${RST}${BLD}║${RST}"
                echo -e "  ${BLD}╚══════════════════════════════════════════════════╝${RST}"
                echo ""
            else
                fail "Login failed — check email/password"
                echo -e "  ${DIM}You can add the user ID later in Settings${RST}"
            fi
        else
            warn "EcoFlow skipped — add user ID later in Settings tab"
        fi
    fi

    # ── Write config ──
    cat > "$CONFIG_FILE" << CFGEOF
# ShadowGrid Configuration
# Generated by installer on $(date)
# Devices are stored in the database — manage via Settings tab

# Server
FLASK_HOST=0.0.0.0
FLASK_PORT=5050
CFGEOF
    ok "Config saved to $CONFIG_FILE"
fi

# ── Step 5: Initialize database ───────────────────────────────────────────
step "5/7" "Initializing database..."

python3 -c "
import sys; sys.path.insert(0, '$INSTALL_DIR')
from server import init_db, init_victron_db, init_energy_db, init_ecoflow_db, init_scanner_db, init_devices_db
try:
    from alerts import init_alerts_db
    init_alerts_db()
except: pass
try:
    from meter_reader import init_meter_db
    init_meter_db()
except: pass
init_db(); init_victron_db(); init_energy_db(); init_ecoflow_db(); init_scanner_db(); init_devices_db()
from server import init_auth_db
init_auth_db()
print('  Database initialized')
" 2>/dev/null && ok "SQLite database ready" || warn "Database init had warnings (will auto-create on first run)"

# ── Step 5b: Security setup ───────────────────────────────────────────────
echo ""
echo -e "  ${BLD}Security Setup${RST}"
echo -e "  ${DIM}Protect the dashboard with a password and optional HTTPS.${RST}"
echo ""
ask "Password-protect the dashboard? (y/N)"
read -r DO_AUTH
if [ "$DO_AUTH" = "y" ] || [ "$DO_AUTH" = "Y" ]; then
    while true; do
        ask "Set dashboard password (min 6 chars)"
        read -rs AUTH_PW
        echo ""
        if [ ${#AUTH_PW} -lt 6 ]; then
            fail "Password too short — need at least 6 characters"
            continue
        fi
        ask "Confirm password"
        read -rs AUTH_PW2
        echo ""
        if [ "$AUTH_PW" != "$AUTH_PW2" ]; then
            fail "Passwords don't match"
            continue
        fi
        break
    done

    python3 -c "
import sys; sys.path.insert(0, '$INSTALL_DIR')
from server import set_password
set_password('$AUTH_PW')
" 2>/dev/null
    unset AUTH_PW AUTH_PW2
    ok "Password set (PBKDF2-SHA256 hashed, credentials purged)"

    ask "Enable HTTPS with self-signed certificate? (y/N)"
    read -r DO_SSL
    if [ "$DO_SSL" = "y" ] || [ "$DO_SSL" = "Y" ]; then
        python3 -c "
import sys; sys.path.insert(0, '$INSTALL_DIR')
from server import generate_ssl_cert, set_auth_setting
generate_ssl_cert('$INSTALL_DIR/cert.pem', '$INSTALL_DIR/key.pem')
set_auth_setting('ssl_enabled', '1')
" 2>/dev/null
        ok "SSL certificate generated (valid 10 years)"
    fi
else
    ok "No password set — dashboard is open access"
    echo -e "  ${DIM}You can enable auth later from the Settings tab${RST}"
fi

# ── Step 6: Install systemd service ───────────────────────────────────────
step "6/7" "Setting up systemd service..."

ask "Install ShadowGrid as a system service? (Y/n)"
read -r INSTALL_SVC
if [ "$INSTALL_SVC" != "n" ] && [ "$INSTALL_SVC" != "N" ]; then
    # Use the venv interpreter if the install dir has one, else system python3.
    if [ -x "$INSTALL_DIR/venv/bin/python" ]; then
        PYTHON_BIN="$INSTALL_DIR/venv/bin/python"
    else
        PYTHON_BIN="/usr/bin/python3"
    fi
    # Generate service file with correct paths
    cat > /tmp/shadowgrid.service << SVCEOF
[Unit]
Description=ShadowGrid Power Monitor
After=network.target bluetooth.target
Wants=bluetooth.target

[Service]
Type=simple
User=$CURRENT_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$PYTHON_BIN $INSTALL_DIR/server.py
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
SVCEOF

    sudo cp /tmp/shadowgrid.service /etc/systemd/system/shadowgrid.service
    sudo systemctl daemon-reload
    sudo systemctl enable shadowgrid
    ok "Service installed and enabled"

    ask "Start ShadowGrid now? (Y/n)"
    read -r START_NOW
    if [ "$START_NOW" != "n" ] && [ "$START_NOW" != "N" ]; then
        sudo systemctl start shadowgrid
        sleep 3
        if systemctl is-active --quiet shadowgrid; then
            ok "ShadowGrid is running"
        else
            fail "Service failed to start — check: journalctl -u shadowgrid -n 20"
        fi
    fi
else
    ok "Skipped service install (run manually with: python3 server.py)"
fi

# ── Step 7: Done ──────────────────────────────────────────────────────────
step "7/7" "Setup complete!"

# Get local IP
LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
PORT=5050

echo ""
echo -e "${GRN}${BLD}  ╔═══════════════════════════════════════╗"
echo "  ║       SHADOWGRID IS READY             ║"
echo -e "  ╚═══════════════════════════════════════╝${RST}"
echo ""
echo -e "  Dashboard:  ${CYN}${BLD}http://${LOCAL_IP:-localhost}:${PORT}${RST}"
echo -e "  Config:     ${DIM}$CONFIG_FILE${RST}"
echo -e "  Database:   ${DIM}$INSTALL_DIR/shadowgrid.db${RST}"
echo -e "  Logs:       ${DIM}journalctl -u shadowgrid -f${RST}"
echo ""
echo -e "  ${BLD}Next steps:${RST}"
echo -e "  1. Open the dashboard in your browser"
echo -e "  2. Go to ${BLD}Settings${RST} tab"
echo -e "  3. Click ${BLD}Scan for Devices${RST} to find your batteries"
echo -e "  4. Click ${BLD}Add${RST} on each device to start monitoring"
echo ""
if [ -n "$EF_USER_ID" ] && [ "$EF_USER_ID" != "FAILED" ]; then
    echo -e "  ${CYN}EcoFlow:${RST} Add your Delta 2 from Settings with:"
    echo -e "    User ID: $EF_USER_ID"
    echo -e "    Serial:  (shown in BLE scan results)"
    echo ""
fi
echo -e "  ${DIM}Documentation: https://github.com/IceNet-01/ShadowGrid${RST}"
echo ""
