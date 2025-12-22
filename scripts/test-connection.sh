#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# ADB Connection Test Script
# Verifies connectivity to Genymotion emulator
# ═══════════════════════════════════════════════════════════════════════════════

set -e

# Default values
EMULATOR_IP="${EMULATOR_IP:-192.168.56.101}"
EMULATOR_PORT="${EMULATOR_PORT:-5555}"
DEVICE_ID="${EMULATOR_IP}:${EMULATOR_PORT}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo ""
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║              ADB Connection Test                                     ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo ""
echo -e "${BLUE}[*]${NC} Target: ${DEVICE_ID}"
echo ""

# Check if ADB is installed
if ! command -v adb &> /dev/null; then
    echo -e "${RED}[✗]${NC} ADB not found. Please install Android SDK Platform Tools."
    exit 1
fi

# Kill any existing ADB server to start fresh
echo -e "${BLUE}[*]${NC} Restarting ADB server..."
adb kill-server 2>/dev/null || true
sleep 1
adb start-server

# Attempt connection
echo -e "${BLUE}[*]${NC} Connecting to ${DEVICE_ID}..."
if adb connect "$DEVICE_ID" 2>&1 | grep -q "connected"; then
    echo -e "${GREEN}[✓]${NC} Connected successfully!"
else
    echo -e "${YELLOW}[!]${NC} Initial connection attempt, retrying..."
    sleep 2
    adb connect "$DEVICE_ID"
fi

# Verify connection
echo ""
echo -e "${BLUE}[*]${NC} Verifying connection..."
if adb -s "$DEVICE_ID" shell echo "OK" 2>/dev/null | grep -q "OK"; then
    echo -e "${GREEN}[✓]${NC} Shell access confirmed"
else
    echo -e "${RED}[✗]${NC} Cannot execute shell commands"
    echo ""
    echo "Troubleshooting:"
    echo "  1. Is Genymotion running?"
    echo "  2. Is ADB over network enabled in the emulator?"
    echo "  3. Check the IP address in emulator settings"
    exit 1
fi

# Get device info
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "DEVICE INFORMATION"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

MODEL=$(adb -s "$DEVICE_ID" shell getprop ro.product.model 2>/dev/null | tr -d '\r')
ANDROID=$(adb -s "$DEVICE_ID" shell getprop ro.build.version.release 2>/dev/null | tr -d '\r')
SDK=$(adb -s "$DEVICE_ID" shell getprop ro.build.version.sdk 2>/dev/null | tr -d '\r')
PATCH=$(adb -s "$DEVICE_ID" shell getprop ro.build.version.security_patch 2>/dev/null | tr -d '\r')
SELINUX=$(adb -s "$DEVICE_ID" shell getenforce 2>/dev/null | tr -d '\r')

echo "  Model:          $MODEL"
echo "  Android:        $ANDROID (API $SDK)"
echo "  Security Patch: $PATCH"
echo "  SELinux:        $SELINUX"

# Quick security check
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "QUICK SECURITY CHECK"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check for root
if adb -s "$DEVICE_ID" shell "su -c 'id'" 2>/dev/null | grep -q "uid=0"; then
    echo -e "  Root Access:    ${GREEN}Available${NC}"
else
    echo -e "  Root Access:    ${YELLOW}Not available${NC}"
fi

# Check debuggable
DEBUGGABLE=$(adb -s "$DEVICE_ID" shell getprop ro.debuggable 2>/dev/null | tr -d '\r')
if [ "$DEBUGGABLE" = "1" ]; then
    echo -e "  Debuggable:     ${YELLOW}Yes (development build)${NC}"
else
    echo -e "  Debuggable:     No"
fi

# Check encryption
ENCRYPTED=$(adb -s "$DEVICE_ID" shell getprop ro.crypto.state 2>/dev/null | tr -d '\r')
if [ "$ENCRYPTED" = "encrypted" ]; then
    echo -e "  Encryption:     ${GREEN}Enabled${NC}"
else
    echo -e "  Encryption:     ${YELLOW}Disabled${NC}"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}[✓]${NC} Connection test complete"
echo ""
echo "You can now run:"
echo "  python scripts/run-scan.py --ip $EMULATOR_IP --port $EMULATOR_PORT"
echo ""
