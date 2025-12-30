#!/bin/bash
# =============================================================================
# AgenticART Genymotion Device Setup Script
# Target: Android 11 (API 30) on Genymotion x86_64
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║          AgenticART Genymotion Setup Script                  ║${NC}"
echo -e "${GREEN}║          Target: Android 11 (API 30) x86_64                  ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"

# -----------------------------------------------------------------------------
# Step 1: Verify ADB Connection
# -----------------------------------------------------------------------------
echo -e "\n${YELLOW}[1/6] Checking ADB connection...${NC}"

if ! adb devices | grep -q "device$"; then
    echo -e "${RED}ERROR: No device connected. Please start Genymotion and connect via ADB.${NC}"
    echo "  Try: adb connect <genymotion-ip>:5555"
    exit 1
fi

DEVICE_ID=$(adb devices | grep "device$" | head -1 | cut -f1)
echo -e "${GREEN}Connected to: $DEVICE_ID${NC}"

# Verify Android version
ANDROID_VERSION=$(adb shell getprop ro.build.version.release)
API_LEVEL=$(adb shell getprop ro.build.version.sdk)
echo "  Android Version: $ANDROID_VERSION (API $API_LEVEL)"

if [ "$API_LEVEL" -lt 30 ]; then
    echo -e "${YELLOW}WARNING: API level $API_LEVEL detected. Recommended: 30 (Android 11)${NC}"
fi

# -----------------------------------------------------------------------------
# Step 2: Verify Architecture
# -----------------------------------------------------------------------------
echo -e "\n${YELLOW}[2/6] Checking device architecture...${NC}"

ARCH=$(adb shell getprop ro.product.cpu.abi)
echo "  Architecture: $ARCH"

if [[ "$ARCH" != *"x86"* ]]; then
    echo -e "${YELLOW}WARNING: Expected x86/x86_64 for Genymotion, got $ARCH${NC}"
fi

# -----------------------------------------------------------------------------
# Step 3: Setup Frida Server
# -----------------------------------------------------------------------------
echo -e "\n${YELLOW}[3/6] Setting up Frida server...${NC}"

# Check if Frida is already installed
if adb shell "test -f /data/local/tmp/frida-server && echo exists" | grep -q "exists"; then
    echo "  Frida server already present"

    # Check if running
    if adb shell "pidof frida-server" > /dev/null 2>&1; then
        echo -e "${GREEN}  Frida server already running${NC}"
    else
        echo "  Starting Frida server..."
        adb shell "/data/local/tmp/frida-server &" &
        sleep 2
        echo -e "${GREEN}  Frida server started${NC}"
    fi
else
    echo "  Frida server not found. Please install manually:"
    echo "    1. Download from: https://github.com/frida/frida/releases"
    echo "    2. Get version matching: frida --version"
    echo "    3. Choose: frida-server-VERSION-android-x86_64.xz"
    echo "    4. Push: adb push frida-server /data/local/tmp/"
    echo "    5. chmod: adb shell chmod 755 /data/local/tmp/frida-server"
fi

# -----------------------------------------------------------------------------
# Step 4: Configure SELinux
# -----------------------------------------------------------------------------
echo -e "\n${YELLOW}[4/6] Configuring SELinux...${NC}"

SELINUX_STATUS=$(adb shell getenforce)
echo "  Current SELinux: $SELINUX_STATUS"

# For testing, we want Permissive (Genymotion default)
# For realistic Purple/Black belt, set to Enforcing
if [ "$SELINUX_STATUS" == "Enforcing" ]; then
    echo -e "${YELLOW}  SELinux is Enforcing - some challenges may fail${NC}"
    echo "  To set Permissive: adb shell setenforce 0"
fi

# -----------------------------------------------------------------------------
# Step 5: Install Test APKs
# -----------------------------------------------------------------------------
echo -e "\n${YELLOW}[5/6] Installing test applications...${NC}"

APK_DIR="$(dirname "$0")/test_apks"

if [ -d "$APK_DIR" ]; then
    for apk in "$APK_DIR"/*.apk; do
        if [ -f "$apk" ]; then
            echo "  Installing $(basename "$apk")..."
            adb install -r "$apk" 2>/dev/null || echo "    (already installed or failed)"
        fi
    done
else
    echo -e "${YELLOW}  No test_apks directory found. Create APKs first.${NC}"
    echo "  Expected location: $APK_DIR"
    echo ""
    echo "  Required test APKs:"
    echo "    - com.agentic.sslpinned.apk      (SSL Pinning)"
    echo "    - com.agentic.nativecheck.apk   (Native Security)"
    echo "    - com.agentic.cryptovault.apk   (Crypto Operations)"
    echo "    - com.agentic.fortified.apk     (Multi-Layer Protection)"
fi

# Check for InsecureBankv2 (common test app)
if adb shell pm list packages | grep -q "insecurebankv2"; then
    echo -e "${GREEN}  InsecureBankv2 already installed${NC}"
fi

# -----------------------------------------------------------------------------
# Step 6: Verify Setup
# -----------------------------------------------------------------------------
echo -e "\n${YELLOW}[6/6] Verifying setup...${NC}"

echo ""
echo "Device Information:"
echo "  ├─ Model: $(adb shell getprop ro.product.model)"
echo "  ├─ Android: $ANDROID_VERSION (API $API_LEVEL)"
echo "  ├─ Architecture: $ARCH"
echo "  ├─ SELinux: $SELINUX_STATUS"
echo "  └─ Root: $(adb shell su -c 'id' 2>/dev/null | grep -q 'uid=0' && echo 'Available' || echo 'Not available')"

echo ""
echo "Installed Test Packages:"
adb shell pm list packages 2>/dev/null | grep -E "agentic|insecurebank" | while read pkg; do
    echo "  ├─ ${pkg#package:}"
done
echo "  └─ (end)"

echo ""
echo "Network Configuration:"
echo "  ├─ Device IP: $(adb shell ip addr show eth0 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)"
echo "  └─ Host Gateway: 10.0.3.2 (Genymotion default)"

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                    Setup Complete                            ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Next steps:"
echo "  1. Build/install test APKs if not present"
echo "  2. Start Frida server: adb shell '/data/local/tmp/frida-server &'"
echo "  3. Run mock server for SSL testing (see README.md)"
echo "  4. Run AgenticART challenges!"
echo ""
echo "Quick test:"
echo "  frida-ps -U  # Should list device processes"
echo ""
