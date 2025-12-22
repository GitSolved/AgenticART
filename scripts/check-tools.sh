#!/bin/bash
# Check all required pentest tools
# Reference: TOOLS.md

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}[✓]${NC} $1"; }
fail() { echo -e "${RED}[✗]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }

MISSING=0
OPTIONAL_MISSING=0

check_tool() {
    local tool=$1
    local required=$2
    if command -v "$tool" &>/dev/null; then
        local version=$($tool --version 2>&1 | head -1 || echo "installed")
        pass "$tool: $version"
    else
        if [ "$required" = "required" ]; then
            fail "$tool: NOT FOUND (required)"
            ((MISSING++))
        else
            warn "$tool: NOT FOUND (optional)"
            ((OPTIONAL_MISSING++))
        fi
    fi
}

check_python_pkg() {
    local pkg=$1
    local required=$2
    if python3 -c "import $pkg" 2>/dev/null; then
        pass "python: $pkg"
    else
        if [ "$required" = "required" ]; then
            fail "python: $pkg NOT FOUND (required)"
            ((MISSING++))
        else
            warn "python: $pkg NOT FOUND (optional)"
            ((OPTIONAL_MISSING++))
        fi
    fi
}

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║              LLM-AndroidPentest Tool Check                   ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

echo "=== Android Tools (Required) ==="
check_tool adb required
check_tool fastboot optional
echo ""

echo "=== Dynamic Analysis (Required) ==="
check_tool frida required
check_tool objection required
echo ""

echo "=== Static Analysis (Required) ==="
check_tool apktool required
check_tool jadx required
check_tool dex2jar optional
echo ""

echo "=== Network/Proxy (Required for MITM) ==="
check_tool mitmproxy required
check_tool nmap required
check_tool nc optional
echo ""

echo "=== Security Frameworks (Recommended) ==="
check_tool drozer optional
# MobSF is Docker-based, check separately
if docker images 2>/dev/null | grep -q "mobile-security-framework-mobsf"; then
    pass "MobSF: Docker image present"
else
    warn "MobSF: Docker image not found (optional)"
    ((OPTIONAL_MISSING++))
fi
echo ""

echo "=== Database Tools ==="
check_tool sqlite3 required
check_tool sqlcipher optional
echo ""

echo "=== Python Packages ==="
check_python_pkg frida required
check_python_pkg objection required
check_python_pkg androguard required
check_python_pkg mitmproxy required
check_python_pkg drozer optional
check_python_pkg pwntools optional
echo ""

echo "=== GUI Tools (Optional) ==="
if [ "$(uname)" = "Darwin" ]; then
    [ -d "/Applications/Burp Suite Community Edition.app" ] && pass "Burp Suite: installed" || warn "Burp Suite: NOT FOUND"
    [ -d "/Applications/OWASP ZAP.app" ] && pass "OWASP ZAP: installed" || warn "OWASP ZAP: NOT FOUND"
    [ -d "/Applications/Wireshark.app" ] && pass "Wireshark: installed" || warn "Wireshark: NOT FOUND"
fi
echo ""

echo "══════════════════════════════════════════════════════════════"
if [ $MISSING -eq 0 ]; then
    echo -e "${GREEN}All required tools installed!${NC}"
    if [ $OPTIONAL_MISSING -gt 0 ]; then
        echo -e "${YELLOW}$OPTIONAL_MISSING optional tools missing${NC}"
    fi
    echo ""
    echo "Quick install missing tools:"
    echo "  pip install -r requirements-security.txt"
    echo ""
    exit 0
else
    echo -e "${RED}$MISSING required tools missing!${NC}"
    echo ""
    echo "Install required tools:"
    echo "  pip install -r requirements-security.txt"
    echo "  brew install apktool jadx android-platform-tools nmap"
    echo ""
    echo "See TOOLS.md for detailed installation instructions."
    exit 1
fi
