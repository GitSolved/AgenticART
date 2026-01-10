# Security Tools Reference

Complete list of tools required for LLM-driven Android penetration testing.

## Quick Status Check

Run this to check which tools are installed:

```bash
./scripts/check-tools.sh
```

---

## Tool Categories

### 1. Android Debug Bridge (ADB) - REQUIRED

| Tool | Purpose | Install |
|------|---------|---------|
| `adb` | Device communication, shell access, file transfer | Android SDK Platform Tools |
| `fastboot` | Bootloader operations, flashing | Android SDK Platform Tools |

```bash
# macOS
brew install android-platform-tools

# Linux
sudo apt install android-tools-adb android-tools-fastboot

# Verify
adb version
```

---

### 2. Dynamic Analysis - REQUIRED

| Tool | Purpose | Install |
|------|---------|---------|
| `frida` | Runtime instrumentation, hooking | pip install frida-tools |
| `frida-server` | On-device Frida daemon | Download from GitHub |
| `objection` | Frida-powered mobile exploration | pip install objection |

```bash
# Install Frida tools
pip install frida-tools

# Install Objection
pip install objection

# Download frida-server for device architecture
# Check arch: adb shell getprop ro.product.cpu.abi
ARCH="x86_64"  # or arm64-v8a, armeabi-v7a
VERSION=$(frida --version)
wget https://github.com/frida/frida/releases/download/${VERSION}/frida-server-${VERSION}-android-${ARCH}.xz
unxz frida-server-${VERSION}-android-${ARCH}.xz

# Push to device
adb push frida-server-* /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &

# Verify
frida-ps -U
```

---

### 3. Static Analysis - REQUIRED

| Tool | Purpose | Install |
|------|---------|---------|
| `apktool` | APK decompilation/recompilation | brew/apt |
| `jadx` | DEX to Java decompiler | brew/apt |
| `dex2jar` | DEX to JAR conversion | brew/apt |
| `jd-gui` | JAR/class file viewer | Download |
| `androguard` | Python APK analysis library | pip install |

```bash
# macOS
brew install apktool jadx dex2jar

# Linux
sudo apt install apktool jadx

# Python library
pip install androguard

# Verify
apktool --version
jadx --version
```

---

### 4. Mobile Security Framework (MobSF) - RECOMMENDED

Automated static and dynamic analysis platform.

| Tool | Purpose | Install |
|------|---------|---------|
| `MobSF` | Automated mobile app security testing | Docker/local |

```bash
# Docker (Recommended)
docker pull opensecurity/mobile-security-framework-mobsf
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf

# Local Installation
git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git
cd Mobile-Security-Framework-MobSF
./setup.sh
./run.sh

# Access at http://localhost:8000
```

**MobSF Capabilities:**
- APK/IPA static analysis
- Source code review
- Malware analysis
- CVSS scoring
- PDF reports

---

### 5. Network/Proxy Tools - REQUIRED FOR MITM

| Tool | Purpose | Install |
|------|---------|---------|
| `mitmproxy` | HTTPS interception proxy | pip/brew |
| `Burp Suite` | Web app security testing | Download |
| `OWASP ZAP` | Open source web scanner | brew/apt |
| `nmap` | Network scanning | brew/apt |
| `Wireshark` | Packet capture/analysis | brew/apt |

```bash
# mitmproxy
pip install mitmproxy
# or
brew install mitmproxy

# OWASP ZAP
brew install --cask owasp-zap
# or
sudo apt install zaproxy

# nmap
brew install nmap
# or
sudo apt install nmap

# Wireshark
brew install --cask wireshark
# or
sudo apt install wireshark

# Burp Suite (manual download)
# https://portswigger.net/burp/communitydownload
```

**Proxy Setup for Android:**
```bash
# Start mitmproxy
mitmproxy -p 8080

# Configure Android proxy
adb shell settings put global http_proxy $(hostname -I | awk '{print $1}'):8080

# Install CA certificate
adb push ~/.mitmproxy/mitmproxy-ca-cert.cer /sdcard/
# Then: Settings > Security > Install from storage

# Clear proxy when done
adb shell settings put global http_proxy :0
```

---

### 6. Android Security Testing (Drozer) - RECOMMENDED

| Tool | Purpose | Install |
|------|---------|---------|
| `drozer` | Android security assessment framework | pip/Docker |
| `drozer-agent` | On-device agent APK | Download |

```bash
# Install drozer
pip install drozer

# Download agent APK
wget https://github.com/WithSecureLabs/drozer/releases/latest/download/drozer-agent.apk

# Install agent on device
adb install drozer-agent.apk

# Start agent, enable server in app, then connect
drozer console connect

# Common commands
dz> run app.package.list -f <keyword>
dz> run app.package.info -a <package>
dz> run app.package.attacksurface <package>
dz> run app.activity.info -a <package>
dz> run app.provider.info -a <package>
dz> run scanner.provider.injection -a <package>
```

---

### 7. Database Tools - REQUIRED

| Tool | Purpose | Install |
|------|---------|---------|
| `sqlite3` | SQLite database inspection | Built-in/brew |
| `sqlcipher` | Encrypted SQLite support | brew/apt |
| `DB Browser for SQLite` | GUI database viewer | brew/apt |

```bash
# sqlite3 (usually pre-installed)
sqlite3 --version

# sqlcipher for encrypted databases
brew install sqlcipher
# or
sudo apt install sqlcipher

# DB Browser (GUI)
brew install --cask db-browser-for-sqlite

# Extract and analyze app database
adb shell run-as com.target.app cat databases/app.db > app.db
sqlite3 app.db ".tables"
sqlite3 app.db "SELECT * FROM users;"
```

---

### 8. Exploit Development - OPTIONAL (Pre-installed in Docker)

These tools are included in the standard `agentic-sandbox` Docker image.

| Tool | Purpose | Install |
|------|---------|---------|
| `pwntools` | CTF/exploit development | pip install |
| `radare2` | Reverse engineering | **Built-in** (Docker) / brew/apt |
| `ghidra` | NSA reverse engineering tool | **Built-in** (Docker) / Download |
| `ropper` | ROP gadget finder | pip install |

```bash
# In Docker Sandbox, just run:
r2 -v
ghidra-headless -h
```

For local installation:
```bash
# pwntools
pip install pwntools

# radare2
brew install radare2
# or
sudo apt install radare2

# ropper
pip install ropper

# Ghidra (manual)
# https://ghidra-sre.org/
```

---

### 9. Root Detection Bypass - OPTIONAL

| Tool | Purpose | Install |
|------|---------|---------|
| `Magisk` | Systemless root + MagiskHide | Install on device |
| `RootCloak` | Xposed module for root hiding | Xposed repo |
| `Frida scripts` | Runtime root detection bypass | Custom |

```bash
# Using Objection for root bypass
objection -g com.target.app explore
com.target.app on (Android: 11) [usb] # android root disable

# Using Frida script
frida -U -f com.target.app -l anti-root.js --no-pause
```

---

### 10. SSL Pinning Bypass - REQUIRED FOR HTTPS APPS

| Tool | Purpose | Install |
|------|---------|---------|
| `objection` | Built-in SSL pinning bypass | pip install |
| `Frida scripts` | Custom SSL bypass | Custom |

```bash
# Objection SSL bypass
objection -g com.target.app explore
com.target.app on (Android: 11) [usb] # android sslpinning disable

# Frida universal SSL bypass
frida -U -f com.target.app -l universal-ssl-bypass.js --no-pause
```

---

## Complete Installation Script

```bash
#!/bin/bash
# Install all Android pentest tools

# Python tools
pip install frida-tools objection drozer androguard mitmproxy pwntools ropper

# macOS (Homebrew)
brew install android-platform-tools apktool jadx dex2jar nmap
brew install --cask wireshark owasp-zap db-browser-for-sqlite

# MobSF via Docker
docker pull opensecurity/mobile-security-framework-mobsf

echo "Installation complete. Run ./scripts/check-tools.sh to verify."
```

---

## Tool Verification Matrix

| Tool | Check Command | Expected Output |
|------|---------------|-----------------|
| adb | `adb version` | Android Debug Bridge version 1.0.x |
| frida | `frida --version` | 16.x.x |
| objection | `objection version` | objection: x.x.x |
| apktool | `apktool --version` | Apktool v2.x.x |
| jadx | `jadx --version` | jadx 1.x.x |
| mitmproxy | `mitmproxy --version` | Mitmproxy: 10.x.x |
| nmap | `nmap --version` | Nmap version 7.x |
| drozer | `drozer version` | drozer x.x.x |
| sqlite3 | `sqlite3 --version` | 3.x.x |

---

## LLM Script Generation Considerations

When the LLM generates scripts, it should:

1. **Check tool availability** before using
2. **Use full paths** when tools might be in non-standard locations
3. **Fall back to alternatives** if primary tool unavailable
4. **Validate target architecture** before pushing binaries

Example tool check in generated scripts:
```python
import shutil

REQUIRED_TOOLS = ['adb', 'frida', 'objection']

def check_tools():
    missing = []
    for tool in REQUIRED_TOOLS:
        if not shutil.which(tool):
            missing.append(tool)
    if missing:
        raise RuntimeError(f"Missing tools: {missing}")
```

---

## Version Compatibility

| Android Version | API Level | Recommended Tools |
|-----------------|-----------|-------------------|
| Android 14 | 34 | Frida 16+, Objection 1.11+ |
| Android 13 | 33 | Frida 15+, Objection 1.11+ |
| Android 12 | 31-32 | Frida 15+, Objection 1.11+ |
| Android 11 | 30 | Frida 14+, Objection 1.10+ |
| Android 10 | 29 | Frida 12+, Objection 1.9+ |

---

## References

- [Frida Documentation](https://frida.re/docs/home/)
- [Objection Wiki](https://github.com/sensepost/objection/wiki)
- [Drozer Guide](https://labs.withsecure.com/tools/drozer)
- [MobSF Documentation](https://mobsf.github.io/docs/)
- [OWASP Mobile Testing Guide](https://owasp.org/www-project-mobile-security-testing-guide/)
