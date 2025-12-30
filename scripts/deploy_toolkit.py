#!/usr/bin/env python3
"""
AgenticART Toolkit Deployer
Automatically bootstraps an Android device with research-grade binaries.
"""

import subprocess
from pathlib import Path

# --- CONFIGURATION ---
TOOLKIT_DIR = Path("dojo/tools/bin")
DEVICE_BASE = "/data/local/tmp/reart"

# Binaries to deploy
TOOLS = {
    "busybox": {
        "url": "https://raw.githubusercontent.com/SahrulGunawan-ID/busybox-static-binaries/main/busybox-arm64",
        "local": TOOLKIT_DIR / "busybox",
    },
    "frida-server": {"url": None, "local": Path("/Users/QH37/frida-server-arm64")},
}


def is_elf(path):
    try:
        with open(path, "rb") as f:
            header = f.read(4)
            return header == b"\x7fELF"
    except Exception:
        return False


def run_cmd(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode().strip()
    except subprocess.CalledProcessError:
        return None


def main():
    print("🚀 AgenticART Toolkit Deployer")
    print("-" * 30)

    TOOLKIT_DIR.mkdir(parents=True, exist_ok=True)

    for name, info in TOOLS.items():
        if not info["local"].exists() or not is_elf(info["local"]):
            if info["url"]:
                print(f"📥 Downloading {name}...")
                subprocess.run(f"curl -L -f {info['url']} -o {info['local']}", shell=True)
            elif name == "frida-server":
                print(f"❌ Error: {name} not found locally. Skipping.")
                continue

        if info["local"].exists() and is_elf(info["local"]):
            info["local"].chmod(0o755)
            print(f"✅ {name} ready.")
        else:
            print(f"❌ {name} is corrupted or not a binary.")

    device_id = run_cmd("adb devices | grep -v 'List' | head -n 1 | awk '{print $1}'")
    if not device_id:
        print("❌ No device detected via ADB.")
        return

    print(f"📱 Target Device: {device_id}")
    run_cmd(f"adb -s {device_id} shell 'mkdir -p {DEVICE_BASE}'")

    for name, info in TOOLS.items():
        if info["local"].exists() and is_elf(info["local"]):
            print(f"📤 Pushing {name} to {DEVICE_BASE}...")
            subprocess.run(
                f"adb -s {device_id} push {info['local']} {DEVICE_BASE}/{name}", shell=True
            )
            run_cmd(f"adb -s {device_id} shell 'chmod 755 {DEVICE_BASE}/{name}'")

    print("\n🔍 Verification:")
    bb_check = run_cmd(f"adb -s {device_id} shell '{DEVICE_BASE}/busybox --help | head -n 1'")
    if bb_check:
        print(f"  [OK] {bb_check}")
    else:
        print("  [FAIL] Toolkit failed to execute on device.")

    print("\n✨ Deployment Summary:")
    print(f"Location: {DEVICE_BASE}")
    print("Commands:")
    print(f"  {DEVICE_BASE}/busybox [tool]")
    print(f"  {DEVICE_BASE}/frida-server &")


if __name__ == "__main__":
    main()
