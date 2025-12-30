#!/usr/bin/env python3
"""
AgenticART Toolkit Deployer
Automatically bootstraps an Android device with research-grade binaries.
"""

import shlex
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
    """Run a command safely without shell=True."""
    try:
        # Split command string into list for safe execution
        cmd_list = shlex.split(cmd)
        return subprocess.check_output(cmd_list, stderr=subprocess.STDOUT).decode().strip()
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
                subprocess.run(
                    ["curl", "-L", "-f", info["url"], "-o", str(info["local"])],
                    check=False,
                )
            elif name == "frida-server":
                print(f"❌ Error: {name} not found locally. Skipping.")
                continue

        if info["local"].exists() and is_elf(info["local"]):
            info["local"].chmod(0o755)
            print(f"✅ {name} ready.")
        else:
            print(f"❌ {name} is corrupted or not a binary.")

    # Get device ID without shell piping
    try:
        result = subprocess.run(
            ["adb", "devices"],
            capture_output=True,
            text=True,
            check=False,
        )
        lines = result.stdout.strip().split("\n")[1:]  # Skip header
        device_id = None
        for line in lines:
            if "\tdevice" in line:
                device_id = line.split("\t")[0]
                break
    except Exception:
        device_id = None
    if not device_id:
        print("❌ No device detected via ADB.")
        return

    print(f"📱 Target Device: {device_id}")
    subprocess.run(
        ["adb", "-s", device_id, "shell", f"mkdir -p {DEVICE_BASE}"],
        check=False,
    )

    for name, info in TOOLS.items():
        if info["local"].exists() and is_elf(info["local"]):
            print(f"📤 Pushing {name} to {DEVICE_BASE}...")
            subprocess.run(
                ["adb", "-s", device_id, "push", str(info["local"]), f"{DEVICE_BASE}/{name}"],
                check=False,
            )
            subprocess.run(
                ["adb", "-s", device_id, "shell", f"chmod 755 {DEVICE_BASE}/{name}"],
                check=False,
            )

    print("\n🔍 Verification:")
    try:
        result = subprocess.run(
            ["adb", "-s", device_id, "shell", f"{DEVICE_BASE}/busybox --help"],
            capture_output=True,
            text=True,
            check=False,
        )
        bb_check = result.stdout.strip().split("\n")[0] if result.stdout else None
    except Exception:
        bb_check = None
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
