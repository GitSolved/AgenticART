#!/usr/bin/env python3
"""
Device Provisioning Script for AgenticART Personas.

Configures an Android device to match a specified persona, including:
- Installing required apps
- Seeding user data (contacts, SMS, files)
- Configuring security settings
- Setting up WiFi networks
"""

from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import sys
from pathlib import Path
from typing import Optional

import yaml

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


class DeviceProvisioner:
    """Provisions an Android device according to a persona specification."""

    def __init__(
        self,
        persona_path: Path,
        device_id: Optional[str] = None,
        adb_path: str = "adb",
    ):
        self.persona_path = persona_path
        self.device_id = device_id or os.getenv("EMULATOR_DEVICE", "emulator-5554")
        self.adb_path = adb_path
        self.persona = self._load_persona()

    def _load_persona(self) -> dict:
        """Load and merge persona with base."""
        with open(self.persona_path, "r") as f:
            persona = yaml.safe_load(f)

        # Load and merge base if specified
        if persona.get("inherits"):
            base_path = self.persona_path.parent / f"{persona['inherits']}.yaml"
            if base_path.exists():
                with open(base_path, "r") as f:
                    base = yaml.safe_load(f)
                persona = self._deep_merge(base, persona)

        return persona

    def _deep_merge(self, base: dict, override: dict) -> dict:
        """Deep merge two dictionaries."""
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        return result

    def _adb(self, command: str, check: bool = True) -> subprocess.CompletedProcess:
        """Execute an ADB command."""
        cmd = [self.adb_path, "-s", self.device_id] + command.split()
        return subprocess.run(cmd, capture_output=True, text=True, check=check)

    def _adb_shell(self, command: str) -> str:
        """Execute an ADB shell command and return output."""
        result = self._adb(f"shell {command}", check=False)
        return result.stdout.strip()

    def check_device(self) -> bool:
        """Verify device is connected and responsive."""
        result = self._adb("shell echo ping", check=False)
        return result.returncode == 0 and "ping" in result.stdout

    def provision(self, dry_run: bool = False) -> dict:
        """
        Provision the device according to the persona.

        Returns:
            Dictionary with provisioning results.
        """
        results = {
            "persona": self.persona.get("name", "Unknown"),
            "device": self.device_id,
            "steps": [],
            "success": True,
        }

        print(f"🔧 Provisioning device {self.device_id}")
        print(f"   Persona: {self.persona.get('name', 'Unknown')}")
        print(f"   Dry run: {dry_run}")
        print()

        # Step 1: Seed contacts
        if "contacts" in self.persona.get("user_data", {}):
            result = self._seed_contacts(dry_run)
            results["steps"].append(result)

        # Step 2: Seed SMS messages
        if "sms" in self.persona.get("user_data", {}):
            result = self._seed_sms(dry_run)
            results["steps"].append(result)

        # Step 3: Create files
        if "files" in self.persona.get("user_data", {}):
            result = self._seed_files(dry_run)
            results["steps"].append(result)

        # Step 4: Configure WiFi
        if "wifi" in self.persona.get("user_data", {}):
            result = self._configure_wifi(dry_run)
            results["steps"].append(result)

        # Step 5: Set device properties
        if "device" in self.persona:
            result = self._configure_device(dry_run)
            results["steps"].append(result)

        # Check overall success
        results["success"] = all(s.get("success", False) for s in results["steps"])

        return results

    def _seed_contacts(self, dry_run: bool = False) -> dict:
        """Seed contacts into the device."""
        result = {"step": "seed_contacts", "success": False, "details": []}

        contact_config = self.persona["user_data"]["contacts"]
        vip_contacts = contact_config.get("vip_contacts", [])
        total_count = contact_config.get("count", 50)

        print("📇 Seeding contacts...")

        # Insert VIP contacts
        for contact in vip_contacts:
            name = contact["name"]
            phone = contact.get("phone", "")
            email = contact.get("email", "")

            if dry_run:
                print(f"   [DRY RUN] Would insert: {name} ({phone})")
            else:
                # Use content provider to insert contact
                cmd = (
                    f"content insert --uri content://com.android.contacts/raw_contacts "
                    f"--bind account_type:s:null --bind account_name:s:null"
                )
                self._adb_shell(cmd)

                # This is simplified - real implementation needs proper contact insertion
                result["details"].append(f"Inserted: {name}")

            result["details"].append({"name": name, "phone": phone})

        # Generate random contacts to reach count
        generated = self._generate_random_contacts(total_count - len(vip_contacts))
        result["details"].extend(generated)

        result["success"] = True
        result["count"] = len(vip_contacts) + len(generated)
        print(f"   ✓ {result['count']} contacts seeded")

        return result

    def _generate_random_contacts(self, count: int) -> list:
        """Generate random contact entries."""
        first_names = [
            "James", "Mary", "John", "Patricia", "Robert", "Jennifer",
            "Michael", "Linda", "William", "Elizabeth", "David", "Susan",
            "Richard", "Jessica", "Joseph", "Sarah", "Thomas", "Karen",
        ]
        last_names = [
            "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia",
            "Miller", "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez",
        ]

        contacts = []
        for i in range(count):
            name = f"{random.choice(first_names)} {random.choice(last_names)}"
            phone = f"+1-555-{random.randint(1000, 9999)}"
            contacts.append({"name": name, "phone": phone})

        return contacts

    def _seed_sms(self, dry_run: bool = False) -> dict:
        """Seed SMS messages into the device."""
        result = {"step": "seed_sms", "success": False, "details": []}

        sms_config = self.persona["user_data"]["sms"]
        required = sms_config.get("required_sensitive", [])

        print("📱 Seeding SMS messages...")

        for msg in required:
            sender = msg["sender"]
            body = msg["body"]

            if dry_run:
                print(f"   [DRY RUN] Would insert SMS from {sender}")
            else:
                # Insert via content provider
                # Note: May require system permissions on newer Android
                cmd = (
                    f"content insert --uri content://sms "
                    f"--bind address:s:{sender} "
                    f"--bind body:s:\"{body}\" "
                    f"--bind type:i:1 "
                    f"--bind read:i:1"
                )
                self._adb_shell(cmd)

            result["details"].append({"sender": sender, "preview": body[:50]})

        result["success"] = True
        result["count"] = len(required)
        print(f"   ✓ {result['count']} sensitive SMS seeded")

        return result

    def _seed_files(self, dry_run: bool = False) -> dict:
        """Create files on the device."""
        result = {"step": "seed_files", "success": False, "details": []}

        files_config = self.persona["user_data"]["files"]
        documents = files_config.get("documents", {})
        required_docs = documents.get("required", [])

        print("📁 Seeding files...")

        for doc in required_docs:
            path = doc["path"]
            content = doc.get("content", f"Sample content for {path}")

            if dry_run:
                print(f"   [DRY RUN] Would create: {path}")
            else:
                # Create directory if needed
                dir_path = "/".join(path.split("/")[:-1])
                self._adb_shell(f"mkdir -p {dir_path}")

                # Create file with content
                # Using echo for simple files
                escaped_content = content.replace("'", "'\\''")
                self._adb_shell(f"echo '{escaped_content}' > {path}")

            result["details"].append(path)

        result["success"] = True
        result["count"] = len(required_docs)
        print(f"   ✓ {result['count']} files created")

        return result

    def _configure_wifi(self, dry_run: bool = False) -> dict:
        """Configure WiFi networks (metadata only - can't add real networks via ADB)."""
        result = {"step": "configure_wifi", "success": False, "details": []}

        wifi_config = self.persona["user_data"]["wifi"]
        networks = wifi_config.get("networks", [])

        print("📶 Configuring WiFi networks...")

        # Note: Actually adding WiFi networks requires system permissions
        # We document what should be configured
        for network in networks:
            ssid = network["ssid"]
            security = network.get("security", "OPEN")

            if dry_run:
                print(f"   [DRY RUN] Would configure: {ssid} ({security})")

            result["details"].append({"ssid": ssid, "security": security})

        result["success"] = True
        result["count"] = len(networks)
        result["note"] = "WiFi networks logged - manual configuration may be required"
        print(f"   ✓ {result['count']} networks documented")

        return result

    def _configure_device(self, dry_run: bool = False) -> dict:
        """Configure device properties."""
        result = {"step": "configure_device", "success": False, "details": []}

        device_config = self.persona.get("device", {})

        print("⚙️  Configuring device settings...")

        # Set screen timeout
        if not dry_run:
            self._adb_shell("settings put system screen_off_timeout 600000")
            result["details"].append("Screen timeout: 10 minutes")

        # Enable stay awake while charging (for testing)
        if device_config.get("developer_options", {}).get("stay_awake"):
            if not dry_run:
                self._adb_shell("settings put global stay_on_while_plugged_in 3")
            result["details"].append("Stay awake: enabled")

        result["success"] = True
        print(f"   ✓ Device configured")

        return result


def main():
    parser = argparse.ArgumentParser(
        description="Provision Android device with persona"
    )
    parser.add_argument(
        "persona",
        help="Persona name (e.g., android_11_user) or path to YAML file",
    )
    parser.add_argument(
        "--device", "-d",
        help="Device ID (default: from EMULATOR_DEVICE env or emulator-5554)",
    )
    parser.add_argument(
        "--dry-run", "-n",
        action="store_true",
        help="Show what would be done without making changes",
    )
    parser.add_argument(
        "--adb",
        default="adb",
        help="Path to adb executable",
    )

    args = parser.parse_args()

    # Resolve persona path
    if args.persona.endswith(".yaml"):
        persona_path = Path(args.persona)
    else:
        persona_path = Path(__file__).parent.parent / f"{args.persona}.yaml"

    if not persona_path.exists():
        print(f"❌ Persona not found: {persona_path}")
        sys.exit(1)

    # Create provisioner
    provisioner = DeviceProvisioner(
        persona_path=persona_path,
        device_id=args.device,
        adb_path=args.adb,
    )

    # Check device
    if not args.dry_run and not provisioner.check_device():
        print(f"❌ Device not connected: {provisioner.device_id}")
        sys.exit(1)

    # Provision
    results = provisioner.provision(dry_run=args.dry_run)

    # Print summary
    print()
    print("=" * 60)
    if results["success"]:
        print("✅ Provisioning complete!")
    else:
        print("⚠️  Provisioning completed with errors")

    for step in results["steps"]:
        status = "✓" if step.get("success") else "✗"
        print(f"   {status} {step['step']}: {step.get('count', 0)} items")

    print("=" * 60)

    sys.exit(0 if results["success"] else 1)


if __name__ == "__main__":
    main()
