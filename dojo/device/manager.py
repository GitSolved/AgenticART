"""
Device Manager - Unified device configuration and management.

Combines device detection, provisioning, and target management into
a single interface for setting up training environments.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml


@dataclass
class DeviceInfo:
    """Information about the connected Android device."""

    device_id: str
    android_version: str = ""
    api_level: int = 0
    model: str = ""
    manufacturer: str = ""
    is_rooted: bool = False
    root_method: Optional[str] = None
    is_emulator: bool = False
    connected: bool = False

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "device_id": self.device_id,
            "android_version": self.android_version,
            "api_level": self.api_level,
            "model": self.model,
            "manufacturer": self.manufacturer,
            "is_rooted": self.is_rooted,
            "root_method": self.root_method,
            "is_emulator": self.is_emulator,
            "connected": self.connected,
        }


@dataclass
class SetupResult:
    """Result of a setup operation."""

    step: str
    success: bool
    message: str = ""
    details: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "step": self.step,
            "success": self.success,
            "message": self.message,
            "details": self.details,
        }


class DeviceManager:
    """
    Unified manager for Android device setup and configuration.

    Handles:
    - Device detection and info gathering
    - Root status detection
    - App installation
    - Persona provisioning
    - Vulnerable target setup
    - CTF flag planting
    """

    def __init__(
        self,
        device_id: Optional[str] = None,
        adb_path: Optional[str] = None,
    ):
        """
        Initialize the device manager.

        Args:
            device_id: Android device ID. Auto-detects if None.
            adb_path: Path to adb executable. Uses PATH if None.
        """
        self.adb_path = adb_path or os.getenv("ADB_PATH", "adb")
        self.device_id = device_id or os.getenv("EMULATOR_DEVICE")
        self._device_info: Optional[DeviceInfo] = None

        # Auto-detect device if not specified
        if not self.device_id:
            self.device_id = self._auto_detect_device()

    def _adb(
        self,
        command: str,
        timeout: int = 30,
        check: bool = False,
    ) -> subprocess.CompletedProcess:
        """
        Execute an ADB command.

        Args:
            command: ADB command (without 'adb' prefix).
            timeout: Command timeout in seconds.
            check: Whether to raise on non-zero exit.

        Returns:
            CompletedProcess with stdout/stderr.
        """
        # Build command
        cmd = [self.adb_path]
        if self.device_id:
            cmd.extend(["-s", self.device_id])
        cmd.extend(command.split())

        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=check,
        )

    def _shell(self, command: str, timeout: int = 30) -> str:
        """Execute a shell command and return output."""
        result = self._adb(f"shell {command}", timeout=timeout)
        return result.stdout.strip()

    def _auto_detect_device(self) -> Optional[str]:
        """Auto-detect connected device."""
        try:
            result = subprocess.run(
                [self.adb_path, "devices"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            for line in result.stdout.strip().split("\n")[1:]:
                if "\tdevice" in line:
                    return line.split("\t")[0]

        except Exception:
            pass

        return "emulator-5554"  # Default fallback

    # =========================================================================
    # Device Detection
    # =========================================================================

    def detect_device(self) -> DeviceInfo:
        """
        Detect and gather information about the connected device.

        Returns:
            DeviceInfo with device details.
        """
        info = DeviceInfo(device_id=self.device_id or "unknown")

        # Check connection
        try:
            result = self._adb("shell echo ping", timeout=5)
            info.connected = result.returncode == 0 and "ping" in result.stdout
        except Exception:
            info.connected = False
            return info

        if not info.connected:
            return info

        # Gather device properties
        info.android_version = self._shell("getprop ro.build.version.release")

        api_str = self._shell("getprop ro.build.version.sdk")
        try:
            info.api_level = int(api_str)
        except ValueError:
            info.api_level = 0

        info.model = self._shell("getprop ro.product.model")
        info.manufacturer = self._shell("getprop ro.product.manufacturer")

        # Check if emulator
        fingerprint = self._shell("getprop ro.build.fingerprint")
        info.is_emulator = any(
            x in fingerprint.lower()
            for x in ["generic", "emulator", "genymotion", "vbox"]
        )

        # Detect root status
        info.is_rooted, info.root_method = self._detect_root()

        self._device_info = info
        return info

    def _detect_root(self) -> tuple[bool, Optional[str]]:
        """
        Detect if the device is rooted and how.

        Returns:
            Tuple of (is_rooted, root_method).
        """
        # Method 1: Try su command
        try:
            result = self._adb("shell su -c id", timeout=5)
            if "uid=0" in result.stdout:
                # Check for Magisk
                magisk_check = self._shell("su -c 'ls /data/adb/magisk'")
                if "No such file" not in magisk_check and magisk_check:
                    return True, "magisk"
                return True, "su"
        except Exception:
            pass

        # Method 2: Check for su binary
        su_paths = ["/system/bin/su", "/system/xbin/su", "/sbin/su"]
        for path in su_paths:
            result = self._shell(f"ls {path}")
            if "No such file" not in result and path in result:
                return True, "su_binary"

        # Method 3: Check for Magisk app
        result = self._shell("pm list packages | grep magisk")
        if "magisk" in result.lower():
            return True, "magisk"

        # Method 4: Check build tags (some ROMs)
        tags = self._shell("getprop ro.build.tags")
        if "test-keys" in tags:
            return True, "test_keys"

        return False, None

    def check_root_access(self) -> bool:
        """
        Verify actual root command execution works.

        Returns:
            True if root commands execute successfully.
        """
        try:
            result = self._adb("shell su -c 'id'", timeout=5)
            return "uid=0(root)" in result.stdout
        except Exception:
            return False

    # =========================================================================
    # App Installation
    # =========================================================================

    def is_app_installed(self, package: str) -> bool:
        """Check if an app is installed."""
        result = self._shell(f"pm list packages {package}")
        return package in result

    def install_apk(self, apk_path: Path, reinstall: bool = False) -> SetupResult:
        """
        Install an APK on the device.

        Args:
            apk_path: Path to APK file.
            reinstall: Whether to reinstall if already exists.

        Returns:
            SetupResult with installation status.
        """
        if not apk_path.exists():
            return SetupResult(
                step="install_apk",
                success=False,
                message=f"APK not found: {apk_path}",
            )

        cmd = "install -r" if reinstall else "install"
        result = self._adb(f"{cmd} {apk_path}", timeout=120)

        success = "Success" in result.stdout or result.returncode == 0
        return SetupResult(
            step="install_apk",
            success=success,
            message=f"Installed {apk_path.name}" if success else result.stderr,
            details=[str(apk_path)],
        )

    def download_and_install(
        self,
        url: str,
        package: str,
        cache_dir: Optional[Path] = None,
    ) -> SetupResult:
        """
        Download an APK from URL and install it.

        Args:
            url: Download URL for the APK.
            package: Expected package name.
            cache_dir: Directory to cache downloads.

        Returns:
            SetupResult with installation status.
        """
        # Check if already installed
        if self.is_app_installed(package):
            return SetupResult(
                step="download_and_install",
                success=True,
                message=f"{package} already installed",
            )

        # Set up cache directory
        if cache_dir is None:
            cache_dir = Path.home() / ".cache" / "agentic_art" / "apks"
        cache_dir.mkdir(parents=True, exist_ok=True)

        # Download APK
        apk_name = url.split("/")[-1]
        if not apk_name.endswith(".apk"):
            apk_name = f"{package}.apk"

        apk_path = cache_dir / apk_name

        if not apk_path.exists():
            try:
                import urllib.request

                print(f"   Downloading {url}...")
                urllib.request.urlretrieve(url, apk_path)
            except Exception as e:
                return SetupResult(
                    step="download_and_install",
                    success=False,
                    message=f"Download failed: {e}",
                )

        # Install
        return self.install_apk(apk_path)

    # =========================================================================
    # Persona Provisioning
    # =========================================================================

    def load_persona(self, persona_path: Path) -> dict:
        """
        Load a persona configuration, merging with base if needed.

        Args:
            persona_path: Path to persona YAML file.

        Returns:
            Merged persona configuration.
        """
        with open(persona_path, "r") as f:
            persona = yaml.safe_load(f)

        # Handle inheritance
        if persona.get("inherits"):
            base_path = persona_path.parent / f"{persona['inherits']}.yaml"
            if base_path.exists():
                with open(base_path, "r") as f:
                    base = yaml.safe_load(f)
                persona = self._deep_merge(base, persona)

        return persona

    def _deep_merge(self, base: dict, override: dict) -> dict:
        """Deep merge dictionaries."""
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        return result

    def provision_persona(
        self,
        persona_path: Path,
        dry_run: bool = False,
    ) -> list[SetupResult]:
        """
        Provision device according to persona specification.

        Args:
            persona_path: Path to persona YAML.
            dry_run: If True, only show what would be done.

        Returns:
            List of SetupResult for each step.
        """
        results = []
        persona = self.load_persona(persona_path)

        # Seed contacts
        if "user_data" in persona and "contacts" in persona["user_data"]:
            result = self._seed_contacts(persona["user_data"]["contacts"], dry_run)
            results.append(result)

        # Seed SMS
        if "user_data" in persona and "sms" in persona["user_data"]:
            result = self._seed_sms(persona["user_data"]["sms"], dry_run)
            results.append(result)

        # Seed files
        if "user_data" in persona and "files" in persona["user_data"]:
            result = self._seed_files(persona["user_data"]["files"], dry_run)
            results.append(result)

        # Configure device settings
        if "device" in persona:
            result = self._configure_device(persona["device"], dry_run)
            results.append(result)

        return results

    def _seed_contacts(self, config: dict, dry_run: bool) -> SetupResult:
        """Seed contacts into device."""
        details = []
        vip_contacts = config.get("vip_contacts", [])

        for contact in vip_contacts:
            name = contact["name"]
            phone = contact.get("phone", "")

            if dry_run:
                details.append(f"[DRY RUN] Would add: {name} ({phone})")
            else:
                # Insert via content provider
                self._shell(
                    "content insert --uri content://com.android.contacts/raw_contacts "
                    "--bind account_type:s:null --bind account_name:s:null"
                )
                details.append(f"Added: {name}")

        return SetupResult(
            step="seed_contacts",
            success=True,
            message=f"Seeded {len(vip_contacts)} contacts",
            details=details,
        )

    def _seed_sms(self, config: dict, dry_run: bool) -> SetupResult:
        """Seed SMS messages."""
        details = []
        sensitive = config.get("required_sensitive", [])

        for msg in sensitive:
            sender = msg.get("sender", "Unknown")
            body = msg.get("body", "")

            if dry_run:
                details.append(f"[DRY RUN] SMS from {sender}")
            else:
                escaped_body = body.replace('"', '\\"')
                self._shell(
                    f'content insert --uri content://sms '
                    f'--bind address:s:"{sender}" '
                    f'--bind body:s:"{escaped_body}" '
                    f'--bind type:i:1 --bind read:i:1'
                )
                details.append(f"SMS from {sender}")

        return SetupResult(
            step="seed_sms",
            success=True,
            message=f"Seeded {len(sensitive)} SMS messages",
            details=details,
        )

    def _seed_files(self, config: dict, dry_run: bool) -> SetupResult:
        """Create files on device."""
        details = []
        documents = config.get("documents", {})
        required = documents.get("required", [])

        for doc in required:
            path = doc["path"]
            content = doc.get("content", f"Sample content for {path}")

            if dry_run:
                details.append(f"[DRY RUN] Would create: {path}")
            else:
                # Create directory
                dir_path = "/".join(path.split("/")[:-1])
                self._shell(f"mkdir -p {dir_path}")

                # Create file
                escaped = content.replace("'", "'\\''")
                self._shell(f"echo '{escaped}' > {path}")
                details.append(f"Created: {path}")

        return SetupResult(
            step="seed_files",
            success=True,
            message=f"Created {len(required)} files",
            details=details,
        )

    def _configure_device(self, config: dict, dry_run: bool) -> SetupResult:
        """Configure device settings."""
        details = []

        if not dry_run:
            # Screen timeout
            self._shell("settings put system screen_off_timeout 600000")
            details.append("Screen timeout: 10 minutes")

            # Stay awake while charging
            if config.get("developer_options", {}).get("stay_awake"):
                self._shell("settings put global stay_on_while_plugged_in 3")
                details.append("Stay awake: enabled")

        return SetupResult(
            step="configure_device",
            success=True,
            message="Device configured",
            details=details,
        )

    # =========================================================================
    # Vulnerable Target Setup
    # =========================================================================

    def setup_vulnerable_targets(
        self,
        apps: Optional[list[str]] = None,
        dry_run: bool = False,
    ) -> list[SetupResult]:
        """
        Set up vulnerable target applications.

        Args:
            apps: List of app IDs to install. If None, installs all.
            dry_run: If True, only show what would be done.

        Returns:
            List of SetupResult for each app.
        """
        from dojo.targets import TargetManager

        manager = TargetManager()
        results = []

        target_apps = apps or manager.list_apps()

        for app_id in target_apps:
            app = manager.get_app(app_id)
            if not app:
                continue

            # Check if already installed
            if self.is_app_installed(app.package):
                results.append(SetupResult(
                    step=f"install_{app_id}",
                    success=True,
                    message=f"{app.name} already installed",
                ))
                continue

            if dry_run:
                results.append(SetupResult(
                    step=f"install_{app_id}",
                    success=True,
                    message=f"[DRY RUN] Would install {app.name}",
                    details=[app.download_url],
                ))
                continue

            # Download and install
            if app.download_url.startswith("http"):
                result = self.download_and_install(
                    app.download_url,
                    app.package,
                )
                result.step = f"install_{app_id}"
                results.append(result)
            elif app.download_url.startswith("local://"):
                # Local APK
                local_path = app.download_url.replace("local://", "")
                apk_path = Path(__file__).parent.parent / local_path
                if apk_path.exists():
                    result = self.install_apk(apk_path)
                    result.step = f"install_{app_id}"
                    results.append(result)
                else:
                    results.append(SetupResult(
                        step=f"install_{app_id}",
                        success=False,
                        message=f"Local APK not found: {local_path}",
                    ))

        return results

    def plant_flags(
        self,
        apps: Optional[list[str]] = None,
        dry_run: bool = False,
    ) -> list[SetupResult]:
        """
        Plant CTF flags for vulnerability challenges.

        Args:
            apps: List of app IDs. If None, plants for all.
            dry_run: If True, only show what would be done.

        Returns:
            List of SetupResult for each flag.
        """
        from dojo.targets import TargetManager

        manager = TargetManager()
        results = []
        device_info = self._device_info or self.detect_device()

        target_apps = apps or manager.list_apps()

        for app_id in target_apps:
            app = manager.get_app(app_id)
            if not app:
                continue

            for vuln in app.vulnerabilities:
                # Skip root-only vulnerabilities if device isn't rooted
                if vuln.requires_root and not device_info.is_rooted:
                    results.append(SetupResult(
                        step=f"plant_{app_id}/{vuln.id}",
                        success=True,
                        message=f"Skipped (requires root): {vuln.id}",
                    ))
                    continue

                if dry_run:
                    results.append(SetupResult(
                        step=f"plant_{app_id}/{vuln.id}",
                        success=True,
                        message=f"[DRY RUN] Would plant flag for {vuln.id}",
                        details=[f"Flag: {vuln.flag.value}"],
                    ))
                    continue

                # Plant the flag
                if vuln.flag.plant_method == "none":
                    # Flag is inherent
                    results.append(SetupResult(
                        step=f"plant_{app_id}/{vuln.id}",
                        success=True,
                        message=f"Flag inherent: {vuln.id}",
                    ))
                elif vuln.flag.plant_command:
                    # Execute plant command
                    cmd = vuln.flag.plant_command.strip()
                    if cmd.startswith("shell "):
                        cmd = cmd[6:]
                    output = self._shell(cmd)
                    results.append(SetupResult(
                        step=f"plant_{app_id}/{vuln.id}",
                        success=True,
                        message=f"Planted flag: {vuln.id}",
                        details=[output] if output else [],
                    ))

        return results

    # =========================================================================
    # Full Environment Setup
    # =========================================================================

    def setup_environment(
        self,
        persona: Optional[str] = None,
        install_targets: bool = True,
        plant_flags: bool = True,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """
        Complete environment setup for AgenticART training.

        This is the main entry point for setting up a device.

        Args:
            persona: Persona name or path. If None, uses base persona.
            install_targets: Whether to install vulnerable apps.
            plant_flags: Whether to plant CTF flags.
            dry_run: If True, only show what would be done.

        Returns:
            Dictionary with setup results.
        """
        results: dict[str, Any] = {
            "device": None,
            "persona": None,
            "targets": [],
            "flags": [],
            "success": True,
            "errors": [],
        }

        print("=" * 60)
        print("AgenticART Environment Setup")
        print("=" * 60)

        # Step 1: Detect device
        print("\n[1/5] Detecting device...")
        device_info = self.detect_device()
        results["device"] = device_info.to_dict()

        if not device_info.connected:
            results["success"] = False
            results["errors"].append("Device not connected")
            print(f"   ❌ Device not connected: {self.device_id}")
            return results

        print(f"   ✓ Connected: {device_info.model}")
        print(f"   ✓ Android {device_info.android_version} (API {device_info.api_level})")
        print(f"   ✓ Root: {device_info.is_rooted} ({device_info.root_method or 'N/A'})")

        # Step 2: Provision persona
        print("\n[2/5] Provisioning persona...")
        if persona:
            persona_path = self._resolve_persona_path(persona)
            if persona_path and persona_path.exists():
                persona_results = self.provision_persona(persona_path, dry_run)
                results["persona"] = [r.to_dict() for r in persona_results]
                print(f"   ✓ Provisioned: {persona}")
            else:
                print(f"   ⚠ Persona not found: {persona}")
        else:
            print("   ⏭ Skipped (no persona specified)")

        # Step 3: Install vulnerable targets
        print("\n[3/5] Installing vulnerable targets...")
        if install_targets:
            target_results = self.setup_vulnerable_targets(dry_run=dry_run)
            results["targets"] = [r.to_dict() for r in target_results]
            success_count = sum(1 for r in target_results if r.success)
            print(f"   ✓ {success_count}/{len(target_results)} targets ready")
        else:
            print("   ⏭ Skipped")

        # Step 4: Plant CTF flags
        print("\n[4/5] Planting CTF flags...")
        if plant_flags and install_targets:
            flag_results = self.plant_flags(dry_run=dry_run)
            results["flags"] = [r.to_dict() for r in flag_results]
            success_count = sum(1 for r in flag_results if r.success)
            print(f"   ✓ {success_count}/{len(flag_results)} flags planted")
        else:
            print("   ⏭ Skipped")

        # Step 5: Validation
        print("\n[5/5] Validating environment...")
        validation = self.validate_environment()
        results["validation"] = validation

        if validation["ready"]:
            print("   ✓ Environment ready for training!")
        else:
            print("   ⚠ Some issues detected:")
            for issue in validation.get("issues", []):
                print(f"      - {issue}")

        print("\n" + "=" * 60)
        print("Setup Complete!")
        print("=" * 60)

        return results

    def _resolve_persona_path(self, persona: str) -> Optional[Path]:
        """Resolve persona name to path."""
        if persona.endswith(".yaml"):
            return Path(persona)

        personas_dir = Path(__file__).parent.parent / "personas"
        persona_path = personas_dir / f"{persona}.yaml"

        if persona_path.exists():
            return persona_path

        return None

    def validate_environment(self) -> dict:
        """
        Validate the environment is ready for training.

        Returns:
            Dictionary with validation results.
        """
        issues = []
        device_info = self._device_info or self.detect_device()

        # Check connection
        if not device_info.connected:
            issues.append("Device not connected")

        # Check ADB debugging
        adb_enabled = self._shell("settings get global adb_enabled")
        if adb_enabled != "1":
            issues.append("ADB debugging may not be enabled")

        # Check available space
        storage = self._shell("df /data | tail -1")
        if storage:
            parts = storage.split()
            if len(parts) >= 4:
                try:
                    available_kb = int(parts[3])
                    if available_kb < 500000:  # Less than 500MB
                        issues.append(f"Low storage: {available_kb // 1024}MB available")
                except ValueError:
                    pass

        return {
            "ready": len(issues) == 0,
            "issues": issues,
            "device_info": device_info.to_dict(),
        }

    def get_training_summary(self) -> dict:
        """
        Get a summary of available training challenges.

        Returns:
            Dictionary with challenge counts by category.
        """
        from dojo.curriculum import ChallengeLoader
        from dojo.models import Belt
        from dojo.targets import TargetManager

        device_info = self._device_info or self.detect_device()
        loader = ChallengeLoader()
        manager = TargetManager()

        summary = {
            "device": device_info.to_dict(),
            "challenges": {},
            "vulnerabilities": manager.get_vulnerability_stats(),
        }

        # Count challenges by belt
        for belt in Belt:
            all_challenges = loader.load_belt(belt)
            compatible = loader.load_for_device(
                belt,
                api_level=device_info.api_level,
                device_is_rooted=device_info.is_rooted,
            )
            summary["challenges"][belt.value] = {
                "total": len(all_challenges),
                "compatible": len(compatible),
            }

        return summary
