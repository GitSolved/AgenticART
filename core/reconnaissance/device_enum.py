"""
Android Device Enumeration

Gathers comprehensive information about target Android devices.
Used in the reconnaissance phase of the pentest chain.
"""

import subprocess
import re
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class DeviceInfo:
    """Comprehensive Android device information."""
    # Basic Info
    model: str
    manufacturer: str
    device_name: str

    # Android Version
    android_version: str
    api_level: int
    build_id: str
    security_patch: str

    # Hardware
    architecture: str
    kernel_version: str
    cpu_info: str

    # Security Status
    selinux_status: str
    is_rooted: bool
    is_debuggable: bool
    is_encrypted: bool
    verified_boot: str

    # Network
    ip_address: Optional[str] = None
    wifi_status: Optional[str] = None


class ADBConnection:
    """Manages ADB connection to target device."""

    def __init__(self, device_id: Optional[str] = None, adb_path: str = "adb"):
        self.device_id = device_id
        self.adb_path = adb_path

    def execute(self, command: str, timeout: int = 30) -> tuple[str, str, int]:
        """
        Execute ADB command.

        Returns:
            Tuple of (stdout, stderr, return_code)
        """
        cmd = [self.adb_path]
        if self.device_id:
            cmd.extend(["-s", self.device_id])
        cmd.extend(command.split())

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "Command timed out", -1
        except Exception as e:
            return "", str(e), -1

    def shell(self, command: str, timeout: int = 30) -> str:
        """Execute shell command on device."""
        stdout, stderr, code = self.execute(f"shell {command}", timeout)
        if code != 0:
            logger.warning(f"Shell command failed: {stderr}")
        return stdout.strip()

    def get_prop(self, prop: str) -> str:
        """Get Android system property."""
        return self.shell(f"getprop {prop}")

    def is_connected(self) -> bool:
        """Check if device is connected."""
        stdout, _, code = self.execute("devices")
        if self.device_id:
            return self.device_id in stdout
        return "device" in stdout and "offline" not in stdout


class DeviceEnumerator:
    """
    Enumerates Android device information via ADB.

    Usage:
        adb = ADBConnection(device_id="192.168.56.101:5555")
        enum = DeviceEnumerator(adb)
        info = enum.enumerate()
        print(f"Target: {info.model} running Android {info.android_version}")
    """

    def __init__(self, adb: ADBConnection):
        self.adb = adb

    def enumerate(self) -> DeviceInfo:
        """Perform full device enumeration."""
        logger.info("Starting device enumeration...")

        return DeviceInfo(
            # Basic Info
            model=self._get_model(),
            manufacturer=self._get_manufacturer(),
            device_name=self._get_device_name(),

            # Android Version
            android_version=self._get_android_version(),
            api_level=self._get_api_level(),
            build_id=self._get_build_id(),
            security_patch=self._get_security_patch(),

            # Hardware
            architecture=self._get_architecture(),
            kernel_version=self._get_kernel_version(),
            cpu_info=self._get_cpu_info(),

            # Security Status
            selinux_status=self._get_selinux_status(),
            is_rooted=self._check_root(),
            is_debuggable=self._check_debuggable(),
            is_encrypted=self._check_encryption(),
            verified_boot=self._get_verified_boot(),

            # Network
            ip_address=self._get_ip_address(),
            wifi_status=self._get_wifi_status(),
        )

    def _get_model(self) -> str:
        return self.adb.get_prop("ro.product.model")

    def _get_manufacturer(self) -> str:
        return self.adb.get_prop("ro.product.manufacturer")

    def _get_device_name(self) -> str:
        return self.adb.get_prop("ro.product.device")

    def _get_android_version(self) -> str:
        return self.adb.get_prop("ro.build.version.release")

    def _get_api_level(self) -> int:
        try:
            return int(self.adb.get_prop("ro.build.version.sdk"))
        except ValueError:
            return 0

    def _get_build_id(self) -> str:
        return self.adb.get_prop("ro.build.id")

    def _get_security_patch(self) -> str:
        return self.adb.get_prop("ro.build.version.security_patch")

    def _get_architecture(self) -> str:
        return self.adb.get_prop("ro.product.cpu.abi")

    def _get_kernel_version(self) -> str:
        return self.adb.shell("uname -r")

    def _get_cpu_info(self) -> str:
        output = self.adb.shell("cat /proc/cpuinfo | head -20")
        return output[:500]  # Truncate

    def _get_selinux_status(self) -> str:
        return self.adb.shell("getenforce")

    def _check_root(self) -> bool:
        """Check for root access indicators."""
        checks = [
            ("which su", "su"),
            ("ls /system/app/Superuser.apk", "Superuser.apk"),
            ("ls /system/xbin/su", "su"),
            ("ls /data/adb/magisk", "magisk"),
        ]
        for cmd, indicator in checks:
            output = self.adb.shell(cmd)
            if indicator in output and "not found" not in output.lower():
                return True
        return False

    def _check_debuggable(self) -> bool:
        debuggable = self.adb.get_prop("ro.debuggable")
        return debuggable == "1"

    def _check_encryption(self) -> bool:
        state = self.adb.get_prop("ro.crypto.state")
        return state == "encrypted"

    def _get_verified_boot(self) -> str:
        return self.adb.get_prop("ro.boot.verifiedbootstate")

    def _get_ip_address(self) -> Optional[str]:
        output = self.adb.shell("ip addr show wlan0")
        match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", output)
        return match.group(1) if match else None

    def _get_wifi_status(self) -> Optional[str]:
        return self.adb.shell("dumpsys wifi | grep 'Wi-Fi is'")

    def get_installed_packages(self, include_system: bool = False) -> list[str]:
        """Get list of installed packages."""
        flag = "" if include_system else "-3"  # -3 for third-party only
        output = self.adb.shell(f"pm list packages {flag}")
        packages = []
        for line in output.split("\n"):
            if line.startswith("package:"):
                packages.append(line.replace("package:", "").strip())
        return packages

    def get_dangerous_permissions(self) -> dict[str, list[str]]:
        """Find apps with dangerous permissions."""
        dangerous = [
            "READ_CONTACTS", "WRITE_CONTACTS", "READ_CALL_LOG",
            "READ_SMS", "SEND_SMS", "CAMERA", "RECORD_AUDIO",
            "ACCESS_FINE_LOCATION", "READ_EXTERNAL_STORAGE",
        ]

        results = {}
        packages = self.get_installed_packages()

        for pkg in packages[:20]:  # Limit for performance
            output = self.adb.shell(f"dumpsys package {pkg} | grep permission")
            for perm in dangerous:
                if perm in output:
                    if pkg not in results:
                        results[pkg] = []
                    results[pkg].append(perm)

        return results
