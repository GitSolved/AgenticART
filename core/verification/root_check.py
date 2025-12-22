"""
Root Verification

Comprehensive verification that root access has been achieved.
Final phase of the exploitation chain.
"""

import logging
from dataclasses import dataclass
from typing import Optional

from ..reconnaissance import ADBConnection

logger = logging.getLogger(__name__)


@dataclass
class RootVerificationResult:
    """Results of root verification."""
    root_achieved: bool
    uid: int
    root_method: str
    su_binary_path: Optional[str]
    selinux_status: str
    can_write_system: bool
    can_access_data: bool
    persistence: bool
    details: dict


class RootVerifier:
    """
    Verifies successful root access on Android device.

    Checks:
    - UID is 0 (root)
    - su binary is accessible
    - Can write to protected locations
    - Root persists across operations
    """

    def __init__(self, adb: ADBConnection):
        self.adb = adb

    def verify(self) -> RootVerificationResult:
        """
        Perform comprehensive root verification.

        Returns:
            RootVerificationResult with all checks
        """
        logger.info("Starting root verification...")

        uid = self._get_uid()
        su_path = self._find_su_binary()
        root_method = self._detect_root_method()

        return RootVerificationResult(
            root_achieved=uid == 0,
            uid=uid,
            root_method=root_method,
            su_binary_path=su_path,
            selinux_status=self._get_selinux(),
            can_write_system=self._test_system_write(),
            can_access_data=self._test_data_access(),
            persistence=self._test_persistence(),
            details=self._get_detailed_info(),
        )

    def _get_uid(self) -> int:
        """Get current UID when running as root."""
        output = self.adb.shell("su -c 'id -u'")
        try:
            return int(output.strip())
        except ValueError:
            # Try without su
            output = self.adb.shell("id -u")
            try:
                return int(output.strip())
            except ValueError:
                return -1

    def _find_su_binary(self) -> Optional[str]:
        """Find location of su binary."""
        locations = [
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/su/bin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/data/adb/magisk/su",
        ]

        for loc in locations:
            result = self.adb.shell(f"ls {loc} 2>/dev/null")
            if result and "No such file" not in result:
                return loc

        # Try which
        result = self.adb.shell("which su")
        if result and "not found" not in result.lower():
            return result.strip()

        return None

    def _detect_root_method(self) -> str:
        """Detect which rooting method was used."""
        # Check for Magisk
        magisk = self.adb.shell("ls /data/adb/magisk 2>/dev/null")
        if magisk and "No such file" not in magisk:
            version = self.adb.shell("su -c 'magisk -v' 2>/dev/null")
            return f"Magisk ({version.strip()})"

        # Check for SuperSU
        supersu = self.adb.shell("ls /data/app/*supersu* 2>/dev/null")
        if supersu and "No such file" not in supersu:
            return "SuperSU"

        # Check for KernelSU
        kernelsu = self.adb.shell("ls /data/adb/ksu 2>/dev/null")
        if kernelsu and "No such file" not in kernelsu:
            return "KernelSU"

        # ADB root
        adb_root = self.adb.shell("getprop service.adb.root")
        if adb_root == "1":
            return "ADB Root (userdebug/eng)"

        return "Unknown"

    def _get_selinux(self) -> str:
        """Get SELinux enforcement status."""
        return self.adb.shell("su -c 'getenforce' 2>/dev/null || getenforce")

    def _test_system_write(self) -> bool:
        """Test if we can write to /system."""
        # Try to remount system as rw
        self.adb.shell("su -c 'mount -o rw,remount /system'")
        result = self.adb.shell("su -c 'touch /system/.root_test && rm /system/.root_test'")
        return "Read-only" not in result and "Permission denied" not in result

    def _test_data_access(self) -> bool:
        """Test if we can access /data."""
        result = self.adb.shell("su -c 'ls /data/data'")
        return "Permission denied" not in result

    def _test_persistence(self) -> bool:
        """Test if root persists (basic check)."""
        # Run su twice with a delay
        first = self.adb.shell("su -c 'id -u'")
        self.adb.shell("sleep 1")
        second = self.adb.shell("su -c 'id -u'")

        try:
            return int(first.strip()) == 0 and int(second.strip()) == 0
        except ValueError:
            return False

    def _get_detailed_info(self) -> dict:
        """Get additional detailed root information."""
        return {
            "kernel": self.adb.shell("uname -r"),
            "su_version": self.adb.shell("su -v 2>/dev/null"),
            "mount_info": self.adb.shell("mount | grep system | head -1"),
            "init_status": self.adb.shell("su -c 'ls /init*' 2>/dev/null"),
        }

    def quick_check(self) -> bool:
        """Quick check if root is available."""
        output = self.adb.shell("su -c 'echo ROOT_OK' 2>/dev/null")
        return "ROOT_OK" in output

    def generate_report(self, result: RootVerificationResult) -> str:
        """Generate human-readable verification report."""
        status = "" if result.root_achieved else ""

        report = f"""
╔══════════════════════════════════════════════════════════════╗
║                    ROOT VERIFICATION REPORT                   ║
╠══════════════════════════════════════════════════════════════╣
║ Status: {status} {'ROOT ACCESS CONFIRMED' if result.root_achieved else 'ROOT ACCESS FAILED'}
║ UID: {result.uid}
║ Method: {result.root_method}
║ SU Binary: {result.su_binary_path or 'Not found'}
╠══════════════════════════════════════════════════════════════╣
║ CAPABILITIES:
║   SELinux: {result.selinux_status}
║   Write /system: {'Yes' if result.can_write_system else 'No'}
║   Access /data: {'Yes' if result.can_access_data else 'No'}
║   Persistent: {'Yes' if result.persistence else 'No'}
╠══════════════════════════════════════════════════════════════╣
║ DETAILS:
║   Kernel: {result.details.get('kernel', 'Unknown')}
║   SU Version: {result.details.get('su_version', 'Unknown')}
╚══════════════════════════════════════════════════════════════╝
"""
        return report
