"""
Dojo Device Manager

Handles the physical/virtual device lifecycle for AgenticART challenges.
Provides clean environments for empirical verification.
"""

import logging
from pathlib import Path
from typing import Optional

from core.reconnaissance.device_enum import ADBConnection

logger = logging.getLogger(__name__)

class DeviceManager:
    """Manages the lifecycle of the target Android device."""

    def __init__(self, adb: ADBConnection):
        self.adb = adb

    def ensure_ready(self) -> bool:
        """Checks if device is connected and responsive."""
        if not self.adb.is_connected():
            logger.error("Device not connected. Please start Genymotion.")
            return False
        return True

    def reset_environment(self):
        """Prepares a clean slate for a new challenge."""
        logger.info("Resetting device environment...")
        # Clear logs
        self.adb.execute("logcat -c")
        # Clear temporary files
        self.adb.shell("rm -rf /data/local/tmp/*")
        # Ensure SELinux is in expected state (Enforcing for most tests)
        self.adb.shell("setenforce 1")

    def deploy_target(self, apk_path: Path) -> bool:
        """Installs the target APK on the device."""
        if not apk_path.exists():
            logger.error(f"Target APK not found: {apk_path}")
            return False

        logger.info(f"Deploying {apk_path.name} to device...")
        stdout, stderr, code = self.adb.execute(f"install -r {apk_path}")
        if code != 0:
            logger.error(f"Installation failed: {stderr}")
            return False
        return True

    def remove_target(self, package_name: str):
        """Cleans up the target app after challenge completion."""
        logger.info(f"Removing {package_name} from device...")
        self.adb.execute(f"uninstall {package_name}")

    def capture_ground_truth(self, log_tag: str) -> str:
        """Captures specific log signals for verification."""
        return self.adb.shell(f"logcat -d | grep {log_tag}")

    def get_process_id(self, package_name: str) -> Optional[str]:
        """Returns the current PID of the target package."""
        output = self.adb.shell(f"ps -A | grep {package_name} | awk '{{print $2}}'")
        return output.strip() if output else None
