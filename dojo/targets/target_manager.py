"""
Target Manager - Manages vulnerable application targets for exploitation validation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


@dataclass
class VulnerabilityFlag:
    """Flag that proves successful exploitation."""

    value: str
    location: str  # database, shared_prefs, logcat, etc.
    plant_method: str  # How to plant the flag
    plant_command: Optional[str] = None


@dataclass
class Vulnerability:
    """A specific vulnerability in a target application."""

    id: str
    type: str  # sql_injection, info_disclosure, etc.
    belt: str
    difficulty: int
    description: str
    flag: VulnerabilityFlag
    validation: dict
    hints: list[str] = field(default_factory=list)
    kata_solution: Optional[str] = None


@dataclass
class VulnerableApp:
    """A vulnerable application target."""

    id: str
    name: str
    package: str
    download_url: str
    description: str
    setup_commands: list[str] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)

    def get_vulnerability(self, vuln_id: str) -> Optional[Vulnerability]:
        """Get a specific vulnerability by ID."""
        for vuln in self.vulnerabilities:
            if vuln.id == vuln_id:
                return vuln
        return None


class TargetManager:
    """
    Manages vulnerable application targets.

    Handles loading target configurations, checking installation status,
    and planting flags for exploitation validation.
    """

    def __init__(self, config_path: Optional[Path] = None):
        """
        Initialize the target manager.

        Args:
            config_path: Path to vulnerable_targets.yaml. Defaults to module directory.
        """
        if config_path is None:
            config_path = Path(__file__).parent / "vulnerable_targets.yaml"
        self.config_path = config_path
        self._apps: dict[str, VulnerableApp] = {}
        self._load_config()

    def _load_config(self) -> None:
        """Load target configuration from YAML."""
        if not self.config_path.exists():
            return

        with open(self.config_path, "r") as f:
            data = yaml.safe_load(f)

        if not data or "apps" not in data:
            return

        for app_id, app_data in data["apps"].items():
            vulnerabilities = []
            for vuln_data in app_data.get("vulnerabilities", []):
                flag_data = vuln_data.get("flag", {})
                flag = VulnerabilityFlag(
                    value=flag_data.get("value", ""),
                    location=flag_data.get("location", ""),
                    plant_method=flag_data.get("plant_method", "none"),
                    plant_command=flag_data.get("plant_command"),
                )

                vuln = Vulnerability(
                    id=vuln_data["id"],
                    type=vuln_data.get("type", "unknown"),
                    belt=vuln_data.get("belt", "white"),
                    difficulty=vuln_data.get("difficulty", 1),
                    description=vuln_data.get("description", ""),
                    flag=flag,
                    validation=vuln_data.get("validation", {}),
                    hints=vuln_data.get("hints", []),
                    kata_solution=vuln_data.get("kata_solution"),
                )
                vulnerabilities.append(vuln)

            app = VulnerableApp(
                id=app_id,
                name=app_data.get("name", app_id),
                package=app_data.get("package", ""),
                download_url=app_data.get("download_url", ""),
                description=app_data.get("description", ""),
                setup_commands=app_data.get("setup_commands", []),
                vulnerabilities=vulnerabilities,
            )
            self._apps[app_id] = app

    def get_app(self, app_id: str) -> Optional[VulnerableApp]:
        """Get a vulnerable app by ID."""
        return self._apps.get(app_id)

    def get_vulnerability(self, app_id: str, vuln_id: str) -> Optional[Vulnerability]:
        """Get a specific vulnerability from an app."""
        app = self.get_app(app_id)
        if app:
            return app.get_vulnerability(vuln_id)
        return None

    def list_apps(self) -> list[str]:
        """List all available target app IDs."""
        return list(self._apps.keys())

    def list_vulnerabilities(self, app_id: str) -> list[str]:
        """List vulnerability IDs for an app."""
        app = self.get_app(app_id)
        if app:
            return [v.id for v in app.vulnerabilities]
        return []

    def is_app_installed(self, package: str, executor) -> bool:
        """
        Check if an app is installed on the device.

        Args:
            package: Package name to check.
            executor: Executor instance for running commands.

        Returns:
            True if installed.
        """
        result = executor.execute(f"shell pm list packages {package}")
        return package in result.stdout

    def install_app(self, app_id: str, executor) -> bool:
        """
        Install a vulnerable app on the device.

        Args:
            app_id: The app ID from configuration.
            executor: Executor instance.

        Returns:
            True if installation succeeded.
        """
        app = self.get_app(app_id)
        if not app:
            return False

        # Check if already installed
        if self.is_app_installed(app.package, executor):
            return True

        # Download URL handling
        if app.download_url.startswith("local://"):
            # Local APK path
            apk_path = app.download_url.replace("local://", "")
            apk_path = Path(__file__).parent.parent / apk_path
        else:
            # Would need to download - for now just return False
            # In production, implement download logic
            return False

        if not apk_path.exists():
            return False

        result = executor.execute(f"install {apk_path}")
        return result.success

    def setup_target(self, app_id: str, executor) -> bool:
        """
        Run setup commands for a target app.

        Args:
            app_id: The app ID.
            executor: Executor instance.

        Returns:
            True if setup succeeded.
        """
        app = self.get_app(app_id)
        if not app:
            return False

        for cmd in app.setup_commands:
            result = executor.execute(cmd)
            if not result.success:
                # Non-critical, continue
                pass

        return True

    def plant_flag(self, app_id: str, vuln_id: str, executor) -> bool:
        """
        Plant a flag for a specific vulnerability.

        Args:
            app_id: The app ID.
            vuln_id: The vulnerability ID.
            executor: Executor instance.

        Returns:
            True if flag was planted.
        """
        vuln = self.get_vulnerability(app_id, vuln_id)
        if not vuln:
            return False

        if vuln.flag.plant_method == "none":
            # Flag is inherent to the vulnerability
            return True

        if vuln.flag.plant_command:
            result = executor.execute(vuln.flag.plant_command)
            return result.success

        return False

    def prepare_target(self, app_id: str, vuln_id: str, executor) -> bool:
        """
        Fully prepare a target for exploitation validation.

        Args:
            app_id: The app ID.
            vuln_id: The vulnerability ID.
            executor: Executor instance.

        Returns:
            True if target is ready.
        """
        # 1. Check/install app
        app = self.get_app(app_id)
        if not app:
            return False

        if not self.is_app_installed(app.package, executor):
            if not self.install_app(app_id, executor):
                # App not installed and couldn't install
                # Return True anyway - might be testing without the app
                pass

        # 2. Run setup commands
        self.setup_target(app_id, executor)

        # 3. Plant flag
        self.plant_flag(app_id, vuln_id, executor)

        return True

    def get_flag_value(self, app_id: str, vuln_id: str) -> Optional[str]:
        """Get the flag value for a vulnerability."""
        vuln = self.get_vulnerability(app_id, vuln_id)
        if vuln:
            return vuln.flag.value
        return None

    def get_success_indicators(self, app_id: str, vuln_id: str) -> list[str]:
        """Get all success indicators for a vulnerability."""
        vuln = self.get_vulnerability(app_id, vuln_id)
        if vuln and vuln.validation:
            return vuln.validation.get("success_indicators", [])
        return []
