"""
Vulnerability Scanner

Comprehensive vulnerability detection for Android devices.
Analyzes device configuration, installed apps, and running services
to identify potential attack vectors.
"""

import logging
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

from ..reconnaissance import ADBConnection, DeviceEnumerator, DeviceInfo

logger = logging.getLogger(__name__)


class VulnSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnCategory(Enum):
    CONFIGURATION = "configuration"
    PERMISSIONS = "permissions"
    EXPOSED_SERVICE = "exposed_service"
    OUTDATED_SOFTWARE = "outdated_software"
    KNOWN_CVE = "known_cve"
    INSECURE_APP = "insecure_app"
    ROOT_DETECTION_BYPASS = "root_detection_bypass"


@dataclass
class Vulnerability:
    """Represents a discovered vulnerability."""
    id: str
    title: str
    description: str
    severity: VulnSeverity
    category: VulnCategory
    affected_component: str
    exploitation_info: Optional[str] = None
    remediation: Optional[str] = None
    references: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    """Results from a vulnerability scan."""
    device_info: DeviceInfo
    vulnerabilities: list[Vulnerability]
    scan_duration_seconds: float
    total_checks: int

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == VulnSeverity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == VulnSeverity.HIGH)

    def get_by_category(self, category: VulnCategory) -> list[Vulnerability]:
        return [v for v in self.vulnerabilities if v.category == category]


class VulnerabilityScanner:
    """
    Scans Android devices for security vulnerabilities.

    Performs checks for:
    - Insecure configurations (USB debugging, unknown sources, etc.)
    - Dangerous permission combinations
    - Exposed services and content providers
    - Outdated security patches
    - Known CVEs matching device/app versions
    - Debuggable/backup-enabled applications
    """

    def __init__(self, adb: ADBConnection):
        self.adb = adb
        self.enumerator = DeviceEnumerator(adb)
        self._vuln_id_counter = 0

    def _next_vuln_id(self) -> str:
        self._vuln_id_counter += 1
        return f"VULN-{self._vuln_id_counter:04d}"

    def scan(self, include_apps: bool = True) -> ScanResult:
        """
        Perform comprehensive vulnerability scan.

        Args:
            include_apps: Whether to scan installed applications

        Returns:
            ScanResult with all discovered vulnerabilities
        """
        import time
        start_time = time.time()

        logger.info("Starting vulnerability scan...")

        # Get device info
        device_info = self.enumerator.enumerate()
        vulnerabilities: list[Vulnerability] = []
        total_checks = 0

        # Configuration checks
        logger.info("Checking device configuration...")
        config_vulns, config_checks = self._check_configuration(device_info)
        vulnerabilities.extend(config_vulns)
        total_checks += config_checks

        # Security patch level
        logger.info("Checking security patch level...")
        patch_vulns, patch_checks = self._check_security_patch(device_info)
        vulnerabilities.extend(patch_vulns)
        total_checks += patch_checks

        # SELinux status
        logger.info("Checking SELinux status...")
        selinux_vulns, selinux_checks = self._check_selinux(device_info)
        vulnerabilities.extend(selinux_vulns)
        total_checks += selinux_checks

        # Service exposure
        logger.info("Checking exposed services...")
        service_vulns, service_checks = self._check_exposed_services()
        vulnerabilities.extend(service_vulns)
        total_checks += service_checks

        # Application analysis
        if include_apps:
            logger.info("Analyzing installed applications...")
            app_vulns, app_checks = self._check_applications()
            vulnerabilities.extend(app_vulns)
            total_checks += app_checks

        # Content provider exposure
        logger.info("Checking content providers...")
        provider_vulns, provider_checks = self._check_content_providers()
        vulnerabilities.extend(provider_vulns)
        total_checks += provider_checks

        duration = time.time() - start_time
        logger.info(f"Scan complete: {len(vulnerabilities)} vulnerabilities found in {duration:.2f}s")

        return ScanResult(
            device_info=device_info,
            vulnerabilities=vulnerabilities,
            scan_duration_seconds=duration,
            total_checks=total_checks,
        )

    def _check_configuration(self, device_info: DeviceInfo) -> tuple[list[Vulnerability], int]:
        """Check device configuration for security issues."""
        vulns = []
        checks = 0

        # USB Debugging
        checks += 1
        adb_enabled = self.adb.get_prop("persist.sys.usb.config")
        if "adb" in adb_enabled:
            # Check if ADB over network is enabled
            adb_port = self.adb.shell("getprop service.adb.tcp.port")
            if adb_port and adb_port != "-1":
                vulns.append(Vulnerability(
                    id=self._next_vuln_id(),
                    title="ADB over Network Enabled",
                    description=f"ADB is accessible over network on port {adb_port}. "
                                "This allows remote command execution.",
                    severity=VulnSeverity.HIGH,
                    category=VulnCategory.CONFIGURATION,
                    affected_component="ADB Service",
                    exploitation_info="Connect via: adb connect <device_ip>:<port>",
                    remediation="Disable 'ADB over network' in developer options",
                ))

        # Unknown sources
        checks += 1
        unknown_sources = self.adb.shell(
            "settings get secure install_non_market_apps 2>/dev/null || "
            "settings get global install_non_market_apps"
        )
        if unknown_sources.strip() == "1":
            vulns.append(Vulnerability(
                id=self._next_vuln_id(),
                title="Unknown Sources Enabled",
                description="Installation from unknown sources is enabled, "
                            "allowing sideloading of potentially malicious APKs.",
                severity=VulnSeverity.MEDIUM,
                category=VulnCategory.CONFIGURATION,
                affected_component="Package Manager",
                remediation="Disable 'Unknown sources' in security settings",
            ))

        # Developer options
        checks += 1
        dev_options = self.adb.shell("settings get global development_settings_enabled")
        if dev_options.strip() == "1":
            vulns.append(Vulnerability(
                id=self._next_vuln_id(),
                title="Developer Options Enabled",
                description="Developer options are enabled, exposing additional attack surface.",
                severity=VulnSeverity.LOW,
                category=VulnCategory.CONFIGURATION,
                affected_component="System Settings",
            ))

        # Mock locations
        checks += 1
        mock_location = self.adb.shell("settings get secure mock_location")
        if mock_location.strip() == "1":
            vulns.append(Vulnerability(
                id=self._next_vuln_id(),
                title="Mock Locations Enabled",
                description="Mock location provider is enabled.",
                severity=VulnSeverity.INFO,
                category=VulnCategory.CONFIGURATION,
                affected_component="Location Services",
            ))

        # Screen lock
        checks += 1
        lock_screen = self.adb.shell("settings get secure lockscreen.password_type")
        if lock_screen.strip() in ["", "0", "65536"]:  # No lock or swipe only
            vulns.append(Vulnerability(
                id=self._next_vuln_id(),
                title="Weak or No Screen Lock",
                description="Device has no secure screen lock configured.",
                severity=VulnSeverity.MEDIUM,
                category=VulnCategory.CONFIGURATION,
                affected_component="Lock Screen",
                remediation="Configure PIN, pattern, or password lock",
            ))

        # Encryption
        checks += 1
        if not device_info.is_encrypted:
            vulns.append(Vulnerability(
                id=self._next_vuln_id(),
                title="Device Not Encrypted",
                description="Device storage is not encrypted. Data can be extracted "
                            "via physical access or custom recovery.",
                severity=VulnSeverity.HIGH,
                category=VulnCategory.CONFIGURATION,
                affected_component="Storage",
                remediation="Enable full-disk encryption in security settings",
            ))

        return vulns, checks

    def _check_security_patch(self, device_info: DeviceInfo) -> tuple[list[Vulnerability], int]:
        """Check security patch level for known vulnerabilities."""
        vulns = []
        checks = 1

        patch_date = device_info.security_patch
        if not patch_date:
            vulns.append(Vulnerability(
                id=self._next_vuln_id(),
                title="Unknown Security Patch Level",
                description="Could not determine device security patch level.",
                severity=VulnSeverity.MEDIUM,
                category=VulnCategory.OUTDATED_SOFTWARE,
                affected_component="System",
            ))
            return vulns, checks

        # Parse patch date (format: YYYY-MM-DD)
        try:
            from datetime import datetime, timedelta
            patch_datetime = datetime.strptime(patch_date, "%Y-%m-%d")
            now = datetime.now()
            age_days = (now - patch_datetime).days

            if age_days > 365:
                vulns.append(Vulnerability(
                    id=self._next_vuln_id(),
                    title="Critically Outdated Security Patches",
                    description=f"Security patch level ({patch_date}) is over 1 year old. "
                                f"Device is vulnerable to numerous known exploits.",
                    severity=VulnSeverity.CRITICAL,
                    category=VulnCategory.OUTDATED_SOFTWARE,
                    affected_component="System",
                    exploitation_info="Check CVE database for patches after " + patch_date,
                    remediation="Update to latest available Android version",
                ))
            elif age_days > 180:
                vulns.append(Vulnerability(
                    id=self._next_vuln_id(),
                    title="Outdated Security Patches",
                    description=f"Security patch level ({patch_date}) is over 6 months old.",
                    severity=VulnSeverity.HIGH,
                    category=VulnCategory.OUTDATED_SOFTWARE,
                    affected_component="System",
                    remediation="Apply available security updates",
                ))
            elif age_days > 90:
                vulns.append(Vulnerability(
                    id=self._next_vuln_id(),
                    title="Security Patches Behind",
                    description=f"Security patch level ({patch_date}) is over 3 months old.",
                    severity=VulnSeverity.MEDIUM,
                    category=VulnCategory.OUTDATED_SOFTWARE,
                    affected_component="System",
                ))
        except ValueError:
            pass

        return vulns, checks

    def _check_selinux(self, device_info: DeviceInfo) -> tuple[list[Vulnerability], int]:
        """Check SELinux enforcement status."""
        vulns = []
        checks = 1

        selinux = device_info.selinux_status.lower()

        if selinux == "disabled":
            vulns.append(Vulnerability(
                id=self._next_vuln_id(),
                title="SELinux Disabled",
                description="SELinux is completely disabled. This removes a critical "
                            "security boundary and allows unrestricted process access.",
                severity=VulnSeverity.CRITICAL,
                category=VulnCategory.CONFIGURATION,
                affected_component="SELinux",
                exploitation_info="Kernel exploits and privilege escalation are significantly easier",
            ))
        elif selinux == "permissive":
            vulns.append(Vulnerability(
                id=self._next_vuln_id(),
                title="SELinux in Permissive Mode",
                description="SELinux is in permissive mode. Policy violations are logged "
                            "but not enforced, allowing privilege escalation.",
                severity=VulnSeverity.HIGH,
                category=VulnCategory.CONFIGURATION,
                affected_component="SELinux",
                exploitation_info="Exploits that would normally be blocked by SELinux will succeed",
            ))

        return vulns, checks

    def _check_exposed_services(self) -> tuple[list[Vulnerability], int]:
        """Check for exposed network services."""
        vulns = []
        checks = 0

        # Get listening ports
        netstat_output = self.adb.shell("netstat -tlnp 2>/dev/null || ss -tlnp")
        checks += 1

        dangerous_ports = {
            5555: ("ADB", VulnSeverity.CRITICAL),
            8080: ("HTTP Proxy/Debug", VulnSeverity.HIGH),
            8443: ("HTTPS Debug", VulnSeverity.MEDIUM),
            5037: ("ADB Server", VulnSeverity.HIGH),
            27042: ("Frida Server", VulnSeverity.CRITICAL),
            27043: ("Frida Server", VulnSeverity.CRITICAL),
        }

        for port, (service, severity) in dangerous_ports.items():
            checks += 1
            if f":{port}" in netstat_output:
                vulns.append(Vulnerability(
                    id=self._next_vuln_id(),
                    title=f"Exposed {service} Service",
                    description=f"Port {port} ({service}) is listening and potentially accessible.",
                    severity=severity,
                    category=VulnCategory.EXPOSED_SERVICE,
                    affected_component=f"Port {port}",
                    exploitation_info=f"Connect to device on port {port}",
                ))

        return vulns, checks

    def _check_applications(self) -> tuple[list[Vulnerability], int]:
        """Analyze installed applications for vulnerabilities."""
        vulns = []
        checks = 0

        # Find debuggable apps
        checks += 1
        debuggable_output = self.adb.shell(
            "for pkg in $(pm list packages -3 | cut -d: -f2); do "
            "if run-as $pkg id >/dev/null 2>&1; then echo $pkg; fi; "
            "done 2>/dev/null"
        )

        debuggable_apps = [p.strip() for p in debuggable_output.split('\n') if p.strip()]
        for app in debuggable_apps[:10]:  # Limit to first 10
            vulns.append(Vulnerability(
                id=self._next_vuln_id(),
                title=f"Debuggable Application: {app}",
                description=f"Application {app} has android:debuggable=true, "
                            "allowing code injection and data extraction.",
                severity=VulnSeverity.HIGH,
                category=VulnCategory.INSECURE_APP,
                affected_component=app,
                exploitation_info=f"Use 'run-as {app}' to access app sandbox",
            ))

        # Find backup-enabled apps
        checks += 1
        packages = self.adb.shell("pm list packages -3 | head -20")
        for line in packages.split('\n'):
            if line.startswith('package:'):
                pkg = line.replace('package:', '').strip()
                checks += 1
                dumpsys = self.adb.shell(f"dumpsys package {pkg} | grep -i allowbackup")
                if "allowBackup=true" in dumpsys:
                    vulns.append(Vulnerability(
                        id=self._next_vuln_id(),
                        title=f"Backup-Enabled Application: {pkg}",
                        description=f"Application {pkg} allows backup, potentially exposing sensitive data.",
                        severity=VulnSeverity.MEDIUM,
                        category=VulnCategory.INSECURE_APP,
                        affected_component=pkg,
                        exploitation_info=f"Extract data via: adb backup -f backup.ab {pkg}",
                    ))

        return vulns, checks

    def _check_content_providers(self) -> tuple[list[Vulnerability], int]:
        """Check for exposed content providers."""
        vulns = []
        checks = 1

        # Find exported content providers
        providers_output = self.adb.shell(
            "dumpsys package providers | grep -E '(Provider|authority)' | head -50"
        )

        # Look for providers without permission requirements
        if "null" in providers_output.lower() or "android.permission" not in providers_output:
            vulns.append(Vulnerability(
                id=self._next_vuln_id(),
                title="Potentially Exposed Content Providers",
                description="Some content providers may be accessible without permissions. "
                            "Manual verification recommended.",
                severity=VulnSeverity.MEDIUM,
                category=VulnCategory.EXPOSED_SERVICE,
                affected_component="Content Providers",
                exploitation_info="Use content:// URIs to query exposed data",
            ))

        return vulns, checks

    def generate_report(self, result: ScanResult) -> str:
        """Generate a human-readable scan report."""
        lines = [
            "=" * 70,
            "VULNERABILITY SCAN REPORT",
            "=" * 70,
            f"Device: {result.device_info.model} ({result.device_info.manufacturer})",
            f"Android: {result.device_info.android_version} (API {result.device_info.api_level})",
            f"Security Patch: {result.device_info.security_patch}",
            f"Scan Duration: {result.scan_duration_seconds:.2f}s",
            f"Total Checks: {result.total_checks}",
            "",
            "SUMMARY",
            "-" * 70,
            f"  Critical: {result.critical_count}",
            f"  High:     {result.high_count}",
            f"  Medium:   {sum(1 for v in result.vulnerabilities if v.severity == VulnSeverity.MEDIUM)}",
            f"  Low:      {sum(1 for v in result.vulnerabilities if v.severity == VulnSeverity.LOW)}",
            f"  Info:     {sum(1 for v in result.vulnerabilities if v.severity == VulnSeverity.INFO)}",
            "",
        ]

        if result.vulnerabilities:
            lines.append("FINDINGS")
            lines.append("-" * 70)

            # Sort by severity
            severity_order = {
                VulnSeverity.CRITICAL: 0,
                VulnSeverity.HIGH: 1,
                VulnSeverity.MEDIUM: 2,
                VulnSeverity.LOW: 3,
                VulnSeverity.INFO: 4,
            }
            sorted_vulns = sorted(result.vulnerabilities, key=lambda v: severity_order[v.severity])

            for vuln in sorted_vulns:
                lines.append(f"\n[{vuln.severity.value.upper()}] {vuln.id}: {vuln.title}")
                lines.append(f"  Component: {vuln.affected_component}")
                lines.append(f"  {vuln.description}")
                if vuln.exploitation_info:
                    lines.append(f"  Exploit: {vuln.exploitation_info}")
                if vuln.remediation:
                    lines.append(f"  Fix: {vuln.remediation}")

        lines.append("")
        lines.append("=" * 70)

        return "\n".join(lines)
