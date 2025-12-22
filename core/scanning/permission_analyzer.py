"""
Permission Analyzer

Analyzes Android application permissions to identify security risks
and potential attack vectors.
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from ..reconnaissance import ADBConnection

logger = logging.getLogger(__name__)


class PermissionRisk(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NORMAL = "normal"


@dataclass
class PermissionInfo:
    """Information about an Android permission."""
    name: str
    protection_level: str
    risk: PermissionRisk
    description: str
    attack_vector: Optional[str] = None


@dataclass
class AppPermissionProfile:
    """Permission profile for an application."""
    package_name: str
    permissions: list[PermissionInfo]
    total_dangerous: int
    risk_score: float  # 0-100
    risk_factors: list[str] = field(default_factory=list)


# Permission risk database
DANGEROUS_PERMISSIONS = {
    # Location
    "android.permission.ACCESS_FINE_LOCATION": PermissionInfo(
        name="ACCESS_FINE_LOCATION",
        protection_level="dangerous",
        risk=PermissionRisk.HIGH,
        description="Access precise GPS location",
        attack_vector="Track user location in real-time",
    ),
    "android.permission.ACCESS_COARSE_LOCATION": PermissionInfo(
        name="ACCESS_COARSE_LOCATION",
        protection_level="dangerous",
        risk=PermissionRisk.MEDIUM,
        description="Access approximate location",
        attack_vector="Determine user's general location",
    ),
    "android.permission.ACCESS_BACKGROUND_LOCATION": PermissionInfo(
        name="ACCESS_BACKGROUND_LOCATION",
        protection_level="dangerous",
        risk=PermissionRisk.CRITICAL,
        description="Access location in background",
        attack_vector="Continuous location tracking without user awareness",
    ),

    # Camera & Microphone
    "android.permission.CAMERA": PermissionInfo(
        name="CAMERA",
        protection_level="dangerous",
        risk=PermissionRisk.HIGH,
        description="Access device camera",
        attack_vector="Capture photos/video without user knowledge",
    ),
    "android.permission.RECORD_AUDIO": PermissionInfo(
        name="RECORD_AUDIO",
        protection_level="dangerous",
        risk=PermissionRisk.CRITICAL,
        description="Record audio via microphone",
        attack_vector="Record conversations and ambient audio",
    ),

    # Contacts & Call Log
    "android.permission.READ_CONTACTS": PermissionInfo(
        name="READ_CONTACTS",
        protection_level="dangerous",
        risk=PermissionRisk.HIGH,
        description="Read user contacts",
        attack_vector="Harvest contact information for social engineering",
    ),
    "android.permission.WRITE_CONTACTS": PermissionInfo(
        name="WRITE_CONTACTS",
        protection_level="dangerous",
        risk=PermissionRisk.HIGH,
        description="Modify user contacts",
        attack_vector="Inject malicious contact entries",
    ),
    "android.permission.READ_CALL_LOG": PermissionInfo(
        name="READ_CALL_LOG",
        protection_level="dangerous",
        risk=PermissionRisk.HIGH,
        description="Read call history",
        attack_vector="Access call patterns and contacts",
    ),

    # SMS
    "android.permission.READ_SMS": PermissionInfo(
        name="READ_SMS",
        protection_level="dangerous",
        risk=PermissionRisk.CRITICAL,
        description="Read SMS messages",
        attack_vector="Intercept 2FA codes and private messages",
    ),
    "android.permission.SEND_SMS": PermissionInfo(
        name="SEND_SMS",
        protection_level="dangerous",
        risk=PermissionRisk.CRITICAL,
        description="Send SMS messages",
        attack_vector="Send premium SMS or spread malware via text",
    ),
    "android.permission.RECEIVE_SMS": PermissionInfo(
        name="RECEIVE_SMS",
        protection_level="dangerous",
        risk=PermissionRisk.CRITICAL,
        description="Receive SMS messages",
        attack_vector="Intercept incoming SMS including 2FA",
    ),

    # Storage
    "android.permission.READ_EXTERNAL_STORAGE": PermissionInfo(
        name="READ_EXTERNAL_STORAGE",
        protection_level="dangerous",
        risk=PermissionRisk.MEDIUM,
        description="Read external storage",
        attack_vector="Access photos, documents, and downloads",
    ),
    "android.permission.WRITE_EXTERNAL_STORAGE": PermissionInfo(
        name="WRITE_EXTERNAL_STORAGE",
        protection_level="dangerous",
        risk=PermissionRisk.MEDIUM,
        description="Write to external storage",
        attack_vector="Modify or delete user files",
    ),
    "android.permission.MANAGE_EXTERNAL_STORAGE": PermissionInfo(
        name="MANAGE_EXTERNAL_STORAGE",
        protection_level="dangerous",
        risk=PermissionRisk.HIGH,
        description="Full external storage access",
        attack_vector="Access all files on device storage",
    ),

    # Phone
    "android.permission.READ_PHONE_STATE": PermissionInfo(
        name="READ_PHONE_STATE",
        protection_level="dangerous",
        risk=PermissionRisk.MEDIUM,
        description="Read phone state and identity",
        attack_vector="Access IMEI, phone number, and call state",
    ),
    "android.permission.CALL_PHONE": PermissionInfo(
        name="CALL_PHONE",
        protection_level="dangerous",
        risk=PermissionRisk.HIGH,
        description="Make phone calls",
        attack_vector="Call premium numbers without consent",
    ),
    "android.permission.ANSWER_PHONE_CALLS": PermissionInfo(
        name="ANSWER_PHONE_CALLS",
        protection_level="dangerous",
        risk=PermissionRisk.HIGH,
        description="Answer incoming calls",
        attack_vector="Auto-answer calls for eavesdropping",
    ),

    # Calendar
    "android.permission.READ_CALENDAR": PermissionInfo(
        name="READ_CALENDAR",
        protection_level="dangerous",
        risk=PermissionRisk.MEDIUM,
        description="Read calendar events",
        attack_vector="Access schedule and meeting details",
    ),

    # Body Sensors
    "android.permission.BODY_SENSORS": PermissionInfo(
        name="BODY_SENSORS",
        protection_level="dangerous",
        risk=PermissionRisk.MEDIUM,
        description="Access body sensors (heart rate, etc.)",
        attack_vector="Monitor health data",
    ),

    # Nearby Devices
    "android.permission.BLUETOOTH_CONNECT": PermissionInfo(
        name="BLUETOOTH_CONNECT",
        protection_level="dangerous",
        risk=PermissionRisk.MEDIUM,
        description="Connect to Bluetooth devices",
        attack_vector="Access paired devices and data",
    ),

    # Special permissions (not in dangerous group but high risk)
    "android.permission.SYSTEM_ALERT_WINDOW": PermissionInfo(
        name="SYSTEM_ALERT_WINDOW",
        protection_level="signature|appop",
        risk=PermissionRisk.CRITICAL,
        description="Draw over other apps",
        attack_vector="Overlay attacks, clickjacking, credential theft",
    ),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": PermissionInfo(
        name="BIND_ACCESSIBILITY_SERVICE",
        protection_level="signature",
        risk=PermissionRisk.CRITICAL,
        description="Accessibility service binding",
        attack_vector="Read all screen content, perform actions as user",
    ),
    "android.permission.BIND_DEVICE_ADMIN": PermissionInfo(
        name="BIND_DEVICE_ADMIN",
        protection_level="signature",
        risk=PermissionRisk.CRITICAL,
        description="Device administrator",
        attack_vector="Lock device, wipe data, enforce policies",
    ),
    "android.permission.REQUEST_INSTALL_PACKAGES": PermissionInfo(
        name="REQUEST_INSTALL_PACKAGES",
        protection_level="signature",
        risk=PermissionRisk.HIGH,
        description="Request to install packages",
        attack_vector="Install arbitrary APKs",
    ),
}

# Dangerous permission combinations
RISKY_COMBINATIONS = [
    {
        "permissions": ["READ_SMS", "INTERNET"],
        "risk": PermissionRisk.CRITICAL,
        "description": "Can intercept and exfiltrate SMS (including 2FA codes)",
    },
    {
        "permissions": ["RECORD_AUDIO", "INTERNET"],
        "risk": PermissionRisk.CRITICAL,
        "description": "Can record and exfiltrate audio",
    },
    {
        "permissions": ["CAMERA", "INTERNET"],
        "risk": PermissionRisk.CRITICAL,
        "description": "Can capture and exfiltrate photos/video",
    },
    {
        "permissions": ["ACCESS_FINE_LOCATION", "INTERNET"],
        "risk": PermissionRisk.HIGH,
        "description": "Can track and exfiltrate location",
    },
    {
        "permissions": ["READ_CONTACTS", "INTERNET"],
        "risk": PermissionRisk.HIGH,
        "description": "Can harvest and exfiltrate contacts",
    },
    {
        "permissions": ["READ_CALL_LOG", "READ_SMS", "READ_CONTACTS"],
        "risk": PermissionRisk.CRITICAL,
        "description": "Full communication surveillance capability",
    },
    {
        "permissions": ["SYSTEM_ALERT_WINDOW", "RECORD_AUDIO"],
        "risk": PermissionRisk.CRITICAL,
        "description": "Can overlay UI and record audio (phishing + spying)",
    },
]


class PermissionAnalyzer:
    """
    Analyzes application permissions for security risks.

    Identifies:
    - Dangerous individual permissions
    - Risky permission combinations
    - Over-privileged applications
    - Potential attack vectors
    """

    def __init__(self, adb: ADBConnection):
        self.adb = adb

    def analyze_app(self, package_name: str) -> AppPermissionProfile:
        """
        Analyze permissions for a specific application.

        Args:
            package_name: Android package name

        Returns:
            AppPermissionProfile with risk assessment
        """
        logger.info(f"Analyzing permissions for {package_name}")

        # Get app permissions
        output = self.adb.shell(f"dumpsys package {package_name} | grep -A 100 'requested permissions:'")

        permissions: list[PermissionInfo] = []
        granted_perms: list[str] = []

        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('android.permission.'):
                perm_name = line.split(':')[0].strip()
                granted_perms.append(perm_name)

                if perm_name in DANGEROUS_PERMISSIONS:
                    permissions.append(DANGEROUS_PERMISSIONS[perm_name])
                else:
                    # Unknown but potentially dangerous permission
                    short_name = perm_name.replace('android.permission.', '')
                    permissions.append(PermissionInfo(
                        name=short_name,
                        protection_level="unknown",
                        risk=PermissionRisk.LOW,
                        description=f"Permission: {short_name}",
                    ))

        # Calculate risk factors
        risk_factors = []
        risk_score = 0.0

        # Check for dangerous permissions
        dangerous_count = sum(1 for p in permissions if p.risk in [PermissionRisk.CRITICAL, PermissionRisk.HIGH])
        risk_score += dangerous_count * 10

        if dangerous_count > 5:
            risk_factors.append(f"Excessive dangerous permissions ({dangerous_count})")

        # Check for risky combinations
        granted_short = [p.replace('android.permission.', '') for p in granted_perms]
        for combo in RISKY_COMBINATIONS:
            if all(p in granted_short for p in combo["permissions"]):
                risk_factors.append(combo["description"])
                if combo["risk"] == PermissionRisk.CRITICAL:
                    risk_score += 25
                elif combo["risk"] == PermissionRisk.HIGH:
                    risk_score += 15

        # Check for special permissions
        special_perms = ["SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE", "BIND_DEVICE_ADMIN"]
        for sp in special_perms:
            if sp in granted_short:
                risk_factors.append(f"Has special permission: {sp}")
                risk_score += 20

        # Cap score at 100
        risk_score = min(100, risk_score)

        return AppPermissionProfile(
            package_name=package_name,
            permissions=permissions,
            total_dangerous=dangerous_count,
            risk_score=risk_score,
            risk_factors=risk_factors,
        )

    def analyze_all_apps(self, third_party_only: bool = True) -> list[AppPermissionProfile]:
        """
        Analyze permissions for all installed applications.

        Args:
            third_party_only: Only analyze third-party apps

        Returns:
            List of AppPermissionProfile sorted by risk
        """
        flag = "-3" if third_party_only else ""
        output = self.adb.shell(f"pm list packages {flag}")

        profiles = []
        packages = [line.replace('package:', '').strip()
                   for line in output.split('\n') if line.startswith('package:')]

        for pkg in packages[:50]:  # Limit for performance
            try:
                profile = self.analyze_app(pkg)
                if profile.total_dangerous > 0:  # Only include apps with dangerous perms
                    profiles.append(profile)
            except Exception as e:
                logger.warning(f"Failed to analyze {pkg}: {e}")

        # Sort by risk score
        profiles.sort(key=lambda p: p.risk_score, reverse=True)

        return profiles

    def find_over_privileged_apps(self, min_dangerous: int = 5) -> list[AppPermissionProfile]:
        """
        Find applications with excessive permissions.

        Args:
            min_dangerous: Minimum dangerous permissions to flag

        Returns:
            List of over-privileged apps
        """
        all_profiles = self.analyze_all_apps()
        return [p for p in all_profiles if p.total_dangerous >= min_dangerous]

    def find_apps_with_permission(self, permission: str) -> list[str]:
        """
        Find all apps that have a specific permission.

        Args:
            permission: Permission name (with or without android.permission. prefix)

        Returns:
            List of package names
        """
        if not permission.startswith('android.permission.'):
            permission = f"android.permission.{permission}"

        output = self.adb.shell(f"dumpsys package | grep -B 20 '{permission}' | grep 'Package \\['")

        packages = []
        for line in output.split('\n'):
            if 'Package [' in line:
                # Extract package name from "Package [com.example.app]"
                start = line.find('[') + 1
                end = line.find(']')
                if start > 0 and end > start:
                    packages.append(line[start:end])

        return list(set(packages))

    def generate_report(self, profiles: list[AppPermissionProfile]) -> str:
        """Generate a human-readable permission analysis report."""
        lines = [
            "=" * 70,
            "PERMISSION ANALYSIS REPORT",
            "=" * 70,
            f"Applications Analyzed: {len(profiles)}",
            "",
        ]

        # Summary
        critical_apps = [p for p in profiles if p.risk_score >= 75]
        high_risk_apps = [p for p in profiles if 50 <= p.risk_score < 75]

        lines.append("SUMMARY")
        lines.append("-" * 70)
        lines.append(f"  Critical Risk (75+): {len(critical_apps)}")
        lines.append(f"  High Risk (50-74):   {len(high_risk_apps)}")
        lines.append(f"  Moderate/Low:        {len(profiles) - len(critical_apps) - len(high_risk_apps)}")
        lines.append("")

        # Top risky apps
        if profiles:
            lines.append("TOP RISKY APPLICATIONS")
            lines.append("-" * 70)

            for profile in profiles[:10]:
                risk_label = "CRITICAL" if profile.risk_score >= 75 else \
                            "HIGH" if profile.risk_score >= 50 else \
                            "MEDIUM" if profile.risk_score >= 25 else "LOW"

                lines.append(f"\n[{risk_label}] {profile.package_name}")
                lines.append(f"  Risk Score: {profile.risk_score:.0f}/100")
                lines.append(f"  Dangerous Permissions: {profile.total_dangerous}")

                if profile.risk_factors:
                    lines.append("  Risk Factors:")
                    for factor in profile.risk_factors:
                        lines.append(f"    - {factor}")

        lines.append("")
        lines.append("=" * 70)

        return "\n".join(lines)
