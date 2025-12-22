"""
Scanning Module

Vulnerability detection, CVE matching, and security analysis for Android devices.
"""

from .cve_matcher import CVEEntry, CVEMatcher, ExploitAvailability
from .permission_analyzer import AppPermissionProfile, PermissionAnalyzer, PermissionRisk
from .vuln_scanner import ScanResult, Vulnerability, VulnerabilityScanner, VulnSeverity

__all__ = [
    "VulnerabilityScanner",
    "ScanResult",
    "Vulnerability",
    "VulnSeverity",
    "CVEMatcher",
    "CVEEntry",
    "ExploitAvailability",
    "PermissionAnalyzer",
    "PermissionRisk",
    "AppPermissionProfile",
]
