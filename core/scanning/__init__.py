"""
Scanning Module

Vulnerability detection, CVE matching, and security analysis for Android devices.
"""

from .vuln_scanner import VulnerabilityScanner, ScanResult, Vulnerability, VulnSeverity
from .cve_matcher import CVEMatcher, CVEEntry, ExploitAvailability
from .permission_analyzer import PermissionAnalyzer, PermissionRisk, AppPermissionProfile

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
