"""
Vulnerable Targets Module

Manages intentionally vulnerable applications for exploitation validation.
"""

from dojo.targets.target_manager import (
    TargetManager,
    Vulnerability,
    VulnerabilityFlag,
    VulnerableApp,
)

__all__ = [
    "TargetManager",
    "VulnerableApp",
    "Vulnerability",
    "VulnerabilityFlag",
]
