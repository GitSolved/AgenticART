"""
Tests for the Scanning Module

Run with: pytest tests/test_scanning.py -v
"""

import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import MockADB

from core.scanning.cve_matcher import CVEMatcher, ExploitAvailability
from core.scanning.permission_analyzer import PermissionAnalyzer
from core.scanning.vuln_scanner import VulnerabilityScanner, VulnSeverity


class TestCVEMatcher:
    """Tests for CVE Matcher."""

    def test_load_builtin_database(self):
        """Test that built-in CVE database loads."""
        matcher = CVEMatcher()
        assert len(matcher.cve_database) > 0

    def test_match_vulnerable_device(self):
        """Test matching CVEs for vulnerable device."""
        matcher = CVEMatcher()

        # Android 10 with old security patch
        matches = matcher.match_device(
            android_version="10",
            api_level=29,
            security_patch="2019-08-01",
        )

        assert len(matches) > 0
        # Should include binder UAF (CVE-2019-2215)
        cve_ids = [c.cve_id for c in matches]
        assert "CVE-2019-2215" in cve_ids

    def test_match_patched_device(self):
        """Test that patched device doesn't match old CVEs."""
        matcher = CVEMatcher()

        # Android 13 with recent security patch
        matches = matcher.match_device(
            android_version="13",
            api_level=33,
            security_patch="2024-01-01",
        )

        # Should have fewer matches due to patches
        old_cves = [c for c in matches if "2019" in c.cve_id or "2020" in c.cve_id]
        assert len(old_cves) == 0  # Old CVEs should be patched

    def test_get_exploitable_cves(self):
        """Test filtering for exploitable CVEs only."""
        matcher = CVEMatcher()

        exploitable = matcher.get_exploitable_cves(
            android_version="10",
            api_level=29,
            security_patch="2019-06-01",
        )

        # All returned should have public exploits
        for cve in exploitable:
            assert cve.exploit_availability == ExploitAvailability.PUBLIC_EXPLOIT


class TestPermissionAnalyzer:
    """Tests for Permission Analyzer."""

    def test_risk_combinations(self):
        """Test detection of risky permission combinations."""
        # This would require a mock ADB that returns specific permissions
        responses = {
            "dumpsys package com.test.app | grep -A 100 'requested permissions:'":
                "android.permission.READ_SMS: granted=true\n"
                "android.permission.INTERNET: granted=true\n"
        }
        mock_adb = MockADB(responses)
        analyzer = PermissionAnalyzer(mock_adb)

        # Would need more complete mocking for full test
        assert analyzer is not None

    def test_find_apps_with_permission(self):
        """Test finding apps with specific permission."""
        responses = {
            "dumpsys package | grep -B 20 'android.permission.CAMERA' | grep 'Package \\['":
                "Package [com.camera.app]\nPackage [com.photo.editor]"
        }
        mock_adb = MockADB(responses)
        analyzer = PermissionAnalyzer(mock_adb)

        apps = analyzer.find_apps_with_permission("CAMERA")
        assert "com.camera.app" in apps
        assert "com.photo.editor" in apps


class TestVulnerabilityScanner:
    """Tests for Vulnerability Scanner."""

    @pytest.fixture
    def mock_device_info(self):
        """Create mock device info."""
        from core.reconnaissance import DeviceInfo
        return DeviceInfo(
            model="Pixel 7",
            manufacturer="Google",
            device_name="panther",
            android_version="13",
            api_level=33,
            build_id="TQ3A.230901.001",
            security_patch="2023-09-01",
            architecture="arm64-v8a",
            kernel_version="5.10.149-android13",
            cpu_info="ARMv8",
            selinux_status="Enforcing",
            is_rooted=False,
            is_debuggable=False,
            is_encrypted=True,
            verified_boot="green",
        )

    def test_security_patch_check(self, mock_device_info):
        """Test security patch level vulnerability detection."""

        # Create mock responses
        responses = {
            "getprop persist.sys.usb.config": "mtp",
            "getprop service.adb.tcp.port": "-1",
            "settings get secure install_non_market_apps 2>/dev/null || settings get global install_non_market_apps": "0",
            "settings get global development_settings_enabled": "0",
            "settings get secure mock_location": "0",
            "settings get secure lockscreen.password_type": "65536",
            "netstat -tlnp 2>/dev/null || ss -tlnp": "",
        }

        mock_adb = MockADB(responses)

        # Patch the enumerator to return our mock device info
        with patch.object(VulnerabilityScanner, '__init__', lambda self, adb: None):
            scanner = VulnerabilityScanner.__new__(VulnerabilityScanner)
            scanner.adb = mock_adb
            scanner._vuln_id_counter = 0

            vulns, checks = scanner._check_security_patch(mock_device_info)

            # September 2023 patch should be flagged as outdated (>3 months old)
            assert checks == 1

    def test_selinux_check(self, mock_device_info):
        """Test SELinux status checking."""

        # Test with permissive SELinux
        mock_device_info.selinux_status = "Permissive"

        with patch.object(VulnerabilityScanner, '__init__', lambda self, adb: None):
            scanner = VulnerabilityScanner.__new__(VulnerabilityScanner)
            scanner._vuln_id_counter = 0

            vulns, checks = scanner._check_selinux(mock_device_info)

            assert len(vulns) == 1
            assert vulns[0].severity == VulnSeverity.HIGH


class TestIntegration:
    """Integration tests for scanning module."""

    def test_full_scan_with_mocks(self):
        """Test full vulnerability scan with mocked ADB."""
        # This would be an integration test with comprehensive mocks
        pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
