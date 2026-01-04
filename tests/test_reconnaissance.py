"""
Tests for the Reconnaissance Module

Run with: pytest tests/test_reconnaissance.py -v
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import MockADB

from core.reconnaissance.device_enum import DeviceEnumerator
from core.reconnaissance.service_discovery import RiskLevel, ServiceDiscovery


class TestADBConnection:
    """Tests for ADB Connection."""

    def test_shell_command(self):
        """Test shell command execution."""
        responses = {"id": "uid=2000(shell)"}
        mock_adb = MockADB(responses)

        result = mock_adb.shell("id")

        assert "uid=2000" in result
        assert "id" in mock_adb.commands_executed

    def test_get_prop(self):
        """Test property retrieval."""
        responses = {"prop:ro.product.model": "SM-S911B"}
        mock_adb = MockADB(responses)

        result = mock_adb.get_prop("ro.product.model")

        assert result == "SM-S911B"


class TestDeviceEnumerator:
    """Tests for Device Enumerator."""

    @pytest.fixture
    def mock_responses(self):
        """Standard mock responses for a Samsung S23."""
        return {
            "prop:ro.product.model": "SM-S911B",
            "prop:ro.product.manufacturer": "Samsung",
            "prop:ro.product.device": "dm1qxxx",
            "prop:ro.build.version.release": "14",
            "prop:ro.build.version.sdk": "34",
            "prop:ro.build.id": "UP1A.231105.003",
            "prop:ro.build.version.security_patch": "2023-11-01",
            "prop:ro.product.cpu.abi": "arm64-v8a",
            "uname -r": "6.1.25-android14",
            "cat /proc/cpuinfo | head -20": "Processor: ARMv8",
            "getenforce": "Enforcing",
            "which su": "",
            "ls /system/app/Superuser.apk": "",
            "ls /system/xbin/su": "",
            "ls /data/adb/magisk": "",
            "prop:ro.debuggable": "0",
            "prop:ro.crypto.state": "encrypted",
            "prop:ro.boot.verifiedbootstate": "green",
            "ip addr show wlan0": "inet 192.168.1.100/24",
            "dumpsys wifi | grep 'Wi-Fi is'": "Wi-Fi is enabled",
        }

    def test_enumerate_device(self, mock_responses):
        """Test full device enumeration."""
        mock_adb = MockADB(mock_responses)
        enumerator = DeviceEnumerator(mock_adb)

        info = enumerator.enumerate()

        assert info.model == "SM-S911B"
        assert info.manufacturer == "Samsung"
        assert info.android_version == "14"
        assert info.api_level == 34
        assert info.is_encrypted
        assert not info.is_rooted

    def test_root_detection_magisk(self, mock_responses):
        """Test Magisk root detection."""
        mock_responses["ls /data/adb/magisk"] = "magisk.db"
        mock_adb = MockADB(mock_responses)
        enumerator = DeviceEnumerator(mock_adb)

        info = enumerator.enumerate()

        assert info.is_rooted

    def test_root_detection_su_binary(self, mock_responses):
        """Test su binary root detection."""
        mock_responses["which su"] = "/system/xbin/su"
        mock_adb = MockADB(mock_responses)
        enumerator = DeviceEnumerator(mock_adb)

        info = enumerator.enumerate()

        assert info.is_rooted


class TestServiceDiscovery:
    """Tests for Service Discovery."""

    def test_parse_network_services(self):
        """Test network service parsing."""
        responses = {
            "netstat -tlnp": "tcp 0 0 0.0.0.0:5555 0.0.0.0:* LISTEN 1234/adbd",
            "netstat -ulnp": "",
        }
        mock_adb = MockADB(responses)
        discovery = ServiceDiscovery(mock_adb)

        services = discovery.discover_network_services()

        assert len(services) >= 1
        adb_service = next((s for s in services if s.port == 5555), None)
        assert adb_service is not None
        assert adb_service.risk == RiskLevel.CRITICAL

    def test_detect_dangerous_ports(self):
        """Test detection of dangerous ports."""
        responses = {
            "netstat -tlnp": (
                "tcp 0 0 0.0.0.0:5555 0.0.0.0:* LISTEN 1234/adbd\n"
                "tcp 0 0 0.0.0.0:27042 0.0.0.0:* LISTEN 5678/frida-server"
            ),
            "netstat -ulnp": "",
        }
        mock_adb = MockADB(responses)
        discovery = ServiceDiscovery(mock_adb)

        debug_services = discovery.find_debug_services()

        assert len(debug_services) >= 2
        ports = [s.port for s in debug_services]
        assert 5555 in ports
        assert 27042 in ports

    def test_adb_exposure_detection(self):
        """Test specific ADB exposure check."""
        responses = {
            "netstat -tlnp": "tcp 0 0 0.0.0.0:5555 0.0.0.0:* LISTEN 1234/adbd",
            "netstat -ulnp": "",
        }
        mock_adb = MockADB(responses)
        discovery = ServiceDiscovery(mock_adb)

        adb_exposure = discovery.find_adb_exposure()

        assert adb_exposure is not None
        assert adb_exposure.port == 5555
        assert adb_exposure.risk == RiskLevel.CRITICAL


class TestReportGeneration:
    """Tests for report generation."""

    def test_service_discovery_report(self):
        """Test service discovery report generation."""
        responses = {
            "netstat -tlnp": "tcp 0 0 0.0.0.0:5555 0.0.0.0:* LISTEN 1234/adbd",
            "netstat -ulnp": "",
            "dumpsys activity services": "",
            "pm list packages -3 | cut -d: -f2": "",
        }
        mock_adb = MockADB(responses)
        discovery = ServiceDiscovery(mock_adb)

        result = discovery.discover_all()
        report = discovery.generate_report(result)

        assert "SERVICE DISCOVERY REPORT" in report
        assert "5555" in report


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
