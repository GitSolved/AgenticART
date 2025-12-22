"""
Tests for the Reconnaissance Module

Run with: pytest tests/test_reconnaissance.py -v
"""

import os
import sys
from typing import Optional

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.reconnaissance.device_enum import DeviceEnumerator
from core.reconnaissance.service_discovery import RiskLevel, ServiceDiscovery


class MockADB:
    """Mock ADB connection for testing."""

    def __init__(self, responses: Optional[dict] = None) -> None:
        self.responses = responses or {}
        self.commands_executed: list[str] = []
        self.device_id = "192.168.56.101:5555"

    def shell(self, command: str) -> str:
        self.commands_executed.append(command)
        for pattern, response in self.responses.items():
            if pattern in command:
                return response
        return ""

    def get_prop(self, prop: str) -> str:
        return self.responses.get(f"prop:{prop}", "")

    def execute(self, command: str, timeout: int = 30) -> tuple[str, str, int]:
        self.commands_executed.append(command)
        stdout = self.responses.get(f"exec:{command}", "")
        return stdout, "", 0

    def is_connected(self) -> bool:
        return True


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
        responses = {"prop:ro.product.model": "Pixel 7"}
        mock_adb = MockADB(responses)

        result = mock_adb.get_prop("ro.product.model")

        assert result == "Pixel 7"


class TestDeviceEnumerator:
    """Tests for Device Enumerator."""

    @pytest.fixture
    def mock_responses(self):
        """Standard mock responses for a Pixel 7."""
        return {
            "prop:ro.product.model": "Pixel 7",
            "prop:ro.product.manufacturer": "Google",
            "prop:ro.product.device": "panther",
            "prop:ro.build.version.release": "13",
            "prop:ro.build.version.sdk": "33",
            "prop:ro.build.id": "TQ3A.230901.001",
            "prop:ro.build.version.security_patch": "2023-09-01",
            "prop:ro.product.cpu.abi": "arm64-v8a",
            "uname -r": "5.10.149-android13",
            "cat /proc/cpuinfo | head -20": "Processor: ARMv8",
            "getenforce": "Enforcing",
            "which su": "",
            "ls /system/app/Superuser.apk": "No such file",
            "ls /system/xbin/su": "No such file",
            "ls /data/adb/magisk": "No such file",
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

        assert info.model == "Pixel 7"
        assert info.manufacturer == "Google"
        assert info.android_version == "13"
        assert info.api_level == 33
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
