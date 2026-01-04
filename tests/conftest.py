"""
Shared test fixtures for AgenticART tests.

This module provides common mocks and fixtures used across multiple test files.
"""

from typing import Optional

import pytest


class MockADB:
    """Mock ADB connection for testing.

    Provides a configurable mock that can simulate ADB responses
    based on command patterns or exact matches.

    Usage:
        # With pattern matching
        mock = MockADB(responses={"getprop": "14", "pm list": "package:com.app"})

        # With exact matches
        mock = MockADB(responses={"getprop ro.build.version.release": "14"})

        # Access executed commands
        mock.shell("getprop ro.build.version.release")
        assert "getprop" in mock.commands_executed[0]
    """

    def __init__(
        self,
        responses: Optional[dict[str, str]] = None,
        device_id: str = "192.168.56.101:5555",
    ) -> None:
        """Initialize MockADB with optional responses.

        Args:
            responses: Dict mapping command patterns to responses.
                      Supports both exact matches and pattern matching.
            device_id: Mock device identifier.
        """
        self.responses = responses or {}
        self.commands_executed: list[str] = []
        self.device_id = device_id
        self._connected = True

    def shell(self, command: str, timeout: int = 30) -> str:
        """Execute a shell command and return mock response.

        Args:
            command: The shell command to execute.
            timeout: Command timeout (ignored in mock).

        Returns:
            Mock response based on configured patterns.
        """
        self.commands_executed.append(command)

        # Try exact match first
        if command in self.responses:
            return str(self.responses[command])

        # Then try pattern matching
        for pattern, response in self.responses.items():
            if pattern in command:
                return str(response)

        return ""

    def get_prop(self, prop: str) -> str:
        """Get a device property.

        Args:
            prop: Property name (e.g., "ro.build.version.release").

        Returns:
            Mock property value.
        """
        # Check for prop-specific response
        prop_key = f"prop:{prop}"
        if prop_key in self.responses:
            return str(self.responses[prop_key])

        # Check for getprop command pattern
        getprop_key = f"getprop {prop}"
        if getprop_key in self.responses:
            return str(self.responses[getprop_key])

        # Try pattern matching
        for pattern, response in self.responses.items():
            if prop in pattern:
                return str(response)

        return ""

    def execute(self, command: str, timeout: int = 30) -> tuple[str, str, int]:
        """Execute a raw ADB command.

        Args:
            command: The ADB command to execute.
            timeout: Command timeout (ignored in mock).

        Returns:
            Tuple of (stdout, stderr, exit_code).
        """
        self.commands_executed.append(command)

        # Check for exec-specific response
        exec_key = f"exec:{command}"
        if exec_key in self.responses:
            return str(self.responses[exec_key]), "", 0

        return "", "", 0

    def is_connected(self) -> bool:
        """Check if device is connected.

        Returns:
            True if connected (always True for mock).
        """
        return self._connected

    def set_connected(self, connected: bool) -> None:
        """Set the connection state for testing.

        Args:
            connected: Whether the mock should report as connected.
        """
        self._connected = connected

    def clear_history(self) -> None:
        """Clear the command execution history."""
        self.commands_executed.clear()


@pytest.fixture
def mock_adb() -> MockADB:
    """Pytest fixture providing a fresh MockADB instance."""
    return MockADB()


@pytest.fixture
def mock_adb_with_device_info() -> MockADB:
    """Pytest fixture providing MockADB with common device info responses."""
    return MockADB(
        responses={
            "prop:ro.build.version.release": "14",
            "prop:ro.build.version.sdk": "34",
            "prop:ro.product.model": "Pixel 7",
            "prop:ro.product.manufacturer": "Google",
            "prop:ro.build.version.security_patch": "2024-01-05",
            "getprop ro.build.version.release": "14",
            "pm list packages": "package:com.android.settings\npackage:com.android.browser",
            "id": "uid=2000(shell) gid=2000(shell)",
        }
    )
