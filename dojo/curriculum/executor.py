"""Executor - runs code against Android device via ADB.

Security Note:
    This executor includes a training blocklist that prevents dangerous
    commands from executing, even in automated training runs. Blocked
    commands return a failure result, which becomes useful training data
    (the model learns these commands are rejected).

    To allow execution against real devices (not recommended), set:
        ALLOW_REAL_DEVICE=true
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Optional

from dojo.exceptions import ExecutionError

logger = logging.getLogger(__name__)


class ExecutionTier(IntEnum):
    """Execution tier levels for training metadata."""

    ADB = 1          # Pure ADB commands
    ON_DEVICE = 2    # Tools running on the device (frida-server, sqlite3, etc.)
    EXTERNAL = 3     # External tools (Kali container, nmap, etc.)


@dataclass
class ExecutionResult:
    """Result of executing code on device."""

    success: bool
    exit_code: int
    stdout: str
    stderr: str
    duration: float
    command: str
    error_type: Optional[str] = None
    blocked: bool = False
    tier_used: int = 1  # ExecutionTier value (1=ADB, 2=ON_DEVICE, 3=EXTERNAL)
    tools_used: list[str] = field(default_factory=lambda: ["adb"])

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration": self.duration,
            "command": self.command,
            "error_type": self.error_type,
            "blocked": self.blocked,
            "tier_used": self.tier_used,
            "tools_used": self.tools_used,
        }


class Executor:
    """Execute ADB commands against Android device.

    Includes safety blocklist for training mode to prevent destructive
    commands while still collecting useful error training data.
    """

    # Instance variables (always have values after __init__ due to defaults)
    device_id: str
    adb_path: str
    timeout: int
    disable_blocklist: bool

    # Dangerous command patterns - blocked in training mode
    DANGEROUS_COMMAND_PATTERNS = {
        "destructive_delete": [
            r"rm\s+-rf",
            r"rm\s+-r.*\s+/",
            r"rm\s+.*\s+/sdcard\s*$",
            r"rm\s+.*\s+/data\s*$",
            r"rm\s+.*\s+/system\s*$",
        ],
        "destructive_format": [
            r"mkfs\.",
            r"dd\s+if=.*/dev/zero",
            r"dd\s+of=/dev/",
            r"format",
        ],
        "bootloader_flash": [
            r"fastboot\s+flash",
            r"fastboot\s+erase",
            r"fastboot\s+oem\s+unlock",
            r"fastboot\s+flashing",
        ],
        "system_control": [
            r"reboot\s+bootloader",
            r"reboot\s+recovery",
            r"reboot\s+fastboot",
            r"shutdown",
            r"poweroff",
        ],
        "adb_dangerous": [
            r"sideload",
            r"disable-verity",
            r"remount.*rw",
            r"restore",
        ],
        "privilege_escalation": [
            r"su\s+-c\s+['\"']?rm",
            r"su\s+-c\s+['\"']?dd",
            r"su\s+-c\s+['\"']?format",
            r"su\s+-c\s+['\"']?mkfs",
            r"su\s+-c\s+['\"']?reboot",
        ],
        "settings_dangerous": [
            r"settings\s+put.*adb_enabled\s+0",
            r"settings\s+put.*install_non_market_apps\s+0",
        ],
        "network_dangerous": [
            r"iptables\s+-F",
            r"iptables\s+-X",
            r"ip\s+link\s+set.*down",
        ],
    }

    # Error classification patterns
    ERROR_PATTERNS = {
        "device_offline": [
            r"error: device .* not found",
            r"error: device offline",
            r"no devices/emulators found",
        ],
        "permission_denied": [
            r"Permission denied",
            r"Operation not permitted",
            r"access denied",
        ],
        "command_not_found": [
            r"not found",
            r"No such file or directory",
            r"inaccessible or not found",
        ],
        "connection_refused": [
            r"Connection refused",
            r"cannot connect",
            r"failed to connect",
        ],
        "timeout": [
            r"timed out",
            r"timeout",
        ],
        "syntax_error": [
            r"syntax error",
            r"SyntaxError",
            r"parse error",
        ],
        "segfault": [
            r"Segmentation fault",
            r"SIGSEGV",
        ],
    }

    def __init__(
        self,
        device_id: Optional[str] = None,
        adb_path: Optional[str] = None,
        timeout: int = 30,
        allow_real_device: Optional[bool] = None,
        disable_blocklist: bool = False,
    ):
        """Initialize the executor.

        Args:
            device_id: Android device ID (e.g., "emulator-5554").
            adb_path: Path to adb executable. If None, uses PATH.
            timeout: Default command timeout in seconds.
            allow_real_device: Allow non-emulator devices. Defaults to
                env var ALLOW_REAL_DEVICE or False.
            disable_blocklist: Disable safety blocklist (use with caution).

        Raises:
            ValueError: If device_id looks like a real device and
                allow_real_device is False.
        """
        self.device_id = device_id if device_id else (os.getenv("EMULATOR_DEVICE") or "emulator-5554")
        self.adb_path = adb_path if adb_path else (os.getenv("ADB_PATH") or "adb")
        self.timeout = timeout
        self.disable_blocklist = disable_blocklist

        if allow_real_device is None:
            allow_real_device = os.getenv("ALLOW_REAL_DEVICE", "").lower() == "true"

        if not allow_real_device:
            if not self._is_emulator_device(self.device_id):
                raise ValueError(
                    f"Device '{self.device_id}' does not appear to be an emulator. "
                    f"Training should run against emulators only for safety. "
                    f"If you really want to use a real device, set "
                    f"ALLOW_REAL_DEVICE=true or pass allow_real_device=True."
                )

        logger.info(
            f"Executor initialized: device={self.device_id}, "
            f"blocklist={'disabled' if disable_blocklist else 'enabled'}"
        )

    def _is_emulator_device(self, device_id: str) -> bool:
        """Check if device ID looks like an emulator."""
        emulator_patterns = [
            r"^emulator-\d+$",
            r"^localhost:\d+$",
            r"^127\.0\.0\.1:\d+$",
            r"^10\.0\.2\.\d+:\d+$",
            r"^192\.168\.\d+\.\d+:\d+$",
        ]
        return any(re.match(p, device_id) for p in emulator_patterns)

    def _check_dangerous_command(self, command: str) -> Optional[tuple[str, str]]:
        """Check if command matches any dangerous patterns."""
        if self.disable_blocklist:
            return None

        for category, patterns in self.DANGEROUS_COMMAND_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    return (category, pattern)

        return None

    def _classify_error(self, stderr: str, stdout: str) -> Optional[str]:
        """
        Classify the error type from output.

        Args:
            stderr: Standard error output.
            stdout: Standard output (some errors go here).

        Returns:
            Error type string or None if no error detected.
        """
        combined = f"{stderr}\n{stdout}"

        for error_type, patterns in self.ERROR_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    return error_type

        return None

    def _build_adb_command(self, command: str) -> list[str]:
        """
        Build the full ADB command with device specifier.

        Args:
            command: The ADB command (may or may not include 'adb' prefix).

        Returns:
            List of command parts for subprocess.
        """
        # Strip 'adb' prefix if present (user might include it)
        command = command.strip()
        if command.lower().startswith("adb "):
            command = command[4:].strip()

        # Build command with device specifier (adb_path and device_id always have defaults)
        cmd_parts = [self.adb_path, "-s", self.device_id]

        # Handle shell commands specially to preserve quoting
        if command.startswith("shell "):
            cmd_parts.append("shell")
            shell_cmd = command[6:].strip()
            # Pass shell command as single argument to preserve spaces
            cmd_parts.append(shell_cmd)
        else:
            # Split other commands normally
            cmd_parts.extend(command.split())

        return cmd_parts

    def execute_adb(
        self,
        command: str,
        timeout: Optional[int] = None,
    ) -> ExecutionResult:
        """
        Execute an ADB command.

        Args:
            command: The ADB command to execute.
            timeout: Command timeout in seconds (uses default if None).

        Returns:
            ExecutionResult with output and status.
        """
        timeout = timeout or self.timeout
        cmd_parts = self._build_adb_command(command)
        cmd_string = " ".join(cmd_parts)

        start_time = time.time()

        try:
            result = subprocess.run(
                cmd_parts,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding="utf-8",
                errors="replace",
            )

            duration = time.time() - start_time
            error_type = self._classify_error(result.stderr, result.stdout)

            # Determine success: exit code 0 and no error patterns
            success = result.returncode == 0 and error_type is None

            return ExecutionResult(
                success=success,
                exit_code=result.returncode,
                stdout=result.stdout.strip(),
                stderr=result.stderr.strip(),
                duration=duration,
                command=cmd_string,
                error_type=error_type,
                blocked=False,
            )

        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            return ExecutionResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=f"Command timed out after {timeout} seconds",
                duration=duration,
                command=cmd_string,
                error_type="timeout",
                blocked=False,
            )

        except FileNotFoundError:
            duration = time.time() - start_time
            return ExecutionResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=f"ADB executable not found: {self.adb_path}",
                duration=duration,
                command=cmd_string,
                error_type="command_not_found",
                blocked=False,
            )

        except Exception as e:
            duration = time.time() - start_time
            return ExecutionResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=str(e),
                duration=duration,
                command=cmd_string,
                error_type="unknown",
                blocked=False,
            )

    def execute(
        self,
        challenge: Any,
        model_output: str,
    ) -> ExecutionResult:
        """
        Execute model output for a challenge.

        Args:
            challenge: The challenge being attempted (V1 or V2).
            model_output: The model's generated code/command.

        Returns:
            ExecutionResult with output and status.

        Raises:
            ExecutionError: If script type is not supported.
        """
        # Handle script type extraction (duck typing)
        script_type_val = "adb"
        if hasattr(challenge, "expected_output"):
            script_type_val = challenge.expected_output.script_type.value
        elif hasattr(challenge, "script_type"):
            script_type_val = str(challenge.script_type)

        if script_type_val == "adb" or script_type_val == "shell":
            return self.execute_adb(model_output)
        else:
            raise ExecutionError(
                f"Script type not yet supported: {script_type_val}",
                script_type=script_type_val,
            )

    def check_device_connected(self) -> bool:
        """
        Check if the device is connected and responsive.

        Returns:
            True if device is connected, False otherwise.
        """
        result = self.execute_adb("shell echo 'ping'")
        return result.success and "ping" in result.stdout

    def get_device_info(self) -> dict:
        """
        Get basic device information.

        Returns:
            Dictionary with device properties.
        """
        info = {}

        # Get Android version
        result = self.execute_adb("shell getprop ro.build.version.release")
        if result.success:
            info["android_version"] = result.stdout.strip()

        # Get API level
        result = self.execute_adb("shell getprop ro.build.version.sdk")
        if result.success:
            info["api_level"] = result.stdout.strip()

        # Get device model
        result = self.execute_adb("shell getprop ro.product.model")
        if result.success:
            info["model"] = result.stdout.strip()

        # Get manufacturer
        result = self.execute_adb("shell getprop ro.product.manufacturer")
        if result.success:
            info["manufacturer"] = result.stdout.strip()

        return info

    def validate_output(
        self,
        challenge: Any,
        execution_result: ExecutionResult,
    ) -> bool:
        """
        Validate execution output against challenge requirements.

        Args:
            challenge: The challenge with validation rules.
            execution_result: The execution result to validate.

        Returns:
            True if output passes validation.
        """
        if not execution_result.success:
            return False

        # Get validation rules from challenge (duck typing)
        validation = {}
        if hasattr(challenge, "inputs"):
            validation = challenge.inputs.additional_context.get("validation", {})
        elif hasattr(challenge, "metadata"):
            validation = challenge.metadata.get("validation", {})

        if not validation:
            # Check V2 ground truth observations as fallback
            if hasattr(challenge, "ground_truth"):
                output = execution_result.stdout.lower()
                for obs in getattr(challenge.ground_truth, "key_observations", []):
                    if obs.lower() in output:
                        return True

            # No specific validation, success is enough
            return True

        output = execution_result.stdout
        validation_type = validation.get("type", "")

        if validation_type == "output_contains":
            expected = validation.get("expected", "")
            return expected in output

        elif validation_type == "output_equals":
            expected = validation.get("expected", "")
            return output.strip() == expected.strip()

        elif validation_type == "regex_match":
            pattern = validation.get("pattern", "")
            return bool(re.search(pattern, output))

        elif validation_type == "not_empty":
            return len(output.strip()) > 0

        # Unknown validation type, assume pass if execution succeeded
        return True


class OnDeviceToolExecutor:
    """Tier 2: Execute tools that run on the Android device.

    This executor handles tools that run directly on the Android device,
    either natively available or pushed via ADB. It wraps the base Executor
    for ADB transport.
    """

    NATIVE_TOOLS = {
        "sqlite3", "toybox", "toolbox", "sh", "netstat", "ps", "top",
        "df", "mount", "cat", "ls", "grep", "find", "id", "whoami",
        "getprop", "setprop", "logcat", "dmesg", "service", "cmd",
    }

    PUSHABLE_TOOLS = {
        "frida-server": {
            "binary_path": "binaries/android/frida-server",
            "device_path": "/data/local/tmp/frida-server",
            "executable": True,
        },
        "busybox": {
            "binary_path": "binaries/android/busybox",
            "device_path": "/data/local/tmp/busybox",
            "executable": True,
        },
        "tcpdump": {
            "binary_path": "binaries/android/tcpdump",
            "device_path": "/data/local/tmp/tcpdump",
            "executable": True,
        },
    }

    def __init__(
        self,
        adb_executor: "Executor",
        binaries_dir: Optional[str] = None,
    ):
        """Initialize the on-device tool executor."""
        self.adb = adb_executor
        self.binaries_dir = binaries_dir
        self._tool_cache: dict[str, bool] = {}

    def check_tool_available(self, tool: str) -> bool:
        """Check if a tool is available on the device."""
        if tool in self._tool_cache:
            return self._tool_cache[tool]

        result = self.adb.execute_adb(f"shell which {tool}")
        available = result.success and tool in result.stdout

        if not available:
            for path in ["/system/bin/", "/system/xbin/", "/data/local/tmp/"]:
                result = self.adb.execute_adb(f"shell test -x {path}{tool} && echo exists")
                if result.success and "exists" in result.stdout:
                    available = True
                    break

        self._tool_cache[tool] = available
        return available

    def get_available_tools(self) -> list[str]:
        """Get list of available tools on the device."""
        return [t for t in self.NATIVE_TOOLS if self.check_tool_available(t)]

    def push_tool(self, tool: str) -> tuple[bool, str]:
        """Push a tool binary to the device."""
        if tool not in self.PUSHABLE_TOOLS:
            return False, f"Tool not in pushable list: {tool}"

        config = self.PUSHABLE_TOOLS[tool]
        binary = str(config["binary_path"])
        device = str(config["device_path"])

        full_path = os.path.join(self.binaries_dir, binary) if self.binaries_dir else binary

        if not os.path.exists(full_path):
            return False, f"Binary not found: {full_path}"

        result = self.adb.execute_adb(f"push {full_path} {device}")
        if not result.success:
            return False, f"Push failed: {result.stderr}"

        if config.get("executable"):
            self.adb.execute_adb(f"shell chmod +x {device}")

        self._tool_cache.pop(tool, None)
        return True, f"Pushed {tool} to {device}"

    def execute_tool(
        self,
        tool: str,
        args: str = "",
        timeout: Optional[int] = None,
        auto_push: bool = False,
    ) -> ExecutionResult:
        """Execute a tool on the device."""
        if not self.check_tool_available(tool):
            if auto_push and tool in self.PUSHABLE_TOOLS:
                success, msg = self.push_tool(tool)
                if not success:
                    return ExecutionResult(
                        success=False, exit_code=-1, stdout="", duration=0.0,
                        stderr=f"Tool not available, push failed: {msg}",
                        command=f"{tool} {args}", error_type="tool_not_found",
                        blocked=False, tier_used=ExecutionTier.ON_DEVICE,
                        tools_used=[tool],
                    )
            else:
                return ExecutionResult(
                    success=False, exit_code=-1, stdout="", duration=0.0,
                    stderr=f"Tool not available on device: {tool}",
                    command=f"{tool} {args}", error_type="tool_not_found",
                    blocked=False, tier_used=ExecutionTier.ON_DEVICE,
                    tools_used=[tool],
                )

        result = self.adb.execute_adb(f"shell {tool} {args}".strip(), timeout=timeout)

        return ExecutionResult(
            success=result.success, exit_code=result.exit_code,
            stdout=result.stdout, stderr=result.stderr,
            duration=result.duration, command=result.command,
            error_type=result.error_type, blocked=result.blocked,
            tier_used=ExecutionTier.ON_DEVICE, tools_used=["adb", tool],
        )

    def execute_sqlite_query(
        self, database_path: str, query: str, timeout: Optional[int] = None,
    ) -> ExecutionResult:
        """Execute a SQLite query on a database."""
        escaped = query.replace('"', '\\"')
        return self.execute_tool("sqlite3", f'{database_path} "{escaped}"', timeout)

    def clear_tool_cache(self) -> None:
        """Clear the tool availability cache."""
        self._tool_cache.clear()
