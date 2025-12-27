"""Executor - runs code against Android device via ADB."""

from __future__ import annotations

import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from dojo.exceptions import ExecutionError
from dojo.models import Challenge, ScriptType


@dataclass
class ExecutionResult:
    """Result of executing code on device."""

    success: bool
    exit_code: int
    stdout: str
    stderr: str
    duration: float
    command: str
    error_type: Optional[str] = None  # classified error type

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
        }


class Executor:
    """Execute ADB commands against Android device."""

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
    ):
        """
        Initialize the executor.

        Args:
            device_id: Android device ID (e.g., "emulator-5554").
            adb_path: Path to adb executable. If None, uses PATH.
            timeout: Default command timeout in seconds.
        """
        self.device_id = device_id or os.getenv("EMULATOR_DEVICE", "emulator-5554")
        self.adb_path = adb_path or os.getenv(
            "ADB_PATH",
            "adb"  # Assume it's in PATH
        )
        self.timeout = timeout

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

        # Build command with device specifier
        assert self.adb_path is not None
        assert self.device_id is not None
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
            )

    def execute_frida(
        self,
        script_content: str,
        target_process: str = "com.genymotion.settings",
        timeout: int = 20,
    ) -> ExecutionResult:
        """
        Execute a Frida script against a target process using a temporary file.
        This method avoids shell escaping issues with multi-line scripts.
        """
        start_time = time.time()
        temp_js = Path("temp_frida_script.js")

        # Ensure we write valid UTF-8 and strip any accidental markdown backticks the model might have added
        clean_script = script_content.replace("```javascript", "").replace("```js", "").replace("```", "").strip()
        temp_js.write_text(clean_script, encoding="utf-8")

        try:
            # We use -f (spawn) instead of -n (attach) for better stability in automated tests
            # and --runtime=v8 for modern JS support.
            cmd = [
                "frida", "-U",
                "-f", target_process,
                "-l", str(temp_js),
                "--runtime=v8"
            ]

            # Use Popen to capture output while allowing it to run
            # We look for [SUCCESS] or other markers in the output
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding="utf-8",
                errors="replace"
            )

            duration = time.time() - start_time
            # Standard Frida exit is usually success if the script loaded
            success = result.returncode == 0

            return ExecutionResult(
                success=success,
                exit_code=result.returncode,
                stdout=result.stdout.strip(),
                stderr=result.stderr.strip(),
                duration=duration,
                command="frida -U -f " + target_process + " -l [temp_script.js]"
            )

        except subprocess.TimeoutExpired as e:
            # This is actually the common case for Frida (it stays alive)
            # We check the output captured so far
            duration = time.time() - start_time
            stdout = e.stdout.decode() if e.stdout else ""
            stderr = e.stderr.decode() if e.stderr else ""

            # Logic: If the script printed SOMETHING or didn't crash, consider it a success
            is_valid = len(stdout.strip()) > 0 and "Failed" not in stdout

            return ExecutionResult(
                success=is_valid,
                exit_code=0 if is_valid else -1,
                stdout=stdout.strip(),
                stderr=stderr.strip(),
                duration=duration,
                command="frida [timed_out_but_captured]"
            )
        except Exception as e:
            return ExecutionResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=str(e),
                duration=time.time() - start_time,
                command="frida-error"
            )
        finally:
            if temp_js.exists():
                temp_js.unlink()

    def execute_c_exploit(
        self,
        script_content: str,
        timeout: int = 15,
    ) -> ExecutionResult:
        """
        Validate C-based exploit logic.
        Uses local host compiler to check for syntax/logic errors.
        Note: This does not run on the device yet (requires NDK).
        """
        start_time = time.time()
        temp_c = Path("temp_exploit.c")
        temp_obj = Path("temp_exploit.out")
        temp_c.write_text(script_content)

        try:
            # 1. Attempt to compile locally (Syntax Check)
            # We use -fsyntax-only to just check code correctness
            cmd = ["clang", "-fsyntax-only", str(temp_c)]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            duration = time.time() - start_time
            success = result.returncode == 0

            stdout = "Syntax Check Passed" if success else ""
            stderr = result.stderr.strip()

            if not success:
                error_type = "c_syntax_error"
            else:
                error_type = None

            return ExecutionResult(
                success=success,
                exit_code=result.returncode,
                stdout=stdout,
                stderr=stderr,
                duration=duration,
                command="clang -fsyntax-only [exploit.c]",
                error_type=error_type
            )

        except Exception as e:
            return ExecutionResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=str(e),
                duration=time.time() - start_time,
                command="compiler-missing",
                error_type="tool_missing"
            )
        finally:
            if temp_c.exists():
                temp_c.unlink()
            if temp_obj.exists():
                temp_obj.unlink()

    def execute(
        self,
        challenge: Challenge,
        model_output: str,
    ) -> ExecutionResult:
        """
        Execute model output for a challenge.
        Now supports ADB, FRIDA, and C_EXPLOIT.
        """
        script_type = challenge.expected_output.script_type

        if script_type == ScriptType.ADB:
            return self.execute_adb(model_output)
        elif script_type == ScriptType.FRIDA:
            target = challenge.inputs.target_class or "com.genymotion.settings"
            return self.execute_frida(model_output, target_process=target)
        elif script_type == ScriptType.C_EXPLOIT:
            return self.execute_c_exploit(model_output)
        else:
            raise ExecutionError(
                f"Script type not yet supported: {script_type.value}",
                script_type=script_type.value,
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
        challenge: Challenge,
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

        # Get validation rules from challenge
        validation = challenge.inputs.additional_context.get("validation", {})
        if not validation:
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
