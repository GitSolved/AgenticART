"""Error extractor - parses failures into structured context for retry."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from dojo.curriculum.executor import ExecutionResult, Executor


@dataclass
class ErrorContext:
    """Structured error information for retry prompts."""

    error_type: str
    error_message: str
    failed_command: str
    failed_line: Optional[str] = None
    device_state: dict = field(default_factory=dict)
    suggestions: list[str] = field(default_factory=list)
    raw_stderr: str = ""
    raw_stdout: str = ""

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "error_type": self.error_type,
            "error_message": self.error_message,
            "failed_command": self.failed_command,
            "failed_line": self.failed_line,
            "device_state": self.device_state,
            "suggestions": self.suggestions,
        }

    def format_for_prompt(self) -> str:
        """Format error context for inclusion in a retry prompt."""
        lines = [
            f"Error Type: {self.error_type}",
            f"Error Message: {self.error_message}",
        ]

        if self.failed_line:
            lines.append(f"Failed Line: {self.failed_line}")

        if self.suggestions:
            lines.append("\nSuggestions:")
            for suggestion in self.suggestions:
                lines.append(f"  - {suggestion}")

        return "\n".join(lines)


class ErrorExtractor:
    """Extract structured error context from execution failures."""

    # Suggestion rules based on error type
    SUGGESTIONS = {
        "device_offline": [
            "Ensure the Android emulator is running",
            "Check that ADB server is started: 'adb start-server'",
            "Verify device ID is correct with: 'adb devices'",
        ],
        "permission_denied": [
            "The command may require root access - prefix with 'su -c'",
            "Check if the path is accessible to the shell user",
            "SELinux may be blocking access - check with 'getenforce'",
        ],
        "command_not_found": [
            "Verify the command exists on the Android device",
            "Check the full path to the binary",
            "The command may not be available on this Android version",
        ],
        "connection_refused": [
            "Check if the target service is running",
            "Verify the port number is correct",
            "Firewall may be blocking the connection",
        ],
        "timeout": [
            "The command is taking too long - try a simpler approach",
            "The device may be unresponsive - check emulator status",
            "Consider breaking the task into smaller steps",
        ],
        "syntax_error": [
            "Check command syntax and escaping",
            "Verify quotes are properly matched",
            "Shell special characters may need escaping",
        ],
        "segfault": [
            "The command crashed - this may indicate a bug",
            "Try with different arguments",
            "Check if the binary is compatible with device architecture",
        ],
        "unknown": [
            "Review the error message for clues",
            "Try a simpler version of the command first",
            "Check if prerequisites are met",
        ],
    }

    # Patterns to extract specific error details
    DETAIL_PATTERNS = {
        "path": r"(?:No such file or directory|not found)[:\s]*([^\n]+)",
        "permission": r"(?:Permission denied|cannot access)[:\s]*([^\n]+)",
        "command": r"(?:command not found|not found)[:\s]*(\S+)",
    }

    def __init__(self, executor: Optional["Executor"] = None):
        """
        Initialize error extractor.

        Args:
            executor: Optional executor for gathering device state.
        """
        self.executor = executor

    def extract(
        self,
        result: ExecutionResult,
        original_command: str,
    ) -> ErrorContext:
        """
        Extract structured error context from a failed execution.

        Args:
            result: The failed execution result.
            original_command: The command that was attempted.

        Returns:
            ErrorContext with structured error information.
        """
        error_type = result.error_type or "unknown"
        error_message = self._extract_error_message(result)
        failed_line = self._extract_failed_line(result, original_command)
        suggestions = self._get_suggestions(error_type, result)
        device_state = self._get_device_state()

        return ErrorContext(
            error_type=error_type,
            error_message=error_message,
            failed_command=original_command,
            failed_line=failed_line,
            device_state=device_state,
            suggestions=suggestions,
            raw_stderr=result.stderr,
            raw_stdout=result.stdout,
        )

    def _extract_error_message(self, result: ExecutionResult) -> str:
        """Extract a clean error message from the result."""
        # Prefer stderr, fall back to stdout
        error_text = result.stderr or result.stdout

        if not error_text:
            return f"Command failed with exit code {result.exit_code}"

        # Clean up the error message
        lines = error_text.strip().split("\n")

        # Find the most relevant error line
        for line in lines:
            line = line.strip()
            if any(keyword in line.lower() for keyword in [
                "error", "failed", "denied", "not found", "cannot", "unable"
            ]):
                return line

        # Return first non-empty line
        for line in lines:
            if line.strip():
                return line.strip()

        return error_text[:200]  # Truncate if too long

    def _extract_failed_line(
        self,
        result: ExecutionResult,
        original_command: str,
    ) -> Optional[str]:
        """Try to identify the specific line that failed."""
        combined = f"{result.stderr}\n{result.stdout}"

        # For single-line commands, the command itself is the failed line
        if "\n" not in original_command.strip():
            return original_command.strip()

        # Try to extract path or command from error
        for pattern_name, pattern in self.DETAIL_PATTERNS.items():
            match = re.search(pattern, combined, re.IGNORECASE)
            if match:
                return match.group(1).strip()

        return None

    def _get_suggestions(
        self,
        error_type: str,
        result: ExecutionResult,
    ) -> list[str]:
        """Get fix suggestions based on error type."""
        suggestions = self.SUGGESTIONS.get(error_type, self.SUGGESTIONS["unknown"]).copy()

        # Add context-specific suggestions
        combined = f"{result.stderr}\n{result.stdout}".lower()

        if "selinux" in combined or "enforcing" in combined:
            suggestions.insert(0, "SELinux is enforcing - consider 'setenforce 0' or policy modification")

        if "root" in combined or "uid" in combined:
            suggestions.insert(0, "This operation may require root privileges")

        if "busy" in combined:
            suggestions.insert(0, "Resource is busy - wait and retry, or close other processes")

        return suggestions[:5]  # Limit to 5 suggestions

    def _get_device_state(self) -> dict:
        """Gather current device state for context."""
        if not self.executor:
            return {}

        state = {}

        try:
            # Check if device is connected
            state["connected"] = self.executor.check_device_connected()

            if state["connected"]:
                # Get basic device info
                info = self.executor.get_device_info()
                state.update(info)

        except Exception:
            # Don't fail extraction if state gathering fails
            state["connected"] = False

        return state

    def classify_severity(self, error_context: ErrorContext) -> str:
        """
        Classify error severity.

        Args:
            error_context: The extracted error context.

        Returns:
            Severity level: "low", "medium", "high"
        """
        # High severity - requires significant changes
        high_severity = ["permission_denied", "segfault", "device_offline"]
        if error_context.error_type in high_severity:
            return "high"

        # Medium severity - might need approach change
        medium_severity = ["command_not_found", "connection_refused", "timeout"]
        if error_context.error_type in medium_severity:
            return "medium"

        # Low severity - likely minor fix
        return "low"
