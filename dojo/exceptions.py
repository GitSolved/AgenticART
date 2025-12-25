"""Custom exceptions for the Dojo framework."""

from __future__ import annotations

from typing import Optional


class DojoError(Exception):
    """Base exception for all Dojo errors."""

    def __init__(self, message: str, details: Optional[dict] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ChallengeNotFoundError(DojoError):
    """Raised when a challenge ID doesn't exist."""

    def __init__(self, challenge_id: str, belt: Optional[str] = None):
        self.challenge_id = challenge_id
        self.belt = belt
        message = f"Challenge not found: {challenge_id}"
        if belt:
            message += f" (belt: {belt})"
        super().__init__(message, {"challenge_id": challenge_id, "belt": belt})


class InvalidBeltError(DojoError):
    """Raised when an invalid belt is specified."""

    def __init__(self, belt: str):
        self.belt = belt
        valid_belts = ["white", "yellow", "orange", "green", "blue", "purple", "brown", "black"]
        super().__init__(
            f"Invalid belt: {belt}. Valid belts: {', '.join(valid_belts)}",
            {"belt": belt, "valid_belts": valid_belts},
        )


class GradingError(DojoError):
    """Raised when grading fails."""

    def __init__(self, message: str, challenge_id: Optional[str] = None, cause: Optional[Exception] = None):
        self.challenge_id = challenge_id
        self.cause = cause
        details = {"challenge_id": challenge_id}
        if cause:
            details["cause"] = str(cause)
        super().__init__(message, details)


class ExportError(DojoError):
    """Raised when training data export fails."""

    def __init__(self, message: str, format: Optional[str] = None, cause: Optional[Exception] = None):
        self.format = format
        self.cause = cause
        details = {"format": format}
        if cause:
            details["cause"] = str(cause)
        super().__init__(message, details)


class ExecutionError(DojoError):
    """Raised when script execution fails."""

    def __init__(
        self,
        message: str,
        script_type: Optional[str] = None,
        exit_code: Optional[int] = None,
        stderr: Optional[str] = None,
    ):
        self.script_type = script_type
        self.exit_code = exit_code
        self.stderr = stderr
        super().__init__(
            message,
            {
                "script_type": script_type,
                "exit_code": exit_code,
                "stderr": stderr,
            },
        )


class ValidationError(DojoError):
    """Raised when validation fails."""

    def __init__(self, message: str, issues: Optional[list[str]] = None):
        self.issues = issues or []
        super().__init__(message, {"issues": self.issues})


class ConfigurationError(DojoError):
    """Raised when configuration is invalid."""

    def __init__(self, message: str, config_key: Optional[str] = None):
        self.config_key = config_key
        super().__init__(message, {"config_key": config_key})


class CurriculumError(DojoError):
    """Raised when there's an issue with curriculum loading."""

    def __init__(self, message: str, file_path: Optional[str] = None, cause: Optional[Exception] = None):
        self.file_path = file_path
        self.cause = cause
        details = {"file_path": file_path}
        if cause:
            details["cause"] = str(cause)
        super().__init__(message, details)
