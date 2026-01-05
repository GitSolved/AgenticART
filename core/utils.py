"""
Core Utilities for AgenticART
"""

import re
from datetime import datetime, timezone
from typing import Optional

# Valid Android package name pattern (e.g., com.example.app)
# Must start with letter, contain only alphanumeric, underscore, and dots
ANDROID_PACKAGE_PATTERN = re.compile(r'^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$')


def validate_package_name(package: str) -> str:
    """
    Validate an Android package name to prevent command injection.

    Args:
        package: The package name to validate.

    Returns:
        The validated package name.

    Raises:
        ValueError: If package name is invalid or contains shell metacharacters.
    """
    if not package or not isinstance(package, str):
        raise ValueError("Package name must be a non-empty string")

    if not ANDROID_PACKAGE_PATTERN.match(package):
        raise ValueError(
            f"Invalid package name '{package}'. Must match pattern: "
            "com.example.app (letters, numbers, underscores, separated by dots)"
        )

    return package


def get_utc_now() -> datetime:
    """Get current UTC time with timezone info."""
    return datetime.now(timezone.utc)


def format_timestamp(dt: Optional[datetime] = None, format_str: str = "%Y%m%d_%H%M%S") -> str:
    """Format timestamp consistently."""
    if dt is None:
        dt = get_utc_now()
    return dt.strftime(format_str)


def calculate_duration(start_time: datetime) -> float:
    """Calculate duration in seconds from start_time to now."""
    return (get_utc_now() - start_time).total_seconds()
