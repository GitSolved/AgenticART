"""
Core Utilities for AgenticART
"""

from datetime import datetime, timezone
from typing import Optional


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
