"""
Working Memory

Maintains current session state for the Planner/Summarizer loop.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional
from core.utils import get_utc_now, calculate_duration


@dataclass
class MemoryEntry:
    """Single memory entry."""
    key: str
    value: Any
    timestamp: datetime = field(default_factory=get_utc_now)
    ttl_seconds: Optional[int] = None


class WorkingMemory:
    """
    In-session working memory.

    Stores:
    - Current target information
    - Phase progress
    - Active findings
    - Command history
    """

    def __init__(self):
        self._store: dict[str, MemoryEntry] = {}
        self.session_start = get_utc_now()

    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """Store a value in working memory."""
        self._store[key] = MemoryEntry(key=key, value=value, ttl_seconds=ttl)

    def get(self, key: str, default: Any = None) -> Any:
        """Retrieve a value from working memory."""
        entry = self._store.get(key)
        if entry is None:
            return default

        # Check TTL
        if entry.ttl_seconds:
            elapsed = calculate_duration(entry.timestamp)
            if elapsed > entry.ttl_seconds:
                del self._store[key]
                return default

        return entry.value

    def update(self, key: str, value: Any):
        """Update existing value, preserving timestamp."""
        if key in self._store:
            self._store[key].value = value
        else:
            self.set(key, value)

    def append(self, key: str, value: Any):
        """Append to a list value."""
        current = self.get(key, [])
        if isinstance(current, list):
            current.append(value)
            self.update(key, current)

    def clear(self):
        """Clear all working memory."""
        self._store.clear()

    def export(self) -> dict:
        """Export working memory state."""
        return {k: v.value for k, v in self._store.items()}

    def get_session_duration(self) -> float:
        """Get session duration in seconds."""
        return calculate_duration(self.session_start)
