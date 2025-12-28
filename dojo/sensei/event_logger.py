"""Structured event logging for KATA/training events.

Provides persistent, queryable records for each training event,
separate from the live UI feed.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class EventRecord:
    """
    Structured record for a single KATA/training event.

    All fields needed for experiment tracking and analysis.
    """

    # Experiment identifiers
    run_id: str
    model_id: str
    config_hash: str

    # Challenge identifiers
    challenge_id: str
    attempt_number: int

    # Prompt and context
    prompt: str
    system_context: Optional[str] = None
    input_context: Optional[str] = None

    # Outputs
    model_output: str = ""
    reference_output: Optional[str] = None  # Kata/gold solution

    # Evaluation
    eval_label: str = "UNKNOWN"  # POSITIVE, NEGATIVE, RECOVERY, GRADER_ERROR, etc.
    grade: Optional[str] = None
    score: int = 0

    # Task classification
    task_tags: List[str] = field(default_factory=list)

    # Execution details
    execution_success: bool = False
    error_type: Optional[str] = None
    error_message: Optional[str] = None
    duration_seconds: float = 0.0

    # Environment
    device_id: Optional[str] = None
    android_version: Optional[str] = None
    belt: Optional[str] = None

    # Metadata
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), default=str)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EventRecord":
        """Create from dictionary."""
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


def generate_config_hash(config: Dict[str, Any]) -> str:
    """
    Generate a stable hash for experiment configuration.

    Args:
        config: Configuration dictionary (model params, belt, etc.)

    Returns:
        8-character hex hash for the configuration.
    """
    # Sort keys for stable serialization
    config_str = json.dumps(config, sort_keys=True, default=str)
    return hashlib.sha256(config_str.encode()).hexdigest()[:8]


def infer_task_tags(challenge_id: str, output: str, description: str = "") -> List[str]:
    """
    Infer task tags from challenge ID and output.

    Args:
        challenge_id: The challenge identifier.
        output: The model output.
        description: Optional challenge description.

    Returns:
        List of inferred task tags.
    """
    tags = []
    combined = f"{challenge_id} {output} {description}".lower()

    # Platform tags
    tags.append("android")

    # Script type inference
    if "shell" in combined or "adb" in combined:
        tags.append("android.shell")
    if "frida" in combined or "java.use" in combined:
        tags.append("android.frida")
    if "#include" in combined or "ioctl" in combined:
        tags.append("android.native")

    # Domain-specific tags
    tag_patterns = {
        "android.shell.network": ["ip addr", "ip route", "netstat", "ss ", "ifconfig", "ping"],
        "android.shell.pm": ["pm list", "pm path", "pm dump", "pm grant"],
        "android.shell.am": ["am start", "am broadcast", "am force-stop"],
        "android.shell.dumpsys": ["dumpsys"],
        "android.shell.getprop": ["getprop"],
        "android.shell.logcat": ["logcat"],
        "android.shell.proc": ["/proc/", "cat /proc", "pidof"],
        "android.shell.settings": ["settings get", "settings put"],
        "android.ipc.intent": ["intent", "broadcast"],
        "android.ipc.content": ["content://", "content provider"],
        "android.security.permissions": ["permission", "grant", "revoke"],
        "android.security.selinux": ["selinux", "setenforce", "getenforce"],
        "vulnerability.recon": ["version", "fingerprint", "enumerate"],
        "vulnerability.exploit": ["exploit", "payload", "overflow", "injection"],
    }

    for tag, patterns in tag_patterns.items():
        if any(p in combined for p in patterns):
            tags.append(tag)

    # Belt-based tags
    belt_prefixes = ["white", "yellow", "orange", "green", "blue", "purple", "brown", "black"]
    for belt in belt_prefixes:
        if challenge_id.startswith(belt):
            tags.append(f"belt.{belt}")
            break

    return list(set(tags))  # Deduplicate


class EventLogger:
    """
    Structured event logger for KATA/training events.

    Stores events in JSONL format per run for easy querying and analysis.
    """

    def __init__(
        self,
        output_dir: Optional[Path] = None,
        run_id: Optional[str] = None,
        model_id: str = "unknown",
        config: Optional[Dict[str, Any]] = None,
    ):
        """
        Initialize the event logger.

        Args:
            output_dir: Directory for event logs.
            run_id: Unique run identifier. Auto-generated if not provided.
            model_id: Model identifier.
            config: Experiment configuration for hashing.
        """
        self.output_dir = output_dir or Path("./dojo_output/event_logs")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.run_id = run_id or f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
        self.model_id = model_id
        self.config = config or {}
        self.config_hash = generate_config_hash(self.config)

        # Log file for this run
        self.log_file = self.output_dir / f"{self.run_id}.jsonl"

        # In-memory buffer for batch operations
        self._buffer: List[EventRecord] = []
        self._event_count = 0

    def log_event(
        self,
        challenge_id: str,
        attempt_number: int,
        prompt: str,
        model_output: str,
        eval_label: str,
        reference_output: Optional[str] = None,
        system_context: Optional[str] = None,
        input_context: Optional[str] = None,
        grade: Optional[str] = None,
        score: int = 0,
        task_tags: Optional[List[str]] = None,
        execution_success: bool = False,
        error_type: Optional[str] = None,
        error_message: Optional[str] = None,
        duration_seconds: float = 0.0,
        device_id: Optional[str] = None,
        android_version: Optional[str] = None,
        belt: Optional[str] = None,
        description: str = "",
    ) -> EventRecord:
        """
        Log a structured event record.

        Args:
            challenge_id: Challenge identifier.
            attempt_number: Attempt number (1-indexed).
            prompt: Full prompt sent to model.
            model_output: Raw model output.
            eval_label: Evaluation label (POSITIVE, NEGATIVE, etc.)
            reference_output: Optional reference/kata solution.
            system_context: Optional system prompt.
            input_context: Optional input context.
            grade: Optional grade (A, B, C, D, F).
            score: Numeric score.
            task_tags: Optional task tags (auto-inferred if not provided).
            execution_success: Whether execution succeeded.
            error_type: Optional error type.
            error_message: Optional error message.
            duration_seconds: Execution duration.
            device_id: Optional device ID.
            android_version: Optional Android version.
            belt: Optional belt level.
            description: Optional challenge description for tag inference.

        Returns:
            The created EventRecord.
        """
        # Auto-infer task tags if not provided
        if task_tags is None:
            task_tags = infer_task_tags(challenge_id, model_output, description)

        record = EventRecord(
            run_id=self.run_id,
            model_id=self.model_id,
            config_hash=self.config_hash,
            challenge_id=challenge_id,
            attempt_number=attempt_number,
            prompt=prompt,
            system_context=system_context,
            input_context=input_context,
            model_output=model_output,
            reference_output=reference_output,
            eval_label=eval_label,
            grade=grade,
            score=score,
            task_tags=task_tags,
            execution_success=execution_success,
            error_type=error_type,
            error_message=error_message,
            duration_seconds=duration_seconds,
            device_id=device_id,
            android_version=android_version,
            belt=belt,
        )

        # Write to file immediately (append mode)
        self._write_record(record)
        self._event_count += 1

        return record

    def _write_record(self, record: EventRecord) -> None:
        """Write a single record to the log file."""
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(record.to_json() + "\n")

    def log_from_attempt(
        self,
        challenge: Any,  # Challenge object
        attempt: Any,  # AttemptRecord object
        assessment: Optional[Any] = None,  # SenseiAssessment object
        eval_label: Optional[str] = None,
    ) -> EventRecord:
        """
        Log an event from Challenger's AttemptRecord.

        Args:
            challenge: The Challenge object.
            attempt: The AttemptRecord object.
            assessment: Optional SenseiAssessment object.
            eval_label: Optional explicit eval_label (auto-determined if not provided).

        Returns:
            The created EventRecord.
        """
        # Determine eval_label if not provided
        if eval_label is None:
            if attempt.execution_result.success:
                eval_label = "POSITIVE"
            elif attempt.error_context:
                eval_label = "ERROR"
            else:
                eval_label = "NEGATIVE"

        # Extract error info
        error_type = None
        error_message = None
        if attempt.error_context:
            error_type = attempt.error_context.error_type
            error_message = attempt.error_context.error_message

        # Get grade/score from assessment
        grade = None
        score = 0
        if assessment:
            grade = assessment.grade.value if assessment.grade else None
            score = assessment.score

            # Check for grader error
            if assessment.corrected_output and self._is_infrastructure_error(
                assessment.corrected_output
            ):
                eval_label = "GRADER_ERROR"

        return self.log_event(
            challenge_id=challenge.id,
            attempt_number=attempt.attempt_number,
            prompt=attempt.prompt_used,
            model_output=attempt.model_output,
            eval_label=eval_label,
            reference_output=challenge.kata_solution,
            grade=grade,
            score=score,
            execution_success=attempt.execution_result.success,
            error_type=error_type,
            error_message=error_message,
            duration_seconds=attempt.execution_result.duration,
            belt=challenge.belt.value if challenge.belt else None,
            description=challenge.description,
        )

    @staticmethod
    def _is_infrastructure_error(output: str) -> bool:
        """Check if output contains infrastructure error patterns."""
        if not output:
            return False
        error_patterns = [
            "[ERROR:",
            "Traceback (most recent call last)",
            "TypeError:",
            "ValueError:",
            "got an unexpected keyword argument",
        ]
        output_lower = output.lower()
        return any(p.lower() in output_lower for p in error_patterns)

    def get_run_summary(self) -> Dict[str, Any]:
        """Get summary statistics for the current run."""
        events = self.load_events()

        if not events:
            return {
                "run_id": self.run_id,
                "model_id": self.model_id,
                "config_hash": self.config_hash,
                "total_events": 0,
                "by_label": {},
                "by_tag": {},
            }

        # Count by label
        by_label: Dict[str, int] = {}
        by_tag: Dict[str, int] = {}

        for e in events:
            label = e.eval_label
            by_label[label] = by_label.get(label, 0) + 1

            for tag in e.task_tags:
                by_tag[tag] = by_tag.get(tag, 0) + 1

        return {
            "run_id": self.run_id,
            "model_id": self.model_id,
            "config_hash": self.config_hash,
            "total_events": len(events),
            "by_label": by_label,
            "by_tag": by_tag,
        }

    def load_events(self, limit: Optional[int] = None) -> List[EventRecord]:
        """Load events from the log file."""
        if not self.log_file.exists():
            return []

        events = []
        with open(self.log_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        data = json.loads(line)
                        events.append(EventRecord.from_dict(data))
                    except json.JSONDecodeError:
                        continue

        if limit:
            events = events[-limit:]

        return events

    def query_events(
        self,
        eval_label: Optional[str] = None,
        challenge_prefix: Optional[str] = None,
        tag: Optional[str] = None,
        limit: int = 100,
    ) -> List[EventRecord]:
        """
        Query events with filters.

        Args:
            eval_label: Filter by eval label.
            challenge_prefix: Filter by challenge ID prefix.
            tag: Filter by task tag.
            limit: Maximum number of results.

        Returns:
            Filtered list of EventRecords.
        """
        events = self.load_events()

        if eval_label:
            events = [e for e in events if e.eval_label == eval_label]

        if challenge_prefix:
            events = [e for e in events if e.challenge_id.startswith(challenge_prefix)]

        if tag:
            events = [e for e in events if tag in e.task_tags]

        return events[-limit:]

    @property
    def event_count(self) -> int:
        """Get total event count for this run."""
        return self._event_count
