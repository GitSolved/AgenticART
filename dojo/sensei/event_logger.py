"""Structured event logging for KATA/training events.

Provides persistent, queryable records for each training event,
separate from the live UI feed.

Schema Documentation
--------------------
EventRecord fields for offline analysis:

Experiment Identifiers:
  - run_id: str - Unique identifier for the training run
  - model_id: str - Model identifier (e.g., "qwen2.5-coder-7b")
  - config_hash: str - 8-char SHA256 hash of experiment config

Challenge Identifiers:
  - challenge_id: str - KATA challenge ID (e.g., "white_shell_ip_001")
  - attempt_number: int - Attempt number within challenge (1-indexed)

Prompt/Context:
  - prompt: str - Full prompt sent to model
  - system_context: str|null - System prompt if any
  - input_context: str|null - Additional input context

Outputs:
  - model_output: str - Raw model output
  - reference_output: str|null - Kata/gold solution if available

Evaluation:
  - eval_label: str - POSITIVE|NEGATIVE|ERROR|RECOVERY|GRADER_ERROR|UNKNOWN
  - grade: str|null - Letter grade (A, B, C, D, F)
  - score: int - Numeric score (0-100)

Task Classification:
  - task_tags: list[str] - Inferred task tags (e.g., android.shell.network)

Execution Details:
  - execution_success: bool - Whether execution succeeded
  - error_type: str|null - Error classification if failed
  - error_message: str|null - Error details if failed
  - duration_seconds: float - Execution duration

Environment:
  - device_id: str|null - Target device identifier
  - android_version: str|null - Android version
  - belt: str|null - Belt level (white, yellow, etc.)

Metadata:
  - event_id: str - UUID for this event
  - timestamp: str - ISO 8601 timestamp

Export Formats:
  - JSONL: Line-delimited JSON, one record per line
  - Parquet: Columnar format for efficient analytics (requires pyarrow)

Example notebook usage:
  import pandas as pd
  df = pd.read_parquet("run_20241228_123456.parquet")
  df.groupby("eval_label").size()
"""

from __future__ import annotations

import hashlib
import json
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

        self.run_id = (
            run_id or f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
        )
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

    # -------------------------------------------------------------------------
    # Export Methods
    # -------------------------------------------------------------------------

    def export_jsonl(self, output_path: Optional[Path] = None) -> Path:
        """
        Export all events to a JSONL file with config metadata.

        Args:
            output_path: Optional output path. Defaults to exports directory.

        Returns:
            Path to the exported file.
        """
        export_dir = self.output_dir / "exports"
        export_dir.mkdir(parents=True, exist_ok=True)

        if output_path is None:
            output_path = export_dir / f"{self.run_id}_export.jsonl"

        events = self.load_events()

        with open(output_path, "w", encoding="utf-8") as f:
            # Write config header as first line
            header = {
                "_type": "run_config",
                "run_id": self.run_id,
                "model_id": self.model_id,
                "config": self.config,
                "config_hash": self.config_hash,
                "exported_at": datetime.now().isoformat(),
                "total_events": len(events),
                "schema_version": "1.0",
            }
            f.write(json.dumps(header) + "\n")

            # Write all events
            for event in events:
                f.write(event.to_json() + "\n")

        return output_path

    def export_parquet(self, output_path: Optional[Path] = None) -> Path:
        """
        Export all events to a Parquet file for efficient analytics.

        Requires pandas and pyarrow to be installed.

        Args:
            output_path: Optional output path. Defaults to exports directory.

        Returns:
            Path to the exported file.

        Raises:
            ImportError: If pandas is not available.
        """
        try:
            import pandas as pd
        except ImportError as e:
            raise ImportError(
                "pandas is required for Parquet export. Install with: pip install pandas pyarrow"
            ) from e

        export_dir = self.output_dir / "exports"
        export_dir.mkdir(parents=True, exist_ok=True)

        if output_path is None:
            output_path = export_dir / f"{self.run_id}_export.parquet"

        events = self.load_events()

        if not events:
            # Create empty DataFrame with schema
            df = pd.DataFrame(columns=list(EventRecord.__dataclass_fields__.keys()))
        else:
            # Convert events to DataFrame
            records = [e.to_dict() for e in events]
            df = pd.DataFrame(records)

            # Convert task_tags list to JSON string for Parquet compatibility
            if "task_tags" in df.columns:
                df["task_tags"] = df["task_tags"].apply(json.dumps)

        # Add run metadata as DataFrame attributes (stored in Parquet metadata)
        df.attrs["run_id"] = self.run_id
        df.attrs["model_id"] = self.model_id
        df.attrs["config_hash"] = self.config_hash
        df.attrs["exported_at"] = datetime.now().isoformat()

        # Write to Parquet
        df.to_parquet(output_path, index=False, engine="auto")

        return output_path

    def export_run_bundle(self, output_dir: Optional[Path] = None) -> Dict[str, Path]:
        """
        Export a complete run bundle with all formats and metadata.

        Creates:
          - {run_id}_export.jsonl - Events in JSONL format
          - {run_id}_export.parquet - Events in Parquet format (if pandas available)
          - {run_id}_config.json - Full configuration and summary

        Args:
            output_dir: Optional output directory. Defaults to exports directory.

        Returns:
            Dictionary mapping format names to file paths.
        """
        if output_dir is None:
            output_dir = self.output_dir / "exports"
        output_dir.mkdir(parents=True, exist_ok=True)

        exported_files: Dict[str, Path] = {}

        # Export JSONL
        jsonl_path = self.export_jsonl(output_dir / f"{self.run_id}_export.jsonl")
        exported_files["jsonl"] = jsonl_path

        # Export Parquet (if pandas available)
        try:
            parquet_path = self.export_parquet(output_dir / f"{self.run_id}_export.parquet")
            exported_files["parquet"] = parquet_path
        except ImportError:
            pass  # Skip Parquet if pandas not available

        # Export config and summary
        summary = self.get_run_summary()
        config_data = {
            "run_id": self.run_id,
            "model_id": self.model_id,
            "config": self.config,
            "config_hash": self.config_hash,
            "exported_at": datetime.now().isoformat(),
            "summary": summary,
            "schema_version": "1.0",
            "schema_docs": get_schema_documentation(),
        }

        config_path = output_dir / f"{self.run_id}_config.json"
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config_data, f, indent=2, default=str)
        exported_files["config"] = config_path

        return exported_files

    @staticmethod
    def list_available_runs(output_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
        """
        List all available runs in the output directory.

        Args:
            output_dir: Directory containing event logs.

        Returns:
            List of run metadata dictionaries.
        """
        if output_dir is None:
            output_dir = Path("./dojo_output/event_logs")

        if not output_dir.exists():
            return []

        runs = []
        for log_file in output_dir.glob("*.jsonl"):
            if log_file.name.endswith("_export.jsonl"):
                continue  # Skip export files

            run_id = log_file.stem
            try:
                # Read first line for metadata if available
                with open(log_file, "r", encoding="utf-8") as f:
                    first_line = f.readline()
                    if first_line:
                        first_event = json.loads(first_line)
                        runs.append(
                            {
                                "run_id": run_id,
                                "model_id": first_event.get("model_id", "unknown"),
                                "config_hash": first_event.get("config_hash", ""),
                                "log_file": log_file,
                                "size_bytes": log_file.stat().st_size,
                                "modified": datetime.fromtimestamp(
                                    log_file.stat().st_mtime
                                ).isoformat(),
                            }
                        )
            except (json.JSONDecodeError, KeyError):
                runs.append(
                    {
                        "run_id": run_id,
                        "model_id": "unknown",
                        "log_file": log_file,
                        "size_bytes": log_file.stat().st_size,
                    }
                )

        return sorted(runs, key=lambda x: x.get("modified", ""), reverse=True)


def get_schema_documentation() -> Dict[str, Any]:
    """
    Get the EventRecord schema as a structured dictionary.

    Returns:
        Schema documentation suitable for JSON export.
    """
    return {
        "schema_version": "1.0",
        "description": "AgenticART KATA Event Log Schema",
        "fields": {
            "run_id": {
                "type": "string",
                "description": "Unique identifier for the training run",
                "example": "run_20241228_143052_a1b2c3",
            },
            "model_id": {
                "type": "string",
                "description": "Model identifier",
                "example": "qwen2.5-coder-7b",
            },
            "config_hash": {
                "type": "string",
                "description": "8-character SHA256 hash of experiment config",
                "example": "a1b2c3d4",
            },
            "challenge_id": {
                "type": "string",
                "description": "KATA challenge identifier",
                "example": "white_shell_ip_001",
            },
            "attempt_number": {
                "type": "integer",
                "description": "Attempt number within challenge (1-indexed)",
                "example": 1,
            },
            "prompt": {
                "type": "string",
                "description": "Full prompt sent to model",
            },
            "system_context": {
                "type": "string|null",
                "description": "System prompt if any",
            },
            "input_context": {
                "type": "string|null",
                "description": "Additional input context",
            },
            "model_output": {
                "type": "string",
                "description": "Raw model output",
            },
            "reference_output": {
                "type": "string|null",
                "description": "Kata/gold solution if available",
            },
            "eval_label": {
                "type": "string",
                "description": "Evaluation label",
                "enum": [
                    "POSITIVE",
                    "NEGATIVE",
                    "ERROR",
                    "RECOVERY",
                    "GRADER_ERROR",
                    "UNKNOWN",
                ],
            },
            "grade": {
                "type": "string|null",
                "description": "Letter grade",
                "enum": ["A", "B", "C", "D", "F", None],
            },
            "score": {
                "type": "integer",
                "description": "Numeric score (0-100)",
            },
            "task_tags": {
                "type": "array[string]",
                "description": "Inferred task classification tags",
                "examples": [
                    "android",
                    "android.shell",
                    "android.shell.network",
                    "android.frida",
                    "belt.white",
                ],
            },
            "execution_success": {
                "type": "boolean",
                "description": "Whether execution succeeded",
            },
            "error_type": {
                "type": "string|null",
                "description": "Error classification if failed",
            },
            "error_message": {
                "type": "string|null",
                "description": "Error details if failed",
            },
            "duration_seconds": {
                "type": "float",
                "description": "Execution duration in seconds",
            },
            "device_id": {
                "type": "string|null",
                "description": "Target device identifier",
            },
            "android_version": {
                "type": "string|null",
                "description": "Android version",
            },
            "belt": {
                "type": "string|null",
                "description": "Belt level",
                "enum": [
                    "white",
                    "yellow",
                    "orange",
                    "green",
                    "blue",
                    "purple",
                    "brown",
                    "black",
                ],
            },
            "event_id": {
                "type": "string",
                "description": "UUID for this event",
            },
            "timestamp": {
                "type": "string",
                "description": "ISO 8601 timestamp",
            },
        },
        "file_formats": {
            "jsonl": {
                "description": "Line-delimited JSON, first line is run config header",
                "extension": ".jsonl",
            },
            "parquet": {
                "description": "Apache Parquet columnar format for analytics",
                "extension": ".parquet",
                "note": "task_tags stored as JSON string",
            },
        },
    }
