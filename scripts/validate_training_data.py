#!/usr/bin/env python3
"""
Validate training data JSONL files for AgenticART.

This script validates the format and quality of training data files,
ensuring they meet the requirements for model training.

Usage:
    python scripts/validate_training_data.py
    python scripts/validate_training_data.py --file path/to/data.jsonl
    python scripts/validate_training_data.py --strict

Exit codes:
    0 - All validations passed
    1 - Validation errors found
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


class ValidationError:
    """Represents a validation error."""

    def __init__(self, file: str, line: int, message: str, severity: str = "error"):
        self.file = file
        self.line = line
        self.message = message
        self.severity = severity

    def __str__(self) -> str:
        return f"{self.severity.upper()}: {self.file}:{self.line} - {self.message}"


class TrainingDataValidator:
    """Validates JSONL training data files."""

    # Required fields for trajectory format
    REQUIRED_TRAJECTORY_FIELDS = [
        "challenge_id",
        "objective",
        "steps",
    ]

    # Required fields for chat format
    REQUIRED_CHAT_FIELDS = [
        "messages",
    ]

    def __init__(self, strict: bool = False):
        self.strict = strict
        self.errors: list[ValidationError] = []
        self.warnings: list[ValidationError] = []

    def validate_file(self, filepath: Path) -> bool:
        """Validate a single JSONL file."""
        if not filepath.exists():
            self.errors.append(
                ValidationError(str(filepath), 0, "File does not exist")
            )
            return False

        if not filepath.suffix == ".jsonl":
            self.warnings.append(
                ValidationError(
                    str(filepath), 0, "File does not have .jsonl extension", "warning"
                )
            )

        entries = []
        hashes: set[str] = set()

        with open(filepath, "r") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                # Validate JSON format
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as e:
                    self.errors.append(
                        ValidationError(
                            str(filepath), line_num, f"Invalid JSON: {e}"
                        )
                    )
                    continue

                # Check for duplicates
                entry_hash = hashlib.md5(line.encode()).hexdigest()
                if entry_hash in hashes:
                    self.errors.append(
                        ValidationError(
                            str(filepath), line_num, "Duplicate entry detected"
                        )
                    )
                else:
                    hashes.add(entry_hash)

                # Validate entry structure
                self._validate_entry(filepath, line_num, entry)
                entries.append(entry)

        # Validate overall quality metrics
        if entries:
            self._validate_quality_metrics(filepath, entries)

        return len(self.errors) == 0

    def _validate_entry(self, filepath: Path, line_num: int, entry: dict) -> None:
        """Validate a single entry."""
        # Determine format type
        if "messages" in entry:
            self._validate_chat_format(filepath, line_num, entry)
        elif "steps" in entry:
            self._validate_trajectory_format(filepath, line_num, entry)
        else:
            self.errors.append(
                ValidationError(
                    str(filepath),
                    line_num,
                    "Unknown format: missing 'messages' or 'steps' field",
                )
            )

    def _validate_trajectory_format(
        self, filepath: Path, line_num: int, entry: dict
    ) -> None:
        """Validate trajectory format entry."""
        for field in self.REQUIRED_TRAJECTORY_FIELDS:
            if field not in entry:
                self.errors.append(
                    ValidationError(
                        str(filepath), line_num, f"Missing required field: {field}"
                    )
                )

        # Validate steps if present
        if "steps" in entry:
            steps = entry["steps"]
            if not isinstance(steps, list):
                self.errors.append(
                    ValidationError(
                        str(filepath), line_num, "'steps' must be a list"
                    )
                )
            elif len(steps) == 0:
                self.warnings.append(
                    ValidationError(
                        str(filepath), line_num, "Empty steps list", "warning"
                    )
                )
            else:
                for i, step in enumerate(steps):
                    self._validate_step(filepath, line_num, step, i)

    def _validate_step(
        self, filepath: Path, line_num: int, step: dict, step_idx: int
    ) -> None:
        """Validate a single step in a trajectory."""
        if not isinstance(step, dict):
            self.errors.append(
                ValidationError(
                    str(filepath), line_num, f"Step {step_idx} is not a dict"
                )
            )
            return

        # Steps should have thought and action
        if "thought" not in step and "action" not in step:
            self.warnings.append(
                ValidationError(
                    str(filepath),
                    line_num,
                    f"Step {step_idx} missing both 'thought' and 'action'",
                    "warning",
                )
            )

    def _validate_chat_format(
        self, filepath: Path, line_num: int, entry: dict
    ) -> None:
        """Validate chat/messages format entry."""
        messages = entry.get("messages", [])

        if not isinstance(messages, list):
            self.errors.append(
                ValidationError(
                    str(filepath), line_num, "'messages' must be a list"
                )
            )
            return

        if len(messages) == 0:
            self.errors.append(
                ValidationError(
                    str(filepath), line_num, "Empty messages list"
                )
            )
            return

        for i, msg in enumerate(messages):
            if not isinstance(msg, dict):
                self.errors.append(
                    ValidationError(
                        str(filepath), line_num, f"Message {i} is not a dict"
                    )
                )
                continue

            if "role" not in msg:
                self.errors.append(
                    ValidationError(
                        str(filepath), line_num, f"Message {i} missing 'role'"
                    )
                )

            if "content" not in msg:
                self.errors.append(
                    ValidationError(
                        str(filepath), line_num, f"Message {i} missing 'content'"
                    )
                )

    def _validate_quality_metrics(self, filepath: Path, entries: list[dict]) -> None:
        """Validate overall quality metrics."""
        total = len(entries)

        # Check for minimum dataset size
        if total < 10 and self.strict:
            self.warnings.append(
                ValidationError(
                    str(filepath),
                    0,
                    f"Dataset has only {total} entries (recommend >= 10)",
                    "warning",
                )
            )

        # Check success rate for trajectory format
        if entries and "final_outcome" in entries[0]:
            success_count = sum(
                1 for e in entries if e.get("final_outcome") == "success"
            )
            success_rate = success_count / total

            if success_rate < 0.3:
                self.warnings.append(
                    ValidationError(
                        str(filepath),
                        0,
                        f"Low success rate: {success_rate:.1%} (recommend >= 30%)",
                        "warning",
                    )
                )

    def validate_directory(self, dirpath: Path) -> bool:
        """Validate all JSONL files in a directory."""
        jsonl_files = list(dirpath.glob("**/*.jsonl"))

        if not jsonl_files:
            self.warnings.append(
                ValidationError(
                    str(dirpath), 0, "No JSONL files found", "warning"
                )
            )
            return True

        all_valid = True
        for filepath in jsonl_files:
            if not self.validate_file(filepath):
                all_valid = False

        return all_valid

    def print_report(self) -> None:
        """Print validation report."""
        print("\n" + "=" * 60)
        print("Training Data Validation Report")
        print("=" * 60)

        if self.errors:
            print(f"\n❌ ERRORS ({len(self.errors)}):")
            for error in self.errors:
                print(f"  {error}")

        if self.warnings:
            print(f"\n⚠️  WARNINGS ({len(self.warnings)}):")
            for warning in self.warnings:
                print(f"  {warning}")

        if not self.errors and not self.warnings:
            print("\n✅ All validations passed!")
        elif not self.errors:
            print(f"\n✅ Validation passed with {len(self.warnings)} warning(s)")
        else:
            print(f"\n❌ Validation failed with {len(self.errors)} error(s)")


def find_training_data_dirs() -> list[Path]:
    """Find common locations for training data."""
    possible_paths = [
        Path("trajectories/"),
        Path("dojo/master_dataset/"),
        Path("dojo/finetune/training_data/"),
        Path("training_data/"),
    ]

    return [p for p in possible_paths if p.exists()]


def main():
    parser = argparse.ArgumentParser(
        description="Validate JSONL training data files"
    )
    parser.add_argument(
        "--file",
        type=Path,
        help="Specific JSONL file to validate",
    )
    parser.add_argument(
        "--dir",
        type=Path,
        help="Directory containing JSONL files to validate",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Enable strict validation (more warnings)",
    )

    args = parser.parse_args()

    validator = TrainingDataValidator(strict=args.strict)

    if args.file:
        validator.validate_file(args.file)
    elif args.dir:
        validator.validate_directory(args.dir)
    else:
        # Auto-detect training data locations
        dirs = find_training_data_dirs()
        if not dirs:
            print("No training data directories found.")
            print("Looked in: trajectories/, dojo/master_dataset/, training_data/")
            print("\nTo validate a specific file: --file path/to/data.jsonl")
            print("To validate a directory: --dir path/to/dir/")
            sys.exit(0)

        for dirpath in dirs:
            print(f"\nValidating: {dirpath}/")
            validator.validate_directory(dirpath)

    validator.print_report()

    # Exit with error code if validation failed
    sys.exit(1 if validator.errors else 0)


if __name__ == "__main__":
    main()
