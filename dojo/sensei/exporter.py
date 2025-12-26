"""Exporter - exports training data in multiple formats."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional

from dojo.exceptions import ExportError
from dojo.models import Grade, TrainingExample


class ExportFormat(Enum):
    """Supported export formats."""

    JSONL = "jsonl"
    ALPACA = "alpaca"
    SHAREGPT = "sharegpt"
    DPO = "dpo"


@dataclass
class DPOPair:
    """A chosen/rejected pair for DPO training."""

    prompt: str
    chosen: str
    rejected: str
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "prompt": self.prompt,
            "chosen": self.chosen,
            "rejected": self.rejected,
        }

    def to_dict_with_metadata(self) -> dict:
        """Convert to dictionary with metadata."""
        return {
            "prompt": self.prompt,
            "chosen": self.chosen,
            "rejected": self.rejected,
            "metadata": self.metadata,
        }


class TrainingDataExporter:
    """Export training examples in various formats."""

    def __init__(self, output_dir: Optional[Path] = None):
        """
        Initialize the exporter.

        Args:
            output_dir: Directory for output files. Defaults to ./training_data.
        """
        self.output_dir = output_dir or Path("./training_data")
        self._ensure_output_dir()

    def _ensure_output_dir(self) -> None:
        """Create output directory if it doesn't exist."""
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export(
        self,
        examples: list[TrainingExample],
        format: ExportFormat,
        filename: Optional[str] = None,
    ) -> Path:
        """
        Export examples in specified format.

        Args:
            examples: List of training examples.
            format: Export format.
            filename: Optional filename (without extension).

        Returns:
            Path to exported file.

        Raises:
            ExportError: If export fails.
        """
        if not examples:
            raise ExportError("No examples to export", format=format.value)

        # Generate filename if not provided
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"training_{timestamp}"

        # Add extension based on format
        extension = ".jsonl" if format != ExportFormat.ALPACA else ".json"
        filepath = self.output_dir / f"{filename}_{format.value}{extension}"

        try:
            if format == ExportFormat.JSONL:
                self._export_jsonl(examples, filepath)
            elif format == ExportFormat.ALPACA:
                self._export_alpaca(examples, filepath)
            elif format == ExportFormat.SHAREGPT:
                self._export_sharegpt(examples, filepath)
            elif format == ExportFormat.DPO:
                self._export_dpo(examples, filepath)
            else:
                raise ExportError(f"Unknown format: {format}", format=format.value)

            return filepath

        except Exception as e:
            raise ExportError(
                f"Export failed: {e}",
                format=format.value,
                cause=e,
            )

    def export_all_formats(
        self,
        examples: list[TrainingExample],
        prefix: str = "training_data",
    ) -> dict[ExportFormat, Path]:
        """
        Export in all supported formats.

        Args:
            examples: List of training examples.
            prefix: Filename prefix.

        Returns:
            Dict mapping format to file path.
        """
        results = {}
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"{prefix}_{timestamp}"

        for format in ExportFormat:
            try:
                path = self.export(examples, format, base_filename)
                results[format] = path
            except ExportError:
                # Skip formats that fail (e.g., DPO needs pairs)
                continue

        return results

    def _export_jsonl(
        self,
        examples: list[TrainingExample],
        path: Path,
    ) -> None:
        """
        Export as JSONL with full metadata.

        Args:
            examples: List of training examples.
            path: Output file path.
        """
        with open(path, "w", encoding="utf-8") as f:
            for example in examples:
                data = example.to_dict()
                f.write(json.dumps(data, ensure_ascii=False) + "\n")

    def _export_alpaca(
        self,
        examples: list[TrainingExample],
        path: Path,
    ) -> None:
        """
        Export as Alpaca format (JSON array).

        Args:
            examples: List of training examples.
            path: Output file path.
        """
        # Filter to only positive and kata examples for Alpaca
        alpaca_examples = [
            e for e in examples if e.example_type in ("positive", "kata")
        ]

        data = [example.to_alpaca() for example in alpaca_examples]

        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def _export_sharegpt(
        self,
        examples: list[TrainingExample],
        path: Path,
    ) -> None:
        """
        Export as ShareGPT/OpenAI messages format.

        Args:
            examples: List of training examples.
            path: Output file path.
        """
        # Filter to positive and kata examples
        sharegpt_examples = [
            e for e in examples if e.example_type in ("positive", "kata", "error_recovery")
        ]

        with open(path, "w", encoding="utf-8") as f:
            for example in sharegpt_examples:
                data = example.to_sharegpt()
                f.write(json.dumps(data, ensure_ascii=False) + "\n")

    def _export_dpo(
        self,
        examples: list[TrainingExample],
        path: Path,
    ) -> None:
        """
        Export as DPO format with chosen/rejected pairs.

        Args:
            examples: List of training examples.
            path: Output file path.
        """
        pairs = self.create_dpo_pairs(examples)

        if not pairs:
            raise ExportError("No DPO pairs could be created", format="dpo")

        with open(path, "w", encoding="utf-8") as f:
            for pair in pairs:
                f.write(json.dumps(pair.to_dict(), ensure_ascii=False) + "\n")

    def create_dpo_pairs(
        self,
        examples: list[TrainingExample],
    ) -> list[DPOPair]:
        """
        Create DPO pairs from positive/negative examples.

        Strategy:
        1. Match positive (A/B grade) with negative (D/F grade) for same challenge
        2. Match kata solutions with failed attempts
        3. Extract from error recovery sequences

        Args:
            examples: List of training examples.

        Returns:
            List of DPO pairs.
        """
        pairs = []

        # Group by challenge
        by_challenge: dict[str, list[TrainingExample]] = defaultdict(list)
        for example in examples:
            by_challenge[example.source_challenge_id].append(example)

        for challenge_id, challenge_examples in by_challenge.items():
            # Separate by type
            positive = [
                e
                for e in challenge_examples
                if e.example_type in ("positive", "kata")
                and (e.grade is None or e.grade in (Grade.A, Grade.B))
            ]
            negative = [
                e for e in challenge_examples if e.example_type == "negative"
            ]
            error_recovery = [
                e for e in challenge_examples if e.example_type == "error_recovery"
            ]

            # Create pairs from positive/negative
            for pos in positive:
                for neg in negative:
                    rejected_output = self._extract_failed_output(neg.output_text)
                    if rejected_output:
                        pairs.append(
                            DPOPair(
                                prompt=f"{pos.instruction}\n\n{pos.input_text}".strip(),
                                chosen=pos.output_text,
                                rejected=rejected_output,
                                metadata={
                                    "challenge_id": challenge_id,
                                    "source": "positive_vs_negative",
                                },
                            )
                        )

            # Create pairs from error recovery sequences
            for er in error_recovery:
                failed_output = self._extract_failed_from_recovery(er.input_text)
                if failed_output:
                    pairs.append(
                        DPOPair(
                            prompt=er.instruction,
                            chosen=er.output_text,
                            rejected=failed_output,
                            metadata={
                                "challenge_id": challenge_id,
                                "source": "error_recovery",
                            },
                        )
                    )

        return pairs

    def _extract_failed_output(self, negative_output: str) -> Optional[str]:
        """
        Extract the failed output from a negative example.

        Args:
            negative_output: The full negative example output.

        Returns:
            The failed portion or None.
        """
        # Format is: INCORRECT:\n{failed}\n\nCORRECT:\n{correct}
        if "INCORRECT:" in negative_output and "CORRECT:" in negative_output:
            parts = negative_output.split("CORRECT:")
            if parts:
                incorrect_part = parts[0].replace("INCORRECT:", "").strip()
                return incorrect_part

        return None

    def _extract_failed_from_recovery(self, recovery_input: str) -> Optional[str]:
        """
        Extract the failed output from an error recovery input.

        Args:
            recovery_input: The error recovery input text.

        Returns:
            The failed command or None.
        """
        # Format includes "## Failed Attempt" section with code block
        if "## Failed Attempt" in recovery_input:
            lines = recovery_input.split("\n")
            in_failed = False
            failed_lines: list[str] = []

            for line in lines:
                if "## Failed Attempt" in line:
                    in_failed = True
                    continue
                if in_failed:
                    if line.strip() == "```":
                        if failed_lines:
                            break
                        continue
                    if line.startswith("## "):
                        break
                    failed_lines.append(line)

            if failed_lines:
                return "\n".join(failed_lines).strip()

        return None

    def get_export_stats(self, examples: list[TrainingExample]) -> dict:
        """
        Get statistics about potential exports.

        Args:
            examples: List of training examples.

        Returns:
            Statistics dictionary.
        """
        by_type: dict[str, int] = defaultdict(int)
        by_belt: dict[str, int] = defaultdict(int)
        by_grade: dict[str, int] = defaultdict(int)

        for example in examples:
            by_type[example.example_type] += 1
            by_belt[example.belt.value] += 1
            if example.grade:
                by_grade[example.grade.value] += 1

        # Count potential DPO pairs
        dpo_pairs = len(self.create_dpo_pairs(examples))

        return {
            "total_examples": len(examples),
            "by_type": dict(by_type),
            "by_belt": dict(by_belt),
            "by_grade": dict(by_grade),
            "potential_dpo_pairs": dpo_pairs,
            "alpaca_eligible": sum(
                1 for e in examples if e.example_type in ("positive", "kata")
            ),
            "sharegpt_eligible": sum(
                1
                for e in examples
                if e.example_type in ("positive", "kata", "error_recovery")
            ),
        }
