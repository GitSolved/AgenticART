"""Sensei - main orchestrator for grading and training data pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from dojo.curriculum import ChallengeSession
from dojo.models import Belt, Grade, ModelProgress, SenseiAssessment, TrainingExample
from dojo.sensei.exporter import ExportFormat, TrainingDataExporter
from dojo.sensei.grader import Grader
from dojo.sensei.master_refinery import MasterRefinery
from dojo.sensei.progress_tracker import ProgressTracker
from dojo.sensei.training_extractor import TrainingExtractor


@dataclass
class TrainingCycleResult:
    """Result of a complete training cycle."""

    assessments: list[SenseiAssessment]
    examples: list[TrainingExample]
    exports: dict[ExportFormat, Path]
    progress: ModelProgress
    promotion: Optional[Belt] = None
    stats: dict = field(default_factory=dict)

    def summary(self) -> str:
        """Get a human-readable summary."""
        lines = [
            "=== Training Cycle Complete ===",
            f"Sessions graded: {len(self.assessments)}",
            f"Examples extracted: {len(self.examples)}",
            f"Files exported: {len(self.exports)}",
            "",
            f"Model: {self.progress.model_id}",
            f"Belt: {self.progress.current_belt.display}",
            f"Pass Rate: {self.progress.pass_rate:.1f}%",
            f"Avg Score: {self.progress.average_score:.1f}",
        ]

        if self.promotion:
            lines.append(f"PROMOTED TO: {self.promotion.display}")

        return "\n".join(lines)


class Sensei:
    """
    The Sensei orchestrates the grading and training data pipeline.

    Workflow:
    1. Receive ChallengeSession from Challenger (Phase 2)
    2. Grade the session -> SenseiAssessment
    3. Extract training examples -> list[TrainingExample]
    4. Update model progress
    5. Export training data
    """

    def __init__(
        self,
        grader: Optional[Grader] = None,
        extractor: Optional[TrainingExtractor] = None,
        exporter: Optional[TrainingDataExporter] = None,
        progress_tracker: Optional[ProgressTracker] = None,
        output_dir: Optional[Path] = None,
    ):
        """
        Initialize the Sensei.
        """
        # Ensure we use a stable path for the data engine
        self.output_dir = output_dir or Path("./dojo_output")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.grader = grader or Grader()
        self.extractor = extractor or TrainingExtractor()

        # Initialize sub-components with the stable path
        self.exporter = exporter or TrainingDataExporter(
            output_dir=self.output_dir / "training_data"
        )
        self.progress_tracker = progress_tracker or ProgressTracker(
            storage_path=self.output_dir / "progress"
        )
        self.master_refinery = MasterRefinery(master_dir=self.output_dir.parent / "master_dataset")

    def evaluate_session(
        self,
        session: ChallengeSession,
        model_id: str,
    ) -> tuple[SenseiAssessment, list[TrainingExample]]:
        """
        Complete evaluation of a challenge session.

        Args:
            session: The challenge session to evaluate.
            model_id: The model identifier.

        Returns:
            Tuple of (assessment, training_examples).
        """
        # 1. Grade the session
        assessment = self.grader.grade_session(session)
        assessment.model_id = model_id

        # 2. Extract training examples
        examples = self.extractor.extract_from_session(session, assessment)

        # 3. Record in progress tracker
        self.progress_tracker.record_assessment(model_id, assessment)

        return assessment, examples

    def evaluate_sessions(
        self,
        sessions: list[ChallengeSession],
        model_id: str,
    ) -> tuple[list[SenseiAssessment], list[TrainingExample]]:
        """
        Evaluate multiple sessions.

        Args:
            sessions: List of challenge sessions.
            model_id: The model identifier.

        Returns:
            Tuple of (assessments, all_examples).
        """
        assessments = []
        all_examples = []

        for session in sessions:
            assessment, examples = self.evaluate_session(session, model_id)
            assessments.append(assessment)
            all_examples.extend(examples)

        return assessments, all_examples

    def run_training_cycle(
        self,
        sessions: list[ChallengeSession],
        model_id: str,
        export_formats: Optional[list[ExportFormat]] = None,
        auto_promote: bool = True,
    ) -> TrainingCycleResult:
        """
        Complete training cycle: grade, extract, export.

        Args:
            sessions: List of challenge sessions.
            model_id: The model identifier.
            export_formats: Formats to export (defaults to all).
            auto_promote: Whether to auto-promote if eligible.

        Returns:
            TrainingCycleResult with all outputs.
        """
        if export_formats is None:
            export_formats = list(ExportFormat)

        # 1. Evaluate all sessions
        assessments, examples = self.evaluate_sessions(sessions, model_id)

        # 2. Export training data
        exports = {}
        if examples:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            prefix = f"{model_id}_{timestamp}"

            for fmt in export_formats:
                try:
                    path = self.exporter.export(examples, fmt, prefix)
                    exports[fmt] = path
                except Exception:
                    # Skip formats that fail
                    continue

            # Update training stats
            self.progress_tracker.update_training_stats(model_id, len(examples))

            # Sync to Master Dataset (Automated Filtration & Build-up)
            added_alpaca, updated_alpaca = self.master_refinery.sync_alpaca(examples)
            added_discovery = self.master_refinery.sync_discovery(examples)

            # Extract DPO pairs for master sync
            new_dpo_pairs = self.exporter.create_dpo_pairs(examples)
            added_dpo = self.master_refinery.sync_dpo(new_dpo_pairs)

            print(
                f"Master Dataset Sync: +{added_alpaca} SFT, {updated_alpaca} Upgraded, +{added_discovery} Discovery, +{added_dpo} DPO pairs"
            )

        # 3. Get current progress
        progress = self.progress_tracker.get_progress(model_id)

        # 4. Check for promotion
        promotion = None
        if auto_promote:
            eligible, next_belt = self.progress_tracker.check_promotion(model_id)
            if eligible and next_belt:
                self.progress_tracker.promote(model_id)
                promotion = next_belt
                progress = self.progress_tracker.get_progress(model_id)

        # 5. Compile statistics
        stats = {
            "grading": self.grader.get_grading_summary(assessments),
            "extraction": self.extractor.get_extraction_summary(examples),
            "export": self.exporter.get_export_stats(examples) if examples else {},
        }

        return TrainingCycleResult(
            assessments=assessments,
            examples=examples,
            exports=exports,
            progress=progress,
            promotion=promotion,
            stats=stats,
        )

    def get_session_feedback(
        self,
        session: ChallengeSession,
        assessment: SenseiAssessment,
    ) -> str:
        """
        Generate human-readable feedback for a session.

        Args:
            session: The challenge session.
            assessment: The assessment.

        Returns:
            Feedback string.
        """
        lines = [
            f"Challenge: {session.challenge.name} ({session.challenge.id})",
            f"Belt: {session.challenge.belt.display}",
            "",
            f"Grade: {assessment.grade.value}",
            f"Score: {assessment.score}/100",
            f"Attempts: {session.total_attempts}",
            "",
        ]

        # Add issues if any
        if assessment.all_issues:
            lines.append("Issues Found:")
            for issue in assessment.all_issues[:5]:
                lines.append(f"  - {issue}")
            lines.append("")

        # Add correction if available
        if assessment.corrected_output:
            lines.append("Corrected Output:")
            lines.append(f"  {assessment.corrected_output}")
            lines.append("")

        # Add encouragement based on grade
        if assessment.grade == Grade.A:
            lines.append("Excellent work! This is a perfect solution.")
        elif assessment.grade == Grade.B:
            lines.append("Good job! Minor improvements possible.")
        elif assessment.grade == Grade.C:
            lines.append("Acceptable solution. Consider the feedback above.")
        elif assessment.grade == Grade.D:
            lines.append("Needs improvement. Study the corrected output.")
        else:
            lines.append("Failed. Review the error and try again.")

        return "\n".join(lines)

    def get_model_report(self, model_id: str) -> str:
        """
        Generate a progress report for a model.

        Args:
            model_id: The model identifier.

        Returns:
            Report string.
        """
        progress = self.progress_tracker.get_progress(model_id)

        lines = [
            "=" * 50,
            f"MODEL PROGRESS REPORT: {model_id}",
            "=" * 50,
            "",
            progress.display_status(),
            "",
        ]

        # Check promotion eligibility
        eligible, next_belt = self.progress_tracker.check_promotion(model_id)
        if eligible and next_belt:
            lines.append(f"ELIGIBLE FOR PROMOTION TO: {next_belt.display}")
        elif next_belt:
            remaining = 5 - progress.challenges_attempted
            if remaining > 0:
                lines.append(f"Complete {remaining} more challenges for promotion eligibility")
            else:
                needed_rate = 80.0 - progress.pass_rate
                lines.append(f"Need {needed_rate:.1f}% higher pass rate for promotion")

        lines.append("")
        lines.append("=" * 50)

        return "\n".join(lines)

    def get_leaderboard(self) -> str:
        """
        Get formatted leaderboard of all models.

        Returns:
            Leaderboard string.
        """
        leaderboard = self.progress_tracker.export_leaderboard()

        if not leaderboard:
            return "No models tracked yet."

        lines = [
            "=" * 60,
            "DOJO LEADERBOARD",
            "=" * 60,
            "",
            f"{'Rank':<5} {'Model':<25} {'Belt':<10} {'Pass%':<8} {'Avg':<6}",
            "-" * 60,
        ]

        for i, entry in enumerate(leaderboard, 1):
            lines.append(
                f"{i:<5} {entry['model_id']:<25} {entry['belt']:<10} "
                f"{entry['pass_rate']:<8.1f} {entry['average_score']:<6.1f}"
            )

        lines.append("=" * 60)

        return "\n".join(lines)
