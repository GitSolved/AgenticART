"""Progress tracker - persists and manages model progress."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from dojo.models import Belt, Grade, ModelProgress, SenseiAssessment


class ProgressTracker:
    """Track and persist model progress through the belt system."""

    def __init__(self, storage_path: Optional[Path] = None):
        """
        Initialize the progress tracker.

        Args:
            storage_path: Directory for progress files. Defaults to ./progress.
        """
        self.storage_path = storage_path or Path("./progress")
        self._ensure_storage()

    def _ensure_storage(self) -> None:
        """Create storage directory if it doesn't exist."""
        self.storage_path.mkdir(parents=True, exist_ok=True)

    def _get_progress_file(self, model_id: str) -> Path:
        """Get the progress file path for a model."""
        # Sanitize model_id for filesystem
        safe_id = "".join(c if c.isalnum() or c in "-_" else "_" for c in model_id)
        return self.storage_path / f"{safe_id}_progress.json"

    def get_progress(self, model_id: str) -> ModelProgress:
        """
        Get or create progress for a model.

        Args:
            model_id: The model identifier.

        Returns:
            ModelProgress object.
        """
        existing = self.load_progress(model_id)
        if existing:
            return existing

        # Create new progress starting at white belt
        return ModelProgress(
            model_id=model_id,
            current_belt=Belt.WHITE,
        )

    def record_assessment(
        self,
        model_id: str,
        assessment: SenseiAssessment,
    ) -> ModelProgress:
        """
        Record an assessment and update progress.

        Args:
            model_id: The model identifier.
            assessment: The assessment to record.

        Returns:
            Updated ModelProgress.
        """
        progress = self.get_progress(model_id)
        progress.record_assessment(assessment)
        self.save_progress(progress)
        return progress

    def check_promotion(
        self,
        model_id: str,
        required_pass_rate: float = 80.0,
        required_challenges: int = 5,
    ) -> tuple[bool, Optional[Belt]]:
        """
        Check if model is eligible for belt promotion.

        Args:
            model_id: The model identifier.
            required_pass_rate: Minimum pass rate percentage.
            required_challenges: Minimum challenges attempted.

        Returns:
            Tuple of (is_eligible, next_belt).
        """
        progress = self.get_progress(model_id)

        if progress.check_promotion_eligibility(required_pass_rate, required_challenges):
            next_belt = progress.current_belt.next_belt()
            return True, next_belt

        return False, None

    def promote(self, model_id: str) -> Belt:
        """
        Promote model to next belt.

        Args:
            model_id: The model identifier.

        Returns:
            The new belt level.

        Raises:
            ValueError: If model is at max belt or not eligible.
        """
        progress = self.get_progress(model_id)
        next_belt = progress.current_belt.next_belt()

        if next_belt is None:
            raise ValueError(f"Model {model_id} is already at BLACK belt")

        # Reset counters for new belt
        progress.current_belt = next_belt
        progress.challenges_attempted = 0
        progress.challenges_passed = 0
        progress.total_score = 0
        # Keep assessments history

        self.save_progress(progress)
        return next_belt

    def save_progress(self, progress: ModelProgress) -> None:
        """
        Persist progress to storage.

        Args:
            progress: The ModelProgress to save.
        """
        filepath = self._get_progress_file(progress.model_id)

        # Convert to serializable format
        data = {
            "model_id": progress.model_id,
            "current_belt": progress.current_belt.value,
            "challenges_attempted": progress.challenges_attempted,
            "challenges_passed": progress.challenges_passed,
            "total_score": progress.total_score,
            "training_examples_generated": progress.training_examples_generated,
            "last_training_date": (
                progress.last_training_date.isoformat()
                if progress.last_training_date
                else None
            ),
            # Store assessment summaries, not full objects
            "assessment_count": len(progress.assessments),
            "assessments_summary": self._summarize_assessments(progress.assessments),
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def load_progress(self, model_id: str) -> Optional[ModelProgress]:
        """
        Load progress from storage.

        Args:
            model_id: The model identifier.

        Returns:
            ModelProgress or None if not found.
        """
        filepath = self._get_progress_file(model_id)

        if not filepath.exists():
            return None

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)

            progress = ModelProgress(
                model_id=data["model_id"],
                current_belt=Belt.from_string(data["current_belt"]),
                challenges_attempted=data.get("challenges_attempted", 0),
                challenges_passed=data.get("challenges_passed", 0),
                total_score=data.get("total_score", 0),
                training_examples_generated=data.get("training_examples_generated", 0),
            )

            if data.get("last_training_date"):
                progress.last_training_date = datetime.fromisoformat(
                    data["last_training_date"]
                )

            return progress

        except (json.JSONDecodeError, KeyError, ValueError):
            return None

    def _summarize_assessments(
        self,
        assessments: list[SenseiAssessment],
    ) -> list[dict]:
        """
        Create compact summaries of assessments.

        Args:
            assessments: List of assessments.

        Returns:
            List of summary dicts.
        """
        return [
            {
                "challenge_id": a.challenge_id,
                "grade": a.grade.value,
                "score": a.score,
                "timestamp": a.timestamp.isoformat(),
            }
            for a in assessments[-50:]  # Keep last 50
        ]

    def get_all_models(self) -> list[str]:
        """
        List all tracked models.

        Returns:
            List of model IDs.
        """
        models = []
        for filepath in self.storage_path.glob("*_progress.json"):
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    models.append(data.get("model_id", ""))
            except (json.JSONDecodeError, KeyError):
                continue

        return [m for m in models if m]

    def export_leaderboard(self) -> list[dict]:
        """
        Export leaderboard data for all models.

        Returns:
            List of model stats sorted by progress.
        """
        leaderboard = []

        for model_id in self.get_all_models():
            progress = self.get_progress(model_id)
            leaderboard.append(
                {
                    "model_id": model_id,
                    "belt": progress.current_belt.value,
                    "belt_display": progress.current_belt.display,
                    "belt_order": progress.current_belt.order,
                    "challenges_attempted": progress.challenges_attempted,
                    "challenges_passed": progress.challenges_passed,
                    "pass_rate": round(progress.pass_rate, 2),
                    "average_score": round(progress.average_score, 2),
                }
            )

        # Sort by belt (desc), then pass rate (desc), then average score (desc)
        leaderboard.sort(
            key=lambda x: (x["belt_order"], x["pass_rate"], x["average_score"]),
            reverse=True,
        )

        return leaderboard

    def reset_progress(self, model_id: str) -> None:
        """
        Reset progress for a model.

        Args:
            model_id: The model identifier.
        """
        filepath = self._get_progress_file(model_id)
        if filepath.exists():
            filepath.unlink()

    def update_training_stats(
        self,
        model_id: str,
        examples_generated: int,
    ) -> ModelProgress:
        """
        Update training statistics for a model.

        Args:
            model_id: The model identifier.
            examples_generated: Number of examples generated.

        Returns:
            Updated ModelProgress.
        """
        progress = self.get_progress(model_id)
        progress.training_examples_generated += examples_generated
        progress.last_training_date = datetime.now()
        self.save_progress(progress)
        return progress
