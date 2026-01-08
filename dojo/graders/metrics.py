"""
Grading Metrics and Calibration Tracking.

Tracks model performance, confidence calibration, and training progress.
"""

from __future__ import annotations

import json
import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from dojo.models_v2 import (
    Belt,
    PhaseID,
    Pillar,
    ReasoningChain,
)
from dojo.graders.reasoning_grader import GradingResult


@dataclass
class Prediction:
    """A single prediction with confidence for calibration tracking."""

    challenge_id: str
    phase_id: PhaseID
    predicted_vulnerable: bool
    actual_vulnerable: bool
    confidence: float  # 0.0 - 1.0
    score: float  # Grading score
    timestamp: datetime = field(default_factory=datetime.now)

    @property
    def is_correct(self) -> bool:
        return self.predicted_vulnerable == self.actual_vulnerable

    @property
    def is_false_positive(self) -> bool:
        return self.predicted_vulnerable and not self.actual_vulnerable

    @property
    def is_false_negative(self) -> bool:
        return not self.predicted_vulnerable and self.actual_vulnerable


@dataclass
class CalibrationBucket:
    """A bucket for binned calibration analysis."""

    lower_bound: float
    upper_bound: float
    predictions: list[Prediction] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.predictions)

    @property
    def avg_confidence(self) -> float:
        if not self.predictions:
            return (self.lower_bound + self.upper_bound) / 2
        return sum(p.confidence for p in self.predictions) / len(self.predictions)

    @property
    def accuracy(self) -> float:
        if not self.predictions:
            return 0.0
        return sum(1 for p in self.predictions if p.is_correct) / len(self.predictions)

    @property
    def calibration_error(self) -> float:
        """Expected Calibration Error contribution from this bucket."""
        return abs(self.avg_confidence - self.accuracy) * self.count


class CalibrationTracker:
    """
    Tracks and analyzes confidence calibration.

    A well-calibrated model should have:
    - 70% accuracy when it says 70% confident
    - 90% accuracy when it says 90% confident
    """

    def __init__(self, num_bins: int = 10):
        """
        Initialize tracker.

        Args:
            num_bins: Number of confidence bins for calibration analysis
        """
        self.num_bins = num_bins
        self.predictions: list[Prediction] = []
        self._buckets: Optional[list[CalibrationBucket]] = None

    def add_prediction(self, prediction: Prediction) -> None:
        """Add a prediction for tracking."""
        self.predictions.append(prediction)
        self._buckets = None  # Invalidate cache

    def add_from_grading(
        self,
        challenge_id: str,
        phase_id: PhaseID,
        result: GradingResult,
        actual_vulnerable: bool,
        predicted_vulnerable: bool,
        confidence: float,
    ) -> None:
        """Add prediction from grading result."""
        self.add_prediction(Prediction(
            challenge_id=challenge_id,
            phase_id=phase_id,
            predicted_vulnerable=predicted_vulnerable,
            actual_vulnerable=actual_vulnerable,
            confidence=confidence,
            score=result.total_score,
        ))

    def _build_buckets(self) -> list[CalibrationBucket]:
        """Build calibration buckets from predictions."""
        buckets = []
        bin_size = 1.0 / self.num_bins

        for i in range(self.num_bins):
            lower = i * bin_size
            upper = (i + 1) * bin_size
            bucket = CalibrationBucket(lower_bound=lower, upper_bound=upper)

            for pred in self.predictions:
                if lower <= pred.confidence < upper or (i == self.num_bins - 1 and pred.confidence == upper):
                    bucket.predictions.append(pred)

            buckets.append(bucket)

        return buckets

    @property
    def buckets(self) -> list[CalibrationBucket]:
        """Get calibration buckets (cached)."""
        if self._buckets is None:
            self._buckets = self._build_buckets()
        return self._buckets

    def expected_calibration_error(self) -> float:
        """
        Calculate Expected Calibration Error (ECE).

        ECE = Σ (|bucket_count| / n) * |accuracy - confidence|

        Returns:
            ECE score (lower is better, 0 = perfect calibration)
        """
        if not self.predictions:
            return 0.0

        total_error = sum(b.calibration_error for b in self.buckets)
        return total_error / len(self.predictions)

    def maximum_calibration_error(self) -> float:
        """
        Calculate Maximum Calibration Error (MCE).

        Returns the largest calibration error across all bins.
        """
        if not self.predictions:
            return 0.0

        non_empty_buckets = [b for b in self.buckets if b.count > 0]
        if not non_empty_buckets:
            return 0.0

        return max(abs(b.avg_confidence - b.accuracy) for b in non_empty_buckets)

    def overconfidence_rate(self) -> float:
        """
        Calculate how often model is overconfident.

        Returns fraction of predictions where confidence > accuracy.
        """
        overconfident = 0
        for bucket in self.buckets:
            if bucket.count > 0 and bucket.avg_confidence > bucket.accuracy:
                overconfident += bucket.count

        return overconfident / len(self.predictions) if self.predictions else 0.0

    def brier_score(self) -> float:
        """
        Calculate Brier score.

        Brier = (1/n) Σ (confidence - actual)²

        Returns:
            Brier score (lower is better, 0 = perfect)
        """
        if not self.predictions:
            return 0.0

        total = 0.0
        for pred in self.predictions:
            actual = 1.0 if pred.actual_vulnerable else 0.0
            total += (pred.confidence - actual) ** 2

        return total / len(self.predictions)

    def calibration_score(self) -> float:
        """
        Calculate calibration score (1 - ECE).

        Returns:
            Score from 0-1 (higher is better)
        """
        return max(0.0, 1.0 - self.expected_calibration_error())

    def reliability_diagram_data(self) -> list[dict]:
        """
        Get data for plotting reliability diagram.

        Returns:
            List of dicts with bucket data for visualization
        """
        return [
            {
                "bin_center": (b.lower_bound + b.upper_bound) / 2,
                "lower": b.lower_bound,
                "upper": b.upper_bound,
                "confidence": b.avg_confidence,
                "accuracy": b.accuracy,
                "count": b.count,
                "gap": abs(b.avg_confidence - b.accuracy),
            }
            for b in self.buckets
            if b.count > 0
        ]

    def to_dict(self) -> dict:
        """Export metrics as dictionary."""
        return {
            "total_predictions": len(self.predictions),
            "ece": self.expected_calibration_error(),
            "mce": self.maximum_calibration_error(),
            "brier_score": self.brier_score(),
            "calibration_score": self.calibration_score(),
            "overconfidence_rate": self.overconfidence_rate(),
            "reliability_diagram": self.reliability_diagram_data(),
        }


@dataclass
class GradingMetrics:
    """
    Comprehensive metrics for model grading performance.

    Tracks:
    - Overall scores by pillar, belt, phase
    - Error rates (false positives, false negatives)
    - Reasoning quality metrics
    - Calibration
    """

    # Raw data
    grading_results: list[tuple[str, GradingResult]] = field(default_factory=list)
    reasoning_chains: list[ReasoningChain] = field(default_factory=list)

    # Aggregated metrics (cached)
    _pillar_scores: Optional[dict[str, list[float]]] = field(default=None, repr=False)
    _belt_scores: Optional[dict[str, list[float]]] = field(default=None, repr=False)
    _phase_scores: Optional[dict[str, list[float]]] = field(default=None, repr=False)

    # Error tracking
    false_positives: int = 0
    false_negatives: int = 0
    true_positives: int = 0
    true_negatives: int = 0

    # Calibration
    calibration_tracker: CalibrationTracker = field(default_factory=CalibrationTracker)

    # Hallucination tracking
    total_responses: int = 0
    responses_with_hallucinations: int = 0

    def add_result(
        self,
        challenge_id: str,
        result: GradingResult,
        pillar: Pillar,
        belt: Belt,
        actual_vulnerable: bool,
        predicted_vulnerable: bool,
        confidence: float = 0.5,
    ) -> None:
        """Add a grading result to metrics."""
        self.grading_results.append((challenge_id, result))

        # Update pillar scores
        if self._pillar_scores is None:
            self._pillar_scores = defaultdict(list)
        self._pillar_scores[pillar.value].append(result.total_score)

        # Update belt scores
        if self._belt_scores is None:
            self._belt_scores = defaultdict(list)
        self._belt_scores[belt.value].append(result.total_score)

        # Update phase scores
        if self._phase_scores is None:
            self._phase_scores = defaultdict(list)
        self._phase_scores[result.phase_id.value].append(result.total_score)

        # Update error tracking
        if predicted_vulnerable and actual_vulnerable:
            self.true_positives += 1
        elif predicted_vulnerable and not actual_vulnerable:
            self.false_positives += 1
        elif not predicted_vulnerable and actual_vulnerable:
            self.false_negatives += 1
        else:
            self.true_negatives += 1

        # Update calibration
        self.calibration_tracker.add_from_grading(
            challenge_id=challenge_id,
            phase_id=result.phase_id,
            result=result,
            actual_vulnerable=actual_vulnerable,
            predicted_vulnerable=predicted_vulnerable,
            confidence=confidence,
        )

        # Update hallucination tracking
        self.total_responses += 1
        if result.hallucinations:
            self.responses_with_hallucinations += 1

    def add_reasoning_chain(self, chain: ReasoningChain) -> None:
        """Add a complete reasoning chain."""
        self.reasoning_chains.append(chain)

    # ─────────────────────────────────────────────────────────────────────────
    # Score Aggregations
    # ─────────────────────────────────────────────────────────────────────────

    @property
    def overall_score(self) -> float:
        """Calculate overall average score."""
        if not self.grading_results:
            return 0.0
        return sum(r.total_score for _, r in self.grading_results) / len(self.grading_results)

    @property
    def pillar_scores(self) -> dict[str, float]:
        """Get average score per pillar."""
        if not self._pillar_scores:
            return {}
        return {
            pillar: sum(scores) / len(scores)
            for pillar, scores in self._pillar_scores.items()
            if scores
        }

    @property
    def belt_scores(self) -> dict[str, float]:
        """Get average score per belt."""
        if not self._belt_scores:
            return {}
        return {
            belt: sum(scores) / len(scores)
            for belt, scores in self._belt_scores.items()
            if scores
        }

    @property
    def phase_scores(self) -> dict[str, float]:
        """Get average score per phase type."""
        if not self._phase_scores:
            return {}
        return {
            phase: sum(scores) / len(scores)
            for phase, scores in self._phase_scores.items()
            if scores
        }

    # ─────────────────────────────────────────────────────────────────────────
    # Error Rates
    # ─────────────────────────────────────────────────────────────────────────

    @property
    def total_predictions(self) -> int:
        """Total number of vulnerability predictions."""
        return self.true_positives + self.true_negatives + self.false_positives + self.false_negatives

    @property
    def false_positive_rate(self) -> float:
        """Rate of false positive errors (Type I error)."""
        total_negatives = self.true_negatives + self.false_positives
        if total_negatives == 0:
            return 0.0
        return self.false_positives / total_negatives

    @property
    def false_negative_rate(self) -> float:
        """Rate of false negative errors (Type II error)."""
        total_positives = self.true_positives + self.false_negatives
        if total_positives == 0:
            return 0.0
        return self.false_negatives / total_positives

    @property
    def precision(self) -> float:
        """Precision: TP / (TP + FP)."""
        denominator = self.true_positives + self.false_positives
        if denominator == 0:
            return 0.0
        return self.true_positives / denominator

    @property
    def recall(self) -> float:
        """Recall (sensitivity): TP / (TP + FN)."""
        denominator = self.true_positives + self.false_negatives
        if denominator == 0:
            return 0.0
        return self.true_positives / denominator

    @property
    def f1_score(self) -> float:
        """F1 score: harmonic mean of precision and recall."""
        if self.precision + self.recall == 0:
            return 0.0
        return 2 * (self.precision * self.recall) / (self.precision + self.recall)

    @property
    def accuracy(self) -> float:
        """Overall accuracy: (TP + TN) / total."""
        if self.total_predictions == 0:
            return 0.0
        return (self.true_positives + self.true_negatives) / self.total_predictions

    # ─────────────────────────────────────────────────────────────────────────
    # Reasoning Quality
    # ─────────────────────────────────────────────────────────────────────────

    @property
    def avg_reasoning_quality(self) -> float:
        """Average reasoning quality across chains."""
        qualities = [
            c.reasoning_quality.overall
            for c in self.reasoning_chains
            if c.reasoning_quality
        ]
        return sum(qualities) / len(qualities) if qualities else 0.0

    @property
    def avg_depth(self) -> float:
        """Average depth score from reasoning chains."""
        depths = [
            c.reasoning_quality.depth
            for c in self.reasoning_chains
            if c.reasoning_quality
        ]
        return sum(depths) / len(depths) if depths else 0.0

    @property
    def avg_transferability(self) -> float:
        """Average transferability score."""
        transfers = [
            c.reasoning_quality.transferability
            for c in self.reasoning_chains
            if c.reasoning_quality
        ]
        return sum(transfers) / len(transfers) if transfers else 0.0

    # ─────────────────────────────────────────────────────────────────────────
    # Hallucination Metrics
    # ─────────────────────────────────────────────────────────────────────────

    @property
    def hallucination_rate(self) -> float:
        """Rate of responses containing hallucinations."""
        if self.total_responses == 0:
            return 0.0
        return self.responses_with_hallucinations / self.total_responses

    # ─────────────────────────────────────────────────────────────────────────
    # Export
    # ─────────────────────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        """Export all metrics as dictionary."""
        return {
            "summary": {
                "total_graded": len(self.grading_results),
                "total_chains": len(self.reasoning_chains),
                "overall_score": self.overall_score,
            },
            "scores": {
                "by_pillar": self.pillar_scores,
                "by_belt": self.belt_scores,
                "by_phase": self.phase_scores,
            },
            "errors": {
                "true_positives": self.true_positives,
                "true_negatives": self.true_negatives,
                "false_positives": self.false_positives,
                "false_negatives": self.false_negatives,
                "false_positive_rate": self.false_positive_rate,
                "false_negative_rate": self.false_negative_rate,
                "precision": self.precision,
                "recall": self.recall,
                "f1_score": self.f1_score,
                "accuracy": self.accuracy,
            },
            "reasoning": {
                "avg_quality": self.avg_reasoning_quality,
                "avg_depth": self.avg_depth,
                "avg_transferability": self.avg_transferability,
            },
            "calibration": self.calibration_tracker.to_dict(),
            "hallucination": {
                "rate": self.hallucination_rate,
                "affected_responses": self.responses_with_hallucinations,
                "total_responses": self.total_responses,
            },
        }

    def to_json(self, indent: int = 2) -> str:
        """Export as JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def summary(self) -> str:
        """Generate human-readable summary."""
        lines = [
            "═" * 60,
            "GRADING METRICS SUMMARY",
            "═" * 60,
            "",
            f"Total Graded: {len(self.grading_results)}",
            f"Overall Score: {self.overall_score:.2%}",
            "",
            "─" * 40,
            "SCORES BY PILLAR",
            "─" * 40,
        ]

        for pillar, score in sorted(self.pillar_scores.items()):
            lines.append(f"  {pillar}: {score:.2%}")

        lines.extend([
            "",
            "─" * 40,
            "ERROR RATES",
            "─" * 40,
            f"  Precision: {self.precision:.2%}",
            f"  Recall: {self.recall:.2%}",
            f"  F1 Score: {self.f1_score:.2%}",
            f"  False Positive Rate: {self.false_positive_rate:.2%}",
            f"  False Negative Rate: {self.false_negative_rate:.2%}",
            "",
            "─" * 40,
            "CALIBRATION",
            "─" * 40,
            f"  Calibration Score: {self.calibration_tracker.calibration_score():.2%}",
            f"  ECE: {self.calibration_tracker.expected_calibration_error():.4f}",
            f"  Overconfidence Rate: {self.calibration_tracker.overconfidence_rate():.2%}",
            "",
            "─" * 40,
            "REASONING QUALITY",
            "─" * 40,
            f"  Average Quality: {self.avg_reasoning_quality:.2%}",
            f"  Average Depth: {self.avg_depth:.2%}",
            f"  Hallucination Rate: {self.hallucination_rate:.2%}",
            "",
            "═" * 60,
        ])

        return "\n".join(lines)


@dataclass
class TrainingProgressTracker:
    """
    Tracks training progress over time.

    Stores historical metrics to visualize improvement.
    """

    model_id: str
    checkpoints: list[dict] = field(default_factory=list)

    def add_checkpoint(
        self,
        metrics: GradingMetrics,
        epoch: int,
        step: int,
    ) -> None:
        """Add a training checkpoint."""
        self.checkpoints.append({
            "epoch": epoch,
            "step": step,
            "timestamp": datetime.now().isoformat(),
            "overall_score": metrics.overall_score,
            "false_positive_rate": metrics.false_positive_rate,
            "calibration_score": metrics.calibration_tracker.calibration_score(),
            "hallucination_rate": metrics.hallucination_rate,
            "f1_score": metrics.f1_score,
            "pillar_scores": metrics.pillar_scores,
        })

    def improvement_rate(self, metric: str = "overall_score", window: int = 5) -> float:
        """
        Calculate improvement rate over recent checkpoints.

        Args:
            metric: Which metric to track
            window: Number of checkpoints to consider

        Returns:
            Rate of improvement (positive = improving)
        """
        if len(self.checkpoints) < 2:
            return 0.0

        recent = self.checkpoints[-window:] if len(self.checkpoints) >= window else self.checkpoints
        values = [c.get(metric, 0) for c in recent]

        if len(values) < 2:
            return 0.0

        # Simple linear regression slope
        n = len(values)
        sum_x = sum(range(n))
        sum_y = sum(values)
        sum_xy = sum(i * v for i, v in enumerate(values))
        sum_xx = sum(i * i for i in range(n))

        denominator = n * sum_xx - sum_x * sum_x
        if denominator == 0:
            return 0.0

        slope = (n * sum_xy - sum_x * sum_y) / denominator
        return slope

    def to_dict(self) -> dict:
        """Export tracker data."""
        return {
            "model_id": self.model_id,
            "num_checkpoints": len(self.checkpoints),
            "checkpoints": self.checkpoints,
            "current_metrics": self.checkpoints[-1] if self.checkpoints else None,
            "improvement_rates": {
                "overall_score": self.improvement_rate("overall_score"),
                "false_positive_rate": self.improvement_rate("false_positive_rate"),
                "calibration_score": self.improvement_rate("calibration_score"),
            },
        }
