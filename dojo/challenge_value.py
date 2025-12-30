"""
Challenge Value Scoring System

Evaluates each challenge's training value based on:
- Execution success rate
- Signal clarity (grading ambiguity)
- Technique uniqueness
- Compute cost (tokens/time)
- Execution depth (full > detection > syntax-only)

Usage:
    from dojo.challenge_value import ChallengeValueScorer, load_metrics

    scorer = ChallengeValueScorer()
    metrics = load_metrics("dojo_output/metrics.json")
    report = scorer.generate_report(challenges, metrics)
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from dojo.models import Belt, Challenge, Grade

# =============================================================================
# DATA MODELS
# =============================================================================


@dataclass
class AttemptMetrics:
    """Metrics from a single challenge attempt."""

    challenge_id: str
    timestamp: datetime

    # Execution
    executed: bool = False
    execution_success: bool = False
    execution_time_seconds: float = 0.0

    # Grading
    grade: Optional[Grade] = None
    score: int = 0

    # Cost
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0

    # Error info
    error_type: Optional[str] = None
    error_message: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "challenge_id": self.challenge_id,
            "timestamp": self.timestamp.isoformat(),
            "executed": self.executed,
            "execution_success": self.execution_success,
            "execution_time_seconds": self.execution_time_seconds,
            "grade": self.grade.value if self.grade else None,
            "score": self.score,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "error_type": self.error_type,
            "error_message": self.error_message,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AttemptMetrics":
        return cls(
            challenge_id=data["challenge_id"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            executed=data.get("executed", False),
            execution_success=data.get("execution_success", False),
            execution_time_seconds=data.get("execution_time_seconds", 0.0),
            grade=Grade(data["grade"]) if data.get("grade") else None,
            score=data.get("score", 0),
            prompt_tokens=data.get("prompt_tokens", 0),
            completion_tokens=data.get("completion_tokens", 0),
            total_tokens=data.get("total_tokens", 0),
            error_type=data.get("error_type"),
            error_message=data.get("error_message"),
        )


@dataclass
class ChallengeMetrics:
    """Aggregated metrics for a single challenge across all attempts."""

    challenge_id: str
    belt: Belt

    # Attempt history
    attempts: list[AttemptMetrics] = field(default_factory=list)

    # Aggregated stats (computed)
    total_attempts: int = 0
    successful_attempts: int = 0
    failed_attempts: int = 0

    # Timing
    avg_execution_time: float = 0.0
    total_execution_time: float = 0.0

    # Cost
    avg_tokens: float = 0.0
    total_tokens: int = 0

    # Error analysis
    error_counts: dict[str, int] = field(default_factory=dict)

    def add_attempt(self, attempt: AttemptMetrics) -> None:
        """Add an attempt and update aggregated stats."""
        self.attempts.append(attempt)
        self.total_attempts += 1

        if attempt.execution_success:
            self.successful_attempts += 1
        else:
            self.failed_attempts += 1
            if attempt.error_type:
                self.error_counts[attempt.error_type] = (
                    self.error_counts.get(attempt.error_type, 0) + 1
                )

        self.total_execution_time += attempt.execution_time_seconds
        self.total_tokens += attempt.total_tokens

        # Recalculate averages
        self.avg_execution_time = self.total_execution_time / self.total_attempts
        self.avg_tokens = self.total_tokens / self.total_attempts

    @property
    def success_rate(self) -> float:
        """Calculate success rate (0.0 to 1.0)."""
        if self.total_attempts == 0:
            return 0.0
        return self.successful_attempts / self.total_attempts

    @property
    def failure_rate(self) -> float:
        """Calculate failure rate (0.0 to 1.0)."""
        return 1.0 - self.success_rate

    @property
    def most_common_error(self) -> Optional[str]:
        """Get the most common error type."""
        if not self.error_counts:
            return None
        return max(self.error_counts, key=lambda k: self.error_counts.get(k, 0))

    def to_dict(self) -> dict:
        return {
            "challenge_id": self.challenge_id,
            "belt": self.belt.value,
            "total_attempts": self.total_attempts,
            "successful_attempts": self.successful_attempts,
            "failed_attempts": self.failed_attempts,
            "success_rate": round(self.success_rate, 3),
            "avg_execution_time": round(self.avg_execution_time, 2),
            "total_execution_time": round(self.total_execution_time, 2),
            "avg_tokens": round(self.avg_tokens, 0),
            "total_tokens": self.total_tokens,
            "error_counts": self.error_counts,
            "most_common_error": self.most_common_error,
            "attempts": [a.to_dict() for a in self.attempts],
        }


@dataclass
class ChallengeValueScore:
    """Computed value score for a challenge."""

    challenge_id: str
    belt: Belt

    # Component scores (0.0 to 1.0)
    success_rate_score: float = 0.0
    signal_clarity_score: float = 0.0
    uniqueness_score: float = 0.0
    execution_depth_score: float = 0.0

    # Cost factor (lower is better, normalized)
    compute_cost_factor: float = 1.0

    # Final value score
    value_score: float = 0.0

    # Recommendation
    recommendation: str = "keep"  # keep, review, prune
    recommendation_reason: str = ""

    def to_dict(self) -> dict:
        return {
            "challenge_id": self.challenge_id,
            "belt": self.belt.value,
            "success_rate_score": round(self.success_rate_score, 3),
            "signal_clarity_score": round(self.signal_clarity_score, 3),
            "uniqueness_score": round(self.uniqueness_score, 3),
            "execution_depth_score": round(self.execution_depth_score, 3),
            "compute_cost_factor": round(self.compute_cost_factor, 3),
            "value_score": round(self.value_score, 3),
            "recommendation": self.recommendation,
            "recommendation_reason": self.recommendation_reason,
        }


# =============================================================================
# TECHNIQUE CLUSTERING
# =============================================================================


# Attack technique categories for uniqueness scoring
TECHNIQUE_PATTERNS = {
    # Reconnaissance
    "device_recon": [
        r"getprop",
        r"dumpsys",
        r"pm list",
        r"service list",
        r"settings get",
        r"cat /proc",
        r"uname",
    ],
    "package_analysis": [
        r"pm dump",
        r"pm path",
        r"apk",
        r"dex2jar",
        r"jadx",
    ],
    "logcat_analysis": [
        r"logcat",
        r"dmesg",
        r"kmsg",
    ],
    # Information Disclosure
    "file_read": [
        r"cat /",
        r"read.*file",
        r"/sdcard",
        r"/data/data",
    ],
    "database_access": [
        r"sqlite",
        r"\.db",
        r"content://",
    ],
    "credential_leak": [
        r"password",
        r"credential",
        r"token",
        r"secret",
    ],
    # IPC Attacks
    "intent_attack": [
        r"am start",
        r"am broadcast",
        r"intent",
        r"deep.*link",
    ],
    "content_provider": [
        r"content://",
        r"content query",
        r"ContentResolver",
    ],
    "binder": [
        r"binder",
        r"service call",
        r"transact",
    ],
    # Memory/Native
    "buffer_overflow": [
        r"overflow",
        r"buffer",
        r"stack",
        r"heap",
    ],
    "use_after_free": [
        r"use.after.free",
        r"uaf",
        r"dangling",
    ],
    "race_condition": [
        r"race",
        r"toctou",
        r"concurrent",
    ],
    # Privilege Escalation
    "permission_bypass": [
        r"permission",
        r"bypass",
        r"grant",
    ],
    "root_escalation": [
        r"root",
        r"su ",
        r"privilege",
    ],
    # Frida/Hooking
    "frida_hook": [
        r"Interceptor",
        r"Java\.use",
        r"frida",
        r"hook",
    ],
    "ssl_pinning": [
        r"ssl.*pin",
        r"certificate",
        r"trustmanager",
    ],
}


def identify_techniques(challenge: Challenge) -> list[str]:
    """Identify attack techniques used in a challenge."""
    techniques = []

    # Combine description and kata solution for analysis
    text = challenge.description.lower()
    if challenge.kata_solution:
        text += " " + challenge.kata_solution.lower()

    # Also check tags
    tags_text = " ".join(challenge.tags).lower()
    text += " " + tags_text

    for technique, patterns in TECHNIQUE_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                techniques.append(technique)
                break  # Only count each technique once

    return techniques


# =============================================================================
# VALUE SCORER
# =============================================================================


class ChallengeValueScorer:
    """
    Scores challenges based on their training value.

    Value = (success_rate × signal_clarity × uniqueness × exec_depth) / compute_cost

    Thresholds:
    - value >= 0.6: KEEP (good training value)
    - value >= 0.3: REVIEW (may need adjustment)
    - value < 0.3: PRUNE (low value, consider removing)
    """

    # Scoring thresholds
    KEEP_THRESHOLD = 0.6
    REVIEW_THRESHOLD = 0.3

    # Minimum attempts before scoring
    MIN_ATTEMPTS_FOR_SCORING = 3

    # Execution mode scores
    EXEC_MODE_SCORES = {
        "full_execution": 1.0,
        "detection_analysis": 0.7,
        "detection_only": 0.5,
        "simulation": 0.4,
        "syntax_only": 0.3,
        "try_harder": 0.6,
    }

    def __init__(
        self,
        keep_threshold: float = 0.6,
        review_threshold: float = 0.3,
    ):
        self.keep_threshold = keep_threshold
        self.review_threshold = review_threshold

        # Track technique frequency for uniqueness scoring
        self.technique_counts: dict[str, int] = defaultdict(int)
        self.total_challenges: int = 0

    def score_challenge(
        self,
        challenge: Challenge,
        metrics: Optional[ChallengeMetrics] = None,
        all_techniques: Optional[dict[str, list[str]]] = None,
    ) -> ChallengeValueScore:
        """
        Calculate value score for a single challenge.

        Args:
            challenge: The challenge to score.
            metrics: Execution metrics (if available).
            all_techniques: Map of challenge_id -> techniques for uniqueness calc.

        Returns:
            ChallengeValueScore with component scores and recommendation.
        """
        score = ChallengeValueScore(
            challenge_id=challenge.id,
            belt=challenge.belt,
        )

        # 1. Success Rate Score
        if metrics and metrics.total_attempts >= self.MIN_ATTEMPTS_FOR_SCORING:
            score.success_rate_score = metrics.success_rate
        else:
            # No metrics = assume moderate success rate
            score.success_rate_score = 0.5

        # 2. Signal Clarity Score
        score.signal_clarity_score = self._calculate_signal_clarity(challenge, metrics)

        # 3. Uniqueness Score
        techniques = identify_techniques(challenge)
        score.uniqueness_score = self._calculate_uniqueness(
            challenge.id, techniques, all_techniques
        )

        # 4. Execution Depth Score
        score.execution_depth_score = self._calculate_execution_depth(challenge)

        # 5. Compute Cost Factor
        if metrics and metrics.total_attempts > 0:
            # Normalize tokens (10k tokens = cost factor 1.0)
            score.compute_cost_factor = max(0.1, min(2.0, metrics.avg_tokens / 10000))
        else:
            score.compute_cost_factor = 1.0

        # Calculate final value score
        score.value_score = self._calculate_value(score)

        # Generate recommendation
        score.recommendation, score.recommendation_reason = self._generate_recommendation(
            score, metrics
        )

        return score

    def _calculate_signal_clarity(
        self,
        challenge: Challenge,
        metrics: Optional[ChallengeMetrics],
    ) -> float:
        """
        Calculate signal clarity (how clear is pass/fail).

        High clarity: Binary pass/fail with clear criteria
        Low clarity: Ambiguous "analyze" tasks with subjective grading
        """
        clarity = 1.0

        description = challenge.description.lower()

        # Reduce clarity for ambiguous language
        ambiguous_terms = [
            "analyze",
            "investigate",
            "explore",
            "study",
            "examine",
            "review",
            "assess",
            "evaluate",
        ]
        for term in ambiguous_terms:
            if term in description:
                clarity -= 0.1

        # Increase clarity for concrete objectives
        concrete_terms = [
            "extract",
            "dump",
            "read",
            "write",
            "execute",
            "bypass",
            "intercept",
            "hook",
            "find",
        ]
        for term in concrete_terms:
            if term in description:
                clarity += 0.05

        # Check if must_contain patterns exist (clearer grading)
        if challenge.expected_output.must_contain:
            clarity += 0.1

        # Check if kata solution exists (can verify against gold)
        if challenge.kata_solution:
            clarity += 0.1

        # Check metrics for grade variance (high variance = low clarity)
        if metrics and metrics.attempts:
            grades = [a.grade for a in metrics.attempts if a.grade]
            if grades:
                unique_grades = len(set(grades))
                if unique_grades > 2:
                    clarity -= 0.15  # High grade variance

        return max(0.0, min(1.0, clarity))

    def _calculate_uniqueness(
        self,
        challenge_id: str,
        techniques: list[str],
        all_techniques: Optional[dict[str, list[str]]],
    ) -> float:
        """
        Calculate how unique this challenge's techniques are.

        Rare techniques = higher uniqueness score
        Common techniques = lower uniqueness score
        """
        if not techniques:
            return 0.5  # No techniques identified = neutral

        if not all_techniques:
            return 0.7  # No comparison data = assume moderately unique

        # Calculate technique frequency
        technique_freq: dict[str, int] = defaultdict(int)
        total = len(all_techniques)

        for c_techniques in all_techniques.values():
            for t in c_techniques:
                technique_freq[t] += 1

        # Score based on rarity of techniques
        uniqueness_scores = []
        for technique in techniques:
            freq = technique_freq.get(technique, 0)
            # Rarity = 1 - (frequency / total)
            rarity = 1.0 - (freq / total) if total > 0 else 1.0
            uniqueness_scores.append(rarity)

        if uniqueness_scores:
            return sum(uniqueness_scores) / len(uniqueness_scores)

        return 0.5

    def _calculate_execution_depth(self, challenge: Challenge) -> float:
        """
        Calculate execution depth score based on execution mode.

        Full execution > Detection analysis > Detection only > Syntax only
        """
        # Try to get execution mode from additional context
        exec_mode = challenge.inputs.additional_context.get("execution_mode", "full_execution")

        # Also infer from script type
        script_type = challenge.expected_output.script_type.value
        if script_type == "c_exploit":
            # C exploits are typically syntax-only in current implementation
            exec_mode = "syntax_only"

        return self.EXEC_MODE_SCORES.get(exec_mode, 0.5)

    def _calculate_value(self, score: ChallengeValueScore) -> float:
        """
        Calculate final value score.

        Value = (success × clarity × uniqueness × depth) / cost
        """
        numerator = (
            score.success_rate_score
            * score.signal_clarity_score
            * score.uniqueness_score
            * score.execution_depth_score
        )

        # Avoid division by zero
        cost = max(0.1, score.compute_cost_factor)

        return numerator / cost

    def _generate_recommendation(
        self,
        score: ChallengeValueScore,
        metrics: Optional[ChallengeMetrics],
    ) -> tuple[str, str]:
        """
        Generate recommendation based on value score.

        Returns:
            Tuple of (recommendation, reason).
        """
        reasons = []

        # Check for critical issues first
        if metrics:
            # Always fails
            if metrics.total_attempts >= 5 and metrics.success_rate == 0:
                return "prune", "Always fails (0% success rate over 5+ attempts)"

            # Always requires root
            if metrics.most_common_error and "root" in metrics.most_common_error.lower():
                return "review", "Requires root access (not available in non-rooted mode)"

            # Extremely expensive
            if metrics.avg_tokens > 50000:
                reasons.append("Very high token cost")

        # Score-based recommendation
        if score.value_score >= self.keep_threshold:
            return "keep", "Good training value"

        if score.value_score >= self.review_threshold:
            # Identify specific issues
            if score.success_rate_score < 0.3:
                reasons.append("Low success rate")
            if score.signal_clarity_score < 0.5:
                reasons.append("Ambiguous grading criteria")
            if score.uniqueness_score < 0.3:
                reasons.append("Redundant with other challenges")
            if score.execution_depth_score < 0.4:
                reasons.append("Limited execution depth")

            reason = "; ".join(reasons) if reasons else "Moderate value"
            return "review", reason

        # Low value
        if score.success_rate_score < 0.2:
            reasons.append("Very low success rate")
        if score.signal_clarity_score < 0.4:
            reasons.append("Unclear grading")
        if score.uniqueness_score < 0.2:
            reasons.append("Highly redundant")

        reason = "; ".join(reasons) if reasons else "Low overall value"
        return "prune", reason

    def score_all_challenges(
        self,
        challenges: list[Challenge],
        metrics_map: Optional[dict[str, ChallengeMetrics]] = None,
    ) -> list[ChallengeValueScore]:
        """
        Score all challenges with technique-aware uniqueness.

        Args:
            challenges: List of challenges to score.
            metrics_map: Map of challenge_id -> ChallengeMetrics.

        Returns:
            List of ChallengeValueScore objects.
        """
        # First pass: identify techniques for all challenges
        all_techniques = {}
        for challenge in challenges:
            all_techniques[challenge.id] = identify_techniques(challenge)

        # Second pass: score each challenge
        scores = []
        for challenge in challenges:
            metrics = metrics_map.get(challenge.id) if metrics_map else None
            score = self.score_challenge(challenge, metrics, all_techniques)
            scores.append(score)

        return scores

    def generate_report(
        self,
        challenges: list[Challenge],
        metrics_map: Optional[dict[str, ChallengeMetrics]] = None,
    ) -> dict[str, Any]:
        """
        Generate a comprehensive value report for all challenges.

        Args:
            challenges: List of challenges.
            metrics_map: Map of challenge_id -> ChallengeMetrics.

        Returns:
            Report dictionary with scores, stats, and recommendations.
        """
        scores = self.score_all_challenges(challenges, metrics_map)

        # Organize by belt
        by_belt: dict[str, list[ChallengeValueScore]] = defaultdict(list)
        for score in scores:
            by_belt[score.belt.value].append(score)

        # Count recommendations
        keep_count = sum(1 for s in scores if s.recommendation == "keep")
        review_count = sum(1 for s in scores if s.recommendation == "review")
        prune_count = sum(1 for s in scores if s.recommendation == "prune")

        # Calculate average value by belt
        belt_averages = {}
        for belt, belt_scores in by_belt.items():
            avg = sum(s.value_score for s in belt_scores) / len(belt_scores)
            belt_averages[belt] = round(avg, 3)

        # Identify technique coverage
        all_techniques = set()
        technique_coverage: dict[str, int] = defaultdict(int)
        for challenge in challenges:
            techniques = identify_techniques(challenge)
            all_techniques.update(techniques)
            for t in techniques:
                technique_coverage[t] += 1

        # Find gaps (techniques with low coverage)
        technique_gaps = [t for t in TECHNIQUE_PATTERNS.keys() if technique_coverage.get(t, 0) < 3]

        return {
            "summary": {
                "total_challenges": len(challenges),
                "keep": keep_count,
                "review": review_count,
                "prune": prune_count,
                "average_value": round(sum(s.value_score for s in scores) / len(scores), 3)
                if scores
                else 0,
            },
            "by_belt": {
                belt: {
                    "count": len(belt_scores),
                    "average_value": belt_averages[belt],
                    "keep": sum(1 for s in belt_scores if s.recommendation == "keep"),
                    "review": sum(1 for s in belt_scores if s.recommendation == "review"),
                    "prune": sum(1 for s in belt_scores if s.recommendation == "prune"),
                }
                for belt, belt_scores in by_belt.items()
            },
            "technique_coverage": dict(technique_coverage),
            "technique_gaps": technique_gaps,
            "prune_candidates": [s.to_dict() for s in scores if s.recommendation == "prune"],
            "review_candidates": [s.to_dict() for s in scores if s.recommendation == "review"],
            "all_scores": [s.to_dict() for s in scores],
            "generated_at": datetime.now().isoformat(),
        }


# =============================================================================
# METRICS I/O
# =============================================================================


def load_metrics(path: Path | str) -> dict[str, ChallengeMetrics]:
    """
    Load metrics from JSON file.

    Args:
        path: Path to metrics JSON file.

    Returns:
        Map of challenge_id -> ChallengeMetrics.
    """
    path = Path(path)
    if not path.exists():
        return {}

    with open(path) as f:
        data = json.load(f)

    metrics_map = {}
    for challenge_id, challenge_data in data.get("challenges", {}).items():
        metrics = ChallengeMetrics(
            challenge_id=challenge_id,
            belt=Belt(challenge_data.get("belt", "white")),
        )

        # Load attempts
        for attempt_data in challenge_data.get("attempts", []):
            attempt = AttemptMetrics.from_dict(attempt_data)
            metrics.add_attempt(attempt)

        metrics_map[challenge_id] = metrics

    return metrics_map


def save_metrics(metrics_map: dict[str, ChallengeMetrics], path: Path | str) -> None:
    """
    Save metrics to JSON file.

    Args:
        metrics_map: Map of challenge_id -> ChallengeMetrics.
        path: Output path.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    data = {
        "challenges": {cid: metrics.to_dict() for cid, metrics in metrics_map.items()},
        "generated_at": datetime.now().isoformat(),
    }

    with open(path, "w") as f:
        json.dump(data, f, indent=2)


class MetricsCollector:
    """
    Collects metrics during challenge execution.

    Integrates with the grader to track attempt outcomes.
    """

    def __init__(self, output_path: Optional[Path] = None):
        self.metrics: dict[str, ChallengeMetrics] = {}
        self.output_path = output_path or Path("dojo_output/metrics.json")

    def record_attempt(
        self,
        challenge: Challenge,
        executed: bool,
        success: bool,
        execution_time: float,
        grade: Optional[Grade] = None,
        score: int = 0,
        tokens: int = 0,
        error_type: Optional[str] = None,
        error_message: Optional[str] = None,
    ) -> None:
        """Record a challenge attempt."""
        challenge_id = challenge.id

        if challenge_id not in self.metrics:
            self.metrics[challenge_id] = ChallengeMetrics(
                challenge_id=challenge_id,
                belt=challenge.belt,
            )

        attempt = AttemptMetrics(
            challenge_id=challenge_id,
            timestamp=datetime.now(),
            executed=executed,
            execution_success=success,
            execution_time_seconds=execution_time,
            grade=grade,
            score=score,
            total_tokens=tokens,
            error_type=error_type,
            error_message=error_message,
        )

        self.metrics[challenge_id].add_attempt(attempt)

    def save(self) -> None:
        """Save current metrics to disk."""
        save_metrics(self.metrics, self.output_path)

    def load(self) -> None:
        """Load existing metrics from disk."""
        self.metrics = load_metrics(self.output_path)
