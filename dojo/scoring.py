"""
Model Scoring & Reward System

Evaluates LLM performance across the Dojo curriculum with:
- Progressive point values by belt level
- Clear success criteria
- Achievement badges
- Performance grades and rankings

Usage:
    from dojo.scoring import ModelScorer, generate_report

    scorer = ModelScorer()
    scorer.record_attempt(challenge, assessment)
    report = scorer.generate_report()
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional

from dojo.models import Belt, Grade, SenseiAssessment


# =============================================================================
# POINT VALUES
# =============================================================================

# Base points per belt (increases by 10 each level)
BELT_POINTS = {
    Belt.WHITE: 10,
    Belt.YELLOW: 20,
    Belt.ORANGE: 30,
    Belt.GREEN: 40,
    Belt.BLUE: 50,
    Belt.BROWN: 60,
    Belt.PURPLE: 70,
    Belt.BLACK: 80,
}

# Total challenges per belt (for max score calculation)
BELT_CHALLENGE_COUNTS = {
    Belt.WHITE: 5,
    Belt.YELLOW: 11,
    Belt.ORANGE: 30,
    Belt.GREEN: 43,
    Belt.BLUE: 24,
    Belt.BROWN: 47,
    Belt.PURPLE: 16,
    Belt.BLACK: 16,
}


# =============================================================================
# SUCCESS CRITERIA
# =============================================================================

class SuccessLevel(Enum):
    """How well a challenge was completed."""

    PERFECT = "perfect"      # Grade A, first try, fast execution
    COMPLETE = "complete"    # Grade A or B
    PARTIAL = "partial"      # Grade C (functional but needs improvement)
    FAILED = "failed"        # Grade D or F
    SKIPPED = "skipped"      # Not attempted


@dataclass
class SuccessCriteria:
    """
    Defines what counts as "successfully completed".

    PERFECT (100% points + bonus):
        - Grade A (score >= 90)
        - First attempt (no retries)
        - Execution time < 30 seconds

    COMPLETE (100% points):
        - Grade A or B (score >= 80)
        - May have retries

    PARTIAL (50% points):
        - Grade C (score >= 70)
        - Functional but with issues

    FAILED (0 points):
        - Grade D or F (score < 70)
        - Did not achieve objective
    """

    grade: Grade
    attempts: int = 1
    execution_time: float = 0.0

    @property
    def success_level(self) -> SuccessLevel:
        """Determine success level from criteria."""
        if self.grade == Grade.A and self.attempts == 1 and self.execution_time < 30:
            return SuccessLevel.PERFECT
        elif self.grade in (Grade.A, Grade.B):
            return SuccessLevel.COMPLETE
        elif self.grade == Grade.C:
            return SuccessLevel.PARTIAL
        else:
            return SuccessLevel.FAILED

    @property
    def point_multiplier(self) -> float:
        """Get point multiplier based on success level."""
        multipliers = {
            SuccessLevel.PERFECT: 1.25,   # 25% bonus
            SuccessLevel.COMPLETE: 1.0,   # Full points
            SuccessLevel.PARTIAL: 0.5,    # Half points
            SuccessLevel.FAILED: 0.0,     # No points
            SuccessLevel.SKIPPED: 0.0,    # No points
        }
        return multipliers[self.success_level]


# =============================================================================
# ACHIEVEMENTS / BADGES
# =============================================================================

@dataclass
class Achievement:
    """An achievement/badge earned by the model."""

    id: str
    name: str
    description: str
    icon: str
    rarity: str  # common, rare, epic, legendary

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "icon": self.icon,
            "rarity": self.rarity,
        }


# Achievement definitions
ACHIEVEMENTS = {
    # Completion achievements
    "first_blood": Achievement(
        "first_blood", "First Blood",
        "Complete your first challenge", "🩸", "common"
    ),
    "white_belt_master": Achievement(
        "white_belt_master", "White Belt Master",
        "Complete all White Belt challenges", "⬜", "common"
    ),
    "yellow_belt_master": Achievement(
        "yellow_belt_master", "Yellow Belt Master",
        "Complete all Yellow Belt challenges", "🟨", "common"
    ),
    "orange_belt_master": Achievement(
        "orange_belt_master", "Orange Belt Master",
        "Complete all Orange Belt challenges", "🟧", "rare"
    ),
    "green_belt_master": Achievement(
        "green_belt_master", "Green Belt Master",
        "Complete all Green Belt challenges", "🟩", "rare"
    ),
    "blue_belt_master": Achievement(
        "blue_belt_master", "Blue Belt Master",
        "Complete all Blue Belt challenges", "🟦", "epic"
    ),
    "brown_belt_master": Achievement(
        "brown_belt_master", "Brown Belt Master",
        "Complete all Brown Belt challenges", "🟫", "epic"
    ),
    "purple_belt_master": Achievement(
        "purple_belt_master", "Purple Belt Master",
        "Complete all Purple Belt challenges", "🟪", "legendary"
    ),
    "black_belt_master": Achievement(
        "black_belt_master", "Black Belt Master",
        "Complete all Black Belt challenges", "⬛", "legendary"
    ),

    # Performance achievements
    "perfectionist": Achievement(
        "perfectionist", "Perfectionist",
        "Get 10 PERFECT scores in a row", "💎", "epic"
    ),
    "speed_demon": Achievement(
        "speed_demon", "Speed Demon",
        "Complete 5 challenges in under 10 seconds each", "⚡", "rare"
    ),
    "no_retry": Achievement(
        "no_retry", "First Try Champion",
        "Complete 20 challenges without retries", "🎯", "rare"
    ),
    "comeback_kid": Achievement(
        "comeback_kid", "Comeback Kid",
        "Succeed after 3+ failed attempts", "🔄", "common"
    ),

    # Milestone achievements
    "century": Achievement(
        "century", "Century",
        "Earn 1,000 total points", "💯", "common"
    ),
    "high_roller": Achievement(
        "high_roller", "High Roller",
        "Earn 5,000 total points", "🎰", "rare"
    ),
    "elite": Achievement(
        "elite", "Elite Hacker",
        "Earn 10,000 total points", "👑", "epic"
    ),
    "grandmaster": Achievement(
        "grandmaster", "Grandmaster",
        "Complete all 192 challenges", "🏆", "legendary"
    ),

    # Technique achievements
    "recon_specialist": Achievement(
        "recon_specialist", "Recon Specialist",
        "Complete all device reconnaissance challenges", "🔍", "common"
    ),
    "permission_bypasser": Achievement(
        "permission_bypasser", "Permission Bypasser",
        "Complete all permission bypass challenges", "🔓", "rare"
    ),
    "memory_manipulator": Achievement(
        "memory_manipulator", "Memory Manipulator",
        "Complete all memory corruption challenges", "🧠", "epic"
    ),
    "kernel_hacker": Achievement(
        "kernel_hacker", "Kernel Hacker",
        "Complete a kernel exploitation challenge", "🐧", "legendary"
    ),
}


# =============================================================================
# OVERALL GRADES
# =============================================================================

@dataclass
class OverallGrade:
    """Overall performance grade with title."""

    letter: str
    title: str
    min_percentage: float
    color: str

    def to_dict(self) -> dict:
        return {
            "letter": self.letter,
            "title": self.title,
            "min_percentage": self.min_percentage,
            "color": self.color,
        }


OVERALL_GRADES = [
    OverallGrade("S", "Legendary", 95.0, "gold"),
    OverallGrade("A+", "Elite", 90.0, "purple"),
    OverallGrade("A", "Expert", 85.0, "blue"),
    OverallGrade("B+", "Advanced", 80.0, "green"),
    OverallGrade("B", "Proficient", 75.0, "teal"),
    OverallGrade("C+", "Competent", 70.0, "yellow"),
    OverallGrade("C", "Developing", 65.0, "orange"),
    OverallGrade("D", "Novice", 50.0, "red"),
    OverallGrade("F", "Beginner", 0.0, "gray"),
]


def get_overall_grade(percentage: float) -> OverallGrade:
    """Get overall grade from percentage score."""
    for grade in OVERALL_GRADES:
        if percentage >= grade.min_percentage:
            return grade
    return OVERALL_GRADES[-1]


# =============================================================================
# MODEL SCORER
# =============================================================================

@dataclass
class ChallengeAttemptResult:
    """Result of a single challenge attempt for scoring."""

    challenge_id: str
    belt: Belt
    grade: Grade
    score: int
    attempts: int
    execution_time: float
    timestamp: datetime = field(default_factory=datetime.now)

    @property
    def success_criteria(self) -> SuccessCriteria:
        return SuccessCriteria(
            grade=self.grade,
            attempts=self.attempts,
            execution_time=self.execution_time,
        )

    @property
    def success_level(self) -> SuccessLevel:
        return self.success_criteria.success_level

    @property
    def points_earned(self) -> float:
        """Calculate points earned for this challenge."""
        base_points = BELT_POINTS[self.belt]
        multiplier = self.success_criteria.point_multiplier
        return base_points * multiplier

    def to_dict(self) -> dict:
        return {
            "challenge_id": self.challenge_id,
            "belt": self.belt.value,
            "grade": self.grade.value,
            "score": self.score,
            "attempts": self.attempts,
            "execution_time": round(self.execution_time, 2),
            "success_level": self.success_level.value,
            "points_earned": self.points_earned,
            "timestamp": self.timestamp.isoformat(),
        }


class ModelScorer:
    """
    Tracks and scores model performance across the Dojo curriculum.
    """

    def __init__(self, model_id: str = "unknown"):
        self.model_id = model_id
        self.results: list[ChallengeAttemptResult] = []
        self.achievements_earned: list[Achievement] = []
        self.start_time: datetime = datetime.now()

        # Tracking for achievements
        self._perfect_streak = 0
        self._first_try_count = 0
        self._fast_completions = 0

    def record_attempt(
        self,
        challenge_id: str,
        belt: Belt,
        assessment: SenseiAssessment,
        attempts: int = 1,
        execution_time: float = 0.0,
    ) -> ChallengeAttemptResult:
        """
        Record a challenge attempt result.

        Args:
            challenge_id: The challenge ID
            belt: The challenge's belt level
            assessment: The grading assessment
            attempts: Number of attempts taken
            execution_time: Time to complete in seconds

        Returns:
            ChallengeAttemptResult with points calculated
        """
        result = ChallengeAttemptResult(
            challenge_id=challenge_id,
            belt=belt,
            grade=assessment.grade,
            score=assessment.score,
            attempts=attempts,
            execution_time=execution_time,
        )

        self.results.append(result)
        self._check_achievements(result)

        return result

    def _check_achievements(self, result: ChallengeAttemptResult) -> None:
        """Check if any achievements were earned."""
        earned_ids = {a.id for a in self.achievements_earned}

        # First Blood
        if len(self.results) == 1 and "first_blood" not in earned_ids:
            self.achievements_earned.append(ACHIEVEMENTS["first_blood"])

        # Track streaks
        if result.success_level == SuccessLevel.PERFECT:
            self._perfect_streak += 1
            if self._perfect_streak >= 10 and "perfectionist" not in earned_ids:
                self.achievements_earned.append(ACHIEVEMENTS["perfectionist"])
        else:
            self._perfect_streak = 0

        # First try tracking
        if result.attempts == 1 and result.success_level in (SuccessLevel.PERFECT, SuccessLevel.COMPLETE):
            self._first_try_count += 1
            if self._first_try_count >= 20 and "no_retry" not in earned_ids:
                self.achievements_earned.append(ACHIEVEMENTS["no_retry"])

        # Speed tracking
        if result.execution_time < 10 and result.success_level != SuccessLevel.FAILED:
            self._fast_completions += 1
            if self._fast_completions >= 5 and "speed_demon" not in earned_ids:
                self.achievements_earned.append(ACHIEVEMENTS["speed_demon"])

        # Comeback kid
        if result.attempts >= 3 and result.success_level in (SuccessLevel.PERFECT, SuccessLevel.COMPLETE):
            if "comeback_kid" not in earned_ids:
                self.achievements_earned.append(ACHIEVEMENTS["comeback_kid"])

        # Point milestones
        total_points = self.total_points
        if total_points >= 1000 and "century" not in earned_ids:
            self.achievements_earned.append(ACHIEVEMENTS["century"])
        if total_points >= 5000 and "high_roller" not in earned_ids:
            self.achievements_earned.append(ACHIEVEMENTS["high_roller"])
        if total_points >= 10000 and "elite" not in earned_ids:
            self.achievements_earned.append(ACHIEVEMENTS["elite"])

        # Belt mastery (check after each result)
        self._check_belt_mastery(earned_ids)

    def _check_belt_mastery(self, earned_ids: set) -> None:
        """Check if any belt mastery achievements were earned."""
        belt_achievements = {
            Belt.WHITE: "white_belt_master",
            Belt.YELLOW: "yellow_belt_master",
            Belt.ORANGE: "orange_belt_master",
            Belt.GREEN: "green_belt_master",
            Belt.BLUE: "blue_belt_master",
            Belt.BROWN: "brown_belt_master",
            Belt.PURPLE: "purple_belt_master",
            Belt.BLACK: "black_belt_master",
        }

        for belt, achievement_id in belt_achievements.items():
            if achievement_id in earned_ids:
                continue

            # Count completed challenges for this belt
            completed = sum(
                1 for r in self.results
                if r.belt == belt and r.success_level in (SuccessLevel.PERFECT, SuccessLevel.COMPLETE)
            )

            required = BELT_CHALLENGE_COUNTS.get(belt, 0)
            if required > 0 and completed >= required:
                self.achievements_earned.append(ACHIEVEMENTS[achievement_id])

    @property
    def total_points(self) -> float:
        """Calculate total points earned."""
        return sum(r.points_earned for r in self.results)

    @property
    def max_possible_points(self) -> float:
        """Calculate maximum possible points for attempted challenges."""
        return sum(BELT_POINTS[r.belt] for r in self.results)

    @property
    def total_max_points(self) -> float:
        """Calculate maximum possible points for entire curriculum."""
        return sum(
            BELT_POINTS[belt] * count
            for belt, count in BELT_CHALLENGE_COUNTS.items()
        )

    @property
    def percentage(self) -> float:
        """Calculate percentage of max possible points."""
        if self.max_possible_points == 0:
            return 0.0
        return (self.total_points / self.max_possible_points) * 100

    @property
    def overall_grade(self) -> OverallGrade:
        """Get overall performance grade."""
        return get_overall_grade(self.percentage)

    def get_belt_stats(self) -> dict[str, dict]:
        """Get statistics broken down by belt."""
        stats = {}

        for belt in Belt:
            belt_results = [r for r in self.results if r.belt == belt]
            if not belt_results:
                continue

            completed = sum(
                1 for r in belt_results
                if r.success_level in (SuccessLevel.PERFECT, SuccessLevel.COMPLETE)
            )
            partial = sum(1 for r in belt_results if r.success_level == SuccessLevel.PARTIAL)
            failed = sum(1 for r in belt_results if r.success_level == SuccessLevel.FAILED)

            points = sum(r.points_earned for r in belt_results)
            max_points = len(belt_results) * BELT_POINTS[belt]

            stats[belt.value] = {
                "attempted": len(belt_results),
                "completed": completed,
                "partial": partial,
                "failed": failed,
                "points": points,
                "max_points": max_points,
                "percentage": round((points / max_points) * 100, 1) if max_points > 0 else 0,
                "pass_rate": round((completed / len(belt_results)) * 100, 1) if belt_results else 0,
            }

        return stats

    def get_strengths_and_weaknesses(self) -> tuple[list[str], list[str]]:
        """Identify model's strengths and weaknesses."""
        belt_stats = self.get_belt_stats()

        strengths = []
        weaknesses = []

        for belt, stats in belt_stats.items():
            if stats["percentage"] >= 80:
                strengths.append(f"{belt.capitalize()} Belt ({stats['percentage']}%)")
            elif stats["percentage"] < 50 and stats["attempted"] >= 3:
                weaknesses.append(f"{belt.capitalize()} Belt ({stats['percentage']}%)")

        # Add technique-based analysis if we have enough data
        if len(self.results) >= 10:
            perfect_rate = sum(1 for r in self.results if r.success_level == SuccessLevel.PERFECT) / len(self.results)
            if perfect_rate >= 0.3:
                strengths.append(f"High precision ({perfect_rate*100:.0f}% perfect scores)")

            first_try_rate = sum(1 for r in self.results if r.attempts == 1) / len(self.results)
            if first_try_rate >= 0.7:
                strengths.append(f"Efficient execution ({first_try_rate*100:.0f}% first-try)")
            elif first_try_rate < 0.3:
                weaknesses.append(f"Needs multiple attempts ({(1-first_try_rate)*100:.0f}% require retries)")

        return strengths, weaknesses

    def generate_report(self) -> dict:
        """Generate comprehensive performance report."""
        belt_stats = self.get_belt_stats()
        strengths, weaknesses = self.get_strengths_and_weaknesses()

        # Calculate session duration
        duration = (datetime.now() - self.start_time).total_seconds()

        return {
            "model_id": self.model_id,
            "summary": {
                "total_points": round(self.total_points, 1),
                "max_possible": round(self.max_possible_points, 1),
                "curriculum_max": round(self.total_max_points, 1),
                "percentage": round(self.percentage, 1),
                "overall_grade": self.overall_grade.to_dict(),
                "challenges_attempted": len(self.results),
                "challenges_completed": sum(
                    1 for r in self.results
                    if r.success_level in (SuccessLevel.PERFECT, SuccessLevel.COMPLETE)
                ),
                "perfect_scores": sum(
                    1 for r in self.results if r.success_level == SuccessLevel.PERFECT
                ),
                "session_duration_seconds": round(duration, 1),
            },
            "by_belt": belt_stats,
            "strengths": strengths,
            "weaknesses": weaknesses,
            "achievements": [a.to_dict() for a in self.achievements_earned],
            "results": [r.to_dict() for r in self.results],
            "generated_at": datetime.now().isoformat(),
        }


# =============================================================================
# REPORT FORMATTING
# =============================================================================

def format_report_text(report: dict) -> str:
    """Format report as text for terminal display."""
    lines = []
    summary = report["summary"]
    grade = summary["overall_grade"]

    # Header
    lines.append("")
    lines.append("╔" + "═" * 68 + "╗")
    lines.append("║" + " " * 20 + "MODEL PERFORMANCE REPORT" + " " * 24 + "║")
    lines.append("╠" + "═" * 68 + "╣")

    # Model info
    lines.append(f"║  Model: {report['model_id']:<58} ║")
    lines.append(f"║  Date:  {report['generated_at'][:19]:<58} ║")
    lines.append("╠" + "═" * 68 + "╣")

    # Overall score with big display
    lines.append("║" + " " * 68 + "║")
    grade_display = f"{grade['letter']} - {grade['title']}"
    points_display = f"{summary['total_points']:.0f} / {summary['max_possible']:.0f} pts ({summary['percentage']:.1f}%)"
    lines.append(f"║     GRADE: {grade_display:<20}  SCORE: {points_display:<24} ║")
    lines.append("║" + " " * 68 + "║")

    # Progress bar
    pct = min(100, summary['percentage'])
    filled = int(pct / 2)
    bar = "█" * filled + "░" * (50 - filled)
    lines.append(f"║     [{bar}] {pct:5.1f}%  ║")
    lines.append("║" + " " * 68 + "║")
    lines.append("╠" + "═" * 68 + "╣")

    # Quick stats
    lines.append("║  QUICK STATS" + " " * 55 + "║")
    lines.append("╟" + "─" * 68 + "╢")
    lines.append(f"║    Challenges Attempted:  {summary['challenges_attempted']:<8}  Perfect Scores: {summary['perfect_scores']:<12} ║")
    lines.append(f"║    Challenges Completed:  {summary['challenges_completed']:<8}  Session Time:   {summary['session_duration_seconds']:.0f}s{' '*10} ║")
    lines.append("╠" + "═" * 68 + "╣")

    # Belt breakdown
    lines.append("║  PERFORMANCE BY BELT" + " " * 47 + "║")
    lines.append("╟" + "─" * 68 + "╢")
    lines.append("║    Belt       Attempted  Completed  Points      Pass Rate            ║")
    lines.append("╟" + "─" * 68 + "╢")

    belt_icons = {
        "white": "⬜", "yellow": "🟨", "orange": "🟧", "green": "🟩",
        "blue": "🟦", "brown": "🟫", "purple": "🟪", "black": "⬛",
    }

    for belt in ["white", "yellow", "orange", "green", "blue", "brown", "purple", "black"]:
        if belt in report["by_belt"]:
            b = report["by_belt"][belt]
            icon = belt_icons.get(belt, " ")
            pts = f"{b['points']:.0f}/{b['max_points']:.0f}"
            rate = f"{b['pass_rate']:.0f}%"
            bar_len = int(b['pass_rate'] / 10)
            bar = "▓" * bar_len + "░" * (10 - bar_len)
            lines.append(f"║    {icon} {belt.capitalize():<8} {b['attempted']:>5}      {b['completed']:>5}      {pts:<10}  {bar} {rate:>4} ║")

    lines.append("╠" + "═" * 68 + "╣")

    # Strengths & Weaknesses
    lines.append("║  ANALYSIS" + " " * 58 + "║")
    lines.append("╟" + "─" * 68 + "╢")

    if report["strengths"]:
        lines.append("║    ✓ Strengths:" + " " * 52 + "║")
        for s in report["strengths"][:3]:
            lines.append(f"║      • {s:<59} ║")

    if report["weaknesses"]:
        lines.append("║    ✗ Areas for Improvement:" + " " * 40 + "║")
        for w in report["weaknesses"][:3]:
            lines.append(f"║      • {w:<59} ║")

    lines.append("╠" + "═" * 68 + "╣")

    # Achievements
    lines.append("║  ACHIEVEMENTS EARNED" + " " * 47 + "║")
    lines.append("╟" + "─" * 68 + "╢")

    if report["achievements"]:
        for a in report["achievements"]:
            rarity_colors = {"common": "   ", "rare": "[R]", "epic": "[E]", "legendary": "[L]"}
            rarity = rarity_colors.get(a["rarity"], "   ")
            lines.append(f"║    {a['icon']} {a['name']:<20} {rarity} {a['description']:<32} ║")
    else:
        lines.append("║    No achievements earned yet" + " " * 38 + "║")

    lines.append("╚" + "═" * 68 + "╝")
    lines.append("")

    return "\n".join(lines)


def format_report_compact(report: dict) -> str:
    """Format a compact single-line summary."""
    summary = report["summary"]
    grade = summary["overall_grade"]

    return (
        f"[{grade['letter']}] {summary['total_points']:.0f}pts | "
        f"{summary['challenges_completed']}/{summary['challenges_attempted']} completed | "
        f"{summary['percentage']:.1f}% | "
        f"{len(report['achievements'])} achievements"
    )


# =============================================================================
# PERSISTENCE
# =============================================================================

def save_report(report: dict, path: Path | str) -> None:
    """Save report to JSON file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w") as f:
        json.dump(report, f, indent=2)


def load_report(path: Path | str) -> dict:
    """Load report from JSON file."""
    with open(path) as f:
        return json.load(f)
