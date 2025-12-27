"""Core data models for the Dojo framework."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class Belt(Enum):
    """Progressive skill levels in the dojo."""

    WHITE = "white"
    YELLOW = "yellow"
    ORANGE = "orange"
    GREEN = "green"
    BLUE = "blue"
    PURPLE = "purple"
    BROWN = "brown"
    BLACK = "black"

    @property
    def display(self) -> str:
        """Belt with color emoji."""
        icons = {
            "white": "⬜",
            "yellow": "🟨",
            "orange": "🟧",
            "green": "🟩",
            "blue": "🟦",
            "purple": "🟪",
            "brown": "🟫",
            "black": "⬛",
        }
        return f"{icons[self.value]} {self.value.title()}"

    @property
    def order(self) -> int:
        """Numeric order for comparison."""
        return list(Belt).index(self)

    def __lt__(self, other: Belt) -> bool:
        if not isinstance(other, Belt):
            return NotImplemented
        return self.order < other.order

    def __le__(self, other: Belt) -> bool:
        if not isinstance(other, Belt):
            return NotImplemented
        return self.order <= other.order

    def __gt__(self, other: Belt) -> bool:
        if not isinstance(other, Belt):
            return NotImplemented
        return self.order > other.order

    def __ge__(self, other: Belt) -> bool:
        if not isinstance(other, Belt):
            return NotImplemented
        return self.order >= other.order

    @classmethod
    def from_string(cls, value: str) -> Belt:
        """Create Belt from string value."""
        try:
            return cls(value.lower())
        except ValueError:
            raise ValueError(f"Invalid belt: {value}")

    def next_belt(self) -> Optional[Belt]:
        """Get the next belt in progression."""
        belts = list(Belt)
        current_index = belts.index(self)
        if current_index < len(belts) - 1:
            return belts[current_index + 1]
        return None


class Grade(Enum):
    """Assessment grades from Sensei."""

    A = "A"  # Perfect - positive example
    B = "B"  # Good - positive example with minor notes
    C = "C"  # Acceptable - functional but needs improvement
    D = "D"  # Poor - negative example, correction provided
    F = "F"  # Fail - non-functional, correction provided

    @property
    def is_passing(self) -> bool:
        """Check if this grade is passing."""
        return self in (Grade.A, Grade.B, Grade.C)

    @property
    def is_positive_example(self) -> bool:
        """Check if this grade qualifies as a positive training example."""
        return self in (Grade.A, Grade.B)

    @property
    def is_negative_example(self) -> bool:
        """Check if this grade qualifies as a negative training example."""
        return self in (Grade.D, Grade.F)

    @property
    def score_range(self) -> tuple[int, int]:
        """Get the score range for this grade."""
        ranges = {
            Grade.A: (90, 100),
            Grade.B: (80, 89),
            Grade.C: (70, 79),
            Grade.D: (50, 69),
            Grade.F: (0, 49),
        }
        return ranges[self]

    @classmethod
    def from_score(cls, score: int) -> Grade:
        """Determine grade from numeric score."""
        if score >= 90:
            return cls.A
        elif score >= 80:
            return cls.B
        elif score >= 70:
            return cls.C
        elif score >= 50:
            return cls.D
        else:
            return cls.F


class ScriptType(Enum):
    """Types of scripts the dojo can generate and grade."""

    PYTHON = "python"
    BASH = "bash"
    FRIDA = "frida"
    ADB = "adb"
    SHELL = "shell"

    @property
    def file_extension(self) -> str:
        """Get the file extension for this script type."""
        extensions = {
            ScriptType.PYTHON: ".py",
            ScriptType.BASH: ".sh",
            ScriptType.FRIDA: ".js",
            ScriptType.ADB: ".sh",
            ScriptType.SHELL: ".sh",
        }
        return extensions[self]


@dataclass
class ChallengeInput:
    """Input context provided to the model for a challenge."""

    device_context: dict = field(default_factory=dict)
    target_class: Optional[str] = None
    target_method: Optional[str] = None
    cve_id: Optional[str] = None
    additional_context: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "device_context": self.device_context,
            "target_class": self.target_class,
            "target_method": self.target_method,
            "cve_id": self.cve_id,
            "additional_context": self.additional_context,
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class ExpectedOutput:
    """Defines what a correct solution should contain."""

    script_type: ScriptType
    must_contain: list[str] = field(default_factory=list)
    must_not_contain: list[str] = field(default_factory=list)
    expected_patterns: list[str] = field(default_factory=list)

    def validate(self, output: str) -> tuple[bool, list[str]]:
        """
        Validate output against expectations.

        Returns:
            Tuple of (is_valid, list of issues found)
        """
        issues = []

        # Check must_contain
        for pattern in self.must_contain:
            if pattern not in output:
                issues.append(f"Missing required pattern: {pattern}")

        # Check must_not_contain
        for pattern in self.must_not_contain:
            if pattern in output:
                issues.append(f"Contains forbidden pattern: {pattern}")

        return len(issues) == 0, issues


@dataclass
class ScoringRubric:
    """Point allocation for grading."""

    syntax_correct: int = 25
    api_valid: int = 25
    executes_successfully: int = 30
    achieves_objective: int = 20

    @property
    def total_possible(self) -> int:
        """Get total possible points."""
        return (
            self.syntax_correct
            + self.api_valid
            + self.executes_successfully
            + self.achieves_objective
        )

    def calculate_score(
        self,
        syntax_ok: bool,
        api_ok: bool,
        executes: bool,
        achieves: bool,
    ) -> int:
        """Calculate score based on criteria."""
        score = 0
        if syntax_ok:
            score += self.syntax_correct
        if api_ok:
            score += self.api_valid
        if executes:
            score += self.executes_successfully
        if achieves:
            score += self.achieves_objective
        return score


@dataclass
class Challenge:
    """A single dojo challenge for the model to attempt."""

    id: str
    name: str
    description: str
    belt: Belt
    difficulty: int  # 1-5 within belt

    inputs: ChallengeInput
    expected_output: ExpectedOutput
    scoring: ScoringRubric = field(default_factory=ScoringRubric)

    kata_solution: Optional[str] = None  # Golden example if available
    hints: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    def to_prompt(self) -> str:
        """Generate the challenge prompt for the model."""
        prompt = f"{self.description}\n\n"

        if self.inputs.device_context:
            prompt += f"Device Context:\n{json.dumps(self.inputs.device_context, indent=2)}\n\n"

        if self.inputs.target_class:
            prompt += f"Target Class: {self.inputs.target_class}\n"

        if self.inputs.target_method:
            prompt += f"Target Method: {self.inputs.target_method}\n"

        if self.inputs.cve_id:
            prompt += f"CVE: {self.inputs.cve_id}\n"

        return prompt.strip()


@dataclass
class ChallengeResult:
    """Result of a model attempting a challenge."""

    challenge_id: str
    model_output: str
    timestamp: datetime = field(default_factory=datetime.now)
    execution_output: Optional[str] = None
    execution_success: Optional[bool] = None
    execution_error: Optional[str] = None
    retry_count: int = 0

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "challenge_id": self.challenge_id,
            "model_output": self.model_output,
            "timestamp": self.timestamp.isoformat(),
            "execution_output": self.execution_output,
            "execution_success": self.execution_success,
            "execution_error": self.execution_error,
            "retry_count": self.retry_count,
        }


@dataclass
class SenseiAssessment:
    """Sensei's evaluation of a challenge attempt."""

    challenge_id: str
    model_output: str
    grade: Grade
    score: int  # 0-100

    # Detailed feedback
    syntax_issues: list[str] = field(default_factory=list)
    api_errors: list[str] = field(default_factory=list)
    logic_flaws: list[str] = field(default_factory=list)
    security_issues: list[str] = field(default_factory=list)

    # Correction (if grade is D or F)
    corrected_output: Optional[str] = None
    correction_explanation: Optional[str] = None

    # Metadata
    timestamp: datetime = field(default_factory=datetime.now)
    model_id: Optional[str] = None
    execution_output: Optional[str] = None

    @property
    def is_positive_example(self) -> bool:
        """Check if this qualifies as a positive training example."""
        return self.grade.is_positive_example

    @property
    def is_negative_example(self) -> bool:
        """Check if this qualifies as a negative training example."""
        return self.grade.is_negative_example

    @property
    def is_error_recovery_example(self) -> bool:
        """Check if this has a correction that can be used for error recovery training."""
        return self.corrected_output is not None

    @property
    def all_issues(self) -> list[str]:
        """Get all issues combined."""
        return self.syntax_issues + self.api_errors + self.logic_flaws + self.security_issues

    @property
    def issue_count(self) -> int:
        """Get total number of issues."""
        return len(self.all_issues)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "challenge_id": self.challenge_id,
            "model_output": self.model_output,
            "grade": self.grade.value,
            "score": self.score,
            "syntax_issues": self.syntax_issues,
            "api_errors": self.api_errors,
            "logic_flaws": self.logic_flaws,
            "security_issues": self.security_issues,
            "corrected_output": self.corrected_output,
            "correction_explanation": self.correction_explanation,
            "timestamp": self.timestamp.isoformat(),
            "model_id": self.model_id,
            "is_positive_example": self.is_positive_example,
            "is_negative_example": self.is_negative_example,
            "is_error_recovery_example": self.is_error_recovery_example,
        }


@dataclass
class TrainingExample:
    """A single training example for fine-tuning."""

    instruction: str
    input_text: str
    output_text: str

    # Metadata
    source_challenge_id: str
    example_type: str  # "positive", "negative", "error_recovery", "kata"
    belt: Belt
    grade: Optional[Grade] = None
    timestamp: datetime = field(default_factory=datetime.now)

    def to_alpaca(self) -> dict:
        """Export as Alpaca format."""
        return {
            "instruction": self.instruction,
            "input": self.input_text,
            "output": self.output_text,
        }

    def to_sharegpt(self) -> dict:
        """
        Export as ShareGPT/OpenAI messages format.
        Supports multi-turn for error_recovery examples to teach debugging.
        """
        if self.example_type == "error_recovery":
            # Input text for error_recovery contains '## Failed Attempt' and '## Error Information'
            # We want to extract the task and the failed attempt to build a conversation.
            lines = self.input_text.split("\n")
            task = ""
            failed_cmd = ""
            error_info = ""

            current_section = ""
            for line in lines:
                if line.startswith("## Task"):
                    current_section = "task"
                    continue
                elif line.startswith("## Failed Attempt"):
                    current_section = "failed"
                    continue
                elif line.startswith("## Error Information"):
                    current_section = "error"
                    continue
                elif line.startswith("## Instructions"):
                    current_section = "instructions"
                    continue

                if current_section == "task" and line.strip():
                    task += line + "\n"
                elif current_section == "failed" and line.strip() and "```" not in line:
                    failed_cmd += line + "\n"
                elif current_section == "error" and line.strip():
                    error_info += line + "\n"

            return {
                "conversations": [
                    {"from": "human", "value": task.strip()},
                    {"from": "gpt", "value": failed_cmd.strip()},
                    {"from": "human", "value": f"That command failed with the following error:\n\n{error_info.strip()}\n\nPlease provide a corrected version."},
                    {"from": "gpt", "value": self.output_text.strip()},
                ]
            }

        # Default single-turn for positive/kata
        return {
            "conversations": [
                {"from": "human", "value": f"{self.instruction}\n\n{self.input_text}".strip()},
                {"from": "gpt", "value": self.output_text},
            ]
        }

    def to_dpo(self, rejected_output: str) -> dict:
        """Export as DPO format with rejected alternative."""
        return {
            "prompt": f"{self.instruction}\n\n{self.input_text}",
            "chosen": self.output_text,
            "rejected": rejected_output,
        }

    def to_dict(self) -> dict:
        """Convert to dictionary with full metadata."""
        return {
            "instruction": self.instruction,
            "input": self.input_text,
            "output": self.output_text,
            "metadata": {
                "source_challenge_id": self.source_challenge_id,
                "example_type": self.example_type,
                "belt": self.belt.value,
                "grade": self.grade.value if self.grade else None,
                "timestamp": self.timestamp.isoformat(),
            },
        }


@dataclass
class ModelProgress:
    """Track a model's progress through the belt system."""

    model_id: str
    current_belt: Belt
    challenges_attempted: int = 0
    challenges_passed: int = 0
    total_score: int = 0
    assessments: list[SenseiAssessment] = field(default_factory=list)
    training_examples_generated: int = 0
    last_training_date: Optional[datetime] = None

    @property
    def pass_rate(self) -> float:
        """Calculate pass rate as percentage."""
        if self.challenges_attempted == 0:
            return 0.0
        return (self.challenges_passed / self.challenges_attempted) * 100

    @property
    def average_score(self) -> float:
        """Calculate average score."""
        if self.challenges_attempted == 0:
            return 0.0
        return self.total_score / self.challenges_attempted

    def record_assessment(self, assessment: SenseiAssessment) -> None:
        """Record a new assessment."""
        self.assessments.append(assessment)
        self.challenges_attempted += 1
        self.total_score += assessment.score
        if assessment.grade.is_passing:
            self.challenges_passed += 1

    def check_promotion_eligibility(self, required_pass_rate: float = 80.0, required_challenges: int = 5) -> bool:
        """Check if model is eligible for belt promotion."""
        return (
            self.challenges_attempted >= required_challenges
            and self.pass_rate >= required_pass_rate
        )

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "model_id": self.model_id,
            "current_belt": self.current_belt.value,
            "current_belt_display": self.current_belt.display,
            "challenges_attempted": self.challenges_attempted,
            "challenges_passed": self.challenges_passed,
            "pass_rate": round(self.pass_rate, 2),
            "average_score": round(self.average_score, 2),
            "training_examples_generated": self.training_examples_generated,
            "last_training_date": self.last_training_date.isoformat() if self.last_training_date else None,
        }

    def display_status(self) -> str:
        """Generate a display string for current status."""
        return (
            f"Model: {self.model_id}\n"
            f"Belt: {self.current_belt.display}\n"
            f"Progress: {self.challenges_passed}/{self.challenges_attempted} "
            f"({self.pass_rate:.1f}%)\n"
            f"Average Score: {self.average_score:.1f}/100"
        )
