"""V2 Data Models: Reasoning-oriented challenge structures for vulnerability discovery training."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class ChallengeType(Enum):
    """Types of reasoning challenges."""

    OBSERVATION = "observation"  # Identify security-relevant artifacts
    HYPOTHESIS = "hypothesis"  # Form testable security hypotheses
    VERIFICATION = "verification"  # Design and execute tests
    ROOT_CAUSE = "root_cause"  # Deep analysis of WHY
    NEGATIVE = "negative"  # Recognize secure patterns
    TRANSFER = "transfer"  # Apply patterns across contexts
    SYNTHESIS = "synthesis"  # End-to-end discovery


class Pillar(Enum):
    """The seven pillars of discovery training."""

    STATIC_ANALYSIS = "static_analysis"
    NEGATIVE_KNOWLEDGE = "negative_knowledge"
    ROOT_CAUSE = "root_cause"
    PATTERN_TRANSFER = "pattern_transfer"
    METHODOLOGY = "methodology"
    TAXONOMY = "taxonomy"
    PATCH_ANALYSIS = "patch_analysis"


class PhaseID(Enum):
    """Reasoning phases within a challenge."""

    OBSERVE = "observe"
    HYPOTHESIZE = "hypothesize"
    TEST = "test"
    ANALYZE = "analyze"
    SYNTHESIZE = "synthesize"


class ArtifactType(Enum):
    """Types of input artifacts provided to challenges."""

    DECOMPILED_CODE = "decompiled_code"
    MANIFEST = "manifest"
    BINARY_PROPERTIES = "binary_properties"
    RUNTIME_TRACE = "runtime_trace"
    NETWORK_CAPTURE = "network_capture"
    FRIDA_OUTPUT = "frida_output"
    LOGCAT = "logcat"
    PREVIOUS_OUTPUT = "previous_output"
    APK_METADATA = "apk_metadata"
    CVE_DESCRIPTION = "cve_description"
    PATCH_DIFF = "patch_diff"


@dataclass
class Artifact:
    """An input artifact provided to the model."""

    artifact_type: ArtifactType
    content: str
    context: str = ""  # What this artifact represents
    source_file: Optional[str] = None  # Original file path if applicable
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "type": self.artifact_type.value,
            "content": self.content,
            "context": self.context,
            "source_file": self.source_file,
            "metadata": self.metadata,
        }


@dataclass
class EvaluationCriteria:
    """Criteria for evaluating a phase output."""

    name: str
    weight: float  # 0.0 - 1.0, must sum to 1.0 across criteria
    description: str
    scoring_guide: dict = field(default_factory=dict)  # score -> description

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "weight": self.weight,
            "description": self.description,
            "scoring_guide": self.scoring_guide,
        }


@dataclass
class Phase:
    """A reasoning phase within a challenge."""

    phase_id: PhaseID
    instruction: str
    expected_output_schema: dict  # JSON schema for expected output structure
    evaluation_criteria: list[EvaluationCriteria]
    max_tokens: int = 2000
    required: bool = True  # Some phases may be optional

    def to_dict(self) -> dict:
        return {
            "phase_id": self.phase_id.value,
            "instruction": self.instruction,
            "expected_output_schema": self.expected_output_schema,
            "evaluation_criteria": [c.to_dict() for c in self.evaluation_criteria],
            "max_tokens": self.max_tokens,
            "required": self.required,
        }


@dataclass
class GroundTruth:
    """Ground truth for challenge evaluation."""

    vulnerability_present: bool
    vulnerability_type: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    root_cause: Optional[str] = None
    secure_properties: list[str] = field(default_factory=list)  # For negative challenges
    key_observations: list[str] = field(default_factory=list)  # Must-find items
    valid_hypotheses: list[dict] = field(default_factory=list)
    valid_tests: list[dict] = field(default_factory=list)
    exploitation_path: Optional[str] = None
    patch_description: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "vulnerability_present": self.vulnerability_present,
            "vulnerability_type": self.vulnerability_type,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
            "root_cause": self.root_cause,
            "secure_properties": self.secure_properties,
            "key_observations": self.key_observations,
            "valid_hypotheses": self.valid_hypotheses,
            "valid_tests": self.valid_tests,
            "exploitation_path": self.exploitation_path,
            "patch_description": self.patch_description,
        }


@dataclass
class TrainingMetadata:
    """Metadata for training data generation."""

    reasoning_chain_required: bool = True
    dpo_pairs_available: bool = True
    negative_examples: list[str] = field(default_factory=list)  # What NOT to conclude
    common_mistakes: list[str] = field(default_factory=list)  # Frequent errors
    pattern_family: Optional[str] = None  # For transfer learning grouping
    difficulty_factors: list[str] = field(default_factory=list)  # What makes it hard

    def to_dict(self) -> dict:
        return {
            "reasoning_chain_required": self.reasoning_chain_required,
            "dpo_pairs_available": self.dpo_pairs_available,
            "negative_examples": self.negative_examples,
            "common_mistakes": self.common_mistakes,
            "pattern_family": self.pattern_family,
            "difficulty_factors": self.difficulty_factors,
        }


# Import Belt from original models for compatibility
from dojo.models import Belt, Grade


@dataclass
class ChallengeV2:
    """V2 Challenge: Multi-phase reasoning challenge for discovery training."""

    # Identity
    id: str
    name: str

    # Classification
    challenge_type: ChallengeType
    pillar: Pillar
    belt: Belt
    difficulty: int  # 1-10 scale

    # Content
    description: str
    artifacts: list[Artifact]
    phases: list[Phase]

    # Evaluation
    ground_truth: GroundTruth
    training_metadata: TrainingMetadata

    # Fields with defaults must come last
    version: int = 2

    # Relationships
    prerequisites: list[str] = field(default_factory=list)
    unlocks: list[str] = field(default_factory=list)
    related_challenges: list[str] = field(default_factory=list)

    # Tags for filtering
    tags: list[str] = field(default_factory=list)
    cwe_tags: list[str] = field(default_factory=list)
    owasp_tags: list[str] = field(default_factory=list)

    def to_prompt(self, phase_index: int = 0) -> str:
        """Generate prompt for a specific phase."""
        if phase_index >= len(self.phases):
            raise ValueError(f"Phase index {phase_index} out of range")

        phase = self.phases[phase_index]
        prompt_parts = [
            f"# {self.name}",
            "",
            self.description,
            "",
            "## Input Artifacts",
            "",
        ]

        for artifact in self.artifacts:
            prompt_parts.append(f"### {artifact.artifact_type.value}")
            if artifact.context:
                prompt_parts.append(f"*{artifact.context}*")
            prompt_parts.append("```")
            prompt_parts.append(artifact.content)
            prompt_parts.append("```")
            prompt_parts.append("")

        prompt_parts.extend([
            f"## Phase: {phase.phase_id.value.upper()}",
            "",
            phase.instruction,
            "",
            "## Expected Output Format",
            "```json",
            json.dumps(phase.expected_output_schema, indent=2),
            "```",
        ])

        return "\n".join(prompt_parts)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "challenge_type": self.challenge_type.value,
            "pillar": self.pillar.value,
            "belt": self.belt.value,
            "difficulty": self.difficulty,
            "description": self.description,
            "artifacts": [a.to_dict() for a in self.artifacts],
            "phases": [p.to_dict() for p in self.phases],
            "ground_truth": self.ground_truth.to_dict(),
            "training_metadata": self.training_metadata.to_dict(),
            "prerequisites": self.prerequisites,
            "unlocks": self.unlocks,
            "related_challenges": self.related_challenges,
            "tags": self.tags,
            "cwe_tags": self.cwe_tags,
            "owasp_tags": self.owasp_tags,
        }


@dataclass
class PhaseOutput:
    """Model output for a single phase."""

    phase_id: PhaseID
    raw_output: str
    parsed_output: Optional[dict] = None  # Structured extraction
    parse_error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "phase_id": self.phase_id.value,
            "raw_output": self.raw_output,
            "parsed_output": self.parsed_output,
            "parse_error": self.parse_error,
        }


@dataclass
class PhaseEvaluation:
    """Evaluation result for a single phase."""

    phase_id: PhaseID
    score: float  # 0.0 - 1.0
    criteria_scores: dict[str, float]  # criterion_name -> score
    feedback: str
    hallucinations_detected: list[str] = field(default_factory=list)
    missing_observations: list[str] = field(default_factory=list)
    incorrect_conclusions: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        """Check if phase passed (score >= 0.7)."""
        return self.score >= 0.7

    def to_dict(self) -> dict:
        return {
            "phase_id": self.phase_id.value,
            "score": self.score,
            "criteria_scores": self.criteria_scores,
            "feedback": self.feedback,
            "hallucinations_detected": self.hallucinations_detected,
            "missing_observations": self.missing_observations,
            "incorrect_conclusions": self.incorrect_conclusions,
            "passed": self.passed,
        }


@dataclass
class ReasoningQuality:
    """Quality assessment of reasoning across phases."""

    completeness: float  # Did it address all aspects?
    accuracy: float  # Is it factually correct?
    depth: float  # Does it go beyond surface level?
    transferability: float  # Can conclusions generalize?
    coherence: float  # Is the reasoning chain logically consistent?

    @property
    def overall(self) -> float:
        """Calculate overall reasoning quality score."""
        return (
            self.completeness * 0.2 +
            self.accuracy * 0.3 +
            self.depth * 0.2 +
            self.transferability * 0.15 +
            self.coherence * 0.15
        )

    def to_dict(self) -> dict:
        return {
            "completeness": self.completeness,
            "accuracy": self.accuracy,
            "depth": self.depth,
            "transferability": self.transferability,
            "coherence": self.coherence,
            "overall": self.overall,
        }


@dataclass
class ReasoningChain:
    """Complete record of a reasoning challenge attempt."""

    challenge_id: str
    model_id: str
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None

    # Phase-by-phase results
    phase_outputs: list[PhaseOutput] = field(default_factory=list)
    phase_evaluations: list[PhaseEvaluation] = field(default_factory=list)

    # Overall assessment
    reasoning_quality: Optional[ReasoningQuality] = None
    discovery_made: bool = False
    novel_finding: bool = False
    vulnerability_correctly_identified: bool = False

    @property
    def total_score(self) -> float:
        """Calculate total score across all phases."""
        if not self.phase_evaluations:
            return 0.0
        return sum(e.score for e in self.phase_evaluations) / len(self.phase_evaluations)

    @property
    def grade(self) -> Grade:
        """Determine grade from total score."""
        score_percent = self.total_score * 100
        return Grade.from_score(int(score_percent))

    @property
    def success(self) -> bool:
        """Check if challenge was successful."""
        return self.grade.is_passing and self.vulnerability_correctly_identified

    @property
    def duration(self) -> float:
        """Get total duration in seconds."""
        end = self.completed_at or datetime.now()
        return (end - self.started_at).total_seconds()

    def add_phase_result(self, output: PhaseOutput, evaluation: PhaseEvaluation) -> None:
        """Add a phase result."""
        self.phase_outputs.append(output)
        self.phase_evaluations.append(evaluation)

    def to_dict(self) -> dict:
        return {
            "challenge_id": self.challenge_id,
            "model_id": self.model_id,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration": self.duration,
            "phase_outputs": [p.to_dict() for p in self.phase_outputs],
            "phase_evaluations": [e.to_dict() for e in self.phase_evaluations],
            "reasoning_quality": self.reasoning_quality.to_dict() if self.reasoning_quality else None,
            "total_score": self.total_score,
            "grade": self.grade.value,
            "success": self.success,
            "discovery_made": self.discovery_made,
            "novel_finding": self.novel_finding,
            "vulnerability_correctly_identified": self.vulnerability_correctly_identified,
        }


@dataclass
class TrainingExampleV2:
    """V2 Training example with full reasoning chain."""

    # Core content
    instruction: str
    input_text: str
    output_text: str

    # Phase context
    phase_id: PhaseID
    challenge_type: ChallengeType
    pillar: Pillar

    # Source tracking
    source_challenge_id: str

    # Classification (required field)
    example_type: str  # "positive", "negative", "dpo_chosen", "dpo_rejected"

    # Fields with defaults must come last
    source_chain_id: Optional[str] = None
    belt: Belt = Belt.WHITE
    grade: Optional[Grade] = None

    # Quality metrics
    reasoning_quality_score: Optional[float] = None
    hallucination_free: bool = True

    # DPO-specific
    is_dpo_pair: bool = False
    dpo_partner_id: Optional[str] = None  # ID of the paired example
    rejection_reasons: list[str] = field(default_factory=list)

    # Metadata
    timestamp: datetime = field(default_factory=datetime.now)
    tags: list[str] = field(default_factory=list)

    def to_alpaca(self) -> dict:
        """Export as Alpaca format."""
        return {
            "instruction": self.instruction,
            "input": self.input_text,
            "output": self.output_text,
        }

    def to_sharegpt(self) -> dict:
        """Export as ShareGPT/OpenAI messages format."""
        return {
            "conversations": [
                {"from": "system", "value": self.instruction},
                {"from": "human", "value": self.input_text},
                {"from": "gpt", "value": self.output_text},
            ]
        }

    def to_dpo(self, rejected_output: str, rejection_reasons: list[str]) -> dict:
        """Export as DPO format with rejected alternative."""
        return {
            "prompt": f"{self.instruction}\n\n{self.input_text}",
            "chosen": self.output_text,
            "rejected": rejected_output,
            "rejection_reasons": rejection_reasons,
        }

    def to_dict(self) -> dict:
        return {
            "instruction": self.instruction,
            "input": self.input_text,
            "output": self.output_text,
            "phase_id": self.phase_id.value,
            "challenge_type": self.challenge_type.value,
            "pillar": self.pillar.value,
            "source_challenge_id": self.source_challenge_id,
            "source_chain_id": self.source_chain_id,
            "example_type": self.example_type,
            "belt": self.belt.value,
            "grade": self.grade.value if self.grade else None,
            "reasoning_quality_score": self.reasoning_quality_score,
            "hallucination_free": self.hallucination_free,
            "is_dpo_pair": self.is_dpo_pair,
            "dpo_partner_id": self.dpo_partner_id,
            "rejection_reasons": self.rejection_reasons,
            "timestamp": self.timestamp.isoformat(),
            "tags": self.tags,
        }


@dataclass
class PatternFamily:
    """A family of related vulnerability patterns for transfer learning."""

    family_id: str
    name: str
    description: str

    # Pattern definition
    root_cwe: str
    related_cwes: list[str] = field(default_factory=list)
    signature: str = ""  # Abstract pattern signature

    # Instances
    challenge_ids: list[str] = field(default_factory=list)
    min_instances_required: int = 5

    # Transfer evaluation
    holdout_challenge_ids: list[str] = field(default_factory=list)  # For testing transfer

    def to_dict(self) -> dict:
        return {
            "family_id": self.family_id,
            "name": self.name,
            "description": self.description,
            "root_cwe": self.root_cwe,
            "related_cwes": self.related_cwes,
            "signature": self.signature,
            "challenge_ids": self.challenge_ids,
            "min_instances_required": self.min_instances_required,
            "holdout_challenge_ids": self.holdout_challenge_ids,
            "instance_count": len(self.challenge_ids),
            "ready_for_transfer": len(self.challenge_ids) >= self.min_instances_required,
        }


@dataclass
class BeltProgressV2:
    """Track model progress through V2 belt system."""

    model_id: str
    current_belt: Belt

    # Per-pillar progress
    pillar_scores: dict[str, float] = field(default_factory=dict)
    pillar_challenges_completed: dict[str, int] = field(default_factory=dict)

    # Per-phase capability scores
    phase_capabilities: dict[str, float] = field(default_factory=dict)

    # Overall metrics
    total_challenges_attempted: int = 0
    total_challenges_passed: int = 0
    reasoning_chains: list[ReasoningChain] = field(default_factory=list)

    # Discovery metrics
    discoveries_made: int = 0
    novel_findings: int = 0
    false_positive_rate: float = 0.0

    # Pattern transfer metrics
    patterns_learned: list[str] = field(default_factory=list)
    transfer_success_rate: float = 0.0

    @property
    def pass_rate(self) -> float:
        if self.total_challenges_attempted == 0:
            return 0.0
        return (self.total_challenges_passed / self.total_challenges_attempted) * 100

    @property
    def average_reasoning_quality(self) -> float:
        if not self.reasoning_chains:
            return 0.0
        qualities = [
            c.reasoning_quality.overall
            for c in self.reasoning_chains
            if c.reasoning_quality
        ]
        return sum(qualities) / len(qualities) if qualities else 0.0

    def check_belt_promotion(self) -> tuple[bool, str]:
        """Check if model is ready for belt promotion."""
        requirements = self._get_belt_requirements()

        if self.pass_rate < requirements["min_pass_rate"]:
            return False, f"Pass rate {self.pass_rate:.1f}% < required {requirements['min_pass_rate']}%"

        if self.total_challenges_passed < requirements["min_challenges"]:
            return False, f"Challenges passed {self.total_challenges_passed} < required {requirements['min_challenges']}"

        if self.average_reasoning_quality < requirements["min_reasoning_quality"]:
            return False, f"Reasoning quality {self.average_reasoning_quality:.2f} < required {requirements['min_reasoning_quality']}"

        # Belt-specific requirements
        if self.current_belt >= Belt.PURPLE:
            if self.false_positive_rate > requirements.get("max_false_positive_rate", 0.1):
                return False, f"False positive rate {self.false_positive_rate:.2f} > max {requirements['max_false_positive_rate']}"

        if self.current_belt >= Belt.BROWN:
            if self.transfer_success_rate < requirements.get("min_transfer_rate", 0.6):
                return False, f"Transfer rate {self.transfer_success_rate:.2f} < required {requirements['min_transfer_rate']}"

        return True, "Ready for promotion"

    def _get_belt_requirements(self) -> dict:
        """Get promotion requirements for current belt."""
        requirements = {
            Belt.WHITE: {"min_pass_rate": 70, "min_challenges": 30, "min_reasoning_quality": 0.6},
            Belt.YELLOW: {"min_pass_rate": 75, "min_challenges": 50, "min_reasoning_quality": 0.65},
            Belt.ORANGE: {"min_pass_rate": 75, "min_challenges": 70, "min_reasoning_quality": 0.7},
            Belt.GREEN: {"min_pass_rate": 70, "min_challenges": 90, "min_reasoning_quality": 0.7},
            Belt.BLUE: {"min_pass_rate": 70, "min_challenges": 100, "min_reasoning_quality": 0.75},
            Belt.PURPLE: {"min_pass_rate": 75, "min_challenges": 120, "min_reasoning_quality": 0.75, "max_false_positive_rate": 0.1},
            Belt.BROWN: {"min_pass_rate": 75, "min_challenges": 140, "min_reasoning_quality": 0.8, "min_transfer_rate": 0.6},
            Belt.BLACK: {"min_pass_rate": 80, "min_challenges": 150, "min_reasoning_quality": 0.85, "min_transfer_rate": 0.7},
        }
        return requirements.get(self.current_belt, requirements[Belt.WHITE])

    def to_dict(self) -> dict:
        return {
            "model_id": self.model_id,
            "current_belt": self.current_belt.value,
            "pillar_scores": self.pillar_scores,
            "pillar_challenges_completed": self.pillar_challenges_completed,
            "phase_capabilities": self.phase_capabilities,
            "total_challenges_attempted": self.total_challenges_attempted,
            "total_challenges_passed": self.total_challenges_passed,
            "pass_rate": self.pass_rate,
            "average_reasoning_quality": self.average_reasoning_quality,
            "discoveries_made": self.discoveries_made,
            "novel_findings": self.novel_findings,
            "false_positive_rate": self.false_positive_rate,
            "patterns_learned": self.patterns_learned,
            "transfer_success_rate": self.transfer_success_rate,
        }
