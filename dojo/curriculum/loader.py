"""
Unified Curriculum Loader: Sequential V1 → V2 progression.

This module loads the unified curriculum configuration and provides
methods to run challenges in the correct pedagogical order.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterator, Optional

import yaml

from dojo.models import Belt
from dojo.models_v2 import (
    ChallengeV2,
)


class CurriculumPhase(Enum):
    """Curriculum phase."""
    TOOL_MASTERY = "tool_mastery"
    SECURITY_REASONING = "security_reasoning"


@dataclass
class Stage:
    """A curriculum stage containing related challenges."""

    number: int
    name: str
    phase: CurriculumPhase
    belt: Belt
    source: str  # "v1" or "v2"
    description: str
    skills_gained: list[str]
    challenge_ids: list[str]
    prerequisites: list[int]
    unlocks: list[int]

    @property
    def is_v1(self) -> bool:
        return self.source == "v1"

    @property
    def is_v2(self) -> bool:
        return self.source == "v2"


@dataclass
class EvaluationCheckpoint:
    """Checkpoint for evaluating progress."""

    after_stage: int
    name: str
    test_type: str
    pass_threshold: float
    description: str


@dataclass
class UnifiedCurriculum:
    """
    Unified curriculum combining V1 (tool mastery) and V2 (security reasoning).

    Provides sequential progression through all challenges in pedagogically
    correct order.
    """

    version: str
    name: str
    stages: list[Stage]
    checkpoints: list[EvaluationCheckpoint]
    metadata: dict

    # Cached mappings
    _challenge_to_stage: dict[str, int] = field(default_factory=dict, repr=False)
    _stage_map: dict[int, Stage] = field(default_factory=dict, repr=False)
    _challenge_cache: dict[str, ChallengeV2] = field(default_factory=dict, repr=False)

    def __post_init__(self):
        """Build lookup caches."""
        for stage in self.stages:
            self._stage_map[stage.number] = stage
            for cid in stage.challenge_ids:
                self._challenge_to_stage[cid] = stage.number

    @classmethod
    def load(cls, config_path: Optional[Path] = None) -> "UnifiedCurriculum":
        """
        Load unified curriculum from YAML config.

        Args:
            config_path: Path to unified_curriculum.yaml.
                        Defaults to curriculum directory.

        Returns:
            Loaded UnifiedCurriculum instance.
        """
        if config_path is None:
            config_path = Path(__file__).parent / "unified_curriculum.yaml"

        with open(config_path) as f:
            data = yaml.safe_load(f)

        # Parse stages
        stages = []
        for stage_data in data.get("stages", []):
            try:
                belt_val = stage_data["belt"]
                # Handle belt strings that might not match enum exactly (e.g. capitalized)
                if isinstance(belt_val, str):
                    belt_val = belt_val.lower()
                belt = Belt(belt_val)
            except ValueError:
                # Default or error handling
                belt = Belt.WHITE

            stage = Stage(
                number=stage_data["stage"],
                name=stage_data["name"],
                phase=CurriculumPhase(stage_data["phase"]),
                belt=belt,
                source=stage_data["source"],
                description=stage_data["description"].strip(),
                skills_gained=stage_data.get("skills_gained", []),
                challenge_ids=stage_data.get("challenges", []),
                prerequisites=stage_data.get("prerequisites", []),
                unlocks=stage_data.get("unlocks", []),
            )
            stages.append(stage)

        # Parse checkpoints
        checkpoints = []
        eval_data = data.get("evaluation", {})
        for cp_data in eval_data.get("checkpoints", []):
            checkpoint = EvaluationCheckpoint(
                after_stage=cp_data["after_stage"],
                name=cp_data["name"],
                test_type=cp_data["test_type"],
                pass_threshold=cp_data["pass_threshold"],
                description=cp_data["description"],
            )
            checkpoints.append(checkpoint)

        return cls(
            version=data.get("version", "3.0"),
            name=data.get("name", "AgenticART Unified Curriculum"),
            stages=stages,
            checkpoints=checkpoints,
            metadata=data.get("metadata", {}),
        )

    # -------------------------------------------------------------------------
    # Unified Challenge Loading (Praxis Loop)
    # -------------------------------------------------------------------------

    def load_challenge(self, challenge_id: str) -> ChallengeV2:
        """
        Load any challenge (V1 or V2) as a standardized ChallengeV2 object.
        Ensures a single sequential list of challenges in the curriculum.
        """
        if challenge_id in self._challenge_cache:
            return self._challenge_cache[challenge_id]

        stage = self.get_stage_for_challenge(challenge_id)
        if not stage:
            raise ValueError(f"Challenge {challenge_id} not found in curriculum")

        # Now all challenges should be in V2 YAMLs.
        # If it's a V1 ID, it should be present in the verification_tasks of a V2 challenge,
        # OR it has been converted to a V2 YAML entry.

        challenge = self._load_v2(challenge_id)

        self._challenge_cache[challenge_id] = challenge
        return challenge

    def _load_v2(self, challenge_id: str) -> ChallengeV2:
        """Load a V2 challenge directly."""
        from dojo.graders.archive.run_all_challenges import load_all_challenges

        curriculum_dir = Path(__file__).parent
        all_v2 = load_all_challenges(curriculum_dir.parent / "curriculum")

        target_ch = None
        for pillar_challenges in all_v2.values():
            for ch in pillar_challenges:
                if ch.id == challenge_id:
                    target_ch = ch
                    break
            if target_ch:
                break

        if not target_ch:
            raise ValueError(f"Challenge {challenge_id} not found in pillar files")

        return target_ch

    # -------------------------------------------------------------------------
    # Stage Access
    # -------------------------------------------------------------------------

    def get_stage(self, stage_number: int) -> Stage:
        """Get stage by number."""
        if stage_number not in self._stage_map:
            raise ValueError(f"Stage {stage_number} not found")
        return self._stage_map[stage_number]

    def get_stage_for_challenge(self, challenge_id: str) -> Optional[Stage]:
        """Get the stage containing a challenge."""
        stage_num = self._challenge_to_stage.get(challenge_id)
        if stage_num is None:
            return None
        return self._stage_map[stage_num]

    def stages_in_order(self) -> Iterator[Stage]:
        """Iterate stages in curriculum order."""
        for stage in sorted(self.stages, key=lambda s: s.number):
            yield stage

    def v1_stages(self) -> Iterator[Stage]:
        """Iterate V1 (tool mastery) stages only."""
        for stage in self.stages_in_order():
            if stage.is_v1:
                yield stage

    def v2_stages(self) -> Iterator[Stage]:
        """Iterate V2 (security reasoning) stages only."""
        for stage in self.stages_in_order():
            if stage.is_v2:
                yield stage

    # -------------------------------------------------------------------------
    # Challenge Access
    # -------------------------------------------------------------------------

    def all_challenge_ids(self) -> list[str]:
        """Get all challenge IDs in curriculum order."""
        ids = []
        for stage in self.stages_in_order():
            ids.extend(stage.challenge_ids)
        return ids

    def challenges_up_to_stage(self, stage_number: int) -> list[str]:
        """Get all challenge IDs up to and including a stage."""
        ids = []
        for stage in self.stages_in_order():
            if stage.number > stage_number:
                break
            ids.extend(stage.challenge_ids)
        return ids

    def prerequisites_met(self, stage_number: int, completed_stages: set[int]) -> bool:
        """Check if prerequisites are met for a stage."""
        stage = self.get_stage(stage_number)
        return all(prereq in completed_stages for prereq in stage.prerequisites)

    # -------------------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------------------

    def summary(self) -> str:
        """Generate curriculum summary."""
        lines = [
            f"# {self.name} (v{self.version})",
            "",
            f"Total Challenges: {self.metadata.get('total_challenges', len(self.all_challenge_ids()))}",
            f"V1 Challenges: {self.metadata.get('v1_challenges', sum(len(s.challenge_ids) for s in self.v1_stages()))}",
            f"V2 Challenges: {self.metadata.get('v2_challenges', sum(len(s.challenge_ids) for s in self.v2_stages()))}",
            f"Stages: {len(self.stages)}",
            "",
            "## Stage Progression",
            "",
        ]

        for stage in self.stages_in_order():
            prereq_str = f" (requires: {stage.prerequisites})" if stage.prerequisites else ""
            lines.append(
                f"  {stage.number}. [{stage.belt.value.upper()}] {stage.name} "
                f"- {len(stage.challenge_ids)} challenges{prereq_str}"
            )

        return "\n".join(lines)
