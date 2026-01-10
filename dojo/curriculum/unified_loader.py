"""
Unified Curriculum Loader: Sequential V1 → V2 progression.

This module loads the unified curriculum configuration and provides
methods to run challenges in the correct pedagogical order.

Usage:
    from dojo.curriculum.unified_loader import UnifiedCurriculum

    curriculum = UnifiedCurriculum.load()

    # Run all stages sequentially
    for stage in curriculum.stages:
        results = curriculum.run_stage(stage.number)

    # Or run specific stage
    results = curriculum.run_stage(4)  # V2 White Belt

    # Generate training data in curriculum order
    curriculum.generate_training_data("output/training_data.jsonl")
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterator, Optional

import yaml

from dojo.models import Belt
from dojo.models_v2 import (
    ChallengeType,
    ChallengeV2,
    EvaluationCriteria,
    GroundTruth,
    Phase,
    PhaseID,
    Pillar,
    TrainingMetadata,
    VerificationTask,
)

# We avoid direct import of loaders at module level to prevent circular imports if they use UnifiedCurriculum
# They will be imported inside methods.


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

    # Mapping of V2 Reasoning IDs to V1 Verification task IDs
    # This implements the "injection" logic.
    V2_TO_V1_VERIFICATION_MAP = {
        "method_observe_white_001": ["white_001", "white_003"],
        "static_basic_white_001": ["white_002", "white_008"],
        "neg_secure_white_001": ["white_006"],
        "method_hypothesis_yellow_001": ["yellow_001", "yellow_002"],
        "static_dataflow_yellow_001": ["yellow_004", "yellow_007"],
        "method_test_orange_001": ["orange_001", "orange_008"],
        "static_crossfunc_orange_001": ["orange_002", "orange_004"],
        "static_component_green_001": ["yellow_006", "orange_005"],
        "static_crypto_blue_001": ["orange_010", "orange_011"],
    }

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

        if stage.is_v1:
            # Standalone V1 challenge being treated as a sequence item
            challenge = self._load_v1_as_v2(challenge_id)
        else:
            # V2 Reasoning challenge with potential V1 injections
            challenge = self._load_v2_with_injections(challenge_id)

        self._challenge_cache[challenge_id] = challenge
        return challenge

    def _load_v1_as_v2(self, challenge_id: str) -> ChallengeV2:
        """Convert a legacy V1 challenge to a first-class ChallengeV2 object."""
        from dojo.curriculum.loader import ChallengeLoader
        # Load legacy challenge
        loader = ChallengeLoader()
        # V1 loader expects belt to find the file
        try:
            v1_challenge = loader.load_challenge(challenge_id)
        except Exception:
            # Fallback if ID doesn't match belt structure perfectly or other error
            # Try searching all belts
            found = False
            for b in Belt:
                try:
                    v1_challenge = loader.load_challenge(challenge_id)
                    found = True
                    break
                except Exception:
                    continue
            if not found:
                raise ValueError(f"Could not load V1 challenge {challenge_id}")

        # Convert to V2 phase
        phase = Phase(
            phase_id=PhaseID.TEST,
            instruction=v1_challenge.description,
            expected_output_schema={"command": "string", "explanation": "string"},
            evaluation_criteria=[
                EvaluationCriteria("execution", 1.0, "Matches V1 validation rules")
            ]
        )

        # Create verification task from V1 data
        v_task = self._v1_to_verification_task(v1_challenge)

        return ChallengeV2(
            id=v1_challenge.id,
            name=v1_challenge.name,
            challenge_type=ChallengeType.VERIFICATION,
            pillar=Pillar.METHODOLOGY,
            belt=v1_challenge.belt,
            difficulty=v1_challenge.difficulty,
            description=v1_challenge.description,
            artifacts=[],
            phases=[phase],
            ground_truth=GroundTruth(
                vulnerability_present=True,
                valid_tests=[{"command": v1_challenge.kata_solution}]
            ),
            training_metadata=TrainingMetadata(reasoning_chain_required=False),
            verification_tasks=[v_task],  # Non-optional
            tags=v1_challenge.tags
        )

    def _load_v2_with_injections(self, challenge_id: str) -> ChallengeV2:
        """Load a V2 challenge and inject corresponding V1 verification tasks."""
        # Since V2 files are scattered in pillars, we need a way to find them.
        # For now, we assume we can look them up via the pillar directory structure.
        from dojo.graders.run_all_challenges import load_all_challenges

        # This is inefficient (reloading all) but reliable for this Proof of Concept.
        # A production version would index them once.
        curriculum_dir = Path(__file__).parent
        all_challenges_map = load_all_challenges(curriculum_dir.parent / "curriculum")

        target_ch = None
        for challenges in all_challenges_map.values():
            for ch in challenges:
                if ch.id == challenge_id:
                    target_ch = ch
                    break
            if target_ch:
                break

        if not target_ch:
            raise ValueError(f"V2 challenge {challenge_id} not found")

        # Inject V1 tasks if mapped
        v1_ids = self.V2_TO_V1_VERIFICATION_MAP.get(challenge_id, [])
        from dojo.curriculum.loader import ChallengeLoader
        v1_loader = ChallengeLoader()

        injected_tasks = []
        for v1_id in v1_ids:
            try:
                v1_ch = v1_loader.load_challenge(v1_id)
                injected_tasks.append(self._v1_to_verification_task(v1_ch))
            except Exception:
                continue

        # Ensure verification_tasks is non-optional
        target_ch.verification_tasks = injected_tasks
        return target_ch

    def _v1_to_verification_task(self, v1_challenge: Any) -> VerificationTask:
        """Helper to convert V1 challenge to VerificationTask."""
        # Note: 'Any' used for v1_challenge to avoid complex import typing here
        return VerificationTask(
            instruction=v1_challenge.description,
            mcp_tool_call={
                "tool": "adb_shell",
                "command": v1_challenge.kata_solution or "echo 'No solution provided'"
            },
            validation_rule=v1_challenge.inputs.additional_context.get("validation", {})
        )

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
    # Training Data Generation
    # -------------------------------------------------------------------------

    def get_training_sequence(self) -> list[dict]:
        """
        Get training data generation sequence.

        Returns list of dicts with:
        - stage: stage number
        - challenge_ids: list of challenge IDs
        - phase: training phase (warmup, core, advanced)
        """
        sequence = []

        # Get training config from curriculum
        warmup = {1, 2}
        core = {3, 4, 5, 6}

        for stage in self.stages_in_order():
            if stage.number in warmup:
                phase = "warmup"
            elif stage.number in core:
                phase = "core"
            else:
                phase = "advanced"

            sequence.append({
                "stage": stage.number,
                "name": stage.name,
                "challenge_ids": stage.challenge_ids,
                "phase": phase,
                "belt": stage.belt.value,
                "source": stage.source,
            })

        return sequence

    # -------------------------------------------------------------------------
    # Progress Tracking
    # -------------------------------------------------------------------------

    @dataclass
    class Progress:
        """Track curriculum completion progress."""
        completed_challenges: set[str] = field(default_factory=set)
        completed_stages: set[int] = field(default_factory=set)
        current_stage: int = 1
        scores: dict[str, float] = field(default_factory=dict)

        def complete_challenge(self, challenge_id: str, score: float):
            self.completed_challenges.add(challenge_id)
            self.scores[challenge_id] = score

        def complete_stage(self, stage_number: int):
            self.completed_stages.add(stage_number)
            if stage_number >= self.current_stage:
                self.current_stage = stage_number + 1

        @property
        def average_score(self) -> float:
            if not self.scores:
                return 0.0
            return sum(self.scores.values()) / len(self.scores)

    def create_progress_tracker(self) -> Progress:
        """Create a new progress tracker."""
        return self.Progress()

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

        lines.extend([
            "",
            "## Checkpoints",
            "",
        ])

        for cp in self.checkpoints:
            lines.append(f"  After Stage {cp.after_stage}: {cp.name} (threshold: {cp.pass_threshold:.0%})")

        return "\n".join(lines)


# -----------------------------------------------------------------------------
# CLI Interface
# -----------------------------------------------------------------------------

def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Unified Curriculum Loader")
    parser.add_argument("--summary", action="store_true", help="Print curriculum summary")
    parser.add_argument("--stage", type=int, help="Show details for specific stage")
    parser.add_argument("--list-challenges", action="store_true", help="List all challenges in order")
    parser.add_argument("--training-sequence", action="store_true", help="Show training data sequence")

    args = parser.parse_args()

    curriculum = UnifiedCurriculum.load()

    if args.summary:
        print(curriculum.summary())

    elif args.stage:
        stage = curriculum.get_stage(args.stage)
        print(f"Stage {stage.number}: {stage.name}")
        print(f"  Phase: {stage.phase.value}")
        print(f"  Belt: {stage.belt.value}")
        print(f"  Source: {stage.source}")
        print(f"  Prerequisites: {stage.prerequisites}")
        print(f"  Unlocks: {stage.unlocks}")
        print(f"\n  Description:\n    {stage.description}")
        print("\n  Skills Gained:")
        for skill in stage.skills_gained:
            print(f"    - {skill}")
        print(f"\n  Challenges ({len(stage.challenge_ids)}):")
        for cid in stage.challenge_ids:
            print(f"    - {cid}")

    elif args.list_challenges:
        print("# Challenges in Curriculum Order\n")
        for stage in curriculum.stages_in_order():
            print(f"## Stage {stage.number}: {stage.name}")
            for i, cid in enumerate(stage.challenge_ids, 1):
                print(f"  {i}. {cid}")
            print()

    elif args.training_sequence:
        print("# Training Data Generation Sequence\n")
        for item in curriculum.get_training_sequence():
            print(f"Stage {item['stage']} ({item['phase']}): {item['name']}")
            print(f"  Belt: {item['belt']}, Source: {item['source']}")
            print(f"  Challenges: {len(item['challenge_ids'])}")
            print()

    else:
        parser.print_help()


if __name__ == "__main__":
    main()

