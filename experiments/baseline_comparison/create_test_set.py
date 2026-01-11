#!/usr/bin/env python3
"""
Create Holdout Test Set for Baseline Comparison Experiment

CRITICAL: This test set must NEVER be used for training.
Run this ONCE before any fine-tuning to avoid data leakage.
"""

import json
import random
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from dojo.models import Belt
from dojo.models_v2 import (
    Artifact,
    ArtifactType,
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

# We define tiers locally to avoid circular imports
TIERS = ["white", "yellow", "green", "brown", "black", "novel"]

# Map belts to experiment tiers
BELT_TO_TIER = {
    Belt.WHITE: "white",
    Belt.YELLOW: "yellow",
    Belt.GREEN: "green",
    Belt.BROWN: "brown",
    Belt.BLACK: "black",
}

# Target counts per tier (total across all pillars)
TARGET_PER_TIER = {
    "white": 20,
    "yellow": 20,
    "green": 20,
    "brown": 15,
    "black": 10,
    "novel": 15,  # Manually curated - unseen patterns
}


def load_challenge_from_yaml(yaml_data: dict) -> ChallengeV2:
    """Convert YAML challenge data to ChallengeV2 object."""

    # Parse artifacts
    artifacts = []
    for art_data in yaml_data.get("artifacts", []):
        artifact_type = ArtifactType(art_data.get("type", "decompiled_code"))
        artifacts.append(Artifact(
            artifact_type=artifact_type,
            content=art_data.get("content", ""),
            context=art_data.get("context", ""),
        ))

    # Parse phases
    phases = []
    for phase_data in yaml_data.get("phases", []):
        phase_id_str = phase_data.get("phase_id", "observe")
        phase_id = PhaseID(phase_id_str)

        criteria = []
        for crit in phase_data.get("evaluation_criteria", []):
            criteria.append(EvaluationCriteria(
                name=crit.get("name", ""),
                weight=crit.get("weight", 0.25),
                description=crit.get("description", ""),
            ))

        phases.append(Phase(
            phase_id=phase_id,
            instruction=phase_data.get("instruction", ""),
            expected_output_schema=phase_data.get("expected_output_schema", {}),
            evaluation_criteria=criteria,
            max_tokens=phase_data.get("max_tokens", 1500),
        ))

    # Parse ground truth
    gt_data = yaml_data.get("ground_truth", {})
    ground_truth = GroundTruth(
        vulnerability_present=gt_data.get("vulnerability_present", True),
        vulnerability_type=gt_data.get("vulnerability_type"),
        cwe_id=gt_data.get("cwe_id"),
        root_cause=gt_data.get("root_cause", ""),
        key_observations=gt_data.get("key_observations", []),
        secure_properties=gt_data.get("secure_properties", []),
    )

    # Map belt string to enum
    belt_map = {
        "white": Belt.WHITE,
        "yellow": Belt.YELLOW,
        "orange": Belt.ORANGE,
        "green": Belt.GREEN,
        "blue": Belt.BLUE,
        "purple": Belt.PURPLE,
        "brown": Belt.BROWN,
        "black": Belt.BLACK,
    }
    belt = belt_map.get(yaml_data.get("belt", "white"), Belt.WHITE)

    # Map pillar string
    pillar_map = {
        "static_analysis": Pillar.STATIC_ANALYSIS,
        "negative_knowledge": Pillar.NEGATIVE_KNOWLEDGE,
        "root_cause": Pillar.ROOT_CAUSE,
        "pattern_transfer": Pillar.PATTERN_TRANSFER,
        "patch_analysis": Pillar.PATCH_ANALYSIS,
        "methodology": Pillar.METHODOLOGY,
        "taxonomy": Pillar.TAXONOMY,
    }
    pillar = pillar_map.get(yaml_data.get("pillar", "static_analysis"), Pillar.STATIC_ANALYSIS)

    # Map challenge type
    type_map = {
        "observation": ChallengeType.OBSERVATION,
        "hypothesis": ChallengeType.HYPOTHESIS,
        "synthesis": ChallengeType.SYNTHESIS,
        "negative": ChallengeType.NEGATIVE,
        "transfer": ChallengeType.TRANSFER,
    }
    challenge_type = type_map.get(yaml_data.get("type", "observation"), ChallengeType.OBSERVATION)

    # Parse verification_tasks
    verification_tasks = []
    for vt_data in yaml_data.get("verification_tasks", []):
        verification_tasks.append(VerificationTask(
            instruction=vt_data.get("instruction", ""),
            mcp_tool_call=vt_data.get("mcp_tool_call", {}),
            validation_rule=vt_data.get("validation_rule", {}),
        ))

    return ChallengeV2(
        id=yaml_data.get("id", "unknown"),
        name=yaml_data.get("name", "Unknown Challenge"),
        challenge_type=challenge_type,
        pillar=pillar,
        belt=belt,
        difficulty=yaml_data.get("difficulty", 5),
        description=yaml_data.get("description", ""),
        artifacts=artifacts,
        phases=phases,
        ground_truth=ground_truth,
        training_metadata=TrainingMetadata(),
        verification_tasks=verification_tasks,
        cwe_tags=yaml_data.get("cwe_tags", []),
        tags=yaml_data.get("tags", []),
    )


def challenge_to_dict(challenge: ChallengeV2) -> dict:
    """Convert ChallengeV2 to serializable dict."""
    return {
        "id": challenge.id,
        "name": challenge.name,
        "type": challenge.challenge_type.value,
        "pillar": challenge.pillar.value,
        "belt": challenge.belt.value,
        "difficulty": challenge.difficulty,
        "description": challenge.description,
        "artifacts": [
            {
                "type": a.artifact_type.value,
                "content": a.content,
                "context": a.context,
            }
            for a in challenge.artifacts
        ],
        "phases": [
            {
                "phase_id": p.phase_id.value,
                "instruction": p.instruction,
                "expected_output_schema": p.expected_output_schema,
                "evaluation_criteria": [
                    {"name": c.name, "weight": c.weight, "description": c.description}
                    for c in p.evaluation_criteria
                ],
                "max_tokens": p.max_tokens,
            }
            for p in challenge.phases
        ],
        "ground_truth": {
            "vulnerability_present": challenge.ground_truth.vulnerability_present,
            "vulnerability_type": challenge.ground_truth.vulnerability_type,
            "cwe_id": challenge.ground_truth.cwe_id,
            "root_cause": challenge.ground_truth.root_cause,
            "key_observations": challenge.ground_truth.key_observations,
            "secure_properties": challenge.ground_truth.secure_properties,
        },
        "verification_tasks": [
            {
                "instruction": vt.instruction,
                "mcp_tool_call": vt.mcp_tool_call,
                "validation_rule": vt.validation_rule,
            }
            for vt in challenge.verification_tasks
        ],
        "cwe_tags": getattr(challenge, 'cwe_tags', []),
        "tags": getattr(challenge, 'tags', []),
    }


def load_challenges_from_yaml(filepath: Path) -> list[ChallengeV2]:
    """Load challenges from a YAML file."""
    with open(filepath) as f:
        data = yaml.safe_load(f)

    challenges = []
    for challenge_data in data.get("challenges", []):
        try:
            challenge = load_challenge_from_yaml(challenge_data)
            challenge._source_path = filepath  # Track source
            challenges.append(challenge)
        except Exception as e:
            print(f"  Warning: Failed to load {challenge_data.get('id', 'unknown')}: {e}")

    return challenges


def load_all_challenges(curriculum_dir: Path) -> list[ChallengeV2]:
    """Load all challenges from all pillars."""
    all_challenges = []

    pillars_dir = curriculum_dir / "v2" / "pillars"

    if not pillars_dir.exists():
        print(f"Error: Pillars directory not found: {pillars_dir}")
        return []

    for pillar_dir in sorted(pillars_dir.iterdir()):
        if pillar_dir.is_dir():
            challenges_file = pillar_dir / "challenges.yaml"
            if challenges_file.exists():
                print(f"  Loading: {pillar_dir.name}")
                challenges = load_challenges_from_yaml(challenges_file)
                all_challenges.extend(challenges)
                print(f"    Found {len(challenges)} challenges")

    return all_challenges


def stratified_sample(
    challenges: list[ChallengeV2],
    target_per_tier: dict,
    seed: int = 42,
) -> dict[str, list[ChallengeV2]]:
    """
    Sample challenges stratified by difficulty tier and pillar.
    """
    rng = random.Random(seed)

    # Group by tier
    by_tier = {tier: [] for tier in TIERS if tier != "novel"}
    for c in challenges:
        tier = BELT_TO_TIER.get(c.belt)
        if tier:
            by_tier[tier].append(c)

    # Sample from each tier, balancing pillars
    sampled = {}
    for tier, target in target_per_tier.items():
        if tier == "novel":
            sampled[tier] = []  # Novel tier is manually curated
            continue

        available = by_tier.get(tier, [])
        if not available:
            print(f"Warning: No challenges available for tier {tier}")
            sampled[tier] = []
            continue

        # Group by pillar
        by_pillar = {}
        for c in available:
            pillar = c.pillar.value if c.pillar else "unknown"
            if pillar not in by_pillar:
                by_pillar[pillar] = []
            by_pillar[pillar].append(c)

        # Sample evenly from pillars
        per_pillar = max(1, target // len(by_pillar)) if by_pillar else 0
        tier_sample = []

        for pillar, pillar_challenges in by_pillar.items():
            rng.shuffle(pillar_challenges)
            tier_sample.extend(pillar_challenges[:per_pillar])

        # If we need more, sample randomly from remainder
        while len(tier_sample) < target:
            remaining = [c for c in available if c not in tier_sample]
            if not remaining:
                break
            tier_sample.append(rng.choice(remaining))

        # Trim if over target
        tier_sample = tier_sample[:target]
        sampled[tier] = tier_sample

    return sampled


def create_test_set(
    curriculum_dir: Path,
    output_dir: Path,
    seed: int = 42,
) -> None:
    """Create the holdout test set."""

    print("=" * 60)
    print("CREATING HOLDOUT TEST SET")
    print("=" * 60)
    print(f"Curriculum: {curriculum_dir}")
    print(f"Output: {output_dir}")
    print(f"Seed: {seed}")
    print()

    # Load challenges
    print("Loading challenges from YAML files...")
    challenges = load_all_challenges(curriculum_dir)
    print(f"\nLoaded {len(challenges)} total challenges")

    if not challenges:
        print("\nERROR: No challenges found!")
        print("Make sure the curriculum directory has the structure:")
        print("  curriculum/v2/pillars/<pillar_name>/challenges.yaml")
        return

    # Show belt distribution
    belt_counts = {}
    for c in challenges:
        belt = c.belt.value if c.belt else "unknown"
        belt_counts[belt] = belt_counts.get(belt, 0) + 1
    print("\nBelt distribution:")
    for belt, count in sorted(belt_counts.items()):
        print(f"  {belt}: {count}")

    # Sample
    print("\nSampling for test set...")
    sampled = stratified_sample(challenges, TARGET_PER_TIER, seed)

    # Track which challenges are used (to exclude from training)
    used_ids = set()

    # Create output structure
    output_dir.mkdir(parents=True, exist_ok=True)

    for tier, tier_challenges in sampled.items():
        tier_path = output_dir / f"holdout_{tier}"
        tier_path.mkdir(exist_ok=True)

        for challenge in tier_challenges:
            # Save challenge as JSON for the experiment
            dest = tier_path / f"{challenge.id}.json"
            with open(dest, "w") as f:
                json.dump(challenge_to_dict(challenge), f, indent=2)
            used_ids.add(challenge.id)

        print(f"  {tier}: {len(tier_challenges)} challenges")

    # Save manifest of used IDs (for training exclusion)
    manifest = {
        "description": "Holdout test set for baseline comparison experiment",
        "created_with_seed": seed,
        "total_challenges": len(used_ids),
        "challenge_ids": sorted(used_ids),
        "counts_by_tier": {
            tier: len(tier_challenges)
            for tier, tier_challenges in sampled.items()
        },
        "source_curriculum": str(curriculum_dir),
    }

    manifest_path = output_dir / "manifest.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    print()
    print(f"Total test challenges: {len(used_ids)}")
    print(f"Manifest saved to: {manifest_path}")
    print()
    print("=" * 60)
    print("IMPORTANT: Exclude these challenge IDs from ALL training!")
    print("=" * 60)

    # Create a simple exclusion list file
    exclusion_path = output_dir / "exclude_from_training.txt"
    with open(exclusion_path, "w") as f:
        f.write("# Challenge IDs to exclude from training\n")
        f.write("# Generated by create_test_set.py\n\n")
        for cid in sorted(used_ids):
            f.write(f"{cid}\n")

    print(f"Exclusion list saved to: {exclusion_path}")


def main():
    """Create the test set."""
    # Use the correct curriculum path
    curriculum_dir = Path(__file__).parent.parent.parent / "dojo" / "curriculum"
    output_dir = Path(__file__).parent / "test_challenges"

    create_test_set(curriculum_dir, output_dir)


if __name__ == "__main__":
    main()
