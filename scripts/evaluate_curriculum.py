#!/usr/bin/env python3
"""
Curriculum Evaluation Script

Analyzes all challenges and generates a value report identifying:
- High-value challenges (keep)
- Challenges needing review
- Low-value challenges (prune candidates)
- Technique coverage gaps

Usage:
    python scripts/evaluate_curriculum.py
    python scripts/evaluate_curriculum.py --metrics dojo_output/metrics.json
    python scripts/evaluate_curriculum.py --output reports/curriculum_value.json
"""

import argparse
import json
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import yaml

from dojo.challenge_value import (
    ChallengeValueScorer,
    load_metrics,
)
from dojo.models import (
    Belt,
    Challenge,
    ChallengeInput,
    Compatibility,
    ExpectedOutput,
    ScoringRubric,
    ScriptType,
)


def load_challenges_from_curriculum(curriculum_dir: Path) -> list[Challenge]:
    """Load all challenges from curriculum YAML files."""
    challenges = []

    belt_dirs = [
        "white_belt", "yellow_belt", "orange_belt", "green_belt",
        "blue_belt", "brown_belt", "purple_belt", "black_belt",
    ]

    for belt_dir in belt_dirs:
        yaml_path = curriculum_dir / belt_dir / "challenges.yaml"
        if not yaml_path.exists():
            continue

        with open(yaml_path) as f:
            data = yaml.safe_load(f) or {}

        for c_data in data.get("challenges", []):
            try:
                challenge = parse_challenge(c_data)
                challenges.append(challenge)
            except Exception as e:
                print(f"Warning: Failed to parse challenge {c_data.get('id', 'unknown')}: {e}")

    return challenges


def parse_challenge(data: dict) -> Challenge:
    """Parse a challenge from YAML data."""
    # Parse inputs
    inputs_data = data.get("inputs", {})
    inputs = ChallengeInput(
        device_context=inputs_data.get("device_context", {}),
        target_class=inputs_data.get("target_class"),
        target_method=inputs_data.get("target_method"),
        cve_id=inputs_data.get("cve_id"),
        additional_context=inputs_data.get("additional_context", {}),
    )

    # Parse expected output
    expected_data = data.get("expected_output", {})
    script_type_str = data.get("script_type", "adb")
    try:
        script_type = ScriptType(script_type_str)
    except ValueError:
        script_type = ScriptType.ADB

    expected = ExpectedOutput(
        script_type=script_type,
        must_contain=expected_data.get("must_contain", []),
        must_not_contain=expected_data.get("must_not_contain", []),
        expected_patterns=expected_data.get("expected_patterns", []),
    )

    # Parse scoring
    scoring_data = data.get("scoring", {})
    scoring = ScoringRubric(
        syntax_correct=scoring_data.get("syntax_correct", 25),
        api_valid=scoring_data.get("api_valid", 25),
        executes_successfully=scoring_data.get("executes_successfully", 30),
        achieves_objective=scoring_data.get("achieves_objective", 20),
    )

    # Parse compatibility
    compat_str = data.get("compatibility", "universal")
    try:
        compatibility = Compatibility.from_string(compat_str)
    except ValueError:
        compatibility = Compatibility.UNIVERSAL

    return Challenge(
        id=data["id"],
        name=data.get("name", data["id"]),
        description=data.get("description", ""),
        belt=Belt.from_string(data.get("belt", "white")),
        difficulty=data.get("difficulty", 3),
        inputs=inputs,
        expected_output=expected,
        scoring=scoring,
        kata_solution=data.get("kata_solution"),
        hints=data.get("hints", []),
        tags=data.get("tags", []),
        compatibility=compatibility,
    )


def print_summary(report: dict) -> None:
    """Print a formatted summary of the report."""
    summary = report["summary"]

    print("\n" + "=" * 70)
    print("CURRICULUM VALUE REPORT")
    print("=" * 70)

    print(f"\nTotal Challenges: {summary['total_challenges']}")
    print(f"Average Value Score: {summary['average_value']:.3f}")
    print()

    # Recommendations
    print("RECOMMENDATIONS:")
    print(f"  Keep:   {summary['keep']:3d} ({100*summary['keep']/summary['total_challenges']:.0f}%)")
    print(f"  Review: {summary['review']:3d} ({100*summary['review']/summary['total_challenges']:.0f}%)")
    print(f"  Prune:  {summary['prune']:3d} ({100*summary['prune']/summary['total_challenges']:.0f}%)")

    # By belt
    print("\n" + "-" * 70)
    print("BY BELT:")
    print("-" * 70)
    print(f"{'Belt':<10} {'Count':>6} {'Avg Value':>10} {'Keep':>6} {'Review':>8} {'Prune':>7}")
    print("-" * 70)

    for belt in ["white", "yellow", "orange", "green", "blue", "brown", "purple", "black"]:
        if belt in report["by_belt"]:
            b = report["by_belt"][belt]
            print(f"{belt.capitalize():<10} {b['count']:>6} {b['average_value']:>10.3f} {b['keep']:>6} {b['review']:>8} {b['prune']:>7}")

    # Technique coverage
    print("\n" + "-" * 70)
    print("TECHNIQUE COVERAGE:")
    print("-" * 70)

    coverage = report["technique_coverage"]
    for technique, count in sorted(coverage.items(), key=lambda x: -x[1]):
        bar = "#" * min(count, 30)
        print(f"  {technique:<20} {count:>3} {bar}")

    # Technique gaps
    if report["technique_gaps"]:
        print("\n" + "-" * 70)
        print("TECHNIQUE GAPS (< 3 challenges):")
        print("-" * 70)
        for gap in report["technique_gaps"]:
            print(f"  - {gap}")

    # Prune candidates
    if report["prune_candidates"]:
        print("\n" + "-" * 70)
        print("PRUNE CANDIDATES:")
        print("-" * 70)
        for c in report["prune_candidates"][:10]:  # Top 10
            print(f"  {c['challenge_id']}")
            print(f"    Value: {c['value_score']:.3f} | Reason: {c['recommendation_reason']}")

    # Review candidates
    if report["review_candidates"]:
        print("\n" + "-" * 70)
        print("REVIEW CANDIDATES (sample):")
        print("-" * 70)
        for c in report["review_candidates"][:5]:  # Top 5
            print(f"  {c['challenge_id']}")
            print(f"    Value: {c['value_score']:.3f} | Reason: {c['recommendation_reason']}")

    print("\n" + "=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate curriculum challenges for training value"
    )
    parser.add_argument(
        "--curriculum",
        type=Path,
        default=Path("dojo/curriculum"),
        help="Path to curriculum directory",
    )
    parser.add_argument(
        "--metrics",
        type=Path,
        help="Path to metrics JSON file (optional)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("reports/curriculum_value.json"),
        help="Output path for JSON report",
    )
    parser.add_argument(
        "--keep-threshold",
        type=float,
        default=0.6,
        help="Value threshold for 'keep' recommendation",
    )
    parser.add_argument(
        "--review-threshold",
        type=float,
        default=0.3,
        help="Value threshold for 'review' recommendation",
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Output JSON only (no summary)",
    )

    args = parser.parse_args()

    # Load challenges
    print(f"Loading challenges from {args.curriculum}...")
    challenges = load_challenges_from_curriculum(args.curriculum)
    print(f"Loaded {len(challenges)} challenges")

    if not challenges:
        print("No challenges found!")
        sys.exit(1)

    # Load metrics if available
    metrics_map = None
    if args.metrics and args.metrics.exists():
        print(f"Loading metrics from {args.metrics}...")
        metrics_map = load_metrics(args.metrics)
        print(f"Loaded metrics for {len(metrics_map)} challenges")

    # Score challenges
    print("\nScoring challenges...")
    scorer = ChallengeValueScorer(
        keep_threshold=args.keep_threshold,
        review_threshold=args.review_threshold,
    )

    report = scorer.generate_report(challenges, metrics_map)

    # Save report
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nReport saved to {args.output}")

    # Print summary
    if not args.json_only:
        print_summary(report)


if __name__ == "__main__":
    main()
