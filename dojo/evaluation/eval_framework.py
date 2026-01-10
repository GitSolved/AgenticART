#!/usr/bin/env python3
"""
Evaluation Framework for AgenticART Training Effectiveness

Measures whether DPO training actually improves model performance
on mobile security tasks using the Genymotion emulator.

Two evaluation modes:
1. OFFLINE: Test reasoning quality on held-out challenges (fast, no emulator)
2. ONLINE: Run against actual APKs in emulator (slow, real-world validation)
"""

import json
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional


@dataclass
class EvaluationResult:
    """Results from evaluating a model on a challenge."""
    challenge_id: str
    model_name: str

    # Offline metrics (reasoning quality)
    reasoning_score: float = 0.0  # From grader (0-100)
    identified_vulnerability: bool = False
    correct_cwe: bool = False

    # Online metrics (task completion)
    flag_extracted: bool = False
    flag_value: Optional[str] = None
    steps_to_solution: int = 0
    time_seconds: float = 0.0

    # Error tracking
    errors: list = field(default_factory=list)


@dataclass
class ModelComparison:
    """Compare baseline vs fine-tuned model."""
    baseline_model: str
    finetuned_model: str
    challenges_tested: int = 0

    # Aggregated metrics
    baseline_flag_rate: float = 0.0
    finetuned_flag_rate: float = 0.0
    baseline_avg_score: float = 0.0
    finetuned_avg_score: float = 0.0

    # Improvement
    flag_rate_improvement: float = 0.0
    score_improvement: float = 0.0


class TrainingEffectivenessEvaluator:
    """
    Evaluates whether DPO training improved model performance.

    Usage:
        evaluator = TrainingEffectivenessEvaluator(
            baseline_model="qwen2.5:7b",
            finetuned_model="qwen2.5:7b-security-dpo",
            emulator_device="127.0.0.1:6555"  # Genymotion S24
        )

        # Run evaluation
        results = evaluator.run_full_evaluation()

        # Check if training was effective
        if results.flag_rate_improvement > 0.1:
            print("Training improved flag extraction by 10%+!")
    """

    def __init__(
        self,
        baseline_model: str,
        finetuned_model: str,
        emulator_device: str = "127.0.0.1:6555",
        challenges_dir: Optional[Path] = None
    ):
        self.baseline_model = baseline_model
        self.finetuned_model = finetuned_model
        self.emulator_device = emulator_device
        self.challenges_dir = challenges_dir or Path(__file__).parent.parent / "curriculum" / "v2"

        self.results_dir = Path(__file__).parent / "results"
        self.results_dir.mkdir(exist_ok=True)

    def check_emulator_connection(self) -> bool:
        """Verify Genymotion emulator is accessible."""
        try:
            result = subprocess.run(
                ["adb", "-s", self.emulator_device, "shell", "echo", "connected"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return "connected" in result.stdout
        except Exception as e:
            print(f"Emulator check failed: {e}")
            return False

    def run_offline_evaluation(self, model: str, challenge_id: str) -> EvaluationResult:
        """
        Evaluate model reasoning on a challenge WITHOUT running against emulator.
        Uses the reasoning grader to score response quality.
        """
        # TODO: Implement using reasoning grader
        # 1. Load challenge from curriculum
        # 2. Generate model response via Ollama
        # 3. Grade with ReasoningGraderV2
        # 4. Return scores

        return EvaluationResult(
            challenge_id=challenge_id,
            model_name=model,
            reasoning_score=0.0,
            identified_vulnerability=False,
            correct_cwe=False
        )

    def run_online_evaluation(self, model: str, challenge_id: str) -> EvaluationResult:
        """
        Evaluate model on actual APK exploitation in Genymotion.
        This is the real test of training effectiveness.

        Steps:
        1. Install vulnerable APK on emulator
        2. Have model analyze and generate exploit
        3. Execute exploit (Frida script, ADB commands, etc.)
        4. Check if flag was extracted
        """
        if not self.check_emulator_connection():
            return EvaluationResult(
                challenge_id=challenge_id,
                model_name=model,
                errors=["Emulator not connected"]
            )

        # TODO: Implement full online evaluation
        # 1. Map challenge_id to APK
        # 2. Install APK via ADB
        # 3. Run model agent loop
        # 4. Check for flag extraction

        return EvaluationResult(
            challenge_id=challenge_id,
            model_name=model,
            flag_extracted=False,
            steps_to_solution=0
        )

    def compare_models(
        self,
        challenge_ids: list[str],
        mode: str = "offline"
    ) -> ModelComparison:
        """
        Run same challenges against baseline and fine-tuned model.
        Compare results to measure training effectiveness.
        """
        baseline_results = []
        finetuned_results = []

        eval_func = (
            self.run_offline_evaluation if mode == "offline"
            else self.run_online_evaluation
        )

        for challenge_id in challenge_ids:
            print(f"Evaluating {challenge_id}...")

            # Run baseline
            baseline_result = eval_func(self.baseline_model, challenge_id)
            baseline_results.append(baseline_result)

            # Run fine-tuned
            finetuned_result = eval_func(self.finetuned_model, challenge_id)
            finetuned_results.append(finetuned_result)

        # Calculate aggregates
        comparison = ModelComparison(
            baseline_model=self.baseline_model,
            finetuned_model=self.finetuned_model,
            challenges_tested=len(challenge_ids)
        )

        if mode == "online":
            comparison.baseline_flag_rate = sum(
                1 for r in baseline_results if r.flag_extracted
            ) / len(baseline_results)
            comparison.finetuned_flag_rate = sum(
                1 for r in finetuned_results if r.flag_extracted
            ) / len(finetuned_results)
            comparison.flag_rate_improvement = (
                comparison.finetuned_flag_rate - comparison.baseline_flag_rate
            )

        comparison.baseline_avg_score = sum(
            r.reasoning_score for r in baseline_results
        ) / len(baseline_results)
        comparison.finetuned_avg_score = sum(
            r.reasoning_score for r in finetuned_results
        ) / len(finetuned_results)
        comparison.score_improvement = (
            comparison.finetuned_avg_score - comparison.baseline_avg_score
        )

        return comparison

    def save_results(self, comparison: ModelComparison, filename: Optional[str] = None):
        """Save evaluation results to JSON."""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"eval_{timestamp}.json"

        filepath = self.results_dir / filename

        results = {
            "timestamp": datetime.now().isoformat(),
            "baseline_model": comparison.baseline_model,
            "finetuned_model": comparison.finetuned_model,
            "challenges_tested": comparison.challenges_tested,
            "metrics": {
                "baseline_flag_rate": comparison.baseline_flag_rate,
                "finetuned_flag_rate": comparison.finetuned_flag_rate,
                "flag_rate_improvement": comparison.flag_rate_improvement,
                "baseline_avg_score": comparison.baseline_avg_score,
                "finetuned_avg_score": comparison.finetuned_avg_score,
                "score_improvement": comparison.score_improvement
            },
            "conclusion": self._interpret_results(comparison)
        }

        with open(filepath, "w") as f:
            json.dump(results, f, indent=2)

        print(f"Results saved to {filepath}")
        return filepath

    def _interpret_results(self, comparison: ModelComparison) -> str:
        """Generate human-readable conclusion about training effectiveness."""
        conclusions = []

        if comparison.flag_rate_improvement > 0.15:
            conclusions.append(
                f"✅ SIGNIFICANT IMPROVEMENT: Flag extraction improved by "
                f"{comparison.flag_rate_improvement:.1%}"
            )
        elif comparison.flag_rate_improvement > 0.05:
            conclusions.append(
                f"📈 MODERATE IMPROVEMENT: Flag extraction improved by "
                f"{comparison.flag_rate_improvement:.1%}"
            )
        elif comparison.flag_rate_improvement > 0:
            conclusions.append(
                f"📊 SLIGHT IMPROVEMENT: Flag extraction improved by "
                f"{comparison.flag_rate_improvement:.1%}"
            )
        else:
            conclusions.append(
                "⚠️ NO IMPROVEMENT: Fine-tuning did not improve flag extraction"
            )

        if comparison.score_improvement > 10:
            conclusions.append(
                f"✅ Reasoning quality improved by {comparison.score_improvement:.1f} points"
            )

        return " | ".join(conclusions)


# Mapping of challenges to their APKs for online evaluation
CHALLENGE_APK_MAPPING = {
    # Green belt challenges
    "green_persona_001": "cryptovault",
    "green_persona_002": "nativecheck",
    "green_persona_003": "sslpinned",
    "green_persona_004": "fortified",

    # Add more mappings as challenges are created
}


def main():
    """Example usage of the evaluation framework."""
    print("=" * 60)
    print("AgenticART Training Effectiveness Evaluator")
    print("=" * 60)

    # Check if emulator is available
    evaluator = TrainingEffectivenessEvaluator(
        baseline_model="qwen2.5:7b",
        finetuned_model="qwen2.5:7b-security-dpo",  # After DPO training
        emulator_device="127.0.0.1:6555"
    )

    if evaluator.check_emulator_connection():
        print("✅ Genymotion emulator connected")
        print("   Ready for ONLINE evaluation (APK exploitation)")
    else:
        print("⚠️ Emulator not connected")
        print("   Can only run OFFLINE evaluation (reasoning quality)")

    print("\nTo run full evaluation:")
    print("  1. Start Genymotion with Galaxy S24 (Android 14)")
    print("  2. Fine-tune model with DPO training data")
    print("  3. Run: evaluator.compare_models(challenge_ids, mode='online')")

    print("\nChallenge-to-APK mappings:")
    for challenge, apk in CHALLENGE_APK_MAPPING.items():
        print(f"  {challenge} -> {apk}")


if __name__ == "__main__":
    main()
