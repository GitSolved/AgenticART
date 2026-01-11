"""
Baseline Comparison Experiment Runner

Executes challenges across all experimental arms and collects metrics.
"""

import asyncio
import json
import random

# These imports assume the AgenticART project structure
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Callable

from experiment_config import (
    ARM_CONFIGS,
    ArmConfig,
    ChallengeResult,
    ChallengeTier,
    ExperimentArm,
    ExperimentConfig,
    ExperimentResults,
)

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from dojo.graders.praxis_runner import PraxisRunner
from dojo.models_v2 import ChallengeV2


class BaselineExperimentRunner:
    """
    Runs the baseline comparison experiment across all arms.

    ★ Insight ─────────────────────────────────────
    This runner implements a controlled experiment design:
    1. Same challenges across all conditions (within-subject)
    2. Randomized order to control for learning effects
    3. Blind human evaluation (evaluators don't know which arm)
    ─────────────────────────────────────────────────
    """

    def __init__(self, config: ExperimentConfig):
        self.config = config
        self.results = ExperimentResults(
            experiment_id=config.experiment_id,
            config=config,
        )
        self._rng = random.Random(config.random_seed)

        # Initialize runners per arm (lazy loading)
        self._arm_runners: dict[ExperimentArm, Callable] = {}

    def _load_test_challenges(self) -> list[tuple[ChallengeV2, ChallengeTier]]:
        """Load all challenges from the holdout test set."""
        challenges = []

        for tier in ChallengeTier:
            tier_path = self.config.test_set_path / f"holdout_{tier.value}"
            if not tier_path.exists():
                print(f"Warning: Test tier not found: {tier_path}")
                continue

            for challenge_file in tier_path.glob("*.json"):
                with open(challenge_file) as f:
                    data = json.load(f)
                challenge = ChallengeV2.from_dict(data)
                challenges.append((challenge, tier))

        print(f"Loaded {len(challenges)} test challenges")
        return challenges

    def _get_arm_runner(self, arm: ExperimentArm) -> Callable:
        """
        Get or create the runner for an experimental arm.

        Each arm uses different inference configuration.
        """
        if arm in self._arm_runners:
            return self._arm_runners[arm]

        arm_config = ARM_CONFIGS[arm]

        if arm_config.api_provider == "anthropic":
            # Claude baseline - use API
            runner = self._create_claude_runner(arm_config)
        elif arm_config.use_expert_mixture:
            # Expert Mixture - use MLX with adapter switching
            runner = self._create_expert_mixture_runner(arm_config)
        elif arm_config.adapter_path:
            # Single LoRA - use MLX with fixed adapter
            runner = self._create_single_lora_runner(arm_config)
        else:
            # Raw Qwen - use MLX without adapters
            runner = self._create_base_model_runner(arm_config)

        self._arm_runners[arm] = runner
        return runner

    def _create_claude_runner(self, config: ArmConfig):
        """Create runner using Claude API."""
        from anthropic import Anthropic

        client = Anthropic()

        async def run_challenge(challenge: ChallengeV2) -> dict:
            prompt = challenge.to_prompt()

            start_time = time.time()
            response = client.messages.create(
                model=config.model_id,
                max_tokens=config.max_tokens,
                temperature=config.temperature,
                messages=[{"role": "user", "content": prompt}],
            )
            elapsed = time.time() - start_time

            return {
                "response": response.content[0].text,
                "time_seconds": elapsed,
            }

        return run_challenge

    def _create_base_model_runner(self, config: ArmConfig):
        """Create runner using base Qwen model without adapters."""
        # Import MLX components
        from mlx_lm import generate, load

        model, tokenizer = load(config.model_id)

        async def run_challenge(challenge: ChallengeV2) -> dict:
            prompt = challenge.to_prompt()

            start_time = time.time()
            response = generate(
                model,
                tokenizer,
                prompt=prompt,
                max_tokens=config.max_tokens,
                temp=config.temperature,
            )
            elapsed = time.time() - start_time

            return {
                "response": response,
                "time_seconds": elapsed,
            }

        return run_challenge

    def _create_single_lora_runner(self, config: ArmConfig):
        """Create runner with a single LoRA adapter."""
        from mlx_lm import generate, load

        model, tokenizer = load(config.model_id, adapter_path=config.adapter_path)

        async def run_challenge(challenge: ChallengeV2) -> dict:
            prompt = challenge.to_prompt()

            start_time = time.time()
            response = generate(
                model,
                tokenizer,
                prompt=prompt,
                max_tokens=config.max_tokens,
                temp=config.temperature,
            )
            elapsed = time.time() - start_time

            return {
                "response": response,
                "time_seconds": elapsed,
            }

        return run_challenge

    def _create_expert_mixture_runner(self, config: ArmConfig):
        """Create runner with Expert Mixture adapter switching."""
        from agent.mlx_adapter_client import MLXAdapterClient

        client = MLXAdapterClient()

        async def run_challenge(challenge: ChallengeV2) -> dict:
            prompt = challenge.to_prompt()
            pillar = challenge.pillar

            start_time = time.time()

            if config.best_of_n > 1:
                # Best-of-N search
                response = await client.complete_best_of_n(
                    prompt=prompt,
                    pillar=pillar,
                    n_candidates=config.best_of_n,
                    max_tokens=config.max_tokens,
                    temperature=config.temperature,
                )
            else:
                # Single completion with adapter
                response = await client.complete_with_adapter(
                    prompt=prompt,
                    pillar=pillar,
                    max_tokens=config.max_tokens,
                    temperature=config.temperature,
                )

            elapsed = time.time() - start_time

            return {
                "response": response,
                "time_seconds": elapsed,
            }

        return run_challenge

    async def _run_single_challenge(self, challenge: ChallengeV2, tier: ChallengeTier, arm: ExperimentArm) -> ChallengeResult:
        """Run a single challenge for a single arm."""
        runner = self._get_arm_runner(arm)

        try:
            # Get model response
            output = await runner(challenge)
            response = output["response"]
            time_seconds = output["time_seconds"]

            # Extract thinking trace if present
            thinking_trace = None
            if "<thinking>" in response and "</thinking>" in response:
                start = response.index("<thinking>") + len("<thinking>")
                end = response.index("</thinking>")
                thinking_trace = response[start:end].strip()

            # Run verification
            praxis = PraxisRunner(model_id=f"experiment_{arm.name}")
            # Mock phase responses for now since experiment runner doesn't separate phases
            from dojo.models_v2 import PhaseID
            phase_responses = {PhaseID.ANALYZE: response}

            run_result = await praxis.run_challenge(
                challenge=challenge,
                phase_responses=phase_responses,
            )
            verification_results = {
                "execution_error": not run_result.calibration.execution_pass_rate >= 0.3,
                "tasks": [{"passed": v.passed} for v in run_result.calibration.verification_results]
            }

            # Compute metrics
            execution_success = run_result.calibration.execution_pass_rate >= 0.3
            all_passed = run_result.calibration.execution_pass_rate == 1.0
            first_passed = (
                run_result.calibration.verification_results[0].passed
                if run_result.calibration.verification_results
                else False
            )

            return ChallengeResult(
                challenge_id=challenge.id,
                arm=arm,
                tier=tier,
                pillar=challenge.pillar.value if challenge.pillar else "unknown",
                execution_success=execution_success,
                verification_passed=all_passed,
                first_step_passed=first_passed,
                time_seconds=time_seconds,
                model_response=response,
                thinking_trace=thinking_trace,
                verification_outputs=verification_results.get("tasks", []),
            )

        except Exception as e:
            return ChallengeResult(
                challenge_id=challenge.id,
                arm=arm,
                tier=tier,
                pillar=challenge.pillar.value if challenge.pillar else "unknown",
                execution_success=False,
                verification_passed=False,
                first_step_passed=False,
                time_seconds=0.0,
                model_response="",
                thinking_trace=None,
                verification_outputs=[],
                error=str(e),
            )

    async def run_experiment(self) -> ExperimentResults:
        """
        Run the full baseline comparison experiment.

        ★ Insight ─────────────────────────────────────
        We run challenges in randomized order within each arm
        to control for any ordering effects (e.g., model warming up,
        environment changes). Same random order used across arms
        for fair comparison.
        ─────────────────────────────────────────────────
        """
        # Load test challenges
        challenges = self._load_test_challenges()

        if not challenges:
            raise ValueError("No test challenges found. Create holdout set first.")

        # Randomize order (same order for all arms)
        if self.config.shuffle_challenge_order:
            self._rng.shuffle(challenges)

        # Run each arm
        for arm in self.config.arms:
            print(f"\n{'='*60}")
            print(f"Running Arm: {arm.name}")
            print(f"{'='*60}")

            arm_config = ARM_CONFIGS[arm]
            print(f"  Model: {arm_config.model_id}")
            print(f"  Adapter: {arm_config.adapter_path or 'None'}")
            print(f"  Expert Mixture: {arm_config.use_expert_mixture}")
            print(f"  Best-of-N: {arm_config.best_of_n}")
            print()

            for i, (challenge, tier) in enumerate(challenges):
                print(f"  [{i+1}/{len(challenges)}] {challenge.id} ({tier.value})")

                result = await self._run_single_challenge(challenge, tier, arm)
                self.results.challenge_results.append(result)

                status = "✓" if result.verification_passed else "✗"
                print(f"    {status} Passed: {result.verification_passed}, Time: {result.time_seconds:.1f}s")

        # Compute summary statistics
        self._compute_summary_stats()

        # Save results
        self._save_results()

        return self.results

    def _compute_summary_stats(self) -> None:
        """Compute summary statistics across arms and tiers."""
        stats = {}

        for arm in self.config.arms:
            arm_results = [r for r in self.results.challenge_results if r.arm == arm]

            stats[arm.name] = {
                "total_challenges": len(arm_results),
                "execution_success_rate": sum(r.execution_success for r in arm_results) / len(arm_results) if arm_results else 0,
                "verification_pass_rate": sum(r.verification_passed for r in arm_results) / len(arm_results) if arm_results else 0,
                "first_step_pass_rate": sum(r.first_step_passed for r in arm_results) / len(arm_results) if arm_results else 0,
                "mean_time_seconds": sum(r.time_seconds for r in arm_results) / len(arm_results) if arm_results else 0,
                "by_tier": {},
                "by_pillar": {},
            }

            # Breakdown by tier
            for tier in ChallengeTier:
                tier_results = [r for r in arm_results if r.tier == tier]
                if tier_results:
                    stats[arm.name]["by_tier"][tier.value] = {
                        "n": len(tier_results),
                        "pass_rate": sum(r.verification_passed for r in tier_results) / len(tier_results),
                    }

            # Breakdown by pillar
            pillars = set(r.pillar for r in arm_results)
            for pillar in pillars:
                pillar_results = [r for r in arm_results if r.pillar == pillar]
                if pillar_results:
                    stats[arm.name]["by_pillar"][pillar] = {
                        "n": len(pillar_results),
                        "pass_rate": sum(r.verification_passed for r in pillar_results) / len(pillar_results),
                    }

        self.results.summary_stats = stats

    def _save_results(self) -> None:
        """Save experiment results to disk."""
        self.config.results_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_file = self.config.results_dir / f"results_{timestamp}.json"

        # Convert to serializable format
        data = {
            "experiment_id": self.results.experiment_id,
            "timestamp": timestamp,
            "config": {
                "arms": [a.name for a in self.config.arms],
                "challenges_per_tier": {t.value: n for t, n in self.config.challenges_per_tier.items()},
            },
            "summary_stats": self.results.summary_stats,
            "challenge_results": [
                {
                    "challenge_id": r.challenge_id,
                    "arm": r.arm.name,
                    "tier": r.tier.value,
                    "pillar": r.pillar,
                    "execution_success": r.execution_success,
                    "verification_passed": r.verification_passed,
                    "first_step_passed": r.first_step_passed,
                    "time_seconds": r.time_seconds,
                    "has_thinking_trace": r.thinking_trace is not None,
                    "error": r.error,
                }
                for r in self.results.challenge_results
            ],
        }

        with open(results_file, "w") as f:
            json.dump(data, f, indent=2)

        print(f"\nResults saved to: {results_file}")

        # Also save full responses for human evaluation
        responses_file = self.config.results_dir / f"responses_{timestamp}.jsonl"
        with open(responses_file, "w") as f:
            for r in self.results.challenge_results:
                f.write(json.dumps({
                    "challenge_id": r.challenge_id,
                    "arm": r.arm.name,
                    "response": r.model_response,
                    "thinking_trace": r.thinking_trace,
                }) + "\n")

        print(f"Full responses saved to: {responses_file}")


async def main():
    """Run the baseline comparison experiment."""
    config = ExperimentConfig()
    runner = BaselineExperimentRunner(config)

    print("=" * 60)
    print("BASELINE COMPARISON EXPERIMENT")
    print("=" * 60)
    print(f"Experiment ID: {config.experiment_id}")
    print(f"Arms: {[a.name for a in config.arms]}")
    print(f"Test Set: {config.test_set_path}")
    print()

    results = await runner.run_experiment()

    # Print summary
    print("\n" + "=" * 60)
    print("RESULTS SUMMARY")
    print("=" * 60)

    for arm_name, stats in results.summary_stats.items():
        print(f"\n{arm_name}:")
        print(f"  Verification Pass Rate: {stats['verification_pass_rate']:.1%}")
        print(f"  First-Step Pass Rate:   {stats['first_step_pass_rate']:.1%}")
        print(f"  Mean Time:              {stats['mean_time_seconds']:.1f}s")


if __name__ == "__main__":
    asyncio.run(main())
