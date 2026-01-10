"""
Grading Runner: Execute grading pipeline on model responses.

This module provides the main entry point for grading model responses
and generating training data.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from dojo.graders.dpo_generator import DPOPair, DPOPairGenerator, export_dpo_dataset
from dojo.graders.metrics import GradingMetrics, TrainingProgressTracker
from dojo.graders.reasoning_grader import GradingResult, ReasoningGrader
from dojo.models_v2 import (
    ChallengeV2,
    PhaseID,
    PhaseOutput,
    ReasoningChain,
    ReasoningQuality,
)


@dataclass
class GradingRun:
    """Results of a complete grading run."""

    challenge_id: str
    model_id: str
    started_at: datetime
    completed_at: datetime

    # Phase results
    phase_results: list[GradingResult]

    # Overall assessment
    reasoning_chain: ReasoningChain
    reasoning_quality: ReasoningQuality

    # Generated training data
    dpo_pairs: list[DPOPair]

    @property
    def total_score(self) -> float:
        return self.reasoning_chain.total_score

    @property
    def success(self) -> bool:
        return self.reasoning_chain.success


class GradingRunner:
    """
    Main grading execution class.

    Orchestrates the grading pipeline:
    1. Grade each phase of model response
    2. Calculate reasoning quality
    3. Generate DPO training pairs
    4. Track metrics
    """

    def __init__(
        self,
        model_id: str,
        output_dir: Optional[Path] = None,
        generate_dpo: bool = True,
        min_dpo_margin: float = 0.1,
    ):
        """
        Initialize grading runner.

        Args:
            model_id: Identifier for the model being evaluated
            output_dir: Where to save results
            generate_dpo: Whether to generate DPO pairs
            min_dpo_margin: Minimum score margin for DPO pairs
        """
        self.model_id = model_id
        self.output_dir = output_dir or Path("grading_output")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.generate_dpo = generate_dpo
        self.dpo_generator = DPOPairGenerator(min_margin=min_dpo_margin)

        # Metrics tracking
        self.metrics = GradingMetrics()
        self.progress_tracker = TrainingProgressTracker(model_id=model_id)

        # Storage
        self.grading_runs: list[GradingRun] = []
        self.all_dpo_pairs: list[DPOPair] = []

    def grade_challenge(
        self,
        challenge: ChallengeV2,
        phase_responses: dict[PhaseID, str],
        generate_synthetic_dpo: bool = True,
    ) -> GradingRun:
        """
        Grade a complete challenge attempt.

        Args:
            challenge: The challenge that was attempted
            phase_responses: Dict mapping phase IDs to model response text
            generate_synthetic_dpo: Whether to generate synthetic rejection pairs

        Returns:
            GradingRun with all results
        """
        started_at = datetime.now()

        # Initialize grader for this challenge
        grader = ReasoningGrader(challenge)

        # Grade each phase
        phase_results = []
        phase_outputs = []
        phase_evaluations = []

        for phase in challenge.phases:
            if phase.phase_id in phase_responses:
                response_text = phase_responses[phase.phase_id]

                # Grade this phase
                result = grader.grade_phase(phase.phase_id, response_text)
                phase_results.append(result)

                # Create phase output and evaluation
                output = PhaseOutput(
                    phase_id=phase.phase_id,
                    raw_output=response_text,
                    parsed_output=grader.phase_graders[phase.phase_id].parse_response(response_text),
                )
                phase_outputs.append(output)
                phase_evaluations.append(result.to_phase_evaluation())

        # Calculate overall reasoning quality
        _, reasoning_quality = grader.grade_full_chain(phase_responses)

        # Determine if vulnerability was correctly identified
        predicted_vulnerable = self._extract_vulnerability_prediction(phase_responses)
        actual_vulnerable = challenge.ground_truth.vulnerability_present
        correctly_identified = predicted_vulnerable == actual_vulnerable

        # Build reasoning chain
        reasoning_chain = ReasoningChain(
            challenge_id=challenge.id,
            model_id=self.model_id,
            started_at=started_at,
            completed_at=datetime.now(),
            phase_outputs=phase_outputs,
            phase_evaluations=phase_evaluations,
            reasoning_quality=reasoning_quality,
            vulnerability_correctly_identified=correctly_identified,
        )

        # Update metrics
        for result in phase_results:
            confidence = self._extract_confidence(phase_responses)
            self.metrics.add_result(
                challenge_id=challenge.id,
                result=result,
                pillar=challenge.pillar,
                belt=challenge.belt,
                actual_vulnerable=actual_vulnerable,
                predicted_vulnerable=predicted_vulnerable,
                confidence=confidence,
            )

        self.metrics.add_reasoning_chain(reasoning_chain)

        # Generate DPO pairs
        dpo_pairs = []
        if self.generate_dpo and phase_results:
            # Find the best phase response for synthetic pair generation
            best_result = max(phase_results, key=lambda r: r.total_score)
            best_phase_id = best_result.phase_id
            best_response = phase_responses.get(best_phase_id, "")

            if generate_synthetic_dpo and best_result.total_score >= 0.7:
                # Generate synthetic rejected pairs
                synthetic_pairs = self.dpo_generator.generate_synthetic_pairs(
                    challenge=challenge,
                    good_response=best_response,
                    good_score=best_result.total_score,
                    phase_id=best_phase_id,
                    num_pairs=3,
                )
                dpo_pairs.extend(synthetic_pairs)

        self.all_dpo_pairs.extend(dpo_pairs)

        # Build run result
        run = GradingRun(
            challenge_id=challenge.id,
            model_id=self.model_id,
            started_at=started_at,
            completed_at=datetime.now(),
            phase_results=phase_results,
            reasoning_chain=reasoning_chain,
            reasoning_quality=reasoning_quality,
            dpo_pairs=dpo_pairs,
        )

        self.grading_runs.append(run)
        return run

    def grade_multiple_responses(
        self,
        challenge: ChallengeV2,
        responses_list: list[dict[PhaseID, str]],
    ) -> list[GradingRun]:
        """
        Grade multiple response attempts for the same challenge.

        This enables comparison-based DPO pair generation.

        Args:
            challenge: The challenge
            responses_list: List of phase_responses dicts from different attempts

        Returns:
            List of GradingRuns
        """
        runs = []

        for responses in responses_list:
            run = self.grade_challenge(
                challenge=challenge,
                phase_responses=responses,
                generate_synthetic_dpo=False,  # Will generate comparison pairs instead
            )
            runs.append(run)

        # Generate comparison-based DPO pairs
        if len(runs) >= 2:
            # Group responses by phase
            for phase in challenge.phases:
                phase_responses_with_grades = []
                for run in runs:
                    matching_results = [r for r in run.phase_results if r.phase_id == phase.phase_id]
                    if matching_results:
                        # Get original response text (from phase outputs)
                        matching_outputs = [o for o in run.reasoning_chain.phase_outputs
                                          if o.phase_id == phase.phase_id]
                        if matching_outputs:
                            phase_responses_with_grades.append(
                                (matching_outputs[0].raw_output, matching_results[0])
                            )

                if len(phase_responses_with_grades) >= 2:
                    pairs = self.dpo_generator.generate_from_responses(
                        challenge=challenge,
                        responses=phase_responses_with_grades,
                        phase_id=phase.phase_id,
                    )
                    self.all_dpo_pairs.extend(pairs)

        return runs

    def save_results(self, prefix: str = "") -> dict[str, Path]:
        """
        Save all grading results to files.

        Returns:
            Dict of result type to file path
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        prefix = f"{prefix}_" if prefix else ""

        saved_files = {}

        # Save grading runs
        runs_file = self.output_dir / f"{prefix}grading_runs_{timestamp}.json"
        with open(runs_file, 'w') as f:
            json.dump(
                [self._run_to_dict(run) for run in self.grading_runs],
                f,
                indent=2
            )
        saved_files["runs"] = runs_file

        # Save metrics
        metrics_file = self.output_dir / f"{prefix}metrics_{timestamp}.json"
        with open(metrics_file, 'w') as f:
            json.dump(self.metrics.to_dict(), f, indent=2)
        saved_files["metrics"] = metrics_file

        # Save DPO pairs
        if self.all_dpo_pairs:
            dpo_file = self.output_dir / f"{prefix}dpo_pairs_{timestamp}.jsonl"
            export_dpo_dataset(self.all_dpo_pairs, str(dpo_file), format="jsonl")
            saved_files["dpo"] = dpo_file

        # Save metrics summary
        summary_file = self.output_dir / f"{prefix}summary_{timestamp}.txt"
        with open(summary_file, 'w') as f:
            f.write(self.metrics.summary())
        saved_files["summary"] = summary_file

        return saved_files

    def add_checkpoint(self, epoch: int, step: int) -> None:
        """Add a training progress checkpoint."""
        self.progress_tracker.add_checkpoint(
            metrics=self.metrics,
            epoch=epoch,
            step=step,
        )

    def _extract_vulnerability_prediction(self, phase_responses: dict[PhaseID, str]) -> bool:
        """Extract whether model predicted a vulnerability exists."""
        all_text = " ".join(phase_responses.values()).lower()

        # Strong indicators of predicting vulnerable
        vulnerable_indicators = [
            "vulnerability found",
            "is vulnerable",
            "vulnerable to",
            "can be exploited",
            "exploitable",
            "is_vulnerable: true",
            "is_vulnerable\":true",
        ]

        # Strong indicators of predicting secure
        secure_indicators = [
            "not vulnerable",
            "is secure",
            "no vulnerability",
            "is_vulnerable: false",
            "is_vulnerable\":false",
        ]

        has_vulnerable = any(ind in all_text for ind in vulnerable_indicators)
        has_secure = any(ind in all_text for ind in secure_indicators)

        if has_vulnerable and not has_secure:
            return True
        elif has_secure and not has_vulnerable:
            return False
        else:
            # Ambiguous - default based on text analysis
            return "vulnerable" in all_text and "not vulnerable" not in all_text

    def _extract_confidence(self, phase_responses: dict[PhaseID, str]) -> float:
        """Extract confidence value from responses."""
        import re

        all_text = " ".join(phase_responses.values())

        # Look for explicit confidence values
        confidence_patterns = [
            r'confidence[:\s]+([0-9.]+)',
            r'confidence.*?([0-9.]+)',
            r'"confidence":\s*([0-9.]+)',
        ]

        for pattern in confidence_patterns:
            match = re.search(pattern, all_text, re.IGNORECASE)
            if match:
                try:
                    value = float(match.group(1))
                    if 0 <= value <= 1:
                        return value
                    elif 1 < value <= 100:
                        return value / 100
                except ValueError:
                    continue

        # Default confidence based on language
        text_lower = all_text.lower()
        if "high confidence" in text_lower or "confident" in text_lower:
            return 0.85
        elif "medium confidence" in text_lower or "likely" in text_lower:
            return 0.65
        elif "low confidence" in text_lower or "possibly" in text_lower:
            return 0.35

        return 0.5  # Default

    def _run_to_dict(self, run: GradingRun) -> dict:
        """Convert GradingRun to serializable dict."""
        return {
            "challenge_id": run.challenge_id,
            "model_id": run.model_id,
            "started_at": run.started_at.isoformat(),
            "completed_at": run.completed_at.isoformat(),
            "total_score": run.total_score,
            "success": run.success,
            "phase_results": [
                {
                    "phase_id": r.phase_id.value,
                    "total_score": r.total_score,
                    "criterion_scores": {cs.name: cs.score for cs in r.criterion_scores},
                    "feedback": r.feedback,
                    "hallucinations": r.hallucinations,
                    "missing_items": r.missing_items,
                }
                for r in run.phase_results
            ],
            "reasoning_quality": run.reasoning_quality.to_dict() if run.reasoning_quality else None,
            "dpo_pairs_generated": len(run.dpo_pairs),
        }


# ─────────────────────────────────────────────────────────────────────────────
# Convenience Functions
# ─────────────────────────────────────────────────────────────────────────────

def grade_single_response(
    challenge: ChallengeV2,
    response: str,
    phase_id: PhaseID,
) -> GradingResult:
    """
    Convenience function to grade a single response.

    Args:
        challenge: The challenge
        response: The model's response text
        phase_id: Which phase this response is for

    Returns:
        GradingResult
    """
    grader = ReasoningGrader(challenge)
    return grader.grade_phase(phase_id, response)


def quick_evaluate(
    challenge: ChallengeV2,
    phase_responses: dict[PhaseID, str],
) -> dict:
    """
    Quick evaluation returning summary dict.

    Args:
        challenge: The challenge
        phase_responses: Dict of phase responses

    Returns:
        Summary dict with scores and key findings
    """
    grader = ReasoningGrader(challenge)
    results, quality = grader.grade_full_chain(phase_responses)

    return {
        "total_score": sum(r.total_score for r in results) / len(results) if results else 0,
        "phase_scores": {r.phase_id.value: r.total_score for r in results},
        "reasoning_quality": quality.overall if quality else 0,
        "hallucinations": [h for r in results for h in r.hallucinations],
        "missing_items": [m for r in results for m in r.missing_items],
        "passed": all(r.total_score >= 0.6 for r in results),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Example Usage
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Example usage demonstration
    print("Grading Runner - Example Usage")
    print("=" * 50)

    # This would be loaded from a challenge file
    # For demo, showing the structure:
    print("""
    # Basic usage:

    from dojo.graders import GradingRunner
    from dojo.models_v2 import PhaseID

    # Initialize runner
    runner = GradingRunner(
        model_id="my-model-v1",
        output_dir=Path("./results"),
        generate_dpo=True,
    )

    # Grade a challenge
    run = runner.grade_challenge(
        challenge=my_challenge,
        phase_responses={
            PhaseID.OBSERVE: "My observation response...",
            PhaseID.HYPOTHESIZE: "My hypothesis response...",
        }
    )

    print(f"Score: {run.total_score:.2%}")
    print(f"Success: {run.success}")

    # Save results
    saved = runner.save_results(prefix="training_run")
    print(f"Saved to: {saved}")

    # View metrics
    print(runner.metrics.summary())
    """)
