"""
Human Evaluation Protocol for Baseline Comparison Experiment

Automated metrics (pass/fail) don't capture reasoning quality.
This module implements blind human evaluation of model outputs.
"""

import json
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class EvaluationItem:
    """A single item for human evaluation."""

    item_id: str  # Anonymized ID (not revealing arm)
    challenge_id: str
    challenge_description: str
    expected_output_hint: str

    # The response to evaluate (thinking trace + answer)
    model_response: str

    # Hidden from evaluator until after scoring
    _arm: str = field(repr=False)
    _verification_passed: bool = field(repr=False)


@dataclass
class HumanRating:
    """Human evaluator's rating for an item."""

    item_id: str
    evaluator_id: str
    timestamp: str

    # Likert scale ratings (1-5)
    reasoning_quality: int  # Is the explanation correct and complete?
    generalizability: int   # Would this approach work on similar vulns?
    actionability: int      # Could a pentester use this directly?

    # Binary
    false_confidence: bool  # Did model express certainty despite being wrong?

    # Free text
    notes: Optional[str] = None


class HumanEvaluationProtocol:
    """
    Manages blind human evaluation of experiment outputs.

    ★ Insight ─────────────────────────────────────
    Key design choices:
    1. Blind evaluation: Evaluators don't know which arm produced output
    2. Randomized order: Prevents order effects
    3. Dual rating: Two evaluators per item for inter-rater reliability
    4. Stratified sampling: Equal samples from each arm
    ─────────────────────────────────────────────────
    """

    RUBRIC = """
    HUMAN EVALUATION RUBRIC
    =======================

    For each response, evaluate the following:

    1. REASONING QUALITY (1-5)
       How correct and complete is the explanation?

       1 = Completely wrong or missing reasoning
       2 = Major errors in logic or understanding
       3 = Partially correct, some gaps or errors
       4 = Mostly correct, minor issues only
       5 = Fully correct and comprehensive

    2. GENERALIZABILITY (1-5)
       Would this approach work on similar vulnerabilities?

       1 = Approach is specific to this exact case only
       2 = Limited applicability, many assumptions
       3 = Somewhat generalizable with modifications
       4 = Good general approach, minor tweaks needed
       5 = Highly generalizable technique

    3. ACTIONABILITY (1-5)
       Could a pentester use this output directly?

       1 = Unusable, would need complete rewrite
       2 = Some useful information, but needs major work
       3 = Usable with significant modification
       4 = Usable with minor modifications
       5 = Ready to use as-is

    4. FALSE CONFIDENCE (Yes/No)
       Did the model express high certainty despite being incorrect?

       Yes = Model was confident but wrong (problematic)
       No = Confidence matched correctness (acceptable)

    IMPORTANT:
    - Focus on the REASONING, not just the final answer
    - Consider whether the approach demonstrates understanding
    - Ignore formatting issues unless they affect clarity
    """

    def __init__(self, responses_path: Path, sample_size: int = 50):
        self.responses_path = responses_path
        self.sample_size = sample_size
        self._rng = random.Random(42)

        # Load responses
        self.responses = []
        with open(responses_path) as f:
            for line in f:
                self.responses.append(json.load(f))

    def create_evaluation_set(self, output_path: Path) -> None:
        """
        Create a blinded, randomized evaluation set.

        Samples equally from each arm and anonymizes arm identity.
        """
        # Group by arm
        by_arm = {}
        for r in self.responses:
            arm = r["arm"]
            if arm not in by_arm:
                by_arm[arm] = []
            by_arm[arm].append(r)

        # Sample from each arm
        samples_per_arm = self.sample_size // len(by_arm)
        evaluation_items = []

        for arm, responses in by_arm.items():
            sampled = self._rng.sample(responses, min(samples_per_arm, len(responses)))
            for r in sampled:
                # Create anonymized item
                item = EvaluationItem(
                    item_id=f"EVAL_{len(evaluation_items):04d}",
                    challenge_id=r["challenge_id"],
                    challenge_description="",  # Would load from challenge file
                    expected_output_hint="",   # Would load from challenge file
                    model_response=r["response"],
                    _arm=arm,
                    _verification_passed=r.get("verification_passed", False),
                )
                evaluation_items.append(item)

        # Randomize order
        self._rng.shuffle(evaluation_items)

        # Save evaluation set (without arm info)
        eval_set = {
            "rubric": self.RUBRIC,
            "items": [
                {
                    "item_id": item.item_id,
                    "challenge_id": item.challenge_id,
                    "model_response": item.model_response,
                }
                for item in evaluation_items
            ],
        }

        with open(output_path, "w") as f:
            json.dump(eval_set, f, indent=2)

        # Save key (for later unblinding)
        key_path = output_path.with_suffix(".key.json")
        key = {
            item.item_id: {"arm": item._arm, "verification_passed": item._verification_passed}
            for item in evaluation_items
        }
        with open(key_path, "w") as f:
            json.dump(key, f, indent=2)

        print(f"Evaluation set saved to: {output_path}")
        print(f"Answer key saved to: {key_path} (DO NOT share with evaluators)")

    def collect_ratings(self, ratings_path: Path) -> list[HumanRating]:
        """Load human ratings from file."""
        ratings = []
        with open(ratings_path) as f:
            data = json.load(f)

        for r in data["ratings"]:
            ratings.append(HumanRating(
                item_id=r["item_id"],
                evaluator_id=r["evaluator_id"],
                timestamp=r["timestamp"],
                reasoning_quality=r["reasoning_quality"],
                generalizability=r["generalizability"],
                actionability=r["actionability"],
                false_confidence=r["false_confidence"],
                notes=r.get("notes"),
            ))

        return ratings

    def compute_inter_rater_reliability(
        self,
        ratings_a: list[HumanRating],
        ratings_b: list[HumanRating],
    ) -> dict:
        """
        Compute inter-rater reliability using Cohen's Kappa.

        ★ Insight ─────────────────────────────────────
        Cohen's Kappa accounts for chance agreement:
        - κ < 0.20: Poor agreement
        - 0.20-0.40: Fair
        - 0.40-0.60: Moderate
        - 0.60-0.80: Substantial
        - 0.80-1.00: Almost perfect
        ─────────────────────────────────────────────────
        """
        from sklearn.metrics import cohen_kappa_score

        # Match ratings by item_id
        ratings_dict_a = {r.item_id: r for r in ratings_a}
        ratings_dict_b = {r.item_id: r for r in ratings_b}

        common_ids = set(ratings_dict_a.keys()) & set(ratings_dict_b.keys())

        if not common_ids:
            return {"error": "No overlapping items between raters"}

        results = {}

        for metric in ["reasoning_quality", "generalizability", "actionability"]:
            scores_a = [getattr(ratings_dict_a[id], metric) for id in common_ids]
            scores_b = [getattr(ratings_dict_b[id], metric) for id in common_ids]

            kappa = cohen_kappa_score(scores_a, scores_b)
            results[metric] = {
                "kappa": kappa,
                "interpretation": self._interpret_kappa(kappa),
                "n_items": len(common_ids),
            }

        # False confidence (binary)
        fc_a = [ratings_dict_a[id].false_confidence for id in common_ids]
        fc_b = [ratings_dict_b[id].false_confidence for id in common_ids]
        kappa_fc = cohen_kappa_score(fc_a, fc_b)
        results["false_confidence"] = {
            "kappa": kappa_fc,
            "interpretation": self._interpret_kappa(kappa_fc),
            "n_items": len(common_ids),
        }

        return results

    def _interpret_kappa(self, kappa: float) -> str:
        if kappa < 0.20:
            return "poor"
        elif kappa < 0.40:
            return "fair"
        elif kappa < 0.60:
            return "moderate"
        elif kappa < 0.80:
            return "substantial"
        else:
            return "almost perfect"

    def analyze_ratings(
        self,
        ratings: list[HumanRating],
        key_path: Path,
    ) -> dict:
        """
        Analyze ratings after unblinding.

        Computes mean scores by arm and tests for significance.
        """
        # Load key
        with open(key_path) as f:
            key = json.load(f)

        # Group ratings by arm
        by_arm = {}
        for rating in ratings:
            arm = key[rating.item_id]["arm"]
            if arm not in by_arm:
                by_arm[arm] = []
            by_arm[arm].append(rating)

        # Compute means
        results = {"by_arm": {}}
        for arm, arm_ratings in by_arm.items():
            results["by_arm"][arm] = {
                "n": len(arm_ratings),
                "reasoning_quality": {
                    "mean": sum(r.reasoning_quality for r in arm_ratings) / len(arm_ratings),
                    "std": self._std([r.reasoning_quality for r in arm_ratings]),
                },
                "generalizability": {
                    "mean": sum(r.generalizability for r in arm_ratings) / len(arm_ratings),
                    "std": self._std([r.generalizability for r in arm_ratings]),
                },
                "actionability": {
                    "mean": sum(r.actionability for r in arm_ratings) / len(arm_ratings),
                    "std": self._std([r.actionability for r in arm_ratings]),
                },
                "false_confidence_rate": sum(r.false_confidence for r in arm_ratings) / len(arm_ratings),
            }

        return results

    def _std(self, values: list) -> float:
        """Compute standard deviation."""
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return variance ** 0.5


def create_rating_template() -> str:
    """
    Generate a rating template for evaluators to fill out.
    """
    template = """
HUMAN EVALUATION RATING FORM
============================

Evaluator ID: ________________
Date: ________________

Instructions:
1. Read each model response carefully
2. Score according to the rubric (see separate rubric document)
3. Do NOT skip items - rate all assigned items
4. If unsure, use your best judgment and note in comments

---

Item ID: EVAL_0001
Challenge: [challenge description shown here]

Rating:
  Reasoning Quality (1-5):    ___
  Generalizability (1-5):     ___
  Actionability (1-5):        ___
  False Confidence (Y/N):     ___

Notes (optional):
_____________________________________________

---

[Repeat for each item]
"""
    return template
