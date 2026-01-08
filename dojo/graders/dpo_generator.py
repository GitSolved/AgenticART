"""
DPO (Direct Preference Optimization) Pair Generator.

Generates chosen/rejected pairs for preference learning from graded responses.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from dojo.models_v2 import (
    ChallengeV2,
    PhaseID,
    Pillar,
    TrainingExampleV2,
)
from dojo.graders.reasoning_grader import GradingResult


@dataclass
class DPOPair:
    """A Direct Preference Optimization training pair."""

    # Identification
    pair_id: str
    challenge_id: str
    phase_id: PhaseID

    # Training data
    prompt: str
    chosen: str
    rejected: str

    # Metadata
    chosen_score: float
    rejected_score: float
    margin: float  # chosen_score - rejected_score

    # Rejection reasons for analysis
    rejection_reasons: list[str] = field(default_factory=list)

    # Source tracking
    chosen_source: str = "model"  # "model", "expert", "synthetic"
    rejected_source: str = "model"

    # Timestamp
    created_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        """Export as dictionary."""
        return {
            "pair_id": self.pair_id,
            "challenge_id": self.challenge_id,
            "phase_id": self.phase_id.value,
            "prompt": self.prompt,
            "chosen": self.chosen,
            "rejected": self.rejected,
            "chosen_score": self.chosen_score,
            "rejected_score": self.rejected_score,
            "margin": self.margin,
            "rejection_reasons": self.rejection_reasons,
            "chosen_source": self.chosen_source,
            "rejected_source": self.rejected_source,
            "created_at": self.created_at.isoformat(),
        }

    def to_training_format(self) -> dict:
        """Export in standard DPO training format."""
        return {
            "prompt": self.prompt,
            "chosen": self.chosen,
            "rejected": self.rejected,
        }

    def to_preference_format(self) -> dict:
        """Export in preference learning format with metadata."""
        return {
            "prompt": self.prompt,
            "chosen": [{"role": "assistant", "content": self.chosen}],
            "rejected": [{"role": "assistant", "content": self.rejected}],
            "margin": self.margin,
        }


class DPOPairGenerator:
    """
    Generates DPO training pairs from challenge responses.

    Strategies:
    1. Best vs Worst: Compare highest and lowest scored responses
    2. Threshold: Compare passing vs failing responses
    3. Synthetic: Generate common mistake responses for rejection
    4. Contrastive: Pairs that differ on specific criteria
    """

    # Templates for generating synthetic rejected responses
    MISTAKE_TEMPLATES = {
        Pillar.STATIC_ANALYSIS: [
            "hallucinated_api",      # Makes up API names not in code
            "missed_obvious",        # Misses clear vulnerability
            "false_positive",        # Claims vuln in secure code
            "surface_only",          # No depth in analysis
        ],
        Pillar.NEGATIVE_KNOWLEDGE: [
            "false_positive",        # Claims vulnerability exists
            "no_explanation",        # Doesn't explain security properties
            "missing_attack_analysis",  # Doesn't analyze attack resistance
        ],
        Pillar.ROOT_CAUSE: [
            "surface_only",          # Only describes WHAT, not WHY
            "wrong_cwe",             # Incorrect classification
            "no_generalization",     # Treats as isolated case
            "no_principles",         # Doesn't connect to security principles
        ],
        Pillar.PATTERN_TRANSFER: [
            "no_pattern_recognition",  # Doesn't see the pattern
            "wrong_pattern",          # Identifies wrong pattern
            "no_transfer",            # Can't apply to new context
        ],
        Pillar.METHODOLOGY: [
            "jumps_to_conclusion",   # Skips observation phase
            "untestable_hypothesis", # Hypothesis can't be tested
            "no_falsification",      # No way to prove wrong
        ],
        Pillar.TAXONOMY: [
            "wrong_cwe",             # Incorrect CWE
            "no_hierarchy",          # Missing parent/child
            "wrong_owasp",           # Incorrect OWASP category
        ],
        Pillar.PATCH_ANALYSIS: [
            "missed_incomplete",     # Doesn't see incomplete patch
            "wrong_fix",             # Misunderstands the fix
            "no_bypass_analysis",    # Doesn't consider bypasses
        ],
    }

    def __init__(self, min_margin: float = 0.1):
        """
        Initialize generator.

        Args:
            min_margin: Minimum score difference for valid pairs
        """
        self.min_margin = min_margin
        self._pair_counter = 0

    def generate_from_responses(
        self,
        challenge: ChallengeV2,
        responses: list[tuple[str, GradingResult]],
        phase_id: PhaseID,
    ) -> list[DPOPair]:
        """
        Generate DPO pairs from multiple graded responses.

        Args:
            challenge: The challenge that was attempted
            responses: List of (response_text, grading_result) tuples
            phase_id: Which phase these responses are for

        Returns:
            List of DPO pairs
        """
        if len(responses) < 2:
            return []

        pairs = []

        # Sort by score
        sorted_responses = sorted(responses, key=lambda x: x[1].total_score, reverse=True)

        prompt = challenge.to_prompt(
            phase_index=next(
                i for i, p in enumerate(challenge.phases) if p.phase_id == phase_id
            )
        )

        # Strategy 1: Best vs Worst
        best_response, best_result = sorted_responses[0]
        worst_response, worst_result = sorted_responses[-1]

        if best_result.total_score - worst_result.total_score >= self.min_margin:
            pairs.append(self._create_pair(
                challenge=challenge,
                phase_id=phase_id,
                prompt=prompt,
                chosen=best_response,
                rejected=worst_response,
                chosen_score=best_result.total_score,
                rejected_score=worst_result.total_score,
                rejection_reasons=self._extract_rejection_reasons(worst_result),
            ))

        # Strategy 2: Adjacent pairs (for fine-grained preference learning)
        for i in range(len(sorted_responses) - 1):
            better_response, better_result = sorted_responses[i]
            worse_response, worse_result = sorted_responses[i + 1]

            margin = better_result.total_score - worse_result.total_score
            if margin >= self.min_margin:
                pairs.append(self._create_pair(
                    challenge=challenge,
                    phase_id=phase_id,
                    prompt=prompt,
                    chosen=better_response,
                    rejected=worse_response,
                    chosen_score=better_result.total_score,
                    rejected_score=worse_result.total_score,
                    rejection_reasons=self._extract_rejection_reasons(worse_result),
                ))

        # Strategy 3: Threshold-based (passing vs failing)
        passing = [(r, g) for r, g in sorted_responses if g.total_score >= 0.7]
        failing = [(r, g) for r, g in sorted_responses if g.total_score < 0.6]

        if passing and failing:
            # Pick best passing and worst failing
            best_passing = passing[0]
            worst_failing = failing[-1]

            pairs.append(self._create_pair(
                challenge=challenge,
                phase_id=phase_id,
                prompt=prompt,
                chosen=best_passing[0],
                rejected=worst_failing[0],
                chosen_score=best_passing[1].total_score,
                rejected_score=worst_failing[1].total_score,
                rejection_reasons=self._extract_rejection_reasons(worst_failing[1]),
            ))

        return pairs

    def generate_synthetic_pairs(
        self,
        challenge: ChallengeV2,
        good_response: str,
        good_score: float,
        phase_id: PhaseID,
        num_pairs: int = 3,
    ) -> list[DPOPair]:
        """
        Generate DPO pairs with synthetic rejected responses.

        Uses common mistake templates to create realistic bad responses.

        Args:
            challenge: The challenge
            good_response: A high-quality response to use as 'chosen'
            good_score: Score of the good response
            phase_id: Which phase
            num_pairs: How many synthetic pairs to generate

        Returns:
            List of DPO pairs with synthetic rejections
        """
        pairs = []

        prompt = challenge.to_prompt(
            phase_index=next(
                i for i, p in enumerate(challenge.phases) if p.phase_id == phase_id
            )
        )

        # Get mistake templates for this pillar
        templates = self.MISTAKE_TEMPLATES.get(challenge.pillar, [])

        # Also use challenge-specific common mistakes
        common_mistakes = challenge.training_metadata.common_mistakes

        all_mistakes = list(set(templates + common_mistakes))
        random.shuffle(all_mistakes)

        for mistake_type in all_mistakes[:num_pairs]:
            rejected = self._generate_mistake_response(
                challenge=challenge,
                good_response=good_response,
                mistake_type=mistake_type,
                phase_id=phase_id,
            )

            if rejected:
                pairs.append(self._create_pair(
                    challenge=challenge,
                    phase_id=phase_id,
                    prompt=prompt,
                    chosen=good_response,
                    rejected=rejected,
                    chosen_score=good_score,
                    rejected_score=0.3,  # Synthetic mistakes get low scores
                    rejection_reasons=[mistake_type],
                    rejected_source="synthetic",
                ))

        return pairs

    def generate_contrastive_pairs(
        self,
        challenge: ChallengeV2,
        responses: list[tuple[str, GradingResult]],
        phase_id: PhaseID,
        criterion: str,
    ) -> list[DPOPair]:
        """
        Generate pairs that differ specifically on one criterion.

        Useful for training specific capabilities.

        Args:
            challenge: The challenge
            responses: Graded responses
            phase_id: Which phase
            criterion: Which criterion to contrast on (e.g., "accuracy", "depth")

        Returns:
            Pairs where chosen/rejected differ primarily on the specified criterion
        """
        pairs = []

        prompt = challenge.to_prompt(
            phase_index=next(
                i for i, p in enumerate(challenge.phases) if p.phase_id == phase_id
            )
        )

        # Find responses with different scores on the target criterion
        criterion_scores = []
        for response, result in responses:
            for cs in result.criterion_scores:
                if cs.name == criterion:
                    criterion_scores.append((response, result, cs.score))
                    break

        # Sort by criterion score
        criterion_scores.sort(key=lambda x: x[2], reverse=True)

        # Create pairs with significant criterion difference
        for i in range(len(criterion_scores)):
            for j in range(i + 1, len(criterion_scores)):
                better = criterion_scores[i]
                worse = criterion_scores[j]

                criterion_diff = better[2] - worse[2]
                if criterion_diff >= 0.3:  # Significant difference on criterion
                    pairs.append(self._create_pair(
                        challenge=challenge,
                        phase_id=phase_id,
                        prompt=prompt,
                        chosen=better[0],
                        rejected=worse[0],
                        chosen_score=better[1].total_score,
                        rejected_score=worse[1].total_score,
                        rejection_reasons=[f"Low {criterion} score"],
                    ))

        return pairs

    def _create_pair(
        self,
        challenge: ChallengeV2,
        phase_id: PhaseID,
        prompt: str,
        chosen: str,
        rejected: str,
        chosen_score: float,
        rejected_score: float,
        rejection_reasons: list[str],
        chosen_source: str = "model",
        rejected_source: str = "model",
    ) -> DPOPair:
        """Create a DPO pair with proper ID."""
        self._pair_counter += 1
        pair_id = f"dpo_{challenge.id}_{phase_id.value}_{self._pair_counter}"

        return DPOPair(
            pair_id=pair_id,
            challenge_id=challenge.id,
            phase_id=phase_id,
            prompt=prompt,
            chosen=chosen,
            rejected=rejected,
            chosen_score=chosen_score,
            rejected_score=rejected_score,
            margin=chosen_score - rejected_score,
            rejection_reasons=rejection_reasons,
            chosen_source=chosen_source,
            rejected_source=rejected_source,
        )

    def _extract_rejection_reasons(self, result: GradingResult) -> list[str]:
        """Extract reasons why a response was rejected."""
        reasons = []

        # Low-scoring criteria
        for cs in result.criterion_scores:
            if cs.score < 0.5:
                reasons.append(f"Low {cs.name}: {cs.feedback}")

        # Hallucinations
        if result.hallucinations:
            reasons.append(f"Hallucinations: {', '.join(result.hallucinations[:3])}")

        # Missing items
        if result.missing_items:
            reasons.append(f"Missing: {', '.join(result.missing_items[:3])}")

        # Errors
        if result.errors:
            reasons.extend(result.errors)

        return reasons

    def _generate_mistake_response(
        self,
        challenge: ChallengeV2,
        good_response: str,
        mistake_type: str,
        phase_id: PhaseID,
    ) -> Optional[str]:
        """
        Generate a response exhibiting a specific mistake.

        This creates realistic bad responses for DPO training.
        """
        # Template-based generation
        templates = {
            "hallucinated_api": self._make_hallucinated_response,
            "missed_obvious": self._make_incomplete_response,
            "false_positive": self._make_false_positive_response,
            "surface_only": self._make_surface_response,
            "no_explanation": self._make_no_explanation_response,
            "wrong_cwe": self._make_wrong_cwe_response,
            "no_generalization": self._make_no_generalization_response,
            "jumps_to_conclusion": self._make_jump_conclusion_response,
            "untestable_hypothesis": self._make_untestable_response,
        }

        generator = templates.get(mistake_type)
        if generator:
            return generator(good_response, challenge, phase_id)

        # Default: return a truncated/degraded version
        return self._make_degraded_response(good_response)

    def _make_hallucinated_response(
        self,
        good_response: str,
        challenge: ChallengeV2,
        phase_id: PhaseID
    ) -> str:
        """Generate response with hallucinated API names."""
        fake_apis = [
            "SecureDataManager.encryptUserData()",
            "AuthenticationHelper.validateToken()",
            "NetworkSecurityConfig.bypassSSL()",
            "PrivilegeManager.escalatePermissions()",
        ]

        # Replace some technical terms with fake ones
        response = good_response
        for fake in fake_apis[:2]:
            response = response.replace(
                "vulnerability",
                f"vulnerability in {fake}",
                1
            )

        return response + f"\n\nNote: The {random.choice(fake_apis)} method is particularly concerning."

    def _make_incomplete_response(
        self,
        good_response: str,
        challenge: ChallengeV2,
        phase_id: PhaseID
    ) -> str:
        """Generate response that misses key observations."""
        # Take only first 40% of the response
        lines = good_response.split('\n')
        truncated = lines[:max(3, len(lines) // 3)]
        return '\n'.join(truncated)

    def _make_false_positive_response(
        self,
        good_response: str,
        challenge: ChallengeV2,
        phase_id: PhaseID
    ) -> str:
        """Generate response claiming vulnerability in secure code."""
        return """After analyzing the code, I identified the following vulnerabilities:

1. **SQL Injection (CWE-89)**: The code appears to construct database queries dynamically.
   - Confidence: High
   - Impact: Critical

2. **Path Traversal (CWE-22)**: File operations may be vulnerable to directory traversal.
   - Confidence: Medium
   - Impact: High

The application should implement input validation and parameterized queries immediately."""

    def _make_surface_response(
        self,
        good_response: str,
        challenge: ChallengeV2,
        phase_id: PhaseID
    ) -> str:
        """Generate surface-level response without depth."""
        return """The code has a security issue.

The vulnerability is caused by improper input handling.

To fix this, the developers should add proper validation.

CWE: CWE-20 (Improper Input Validation)"""

    def _make_no_explanation_response(
        self,
        good_response: str,
        challenge: ChallengeV2,
        phase_id: PhaseID
    ) -> str:
        """Generate response that doesn't explain WHY."""
        if not challenge.ground_truth.vulnerability_present:
            return """The code is secure.

is_vulnerable: false
confidence: 0.9"""
        else:
            return """The code is vulnerable.

is_vulnerable: true
confidence: 0.8
cwe: CWE-89"""

    def _make_wrong_cwe_response(
        self,
        good_response: str,
        challenge: ChallengeV2,
        phase_id: PhaseID
    ) -> str:
        """Generate response with incorrect CWE."""
        # Replace correct CWE with wrong one
        wrong_cwes = ["CWE-200", "CWE-400", "CWE-500", "CWE-119"]
        response = good_response

        # Find and replace CWE references
        import re
        cwe_pattern = r'CWE-\d+'
        if re.search(cwe_pattern, response):
            response = re.sub(cwe_pattern, random.choice(wrong_cwes), response, count=1)

        return response

    def _make_no_generalization_response(
        self,
        good_response: str,
        challenge: ChallengeV2,
        phase_id: PhaseID
    ) -> str:
        """Generate response treating issue as isolated case."""
        return good_response.replace(
            "pattern", "issue"
        ).replace(
            "similar", "this specific"
        ).replace(
            "family", "case"
        ).replace(
            "applies to", "is limited to"
        )

    def _make_jump_conclusion_response(
        self,
        good_response: str,
        challenge: ChallengeV2,
        phase_id: PhaseID
    ) -> str:
        """Generate response that jumps to conclusions without observations."""
        return """This is clearly a SQL injection vulnerability.

The application is critically vulnerable and should be taken offline immediately.

Recommendation: Complete code rewrite needed.

Severity: Critical
CWE: CWE-89"""

    def _make_untestable_response(
        self,
        good_response: str,
        challenge: ChallengeV2,
        phase_id: PhaseID
    ) -> str:
        """Generate response with untestable hypothesis."""
        return """Hypothesis: The application might have security issues that could potentially affect users under certain conditions.

This could be tested by doing a comprehensive security audit.

Confidence: Medium"""

    def _make_degraded_response(self, good_response: str) -> str:
        """Create a degraded version of good response."""
        # Remove technical details, shorten
        lines = good_response.split('\n')
        degraded = []

        for line in lines[:len(lines) // 2]:
            # Remove code blocks
            if '```' not in line and not line.strip().startswith('-'):
                degraded.append(line)

        return '\n'.join(degraded) if degraded else good_response[:200]


def export_dpo_dataset(
    pairs: list[DPOPair],
    output_path: str,
    format: str = "jsonl"
) -> None:
    """
    Export DPO pairs to file.

    Args:
        pairs: List of DPO pairs
        output_path: Where to save
        format: "jsonl" or "json"
    """
    if format == "jsonl":
        with open(output_path, 'w') as f:
            for pair in pairs:
                f.write(json.dumps(pair.to_training_format()) + '\n')
    else:
        with open(output_path, 'w') as f:
            json.dump([pair.to_dict() for pair in pairs], f, indent=2)


def load_dpo_dataset(input_path: str) -> list[dict]:
    """Load DPO pairs from file."""
    pairs = []

    if input_path.endswith('.jsonl'):
        with open(input_path, 'r') as f:
            for line in f:
                pairs.append(json.loads(line))
    else:
        with open(input_path, 'r') as f:
            pairs = json.load(f)

    return pairs
