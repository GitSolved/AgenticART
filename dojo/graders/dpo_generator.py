"""
DPO (Direct Preference Optimization) Pair Generator.

Generates chosen/rejected pairs for preference learning from graded responses.

Praxis-Aware Generation:
    The Praxis Loop produces calibration signals that are the highest-quality
    training data for teaching models to be appropriately confident:

    | Calibration Category | Signal Weight | Training Role |
    |---------------------|---------------|---------------|
    | HALLUCINATION       | 1.0           | REJECTED (confidently wrong) |
    | TRUE_UNDERSTANDING  | 0.8           | CHOSEN (confidently correct) |
    | UNDER_CALIBRATED    | 0.5           | Needs more confidence |
    | APPROPRIATE_UNCERTAINTY | 0.3       | Already calibrated |
"""

from __future__ import annotations

import json
import random
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Optional

from dojo.graders.reasoning_grader import GradingResult
from dojo.models_v2 import (
    ChallengeV2,
    PhaseID,
    Pillar,
)

# Avoid circular import - PraxisRun is only needed for type hints
if TYPE_CHECKING:
    from dojo.graders.praxis_runner import CalibrationResult, PraxisRun


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
    chosen_source: str = "model"  # "model", "expert", "synthetic", "praxis"
    rejected_source: str = "model"

    # Praxis calibration metadata (added for Praxis-aware training)
    calibration_category: Optional[str] = None  # e.g., "hallucination", "true_understanding"
    signal_weight: float = 1.0  # How valuable is this pair for training?
    stated_confidence: Optional[float] = None  # Model's self-reported confidence
    execution_pass_rate: Optional[float] = None  # Actual verification result
    is_hallucination: bool = False  # Quick flag for filtering

    # Timestamp
    created_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        """Export as dictionary."""
        result = {
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

        # Include Praxis calibration metadata if present
        if self.calibration_category:
            result["calibration"] = {
                "category": self.calibration_category,
                "signal_weight": self.signal_weight,
                "stated_confidence": self.stated_confidence,
                "execution_pass_rate": self.execution_pass_rate,
                "is_hallucination": self.is_hallucination,
            }

        return result

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

    # -------------------------------------------------------------------------
    # THINKING TRACE GENERATION
    # -------------------------------------------------------------------------

    def _has_thinking_trace(self, response: str) -> bool:
        """Check if response already contains a thinking trace."""
        return bool(re.search(r'<thinking>.*?</thinking>', response, re.DOTALL))

    def _generate_thinking_trace(
        self,
        challenge: ChallengeV2,
        response: str,
        phase_id: PhaseID,
    ) -> str:
        """
        Generate a logical multi-step thinking trace for a response.

        The trace identifies source/sink relationships before the tool call,
        following the chain-of-thought pattern to prevent impulsive errors.

        Args:
            challenge: The challenge context
            response: The model response (to extract conclusions from)
            phase_id: Which phase this is for

        Returns:
            A thinking trace string to prepend to the response
        """
        # Extract key info from challenge artifacts
        artifacts = challenge.artifacts
        ground_truth = challenge.ground_truth

        # Build source identification based on artifact types
        sources = []
        sinks = []
        for artifact in artifacts:
            if artifact.artifact_type.value in ["manifest", "decompiled_code"]:
                sources.append(f"Code artifact: {artifact.artifact_type.value}")
            if "intent" in artifact.content.lower():
                sources.append("Intent data from external app")
            if "getstring" in artifact.content.lower() or "getextra" in artifact.content.lower():
                sources.append("User-controlled intent extras")

            # Identify common sinks
            sink_patterns = [
                ("loadUrl", "WebView.loadUrl() - potential JavaScript injection"),
                ("Runtime.getRuntime", "Runtime command execution sink"),
                ("query(", "Database query - SQL injection sink"),
                ("startActivity", "startActivity() - intent redirection sink"),
                ("sendBroadcast", "sendBroadcast() - broadcast injection sink"),
                ("openFileOutput", "File write - path traversal sink"),
                ("setJavaScriptEnabled", "JavaScript enabled in WebView"),
            ]
            for pattern, description in sink_patterns:
                if pattern.lower() in artifact.content.lower():
                    sinks.append(description)

        # Default sources/sinks if none detected
        if not sources:
            sources = ["External input via exported component"]
        if not sinks:
            sinks = ["Sensitive operation identified in code flow"]

        # Build hypothesis based on ground truth
        if ground_truth.vulnerability_present:
            vuln_type = ground_truth.vulnerability_type or "security vulnerability"
            cwe = ground_truth.cwe_id or "CWE-Unknown"
            hypothesis = f"Potential {vuln_type} ({cwe}) due to insufficient input validation"
        else:
            hypothesis = "Code appears secure - need to verify defensive measures are in place"

        # Construct the thinking trace
        trace_parts = [
            "<thinking>",
            "## Step 1: Source Identification",
            "Identified untrusted input sources:",
        ]
        for src in sources[:3]:
            trace_parts.append(f"  - {src}")

        trace_parts.extend([
            "",
            "## Step 2: Sink Identification",
            "Identified sensitive sinks:",
        ])
        for sink in sinks[:3]:
            trace_parts.append(f"  - {sink}")

        trace_parts.extend([
            "",
            "## Step 3: Data Flow Analysis",
            "Tracing data flow from source to sink...",
            "  Input -> [validation check needed] -> Sink operation",
        ])

        trace_parts.extend([
            "",
            "## Step 4: Hypothesis Formation",
            f"  {hypothesis}",
        ])

        trace_parts.extend([
            "",
            "## Step 5: Verification Plan",
            "  - Check if input validation exists between source and sink",
            "  - Verify sanitization is applied correctly",
            "  - Confirm no bypass paths exist",
            "</thinking>",
            "",
        ])

        return "\n".join(trace_parts)

    def _ensure_thinking_trace(
        self,
        response: str,
        challenge: ChallengeV2,
        phase_id: PhaseID,
    ) -> str:
        """
        Ensure a response has a thinking trace prepended.

        If the response already has a thinking trace, return as-is.
        Otherwise, generate and prepend one.

        Args:
            response: The model response
            challenge: Challenge context for trace generation
            phase_id: Current phase

        Returns:
            Response with thinking trace prepended
        """
        if self._has_thinking_trace(response):
            return response

        trace = self._generate_thinking_trace(challenge, response, phase_id)
        return trace + response

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
        ensure_thinking_trace: bool = True,
    ) -> DPOPair:
        """Create a DPO pair with proper ID.

        Args:
            challenge: The challenge context
            phase_id: Which phase
            prompt: The input prompt
            chosen: The preferred response
            rejected: The rejected response
            chosen_score: Score for chosen response
            rejected_score: Score for rejected response
            rejection_reasons: Why the rejected response was rejected
            chosen_source: Source of chosen response
            rejected_source: Source of rejected response
            ensure_thinking_trace: If True, prepend thinking trace to chosen response

        Returns:
            A DPOPair instance
        """
        self._pair_counter += 1
        pair_id = f"dpo_{challenge.id}_{phase_id.value}_{self._pair_counter}"

        # Ensure chosen response has thinking trace if required
        if ensure_thinking_trace and challenge.training_metadata.requires_thinking_trace:
            chosen = self._ensure_thinking_trace(chosen, challenge, phase_id)

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

    # -------------------------------------------------------------------------
    # PRAXIS-AWARE GENERATION
    # -------------------------------------------------------------------------

    def generate_from_praxis_run(
        self,
        praxis_run: "PraxisRun",
        challenge: ChallengeV2,
        model_response: str,
        reference_response: Optional[str] = None,
    ) -> Optional[DPOPair]:
        """
        Generate a DPO pair from a Praxis Loop execution result.

        The Praxis Loop provides the highest-quality training signals:
        - HALLUCINATION: Model was confident but verification failed → REJECTED
        - TRUE_UNDERSTANDING: Model was confident and verification passed → CHOSEN

        Args:
            praxis_run: Result from PraxisRunner.run_challenge()
            challenge: The challenge that was executed
            model_response: The model's full response text
            reference_response: Optional expert/reference response for comparison

        Returns:
            DPOPair if a meaningful training signal was generated, None otherwise
        """
        calibration = praxis_run.calibration
        phase_id = PhaseID.ANALYZE  # Praxis operates at the analysis level

        prompt = challenge.to_prompt(phase_index=0)

        # Determine chosen/rejected based on calibration category
        if calibration.category.value == "hallucination":
            # Model was confidently WRONG - this is the highest value signal
            # The model's response becomes REJECTED
            if reference_response:
                return self._create_praxis_pair(
                    challenge=challenge,
                    phase_id=phase_id,
                    prompt=prompt,
                    chosen=reference_response,
                    rejected=model_response,
                    calibration=calibration,
                    chosen_source="expert",
                    rejected_source="praxis_hallucination",
                )
            else:
                # Generate a synthetic "calibrated" response as chosen
                calibrated_response = self._generate_calibrated_response(
                    model_response, calibration
                )
                return self._create_praxis_pair(
                    challenge=challenge,
                    phase_id=phase_id,
                    prompt=prompt,
                    chosen=calibrated_response,
                    rejected=model_response,
                    calibration=calibration,
                    chosen_source="synthetic_calibrated",
                    rejected_source="praxis_hallucination",
                )

        elif calibration.category.value == "true_understanding":
            # Model was confident and CORRECT - good positive example
            if reference_response:
                # Use model response as chosen, potentially pair with synthetic mistake
                mistake_response = self._generate_overconfident_mistake(
                    model_response, challenge, phase_id
                )
                return self._create_praxis_pair(
                    challenge=challenge,
                    phase_id=phase_id,
                    prompt=prompt,
                    chosen=model_response,
                    rejected=mistake_response,
                    calibration=calibration,
                    chosen_source="praxis_verified",
                    rejected_source="synthetic",
                )

        elif calibration.category.value == "under_calibrated":
            # Model was correct but not confident enough
            # Generate a more confident version as chosen
            confident_response = self._add_appropriate_confidence(model_response)
            return self._create_praxis_pair(
                challenge=challenge,
                phase_id=phase_id,
                prompt=prompt,
                chosen=confident_response,
                rejected=model_response,
                calibration=calibration,
                chosen_source="synthetic_confident",
                rejected_source="praxis_under_calibrated",
            )

        # APPROPRIATE_UNCERTAINTY - lowest signal, usually skip
        return None

    def generate_from_praxis_runs(
        self,
        praxis_runs: list["PraxisRun"],
        challenges: dict[str, ChallengeV2],
        model_responses: dict[str, str],
        reference_responses: Optional[dict[str, str]] = None,
        min_signal_weight: float = 0.3,
    ) -> list[DPOPair]:
        """
        Generate DPO pairs from multiple Praxis Loop executions.

        Prioritizes high-value signals (hallucinations) and filters
        low-value signals based on weight threshold.

        Args:
            praxis_runs: List of PraxisRun results
            challenges: Map of challenge_id -> ChallengeV2
            model_responses: Map of challenge_id -> model response text
            reference_responses: Optional map of challenge_id -> reference response
            min_signal_weight: Minimum signal weight to include (default 0.3)

        Returns:
            List of DPO pairs, sorted by signal weight (highest first)
        """
        pairs = []

        for run in praxis_runs:
            # Skip low-value signals
            if run.calibration.dpo_signal_strength < min_signal_weight:
                continue

            challenge = challenges.get(run.challenge_id)
            if not challenge:
                continue

            response = model_responses.get(run.challenge_id)
            if not response:
                continue

            reference = None
            if reference_responses:
                reference = reference_responses.get(run.challenge_id)

            pair = self.generate_from_praxis_run(
                praxis_run=run,
                challenge=challenge,
                model_response=response,
                reference_response=reference,
            )

            if pair:
                pairs.append(pair)

        # Sort by signal weight (hallucinations first)
        pairs.sort(key=lambda p: p.signal_weight, reverse=True)

        return pairs

    def _create_praxis_pair(
        self,
        challenge: ChallengeV2,
        phase_id: PhaseID,
        prompt: str,
        chosen: str,
        rejected: str,
        calibration: "CalibrationResult",
        chosen_source: str,
        rejected_source: str,
    ) -> DPOPair:
        """Create a DPO pair with Praxis calibration metadata.

        Praxis pairs always get thinking traces on chosen responses to
        teach the model to reason through source/sink identification
        before making tool calls.
        """
        self._pair_counter += 1
        pair_id = f"praxis_{challenge.id}_{calibration.category.value}_{self._pair_counter}"

        # Ensure chosen response has thinking trace (critical for Praxis pairs)
        if challenge.training_metadata.requires_thinking_trace:
            chosen = self._ensure_thinking_trace(chosen, challenge, phase_id)

        return DPOPair(
            pair_id=pair_id,
            challenge_id=challenge.id,
            phase_id=phase_id,
            prompt=prompt,
            chosen=chosen,
            rejected=rejected,
            chosen_score=calibration.execution_pass_rate if calibration.category.value == "true_understanding" else 0.8,
            rejected_score=calibration.execution_pass_rate if calibration.category.value == "hallucination" else 0.2,
            margin=0.6,  # Praxis pairs have high margin by design
            rejection_reasons=[f"Praxis calibration: {calibration.category.value}"],
            chosen_source=chosen_source,
            rejected_source=rejected_source,
            calibration_category=calibration.category.value,
            signal_weight=calibration.dpo_signal_strength,
            stated_confidence=calibration.stated_confidence,
            execution_pass_rate=calibration.execution_pass_rate,
            is_hallucination=calibration.is_hallucination,
        )

    def _generate_calibrated_response(
        self,
        hallucinated_response: str,
        calibration: "CalibrationResult",
    ) -> str:
        """
        Generate a properly calibrated version of a hallucinated response.

        When the model was overconfident but wrong, we generate a response
        that expresses appropriate uncertainty.
        """
        # Add uncertainty markers to the response
        uncertainty_prefix = f"""Based on my analysis, I have **low to medium confidence** in the following assessment.

The verification results suggest my initial hypothesis may be incorrect (execution pass rate: {calibration.execution_pass_rate:.1%}).

"""
        # Reduce confidence markers in the original
        calibrated = hallucinated_response.replace(
            "I am confident", "I tentatively suggest"
        ).replace(
            "definitely", "possibly"
        ).replace(
            "certainly", "potentially"
        ).replace(
            "Confidence: High", "Confidence: Low"
        ).replace(
            "confidence: 0.9", "confidence: 0.4"
        ).replace(
            "confidence: 0.8", "confidence: 0.3"
        )

        return uncertainty_prefix + calibrated

    def _generate_overconfident_mistake(
        self,
        good_response: str,
        challenge: ChallengeV2,
        phase_id: PhaseID,
    ) -> str:
        """Generate an overconfident but wrong response for contrast."""
        return """After thorough analysis, I am **highly confident** (95%) that this code contains multiple critical vulnerabilities.

1. **SQL Injection (CWE-89)** - Confidence: Very High
2. **Path Traversal (CWE-22)** - Confidence: High
3. **Command Injection (CWE-78)** - Confidence: High

These issues require immediate remediation. The application should be taken offline until fixed.

Severity: CRITICAL
Confidence: 0.95"""

    def _add_appropriate_confidence(self, under_confident_response: str) -> str:
        """Add appropriate confidence to an under-confident response."""
        confidence_suffix = """

Based on successful verification of this hypothesis through tool execution, I can state with **high confidence** that this assessment is accurate.

Verification Status: PASSED
Confidence: 0.85"""

        return under_confident_response + confidence_suffix


# =============================================================================
# PRAXIS-AWARE EXPORT FUNCTIONS
# =============================================================================

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


def export_praxis_dpo_dataset(
    pairs: list[DPOPair],
    output_path: str,
    prioritize_hallucinations: bool = True,
    include_calibration_metadata: bool = True,
    hallucination_oversample_factor: int = 3,
) -> dict:
    """
    Export DPO pairs with Praxis-aware weighting and oversampling.

    Hallucination pairs (confidently wrong) are the highest-value training
    signals because they teach the model to be appropriately uncertain.

    Args:
        pairs: List of DPO pairs (should include Praxis pairs)
        output_path: Where to save the dataset
        prioritize_hallucinations: Sort hallucinations first
        include_calibration_metadata: Include calibration info in output
        hallucination_oversample_factor: Repeat hallucination pairs N times

    Returns:
        Statistics about the exported dataset
    """
    # Separate pairs by calibration category
    hallucinations = [p for p in pairs if p.is_hallucination]
    true_understanding = [p for p in pairs if p.calibration_category == "true_understanding"]
    under_calibrated = [p for p in pairs if p.calibration_category == "under_calibrated"]
    other = [p for p in pairs if not p.calibration_category]

    # Build output with oversampling
    output_pairs = []

    # Oversample hallucinations (highest value)
    for _ in range(hallucination_oversample_factor):
        output_pairs.extend(hallucinations)

    # Add true understanding pairs
    output_pairs.extend(true_understanding)

    # Add under-calibrated pairs
    output_pairs.extend(under_calibrated)

    # Add other pairs
    output_pairs.extend(other)

    # Sort if requested (hallucinations first)
    if prioritize_hallucinations:
        output_pairs.sort(key=lambda p: p.signal_weight, reverse=True)

    # Export
    with open(output_path, 'w') as f:
        for pair in output_pairs:
            if include_calibration_metadata:
                f.write(json.dumps(pair.to_dict()) + '\n')
            else:
                f.write(json.dumps(pair.to_training_format()) + '\n')

    # Return statistics
    stats = {
        "total_pairs": len(output_pairs),
        "unique_pairs": len(pairs),
        "hallucination_pairs": len(hallucinations),
        "true_understanding_pairs": len(true_understanding),
        "under_calibrated_pairs": len(under_calibrated),
        "other_pairs": len(other),
        "oversample_factor": hallucination_oversample_factor,
        "hallucination_percentage": (
            len(hallucinations) * hallucination_oversample_factor / len(output_pairs) * 100
            if output_pairs else 0
        ),
    }

    return stats


def get_praxis_dataset_summary(pairs: list[DPOPair]) -> str:
    """
    Generate a human-readable summary of a Praxis DPO dataset.

    Args:
        pairs: List of DPO pairs

    Returns:
        Formatted summary string
    """
    # Count by category
    categories = {}
    for pair in pairs:
        cat = pair.calibration_category or "legacy"
        categories[cat] = categories.get(cat, 0) + 1

    # Calculate signal weights
    total_weight = sum(p.signal_weight for p in pairs)
    hallucination_weight = sum(p.signal_weight for p in pairs if p.is_hallucination)

    lines = [
        "=" * 60,
        "PRAXIS DPO DATASET SUMMARY",
        "=" * 60,
        "",
        f"Total Pairs: {len(pairs)}",
        f"Total Signal Weight: {total_weight:.1f}",
        "",
        "By Calibration Category:",
    ]

    for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
        pct = count / len(pairs) * 100 if pairs else 0
        lines.append(f"  {cat:25s}: {count:5d} ({pct:5.1f}%)")

    if hallucination_weight > 0:
        lines.extend([
            "",
            f"Hallucination Signal Weight: {hallucination_weight:.1f} "
            f"({hallucination_weight / total_weight * 100:.1f}% of total)",
        ])

    lines.append("=" * 60)

    return "\n".join(lines)
