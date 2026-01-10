"""
Training Data Amplifier: Scale up DPO pairs through augmentation.

This module significantly increases training data volume through:
1. Response variation generation (multiple valid answers)
2. Systematic error injection (diverse mistake types)
3. Cross-pillar transfer examples
4. Difficulty scaling (harder/easier variants)
5. Contrastive pair mining
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass
from typing import Any, Optional

from dojo.graders.dpo_generator import DPOPair, DPOPairGenerator
from dojo.models_v2 import (
    ChallengeV2,
    PhaseID,
    Pillar,
)

# ─────────────────────────────────────────────────────────────────────────────
# Response Variation Templates
# ─────────────────────────────────────────────────────────────────────────────

RESPONSE_STRUCTURES = {
    "formal_academic": {
        "intro": "This analysis examines {topic} from a security perspective.",
        "finding": "Finding: {observation}\n  - Evidence: {evidence}\n  - Impact: {impact}",
        "conclusion": "In conclusion, the {verdict} is supported by the evidence above.",
    },
    "security_report": {
        "intro": "## Security Assessment\n\n**Target**: {topic}",
        "finding": "### {observation}\n\n- **Severity**: {severity}\n- **Evidence**: {evidence}\n- **Remediation**: {remediation}",
        "conclusion": "## Verdict\n\n{verdict}",
    },
    "concise_technical": {
        "intro": "Analysis: {topic}",
        "finding": "- {observation}: {evidence}",
        "conclusion": "Result: {verdict}",
    },
    "structured_json_like": {
        "intro": "```\n{{\n  \"analysis\": \"{topic}\",",
        "finding": "  \"finding_{n}\": {{\n    \"observation\": \"{observation}\",\n    \"evidence\": \"{evidence}\"\n  }},",
        "conclusion": "  \"verdict\": \"{verdict}\"\n}}\n```",
    },
    "narrative": {
        "intro": "Upon examining {topic}, several security-relevant observations emerged.",
        "finding": "The {observation} stands out because {evidence}. This is significant given {impact}.",
        "conclusion": "Taking all observations into account, the assessment concludes: {verdict}",
    },
}

# Varied phrasings for the same concept
PHRASING_VARIANTS = {
    "vulnerable": [
        "is vulnerable",
        "contains a vulnerability",
        "has a security flaw",
        "exhibits a weakness",
        "is susceptible to attack",
        "has exploitable behavior",
    ],
    "secure": [
        "is secure",
        "is not vulnerable",
        "implements proper security controls",
        "correctly handles the security concern",
        "resists the attack vector",
        "has appropriate protections",
    ],
    "high_confidence": [
        "confidence: 0.95",
        "high confidence",
        "confident assessment",
        "strongly supported finding",
        "definitive analysis",
    ],
    "medium_confidence": [
        "confidence: 0.70",
        "moderate confidence",
        "likely finding",
        "probable assessment",
    ],
    "observation_intro": [
        "I observed that",
        "Analysis reveals",
        "The code shows",
        "Examination indicates",
        "Review demonstrates",
        "Investigation found",
    ],
}

# Diverse mistake categories for rejection generation
MISTAKE_CATEGORIES: dict[str, Any] = {
    "hallucination": {
        "fake_api": [
            "SecureValidator.checkInput()",
            "AuthManager.bypassAuth()",
            "DataSanitizer.cleanAll()",
            "CryptoHelper.weakHash()",
            "SessionManager.hijackable()",
            "AccessControl.vulnerable()",
        ],
        "fake_cwe": ["CWE-1234", "CWE-9999", "CWE-5678", "CWE-0001"],
        "fake_function": [
            "processUnsafeData()",
            "handleInsecureRequest()",
            "validateWithBypass()",
            "authenticateWeakly()",
        ],
    },
    "logical_errors": {
        "reversed_logic": "The code is {opposite_verdict} because {correct_reasoning}",
        "non_sequitur": "The code uses {observation} therefore it has {unrelated_vuln}",
        "correlation_causation": "Since {feature_a} exists, {unrelated_b} must be vulnerable",
    },
    "incomplete_analysis": {
        "surface_only": "The code has potential security issues.",
        "no_evidence": "{verdict} but I cannot point to specific code.",
        "missing_context": "{observation} without considering the surrounding code.",
    },
    "overconfidence": {
        "premature_conclusion": "This is definitely {verdict} - no further analysis needed.",
        "ignoring_uncertainty": "100% confident that {verdict}.",
        "dismissing_complexity": "Simple case of {vuln_type}, nothing more to analyze.",
    },
    "methodology_failures": {
        "no_hypothesis": "I will start by concluding that {verdict}.",
        "untestable_claim": "The code might have issues under unknown conditions.",
        "confirmation_bias": "Looking for evidence that confirms {predetermined_verdict}.",
    },
}


@dataclass
class AmplificationConfig:
    """Configuration for training data amplification."""

    # Per-challenge targets
    variations_per_good_response: int = 5
    mistakes_per_category: int = 3

    # Cross-pillar settings
    enable_cross_pillar: bool = True
    cross_pillar_pairs_per_challenge: int = 2

    # Difficulty scaling
    enable_difficulty_scaling: bool = True

    # Quality filters
    min_response_length: int = 100
    max_response_length: int = 4000

    # Output targets
    target_total_pairs: int = 2000


class TrainingAmplifier:
    """
    Amplifies training data through diverse augmentation strategies.

    Goal: Scale from ~6 pairs/challenge to ~64 pairs/challenge
    (achieving 2000+ pairs from 31 challenges)
    """

    def __init__(self, config: Optional[AmplificationConfig] = None):
        self.config = config or AmplificationConfig()
        self.dpo_generator = DPOPairGenerator(min_margin=0.1)
        self._pair_counter = 0

    def amplify_challenge(
        self,
        challenge: ChallengeV2,
        good_response: str,
        good_score: float,
        phase_id: PhaseID,
    ) -> list[DPOPair]:
        """
        Generate amplified training pairs for a single challenge.

        Strategies applied:
        1. Structure variations of the good response
        2. Phrasing variations
        3. Systematic mistake injection
        4. Cross-pillar transfer (if enabled)

        Args:
            challenge: The challenge
            good_response: A high-quality response
            good_score: Score of the good response
            phase_id: Which phase

        Returns:
            List of DPO pairs (target: 50-70 per challenge)
        """
        pairs = []

        # Get prompt for all pairs
        prompt = challenge.to_prompt(
            phase_index=next(
                i for i, p in enumerate(challenge.phases) if p.phase_id == phase_id
            )
        )

        # Strategy 1: Generate response variations (chosen responses)
        good_variations = self._generate_response_variations(
            good_response,
            challenge,
            num_variations=self.config.variations_per_good_response
        )

        # Strategy 2: Generate diverse mistakes (rejected responses)
        all_mistakes = self._generate_all_mistake_types(
            good_response,
            challenge,
            phase_id,
        )

        # Create pairs: each good variation paired with multiple mistakes
        for good_var in good_variations:
            # Sample mistakes to pair with this variation
            sampled_mistakes = random.sample(
                all_mistakes,
                min(len(all_mistakes), 8)
            )

            for mistake, mistake_type, estimated_score in sampled_mistakes:
                if len(mistake) >= self.config.min_response_length:
                    pairs.append(self._create_pair(
                        challenge=challenge,
                        phase_id=phase_id,
                        prompt=prompt,
                        chosen=good_var,
                        rejected=mistake,
                        chosen_score=good_score * random.uniform(0.95, 1.0),  # Slight variation
                        rejected_score=estimated_score,
                        rejection_reasons=[mistake_type],
                        rejected_source="synthetic_amplified",
                    ))

        # Strategy 3: Hard negative mining - mistakes that are close to correct
        hard_negatives = self._generate_hard_negatives(
            good_response,
            challenge,
            phase_id,
        )

        for hard_neg, reason in hard_negatives:
            pairs.append(self._create_pair(
                challenge=challenge,
                phase_id=phase_id,
                prompt=prompt,
                chosen=good_response,
                rejected=hard_neg,
                chosen_score=good_score,
                rejected_score=good_score * 0.7,  # Close but not quite
                rejection_reasons=[reason],
                rejected_source="hard_negative",
            ))

        return pairs

    def _generate_response_variations(
        self,
        original: str,
        challenge: ChallengeV2,
        num_variations: int = 5,
    ) -> list[str]:
        """
        Generate structural and phrasing variations of a good response.

        These are all "correct" responses that should be chosen.
        """
        variations = [original]  # Include original

        # Extract key content from original
        key_content = self._extract_key_content(original, challenge)

        # Generate structure variations
        for structure_name, structure in list(RESPONSE_STRUCTURES.items())[:num_variations]:
            variation = self._apply_structure(
                key_content,
                structure,
                challenge,
            )
            if variation and len(variation) >= self.config.min_response_length:
                variations.append(variation)

        # Generate phrasing variations
        for _ in range(num_variations - len(variations)):
            varied = self._apply_phrasing_variations(original)
            if varied != original:
                variations.append(varied)

        return variations[:num_variations + 1]  # +1 for original

    def _generate_all_mistake_types(
        self,
        good_response: str,
        challenge: ChallengeV2,
        phase_id: PhaseID,
    ) -> list[tuple[str, str, float]]:
        """
        Generate comprehensive set of mistake responses.

        Returns: List of (response, mistake_type, estimated_score)
        """
        mistakes = []

        # Hallucination mistakes
        for _ in range(self.config.mistakes_per_category):
            halluc = self._make_hallucination_mistake(good_response, challenge)
            mistakes.append((halluc, "hallucination", 0.2))

        # Logical error mistakes
        for error_type in ["reversed_logic", "non_sequitur"]:
            logical = self._make_logical_error(good_response, challenge, error_type)
            mistakes.append((logical, f"logical_{error_type}", 0.25))

        # Incomplete analysis mistakes
        for level in ["severe", "moderate", "mild"]:
            incomplete = self._make_incomplete_analysis(good_response, level)
            score = {"severe": 0.15, "moderate": 0.35, "mild": 0.5}[level]
            mistakes.append((incomplete, f"incomplete_{level}", score))

        # Overconfidence mistakes
        overconf = self._make_overconfident_response(good_response, challenge)
        mistakes.append((overconf, "overconfidence", 0.3))

        # Methodology failures
        for failure in ["no_hypothesis", "confirmation_bias"]:
            method_fail = self._make_methodology_failure(good_response, challenge, failure)
            mistakes.append((method_fail, f"methodology_{failure}", 0.2))

        # False positive/negative
        if challenge.ground_truth.vulnerability_present:
            false_neg = self._make_false_negative(challenge)
            mistakes.append((false_neg, "false_negative", 0.1))
        else:
            false_pos = self._make_false_positive(challenge)
            mistakes.append((false_pos, "false_positive", 0.1))

        # Wrong CWE classification
        wrong_cwe = self._make_wrong_cwe(good_response, challenge)
        mistakes.append((wrong_cwe, "wrong_classification", 0.35))

        # Surface-level analysis
        surface = self._make_surface_analysis(challenge)
        mistakes.append((surface, "surface_only", 0.25))

        return mistakes

    def _generate_hard_negatives(
        self,
        good_response: str,
        challenge: ChallengeV2,
        phase_id: PhaseID,
    ) -> list[tuple[str, str]]:
        """
        Generate responses that are almost correct but have subtle flaws.

        These are valuable for teaching fine-grained distinctions.
        """
        hard_negatives = []

        # Missing one key observation
        partial = self._remove_one_observation(good_response)
        if partial:
            hard_negatives.append((partial, "missing_one_observation"))

        # Correct findings but wrong confidence
        wrong_conf = self._alter_confidence(good_response, "overstate")
        hard_negatives.append((wrong_conf, "wrong_confidence"))

        # Correct verdict but weak justification
        weak_just = self._weaken_justification(good_response)
        hard_negatives.append((weak_just, "weak_justification"))

        # Good analysis but wrong CWE parent/child
        if "CWE-" in good_response:
            wrong_hierarchy = self._shift_cwe_hierarchy(good_response)
            hard_negatives.append((wrong_hierarchy, "wrong_cwe_hierarchy"))

        return hard_negatives

    # ─────────────────────────────────────────────────────────────────────────
    # Variation Generators
    # ─────────────────────────────────────────────────────────────────────────

    def _extract_key_content(
        self,
        response: str,
        challenge: ChallengeV2,
    ) -> dict:
        """Extract key content elements from a response."""
        # Determine verdict
        is_vuln = challenge.ground_truth.vulnerability_present
        verdict = "vulnerable" if is_vuln else "secure"

        # Extract observations (lines starting with numbers or bullets)
        observations = []
        for line in response.split('\n'):
            line = line.strip()
            if (line and (line[0].isdigit() or line.startswith('-') or line.startswith('*'))
                and len(line) > 20):
                observations.append(line.lstrip('0123456789.-* '))

        # Use ground truth observations if available
        if not observations and challenge.ground_truth.key_observations:
            observations = challenge.ground_truth.key_observations[:5]

        # Get CWE if present
        cwe_match = re.search(r'CWE-\d+', response)
        cwe = cwe_match.group(0) if cwe_match else challenge.ground_truth.cwe_id or "CWE-Unknown"

        # Get impact from root cause or description
        impact = challenge.ground_truth.root_cause or challenge.description or "Security impact"

        return {
            "verdict": verdict,
            "is_vulnerable": is_vuln,
            "observations": observations[:5],
            "cwe": cwe,
            "topic": f"Code sample from {challenge.id}",
            "evidence": "Code analysis and pattern matching",
            "impact": impact[:200] if len(impact) > 200 else impact,
            "severity": "High" if is_vuln else "N/A",
            "remediation": "Apply security best practices and input validation",
        }

    def _apply_structure(
        self,
        content: Any,
        structure: dict[str, str],
        challenge: ChallengeV2,
    ) -> str:
        """Apply a response structure template to content."""
        parts = []

        # Apply structure template
        content_dict: Any = content

        # Intro
        intro = structure["intro"].format(
            topic=content_dict.get("topic", "the code"),  # type: ignore
        )
        parts.append(intro)
        parts.append("")

        # Findings
        for i, obs in enumerate(content_dict.get("observations", [])[:3], 1):  # type: ignore
            finding = structure["finding"].format(
                n=i,
                observation=obs,
                evidence=content_dict.get("evidence", "Analysis"),  # type: ignore
                impact=content_dict.get("impact", "Security impact"),  # type: ignore
                severity=content_dict.get("severity", "Medium"),  # type: ignore
                remediation=content_dict.get("remediation", "Fix needed"),  # type: ignore
            )
            parts.append(finding)
            parts.append("")

        # Conclusion
        verdict_text = "code is vulnerable" if content_dict["is_vulnerable"] else "code is secure"  # type: ignore
        conclusion = structure["conclusion"].format(
            verdict=verdict_text,
        )
        parts.append(conclusion)

        # Add metadata
        parts.append("")
        parts.append(f"**is_vulnerable**: {str(content_dict['is_vulnerable']).lower()}")  # type: ignore
        parts.append("**confidence**: 0.9")
        if content_dict["is_vulnerable"] and content_dict.get("cwe"):  # type: ignore
            parts.append(f"**CWE**: {content_dict['cwe']}")  # type: ignore

        return '\n'.join(parts)

    def _apply_phrasing_variations(self, response: str) -> str:
        """Apply phrasing variations to a response."""
        varied = response

        # Replace vulnerability phrasing
        for original_phrase in PHRASING_VARIANTS["vulnerable"][:3]:
            if original_phrase in varied.lower():
                replacement = random.choice(PHRASING_VARIANTS["vulnerable"])
                varied = re.sub(
                    re.escape(original_phrase),
                    replacement,
                    varied,
                    flags=re.IGNORECASE,
                    count=1
                )
                break

        # Replace secure phrasing
        for original_phrase in PHRASING_VARIANTS["secure"][:3]:
            if original_phrase in varied.lower():
                replacement = random.choice(PHRASING_VARIANTS["secure"])
                varied = re.sub(
                    re.escape(original_phrase),
                    replacement,
                    varied,
                    flags=re.IGNORECASE,
                    count=1
                )
                break

        # Vary observation introductions
        for intro in PHRASING_VARIANTS["observation_intro"]:
            if intro.lower() in varied.lower():
                replacement = random.choice(PHRASING_VARIANTS["observation_intro"])
                varied = re.sub(
                    re.escape(intro),
                    replacement,
                    varied,
                    flags=re.IGNORECASE,
                    count=1
                )
                break

        return varied

    # ─────────────────────────────────────────────────────────────────────────
    # Mistake Generators
    # ─────────────────────────────────────────────────────────────────────────

    def _make_hallucination_mistake(
        self,
        good_response: str,
        challenge: ChallengeV2,
    ) -> str:
        """Generate response with hallucinated content."""
        fake_apis = random.sample(MISTAKE_CATEGORIES["hallucination"]["fake_api"], 2)
        fake_func = random.choice(MISTAKE_CATEGORIES["hallucination"]["fake_function"])

        hallucinated = f"""## Security Analysis

After examining the code, I identified critical security issues:

1. **Insecure API Usage**: The code calls {fake_apis[0]} which is known to be vulnerable.
   This API has been deprecated due to security concerns.

2. **Dangerous Function**: The {fake_func} function processes user input without sanitization.
   This is called from the {fake_apis[1]} module.

3. **Missing Controls**: The code lacks calls to {random.choice(MISTAKE_CATEGORIES["hallucination"]["fake_api"])}.

**is_vulnerable**: true
**confidence**: 0.85
**CWE**: {random.choice(MISTAKE_CATEGORIES["hallucination"]["fake_cwe"])}
"""
        return hallucinated

    def _make_logical_error(
        self,
        good_response: str,
        challenge: ChallengeV2,
        error_type: str,
    ) -> str:
        """Generate response with logical errors."""
        is_vuln = challenge.ground_truth.vulnerability_present

        if error_type == "reversed_logic":
            # Say the opposite of the truth with the same reasoning
            return f"""## Analysis

Based on careful examination:

The code {"is NOT vulnerable" if is_vuln else "IS vulnerable"} because:
- The input handling {"appears secure" if is_vuln else "has issues"}
- The security controls {"are properly implemented" if is_vuln else "are missing"}

**is_vulnerable**: {str(not is_vuln).lower()}
**confidence**: 0.90
"""
        elif error_type == "non_sequitur":
            return """## Analysis

The code uses string concatenation.

Therefore, it must be vulnerable to buffer overflow attacks.

Additionally, since there are function calls, privilege escalation is possible.

**is_vulnerable**: true
**confidence**: 0.8
**CWE**: CWE-120
"""

        return good_response

    def _make_incomplete_analysis(
        self,
        good_response: str,
        level: str,
    ) -> str:
        """Generate incomplete analysis at varying severity levels."""
        lines = good_response.split('\n')

        if level == "severe":
            # Just first few lines
            return '\n'.join(lines[:3])
        elif level == "moderate":
            # First third
            return '\n'.join(lines[:len(lines)//3])
        else:  # mild
            # Missing conclusion
            return '\n'.join(lines[:-5])

    def _make_overconfident_response(
        self,
        good_response: str,
        challenge: ChallengeV2,
    ) -> str:
        """Generate overconfident response."""
        is_vuln = challenge.ground_truth.vulnerability_present

        return f"""## Definitive Security Assessment

This is CLEARLY a {"vulnerable" if is_vuln else "secure"} implementation.

No further analysis is needed - this is a textbook case.

100% confident in this assessment.

**is_vulnerable**: {str(is_vuln).lower()}
**confidence**: 1.0
"""

    def _make_methodology_failure(
        self,
        good_response: str,
        challenge: ChallengeV2,
        failure_type: str,
    ) -> str:
        """Generate response with methodology failures."""
        is_vuln = challenge.ground_truth.vulnerability_present

        if failure_type == "no_hypothesis":
            return f"""The code is {"vulnerable" if is_vuln else "secure"}.

This conclusion was reached immediately upon viewing the code.

**is_vulnerable**: {str(is_vuln).lower()}
**confidence**: 0.75
"""
        elif failure_type == "confirmation_bias":
            return f"""## Analysis

Looking for evidence that the code is {"vulnerable" if is_vuln else "secure"}...

Found what I was looking for:
- The code does {"have" if is_vuln else "not have"} security issues as expected

This confirms my initial assumption.

**is_vulnerable**: {str(is_vuln).lower()}
**confidence**: 0.9
"""

        return good_response

    def _make_false_negative(self, challenge: ChallengeV2) -> str:
        """Generate false negative (claiming secure when vulnerable)."""
        return """## Security Assessment

After thorough analysis, this code appears to be secure.

The implementation follows security best practices:
- Input is handled appropriately
- No obvious injection vectors
- Proper access controls in place

**is_vulnerable**: false
**confidence**: 0.85
"""

    def _make_false_positive(self, challenge: ChallengeV2) -> str:
        """Generate false positive (claiming vulnerable when secure)."""
        return """## Security Assessment

CRITICAL: Multiple vulnerabilities detected!

1. **SQL Injection** - User input reaches database queries
2. **XSS** - Output not properly encoded
3. **Path Traversal** - File operations use user input

Immediate remediation required.

**is_vulnerable**: true
**confidence**: 0.9
**CWE**: CWE-89
"""

    def _make_wrong_cwe(
        self,
        good_response: str,
        challenge: ChallengeV2,
    ) -> str:
        """Generate response with wrong CWE classification."""
        # Get a wrong CWE
        correct_cwe = challenge.ground_truth.cwe_id or "CWE-79"

        # Map to different CWE families
        wrong_cwes = {
            "CWE-89": "CWE-79",   # SQL injection -> XSS
            "CWE-79": "CWE-89",   # XSS -> SQL injection
            "CWE-22": "CWE-78",   # Path traversal -> Command injection
            "CWE-78": "CWE-22",   # Command injection -> Path traversal
            "CWE-287": "CWE-306", # Auth issues swap
        }

        wrong_cwe = wrong_cwes.get(correct_cwe, "CWE-200")

        # Replace in response
        return re.sub(r'CWE-\d+', wrong_cwe, good_response, count=1)

    def _make_surface_analysis(self, challenge: ChallengeV2) -> str:
        """Generate surface-level analysis without depth."""
        is_vuln = challenge.ground_truth.vulnerability_present

        return f"""The code {"has" if is_vuln else "does not have"} security issues.

Looking at the code, it {"appears vulnerable" if is_vuln else "seems safe"}.

**is_vulnerable**: {str(is_vuln).lower()}
**confidence**: 0.7
"""

    # ─────────────────────────────────────────────────────────────────────────
    # Hard Negative Generators
    # ─────────────────────────────────────────────────────────────────────────

    def _remove_one_observation(self, response: str) -> Optional[str]:
        """Remove one key observation from response."""
        lines = response.split('\n')

        # Find numbered observations
        numbered_indices = [
            i for i, line in enumerate(lines)
            if line.strip() and line.strip()[0].isdigit()
        ]

        if len(numbered_indices) > 1:
            # Remove one (not the first)
            to_remove = random.choice(numbered_indices[1:])
            lines.pop(to_remove)
            return '\n'.join(lines)

        return None

    def _alter_confidence(self, response: str, direction: str) -> str:
        """Alter confidence level inappropriately."""
        if direction == "overstate":
            return re.sub(
                r'confidence[:\s]+0\.\d+',
                'confidence: 0.99',
                response,
                flags=re.IGNORECASE
            )
        else:
            return re.sub(
                r'confidence[:\s]+0\.\d+',
                'confidence: 0.3',
                response,
                flags=re.IGNORECASE
            )

    def _weaken_justification(self, response: str) -> str:
        """Keep verdict but weaken the justification."""
        lines = response.split('\n')

        # Remove evidence lines (often contain "because", "due to", "evidence")
        filtered = [
            line for line in lines
            if not any(word in line.lower() for word in ["because", "due to", "evidence:", "proof:"])
        ]

        return '\n'.join(filtered)

    def _shift_cwe_hierarchy(self, response: str) -> str:
        """Shift CWE to wrong level in hierarchy."""
        # Move to parent category (more general)
        parent_shifts = {
            r'CWE-89': 'CWE-943',   # SQLi -> OWASP top 10 category
            r'CWE-79': 'CWE-74',    # XSS -> Injection parent
            r'CWE-22': 'CWE-706',   # Path traversal -> parent
        }

        for pattern, replacement in parent_shifts.items():
            if re.search(pattern, response):
                return re.sub(pattern, replacement, response, count=1)

        return response

    # ─────────────────────────────────────────────────────────────────────────
    # Pair Creation
    # ─────────────────────────────────────────────────────────────────────────

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
        rejected_source: str = "synthetic",
    ) -> DPOPair:
        """Create a DPO pair with proper ID."""
        self._pair_counter += 1
        pair_id = f"amp_{challenge.id}_{phase_id.value}_{self._pair_counter}"

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
            chosen_source="model",
            rejected_source=rejected_source,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Cross-Pillar Transfer Generator
# ─────────────────────────────────────────────────────────────────────────────

class CrossPillarGenerator:
    """
    Generate training pairs that transfer learning across pillars.

    For example:
    - Static analysis skills help with patch analysis
    - Root cause skills help with taxonomy
    - Negative knowledge skills help reduce false positives everywhere
    """

    PILLAR_TRANSFERS = {
        (Pillar.STATIC_ANALYSIS, Pillar.PATCH_ANALYSIS): {
            "skill": "code pattern recognition",
            "transfer": "Recognizing vulnerable patterns helps identify incomplete patches",
        },
        (Pillar.ROOT_CAUSE, Pillar.TAXONOMY): {
            "skill": "understanding vulnerability mechanics",
            "transfer": "Deep understanding enables accurate classification",
        },
        (Pillar.NEGATIVE_KNOWLEDGE, Pillar.STATIC_ANALYSIS): {
            "skill": "recognizing secure patterns",
            "transfer": "Knowing what's secure reduces false positives in analysis",
        },
        (Pillar.METHODOLOGY, Pillar.ROOT_CAUSE): {
            "skill": "structured reasoning",
            "transfer": "Methodical approach reveals root causes",
        },
        (Pillar.PATTERN_TRANSFER, Pillar.PATCH_ANALYSIS): {
            "skill": "pattern abstraction",
            "transfer": "Abstract patterns help evaluate fix completeness",
        },
    }

    def generate_transfer_prompt(
        self,
        source_pillar: Pillar,
        target_pillar: Pillar,
        challenge: ChallengeV2,
    ) -> str:
        """Generate prompt that encourages cross-pillar transfer."""
        transfer_info = self.PILLAR_TRANSFERS.get((source_pillar, target_pillar))

        if not transfer_info:
            return ""

        return f"""Consider this from a {source_pillar.value} perspective.

Your skill in {transfer_info['skill']} is relevant here because:
{transfer_info['transfer']}

Apply this insight to analyze the following:
"""


# ─────────────────────────────────────────────────────────────────────────────
# Batch Amplification Runner
# ─────────────────────────────────────────────────────────────────────────────

def amplify_all_challenges(
    challenges: list[ChallengeV2],
    responses: dict[str, tuple[str, float]],  # challenge_id -> (response, score)
    config: Optional[AmplificationConfig] = None,
) -> list[DPOPair]:
    """
    Amplify training data for all challenges.

    Args:
        challenges: List of challenges
        responses: Dict mapping challenge ID to (good_response, score)
        config: Amplification configuration

    Returns:
        List of all generated DPO pairs
    """
    amplifier = TrainingAmplifier(config)
    all_pairs = []

    for challenge in challenges:
        if challenge.id in responses:
            response, score = responses[challenge.id]

            # Amplify for observation phase
            pairs = amplifier.amplify_challenge(
                challenge=challenge,
                good_response=response,
                good_score=score,
                phase_id=PhaseID.OBSERVE,
            )
            all_pairs.extend(pairs)

    return all_pairs


def calculate_amplification_stats(pairs: list[DPOPair]) -> dict:
    """Calculate statistics about amplified data."""
    if not pairs:
        return {
            "total_pairs": 0,
            "unique_challenges": 0,
            "pairs_per_challenge": 0,
            "rejection_type_distribution": {},
            "average_margin": 0,
            "margin_range": (0, 0),
        }

    # Group by mistake type
    by_rejection: dict[str, int] = {}
    for pair in pairs:
        for reason in pair.rejection_reasons:
            by_rejection[reason] = by_rejection.get(reason, 0) + 1

    # Group by challenge
    by_challenge: dict[str, int] = {}
    for pair in pairs:
        by_challenge[pair.challenge_id] = by_challenge.get(pair.challenge_id, 0) + 1

    # Margin distribution
    margins = [pair.margin for pair in pairs]

    return {
        "total_pairs": len(pairs),
        "unique_challenges": len(by_challenge),
        "pairs_per_challenge": sum(by_challenge.values()) / len(by_challenge) if by_challenge else 0.0,
        "rejection_type_distribution": by_rejection,
        "average_margin": sum(margins) / len(margins) if margins else 0.0,
        "margin_range": (min(margins), max(margins)) if margins else (0.0, 0.0),
    }
