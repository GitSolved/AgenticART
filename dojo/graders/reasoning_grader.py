"""
V2 Reasoning Grader: Evaluates model reasoning quality across challenge phases.

This grader assesses HOW models think, not just WHAT they conclude.
Key metrics: completeness, accuracy, depth, calibration, hallucination detection.
"""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Optional

from dojo.models_v2 import (
    ChallengeV2,
    GroundTruth,
    Phase,
    PhaseEvaluation,
    PhaseID,
    ReasoningQuality,
)


@dataclass
class CriterionScore:
    """Score for a single evaluation criterion."""

    name: str
    score: float  # 0.0 - 1.0
    weight: float
    feedback: str
    details: dict = field(default_factory=dict)

    @property
    def weighted_score(self) -> float:
        return self.score * self.weight


@dataclass
class GradingResult:
    """Complete grading result for a phase."""

    phase_id: PhaseID
    criterion_scores: list[CriterionScore]
    total_score: float
    feedback: str
    hallucinations: list[str] = field(default_factory=list)
    missing_items: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_phase_evaluation(self) -> PhaseEvaluation:
        """Convert to PhaseEvaluation dataclass."""
        return PhaseEvaluation(
            phase_id=self.phase_id,
            score=self.total_score,
            criteria_scores={cs.name: cs.score for cs in self.criterion_scores},
            feedback=self.feedback,
            hallucinations_detected=self.hallucinations,
            missing_observations=self.missing_items,
            incorrect_conclusions=self.errors,
        )


class PhaseGrader(ABC):
    """Abstract base class for phase-specific graders."""

    def __init__(self, artifact_content: str = ""):
        """
        Initialize grader with artifact content for hallucination detection.

        Args:
            artifact_content: Combined text of all artifacts for reference
        """
        self.artifact_content = artifact_content.lower()
        self._extract_artifact_terms()

    def _extract_artifact_terms(self) -> None:
        """Extract technical terms from artifacts for hallucination checking."""
        # Extract potential technical terms (class names, methods, etc.)
        self.artifact_terms: set[str] = set()

        # Java/Kotlin identifiers
        identifiers = re.findall(r'\b[A-Z][a-zA-Z0-9_]*\b', self.artifact_content)
        self.artifact_terms.update(t.lower() for t in identifiers)

        # Method calls
        methods = re.findall(r'\.([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', self.artifact_content)
        self.artifact_terms.update(t.lower() for t in methods)

        # String literals that might be important
        strings = re.findall(r'"([^"]+)"', self.artifact_content)
        self.artifact_terms.update(s.lower() for s in strings if len(s) > 3)

        # CWE references
        cwes = re.findall(r'CWE-\d+', self.artifact_content, re.IGNORECASE)
        self.artifact_terms.update(c.upper() for c in cwes)

    @abstractmethod
    def grade(
        self,
        response: str,
        ground_truth: GroundTruth,
        phase: Phase,
    ) -> GradingResult:
        """Grade a response for this phase type."""
        pass

    def parse_response(self, response: str) -> Optional[dict]:
        """Attempt to parse response as JSON or extract structured content."""
        # Try direct JSON parse
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            pass

        # Try to extract JSON from markdown code blocks
        json_match = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', response, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass

        return None

    def detect_hallucinations(self, response: str) -> list[str]:
        """
        Detect potentially hallucinated technical terms.

        Returns list of terms that appear in response but not in artifacts.
        """
        hallucinations = []
        response_lower = response.lower()

        # Look for technical terms in response
        # Class/type names (PascalCase)
        response_classes = re.findall(r'\b[A-Z][a-zA-Z0-9_]{3,}\b', response)

        # Method names mentioned
        response_methods = re.findall(r'\.([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', response)
        response_methods += re.findall(r'\b([a-z][a-zA-Z0-9_]*)\s*\(\)', response)

        # Check each term
        for term in response_classes + response_methods:
            term_lower = term.lower()
            # Skip common Java/Android terms and common English words used in analysis
            common_terms = {
                # Java/Android types
                'string', 'object', 'list', 'array', 'map', 'set', 'integer', 'boolean',
                'void', 'null', 'true', 'false', 'context', 'intent', 'activity', 'service',
                'bundle', 'view', 'layout', 'fragment', 'application', 'class', 'method',
                'function', 'variable', 'parameter', 'return', 'type', 'data', 'value',
                # Common analysis words (PascalCase words in markdown)
                'section', 'analysis', 'observation', 'finding', 'result', 'conclusion',
                'summary', 'issue', 'problem', 'vulnerability', 'security', 'risk', 'attack',
                'defense', 'protection', 'validation', 'input', 'output', 'source', 'sink',
                'flow', 'path', 'trace', 'tracking', 'transformation', 'check', 'verify',
                'secure', 'insecure', 'safe', 'unsafe', 'dangerous', 'critical', 'high',
                'medium', 'low', 'none', 'blocked', 'allowed', 'denied', 'granted',
                # Common English words that appear as PascalCase in markdown
                'this', 'that', 'these', 'those', 'which', 'what', 'where', 'when', 'why',
                'how', 'because', 'therefore', 'however', 'although', 'while', 'since',
                'before', 'after', 'during', 'between', 'through', 'without', 'within',
                'extraction', 'identification', 'assessment', 'evaluation', 'classification',
                'implementation', 'configuration', 'initialization', 'storage', 'handling',
                'logging', 'surface', 'access', 'meets', 'generated', 'resistance', 'prevents',
                # Markdown/formatting related
                'json', 'code', 'example', 'note', 'important', 'table', 'property', 'status',
                'reasoning', 'category', 'relevant', 'apis', 'android', 'owasp', 'nist',
                # Common technical terms not specific to code
                'textview', 'webview', 'database', 'query', 'injection', 'traversal',
                # Additional common English words from analysis
                'external', 'internal', 'information', 'disclosure', 'business', 'logic',
                'operation', 'effect', 'partial', 'limits', 'converts', 'identified',
                'constant', 'time', 'impractical', 'unique', 'csprng', 'recommendations',
                'insight', 'key', 'typical', 'financial', 'applications', 'component',
                'sensitive', 'untrusted', 'manipulated', 'exposed', 'rooted', 'devices',
                'tainted', 'sanitized', 'reached', 'unchanged', 'mechanism', 'execution',
                # Security terms
                'rainbow', 'tables', 'brute', 'force', 'dictionary', 'timing', 'hash',
                'salt', 'iteration', 'pbkdf2', 'hmac', 'sha256', 'aes', 'rsa', 'ecb', 'cbc',
                'encryption', 'decryption', 'cryptographic', 'cipher', 'digest',
                # More common words that appear as PascalCase
                'stores', 'state', 'line', 'lines', 'provides', 'have', 'properties',
                'comparison', 'does', 'tracked', 'assignment', 'field', 'location',
                'trust', 'level', 'risk_assessment', 'ui_display', 'sql_execution',
                'sink_type', 'data_state', 'tainted_safe', 'security_effect', 'partial_dos_only',
                # Additional verb forms
                'removes', 'normalizes', 'copies', 'sends', 'receives', 'returns', 'creates',
                'handles', 'processes', 'validates', 'sanitizes', 'escapes', 'encodes', 'decodes',
                # Report/documentation headers
                'classes', 'methods', 'analyzed', 'elements', 'calls', 'findings', 'details',
                'approach', 'testing', 'tests', 'coverage', 'results', 'metrics', 'score',
                'passed', 'failed', 'hypothesis', 'prediction', 'evidence', 'confirmed',
                'verified', 'boundary', 'normal', 'attack', 'payload', 'actual', 'expected',
                'observations', 'potential', 'missing', 'throws', 'requires', 'provides',
                'contains', 'implements', 'extends', 'pattern', 'patterns', 'identified',
                'detected', 'found', 'reviewed', 'checked', 'verified', 'validated',
                # Attack resistance terms
                'would', 'fail', 'bypass', 'mitigations', 'encoding', 'resistant',
                'blocked', 'prevents', 'mitigates', 'sanitization', 'layers', 'controls',
                'succeeding', 'exploitation', 'properly', 'secured', 'implemented',
                'multiple', 'demonstrates', 'correctly', 'following', 'reaches',
                'uses', 'using', 'used', 'like', 'such', 'being', 'also', 'each',
            }
            if term_lower in common_terms:
                continue
            # Skip short terms (less than 4 chars) - likely not real identifiers
            if len(term_lower) < 4:
                continue
            # Skip ALL CAPS terms - these are typically section headers in formatted responses
            if term.isupper():
                continue

            # Check if term appears in artifacts
            if term_lower not in self.artifact_terms and term_lower not in self.artifact_content:
                # Fuzzy match to allow for minor variations
                if not any(SequenceMatcher(None, term_lower, t).ratio() > 0.85
                          for t in self.artifact_terms):
                    hallucinations.append(term)

        return list(set(hallucinations))[:10]  # Limit to top 10

    def calculate_similarity(self, text1: str, text2: str) -> float:
        """Calculate text similarity score."""
        return SequenceMatcher(None, text1.lower(), text2.lower()).ratio()

    def check_key_terms_present(
        self,
        response: str,
        required_terms: list[str],
        fuzzy_threshold: float = 0.8
    ) -> tuple[list[str], list[str]]:
        """
        Check which required terms are present/missing in response.

        Returns (found_terms, missing_terms)
        """
        response_lower = response.lower()
        found = []
        missing = []

        for term in required_terms:
            term_lower = term.lower()
            if term_lower in response_lower:
                found.append(term)
            else:
                # Try fuzzy matching
                words = response_lower.split()
                if any(SequenceMatcher(None, term_lower, w).ratio() > fuzzy_threshold
                       for w in words):
                    found.append(term)
                else:
                    missing.append(term)

        return found, missing


class ObservationGrader(PhaseGrader):
    """
    Grades observation phase responses.

    Criteria:
    - Completeness: Found all key observations
    - Accuracy: Observations are factually correct
    - Relevance: Security relevance correctly assessed
    - No Hallucination: Didn't make up facts
    """

    def grade(
        self,
        response: str,
        ground_truth: GroundTruth,
        phase: Phase,
    ) -> GradingResult:
        criterion_scores = []

        # Parse response
        parsed = self.parse_response(response)

        # 1. Completeness - check against key_observations
        key_obs = ground_truth.key_observations
        if key_obs:
            found, missing = self._check_observations(response, key_obs)
            completeness_score = len(found) / len(key_obs) if key_obs else 1.0

            criterion_scores.append(CriterionScore(
                name="completeness",
                score=completeness_score,
                weight=0.30,
                feedback=f"Found {len(found)}/{len(key_obs)} key observations",
                details={"found": found, "missing": missing}
            ))
        else:
            criterion_scores.append(CriterionScore(
                name="completeness",
                score=0.7,  # Default if no key_observations defined
                weight=0.30,
                feedback="No key observations defined for validation",
            ))

        # 2. Accuracy - check for factual errors
        accuracy_score, accuracy_issues = self._check_accuracy(response, ground_truth)
        criterion_scores.append(CriterionScore(
            name="accuracy",
            score=accuracy_score,
            weight=0.30,
            feedback=f"Accuracy check: {len(accuracy_issues)} issues found",
            details={"issues": accuracy_issues}
        ))

        # 3. Relevance - check if security relevance is correctly assessed
        relevance_score = self._check_relevance(response, ground_truth)
        criterion_scores.append(CriterionScore(
            name="relevance",
            score=relevance_score,
            weight=0.20,
            feedback=f"Security relevance assessment score: {relevance_score:.2f}",
        ))

        # 4. No Hallucination
        hallucinations = self.detect_hallucinations(response)
        hallucination_score = 1.0 if not hallucinations else max(0.0, 1.0 - len(hallucinations) * 0.2)
        criterion_scores.append(CriterionScore(
            name="no_hallucination",
            score=hallucination_score,
            weight=0.20,
            feedback=f"Detected {len(hallucinations)} potential hallucinations",
            details={"hallucinations": hallucinations}
        ))

        # Calculate total score
        total_score = sum(cs.weighted_score for cs in criterion_scores)

        # Generate feedback
        feedback = self._generate_feedback(criterion_scores, ground_truth)

        return GradingResult(
            phase_id=PhaseID.OBSERVE,
            criterion_scores=criterion_scores,
            total_score=total_score,
            feedback=feedback,
            hallucinations=hallucinations,
            missing_items=missing if key_obs else [],
        )

    def _check_observations(
        self,
        response: str,
        key_observations: list[str]
    ) -> tuple[list[str], list[str]]:
        """Check which key observations are present in response."""
        found = []
        missing = []
        response_lower = response.lower()

        for obs in key_observations:
            # Extract key terms from the observation
            obs_terms = [t for t in obs.lower().split() if len(t) > 3]

            # Check if enough terms are present
            terms_found = sum(1 for t in obs_terms if t in response_lower)
            if terms_found >= len(obs_terms) * 0.6:  # 60% of terms present
                found.append(obs)
            else:
                missing.append(obs)

        return found, missing

    def _check_accuracy(
        self,
        response: str,
        ground_truth: GroundTruth
    ) -> tuple[float, list[str]]:
        """Check factual accuracy of observations."""
        issues = []

        # Check if vulnerability presence is correctly assessed (if mentioned)
        response_lower = response.lower()

        # Look for incorrect conclusions
        if ground_truth.vulnerability_present:
            if "not vulnerable" in response_lower or "secure" in response_lower:
                if "is not vulnerable" in response_lower or "appears secure" in response_lower:
                    issues.append("Incorrectly concluded code is not vulnerable")
        else:
            if "vulnerable" in response_lower and "not vulnerable" not in response_lower:
                # Check if it's claiming vulnerability (false positive)
                if "is vulnerable" in response_lower or "vulnerability found" in response_lower:
                    issues.append("False positive: claimed vulnerability where none exists")

        # Calculate score based on issues
        score = max(0.0, 1.0 - len(issues) * 0.3)
        return score, issues

    def _check_relevance(self, response: str, ground_truth: GroundTruth) -> float:
        """Check if security relevance is correctly prioritized."""
        # Look for relevance indicators
        high_relevance_terms = ["critical", "high", "important", "security-relevant", "dangerous"]
        medium_relevance_terms = ["moderate", "medium", "notable"]
        low_relevance_terms = ["low", "minor", "informational"]

        response_lower = response.lower()

        # Check if response uses appropriate relevance language
        has_relevance_ranking = any(
            term in response_lower
            for term in high_relevance_terms + medium_relevance_terms + low_relevance_terms
        )

        if has_relevance_ranking:
            # Bonus for proper ranking
            if ground_truth.vulnerability_present:
                # Should have high relevance for vulnerable code
                if any(term in response_lower for term in high_relevance_terms):
                    return 1.0
                elif any(term in response_lower for term in medium_relevance_terms):
                    return 0.7
                else:
                    return 0.4
            else:
                return 0.8  # Any ranking is okay for non-vulnerable

        return 0.6  # Default if no explicit ranking

    def _generate_feedback(
        self,
        scores: list[CriterionScore],
        ground_truth: GroundTruth
    ) -> str:
        """Generate human-readable feedback."""
        feedback_parts = []

        for cs in scores:
            if cs.score < 0.7:
                feedback_parts.append(f"- {cs.name}: needs improvement ({cs.score:.2f})")
            elif cs.score >= 0.9:
                feedback_parts.append(f"- {cs.name}: excellent ({cs.score:.2f})")

        if not feedback_parts:
            return "Good observation phase performance."

        return "Observation Phase Feedback:\n" + "\n".join(feedback_parts)


class HypothesisGrader(PhaseGrader):
    """
    Grades hypothesis formation phase.

    Criteria:
    - Validity: Hypothesis follows logically from observations
    - Testability: Can be verified/falsified
    - Specificity: Precise enough to act on
    - Coverage: Addresses key observations
    - CWE Mapping: Correct vulnerability classification
    """

    def grade(
        self,
        response: str,
        ground_truth: GroundTruth,
        phase: Phase,
    ) -> GradingResult:
        criterion_scores = []
        errors = []

        parsed = self.parse_response(response)

        # 1. Validity - logical soundness
        validity_score, validity_feedback = self._check_validity(response, parsed)
        criterion_scores.append(CriterionScore(
            name="validity",
            score=validity_score,
            weight=0.25,
            feedback=validity_feedback,
        ))

        # 2. Testability
        testability_score, testability_feedback = self._check_testability(response, parsed)
        criterion_scores.append(CriterionScore(
            name="testability",
            score=testability_score,
            weight=0.25,
            feedback=testability_feedback,
        ))

        # 3. Specificity
        specificity_score = self._check_specificity(response, parsed)
        criterion_scores.append(CriterionScore(
            name="specificity",
            score=specificity_score,
            weight=0.20,
            feedback=f"Specificity score: {specificity_score:.2f}",
        ))

        # 4. Coverage
        coverage_score = self._check_coverage(response, ground_truth)
        criterion_scores.append(CriterionScore(
            name="coverage",
            score=coverage_score,
            weight=0.15,
            feedback=f"Coverage of key observations: {coverage_score:.2f}",
        ))

        # 5. CWE Mapping
        cwe_score, cwe_feedback = self._check_cwe_mapping(response, ground_truth)
        if cwe_score < 0.5:
            errors.append(f"Incorrect CWE mapping: {cwe_feedback}")
        criterion_scores.append(CriterionScore(
            name="cwe_mapping",
            score=cwe_score,
            weight=0.15,
            feedback=cwe_feedback,
        ))

        total_score = sum(cs.weighted_score for cs in criterion_scores)
        feedback = self._generate_feedback(criterion_scores, ground_truth)

        return GradingResult(
            phase_id=PhaseID.HYPOTHESIZE,
            criterion_scores=criterion_scores,
            total_score=total_score,
            feedback=feedback,
            errors=errors,
        )

    def _check_validity(self, response: str, parsed: Optional[dict]) -> tuple[float, str]:
        """Check if hypothesis follows logically from observations."""
        # Look for logical structure
        logic_indicators = [
            "because", "therefore", "since", "based on", "given that",
            "this suggests", "indicates", "implies"
        ]

        response_lower = response.lower()
        has_logical_connection = any(ind in response_lower for ind in logic_indicators)

        if has_logical_connection:
            return 0.9, "Hypothesis shows logical connection to observations"

        # Check parsed structure
        if parsed and "hypotheses" in parsed:
            hypotheses = parsed.get("hypotheses", [])
            if hypotheses and all(
                h.get("statement") and h.get("supporting_observations")
                for h in hypotheses if isinstance(h, dict)
            ):
                return 0.85, "Structured hypothesis with supporting observations"

        return 0.6, "Hypothesis could better connect to observations"

    def _check_testability(self, response: str, parsed: Optional[dict]) -> tuple[float, str]:
        """Check if hypothesis can be tested."""
        testability_indicators = [
            "test", "verify", "confirm", "check", "validate",
            "frida", "adb", "burp", "intercept", "payload"
        ]

        response_lower = response.lower()
        has_test_plan = any(ind in response_lower for ind in testability_indicators)

        # Look for specific test steps
        test_step_patterns = [
            r'step \d', r'\d\.\s+', r'first.*then', r'to test.*:'
        ]
        has_steps = any(re.search(p, response_lower) for p in test_step_patterns)

        if has_test_plan and has_steps:
            return 1.0, "Clear, actionable test plan"
        elif has_test_plan:
            return 0.75, "Has test approach but could be more specific"
        else:
            return 0.4, "Missing clear test methodology"

    def _check_specificity(self, response: str, parsed: Optional[dict]) -> float:
        """Check if hypothesis is specific enough to act on."""
        specificity_markers = []

        # Look for specific locations
        if re.search(r'line \d+|at position|in method|in class|in function', response.lower()):
            specificity_markers.append("location")

        # Look for specific mechanisms
        if re.search(r'via|through|by|using', response.lower()):
            specificity_markers.append("mechanism")

        # Look for specific impact
        if re.search(r'allows|enables|leads to|results in|can cause', response.lower()):
            specificity_markers.append("impact")

        # Score based on markers
        if len(specificity_markers) >= 3:
            return 1.0
        elif len(specificity_markers) >= 2:
            return 0.8
        elif len(specificity_markers) >= 1:
            return 0.6
        else:
            return 0.3

    def _check_coverage(self, response: str, ground_truth: GroundTruth) -> float:
        """Check if hypothesis addresses key observations."""
        key_obs = ground_truth.key_observations
        if not key_obs:
            return 0.7  # Default

        response_lower = response.lower()
        covered = 0

        for obs in key_obs:
            # Check if key terms from observation appear in response
            obs_terms = [t for t in obs.lower().split() if len(t) > 3]
            if obs_terms and sum(1 for t in obs_terms if t in response_lower) >= len(obs_terms) * 0.5:
                covered += 1

        return covered / len(key_obs) if key_obs else 0.7

    def _check_cwe_mapping(self, response: str, ground_truth: GroundTruth) -> tuple[float, str]:
        """Check if CWE classification is correct."""
        expected_cwe = ground_truth.cwe_id

        if not expected_cwe:
            return 0.7, "No expected CWE defined"

        # Extract CWE references from response
        cwe_refs = re.findall(r'CWE-(\d+)', response, re.IGNORECASE)

        if not cwe_refs:
            return 0.3, "No CWE classification provided"

        expected_num = re.search(r'\d+', expected_cwe)
        if not expected_num:
            return 0.5, "Could not parse expected CWE"

        expected_num = expected_num.group()

        # Check for exact match
        if expected_num in cwe_refs:
            return 1.0, f"Correct CWE: {expected_cwe}"

        # Check for related CWEs (simplified - would need CWE hierarchy data)
        # Common related CWEs
        cwe_families = {
            "89": ["943", "74"],  # SQL injection family
            "79": ["80", "74"],  # XSS family
            "22": ["23", "73"],  # Path traversal family
            "798": ["259", "321"],  # Hardcoded credentials
            "502": ["913"],  # Deserialization
        }

        related = cwe_families.get(expected_num, [])
        if any(r in cwe_refs for r in related):
            return 0.7, f"Related CWE (expected {expected_cwe})"

        return 0.4, f"Wrong CWE (expected {expected_cwe}, got CWE-{cwe_refs[0]})"

    def _generate_feedback(self, scores: list[CriterionScore], ground_truth: GroundTruth) -> str:
        """Generate feedback for hypothesis phase."""
        weak_areas = [cs for cs in scores if cs.score < 0.7]
        strong_areas = [cs for cs in scores if cs.score >= 0.9]

        feedback = []
        if weak_areas:
            feedback.append("Areas to improve: " + ", ".join(cs.name for cs in weak_areas))
        if strong_areas:
            feedback.append("Strong areas: " + ", ".join(cs.name for cs in strong_areas))

        return "\n".join(feedback) if feedback else "Hypothesis phase completed."


class RootCauseGrader(PhaseGrader):
    """
    Grades root cause analysis phase.

    Criteria:
    - Depth: Goes beyond surface to fundamental cause
    - Accuracy: Correctly identifies the root cause
    - Generalization: Identifies transferable patterns
    - Taxonomy: Correct CWE/OWASP hierarchy
    """

    # Fundamental security principles to look for
    SECURITY_PRINCIPLES = [
        "separation of code and data",
        "least privilege",
        "defense in depth",
        "fail secure",
        "complete mediation",
        "confused deputy",
        "trust boundary",
        "input validation",
        "output encoding",
        "principle of least authority",
    ]

    def grade(
        self,
        response: str,
        ground_truth: GroundTruth,
        phase: Phase,
    ) -> GradingResult:
        criterion_scores = []

        # 1. Depth - goes beyond surface level
        depth_score, depth_feedback = self._check_depth(response, ground_truth)
        criterion_scores.append(CriterionScore(
            name="depth",
            score=depth_score,
            weight=0.30,
            feedback=depth_feedback,
        ))

        # 2. Accuracy - correct root cause
        accuracy_score, accuracy_feedback = self._check_accuracy(response, ground_truth)
        criterion_scores.append(CriterionScore(
            name="accuracy",
            score=accuracy_score,
            weight=0.25,
            feedback=accuracy_feedback,
        ))

        # 3. Generalization - identifies patterns
        gen_score, gen_feedback = self._check_generalization(response)
        criterion_scores.append(CriterionScore(
            name="generalization",
            score=gen_score,
            weight=0.25,
            feedback=gen_feedback,
        ))

        # 4. Taxonomy - correct CWE hierarchy
        taxonomy_score, taxonomy_feedback = self._check_taxonomy(response, ground_truth)
        criterion_scores.append(CriterionScore(
            name="taxonomy",
            score=taxonomy_score,
            weight=0.20,
            feedback=taxonomy_feedback,
        ))

        total_score = sum(cs.weighted_score for cs in criterion_scores)
        feedback = self._generate_feedback(criterion_scores, depth_score, gen_score)

        return GradingResult(
            phase_id=PhaseID.ANALYZE,
            criterion_scores=criterion_scores,
            total_score=total_score,
            feedback=feedback,
        )

    def _check_depth(self, response: str, ground_truth: GroundTruth) -> tuple[float, str]:
        """Check if analysis goes beyond surface level."""
        response_lower = response.lower()

        # Check for fundamental principles
        principles_mentioned = [
            p for p in self.SECURITY_PRINCIPLES
            if p in response_lower
        ]

        # Check for WHY language
        why_indicators = [
            "fundamental", "root cause", "underlying", "principle",
            "because this violates", "the real issue is", "at its core",
            "this happens because", "the fundamental problem"
        ]
        has_why_language = any(ind in response_lower for ind in why_indicators)

        # Check for distinction between surface and root
        has_levels = "surface" in response_lower or "immediate" in response_lower

        # Score calculation
        score = 0.3  # Base score

        if principles_mentioned:
            score += 0.3
        if has_why_language:
            score += 0.2
        if has_levels:
            score += 0.2

        score = min(1.0, score)

        if principles_mentioned:
            feedback = f"Identified principles: {', '.join(principles_mentioned[:3])}"
        elif has_why_language:
            feedback = "Shows reasoning about root cause"
        else:
            feedback = "Analysis is surface-level; dig deeper into WHY"

        return score, feedback

    def _check_accuracy(self, response: str, ground_truth: GroundTruth) -> tuple[float, str]:
        """Check if root cause identification is correct."""
        if not ground_truth.root_cause:
            return 0.7, "No ground truth root cause defined"

        # Extract key concepts from ground truth
        gt_lower = ground_truth.root_cause.lower()
        response_lower = response.lower()

        # Extract important terms from ground truth
        gt_terms = set()
        for term in self.SECURITY_PRINCIPLES:
            if term in gt_lower:
                gt_terms.add(term)

        # Check technical terms
        technical_patterns = [
            r'CWE-\d+',
            r'injection|traversal|overflow|bypass|escalation',
            r'authentication|authorization|validation',
        ]
        for pattern in technical_patterns:
            matches = re.findall(pattern, gt_lower, re.IGNORECASE)
            gt_terms.update(m.lower() for m in matches)

        if not gt_terms:
            # Fallback: word overlap
            gt_words = set(w for w in gt_lower.split() if len(w) > 4)
            response_words = set(w for w in response_lower.split() if len(w) > 4)
            overlap = len(gt_words & response_words) / len(gt_words) if gt_words else 0
            return min(0.8, 0.3 + overlap * 0.5), "Partial alignment with expected analysis"

        # Check how many ground truth terms appear in response
        found_terms = [t for t in gt_terms if t in response_lower]
        score = len(found_terms) / len(gt_terms) if gt_terms else 0.5

        return score, f"Matched {len(found_terms)}/{len(gt_terms)} key concepts"

    def _check_generalization(self, response: str) -> tuple[float, str]:
        """Check if analysis identifies transferable patterns."""
        response_lower = response.lower()

        # Look for pattern identification language
        pattern_indicators = [
            "similar pattern", "same vulnerability", "related to",
            "family of", "class of", "other instances", "also applies to",
            "generalizes to", "pattern family", "this pattern appears in"
        ]

        found_indicators = [ind for ind in pattern_indicators if ind in response_lower]

        # Look for specific pattern names
        pattern_names = [
            "injection", "traversal", "confused deputy", "toctou",
            "race condition", "deserialization", "ssrf", "xss", "csrf"
        ]
        found_patterns = [p for p in pattern_names if p in response_lower]

        if found_indicators and found_patterns:
            return 1.0, f"Excellent generalization: {', '.join(found_patterns[:3])}"
        elif found_patterns:
            return 0.75, f"Identifies patterns: {', '.join(found_patterns[:3])}"
        elif found_indicators:
            return 0.6, "Attempts generalization but could be more specific"
        else:
            return 0.3, "Analysis treats this as isolated case; consider patterns"

    def _check_taxonomy(self, response: str, ground_truth: GroundTruth) -> tuple[float, str]:
        """Check CWE/OWASP taxonomy accuracy."""
        response_lower = response.lower()

        # Extract CWE references
        cwe_refs = re.findall(r'CWE-(\d+)', response, re.IGNORECASE)

        # Check for hierarchy language
        hierarchy_indicators = ["parent", "child", "pillar", "class", "variant", "base"]
        has_hierarchy = any(ind in response_lower for ind in hierarchy_indicators)

        # Check OWASP references
        owasp_refs = re.findall(r'M\d+|A\d+|OWASP', response, re.IGNORECASE)

        # Score calculation
        score = 0.3

        if cwe_refs:
            score += 0.3
            # Check if correct CWE
            if ground_truth.cwe_id:
                expected_num = re.search(r'\d+', ground_truth.cwe_id)
                if expected_num and expected_num.group() in cwe_refs:
                    score += 0.2

        if has_hierarchy:
            score += 0.2

        if owasp_refs:
            score += 0.1

        score = min(1.0, score)

        feedback_parts = []
        if cwe_refs:
            feedback_parts.append(f"CWE: {', '.join(f'CWE-{c}' for c in cwe_refs[:3])}")
        if owasp_refs:
            feedback_parts.append(f"OWASP: {', '.join(owasp_refs[:3])}")
        if has_hierarchy:
            feedback_parts.append("Includes taxonomy hierarchy")

        return score, "; ".join(feedback_parts) if feedback_parts else "Missing taxonomy"

    def _generate_feedback(
        self,
        scores: list[CriterionScore],
        depth_score: float,
        gen_score: float
    ) -> str:
        """Generate comprehensive feedback."""
        feedback = []

        if depth_score < 0.6:
            feedback.append("Go deeper: identify fundamental security principles violated")
        if gen_score < 0.6:
            feedback.append("Consider: where else does this pattern appear?")

        total = sum(cs.weighted_score for cs in scores)
        if total >= 0.8:
            feedback.append("Strong root cause analysis")

        return "\n".join(feedback) if feedback else "Root cause analysis completed"


class NegativeKnowledgeGrader(PhaseGrader):
    """
    Grades negative knowledge phase (identifying SECURE code).

    Criteria:
    - Correct Classification: Identifies as NOT vulnerable
    - Security Property ID: Explains what makes it secure
    - Attack Resistance: Explains why attacks would fail
    - No False Positives: Doesn't claim vulnerabilities that don't exist
    """

    def grade(
        self,
        response: str,
        ground_truth: GroundTruth,
        phase: Phase,
    ) -> GradingResult:
        criterion_scores = []
        errors = []

        # 1. Correct Classification
        classification_score, classification_feedback = self._check_classification(
            response, ground_truth
        )
        if classification_score < 0.5:
            errors.append("Incorrect security classification")
        criterion_scores.append(CriterionScore(
            name="correct_classification",
            score=classification_score,
            weight=0.40,
            feedback=classification_feedback,
        ))

        # 2. Security Property Identification
        property_score, property_feedback = self._check_security_properties(
            response, ground_truth
        )
        criterion_scores.append(CriterionScore(
            name="security_property_id",
            score=property_score,
            weight=0.30,
            feedback=property_feedback,
        ))

        # 3. Attack Resistance
        resistance_score, resistance_feedback = self._check_attack_resistance(response)
        criterion_scores.append(CriterionScore(
            name="attack_resistance",
            score=resistance_score,
            weight=0.20,
            feedback=resistance_feedback,
        ))

        # 4. No False Positives
        fp_score, fp_feedback = self._check_false_positives(response, ground_truth)
        if fp_score < 0.5:
            errors.append("False positive: claimed vulnerability in secure code")
        criterion_scores.append(CriterionScore(
            name="no_false_positives",
            score=fp_score,
            weight=0.10,
            feedback=fp_feedback,
        ))

        total_score = sum(cs.weighted_score for cs in criterion_scores)
        feedback = self._generate_feedback(
            classification_score, property_score, ground_truth
        )

        return GradingResult(
            phase_id=PhaseID.ANALYZE,
            criterion_scores=criterion_scores,
            total_score=total_score,
            feedback=feedback,
            errors=errors,
        )

    def _check_classification(
        self,
        response: str,
        ground_truth: GroundTruth
    ) -> tuple[float, str]:
        """Check if code is correctly classified as secure/vulnerable."""
        response_lower = response.lower()

        # What the code actually is
        is_vulnerable = ground_truth.vulnerability_present

        # What the model thinks
        secure_indicators = [
            "not vulnerable", "secure", "safe", "properly implemented",
            "correctly handles", "no vulnerability", "is_vulnerable.*false"
        ]
        vulnerable_indicators = [
            "is vulnerable", "vulnerability found", "exploitable",
            "can be exploited", "attack vector", "is_vulnerable.*true"
        ]

        claims_secure = any(ind in response_lower for ind in secure_indicators)
        claims_vulnerable = any(ind in response_lower for ind in vulnerable_indicators)

        if is_vulnerable:
            # Code IS vulnerable - model should identify it
            if claims_vulnerable and not claims_secure:
                return 1.0, "Correctly identified vulnerability"
            elif claims_secure:
                return 0.0, "Missed vulnerability (false negative)"
            else:
                return 0.5, "Inconclusive classification"
        else:
            # Code is NOT vulnerable - model should recognize it's secure
            if claims_secure and not claims_vulnerable:
                return 1.0, "Correctly identified as secure"
            elif claims_vulnerable:
                return 0.0, "False positive - claimed vulnerability in secure code"
            else:
                return 0.5, "Inconclusive classification"

    def _check_security_properties(
        self,
        response: str,
        ground_truth: GroundTruth
    ) -> tuple[float, str]:
        """Check if response identifies what makes code secure."""
        if ground_truth.vulnerability_present:
            # If it's vulnerable, security properties check doesn't apply
            return 0.7, "N/A - code is vulnerable"

        secure_properties = ground_truth.secure_properties
        if not secure_properties:
            # Check for general security property language
            general_properties = [
                "parameterized", "sanitized", "validated", "encrypted",
                "authenticated", "authorized", "escapes", "encodes",
                "uses prepared", "constant time", "PBKDF2", "bcrypt"
            ]
            response_lower = response.lower()
            found = [p for p in general_properties if p in response_lower]
            score = min(1.0, 0.3 + len(found) * 0.15)
            return score, f"Identified properties: {', '.join(found[:5])}" if found else "Missing security property analysis"

        # Check against defined secure properties
        response_lower = response.lower()
        found_properties = []
        for prop in secure_properties:
            prop_terms = [t for t in prop.lower().split() if len(t) > 3]
            if prop_terms and sum(1 for t in prop_terms if t in response_lower) >= len(prop_terms) * 0.5:
                found_properties.append(prop)

        score = len(found_properties) / len(secure_properties)
        feedback = f"Identified {len(found_properties)}/{len(secure_properties)} security properties"

        return score, feedback

    def _check_attack_resistance(self, response: str) -> tuple[float, str]:
        """Check if response explains why attacks would fail."""
        response_lower = response.lower()

        resistance_indicators = [
            "attack would fail", "blocks", "prevents", "mitigates",
            "resistant to", "protected against", "cannot be exploited",
            "would be caught", "sanitization prevents", "encoding prevents"
        ]

        found = [ind for ind in resistance_indicators if ind in response_lower]

        # Look for specific attack mentions with resistance
        attack_mentions = re.findall(
            r'(injection|traversal|xss|overflow|bypass).*?(fail|block|prevent|resist)',
            response_lower
        )

        if found and attack_mentions:
            return 1.0, "Excellent attack resistance analysis"
        elif found:
            return 0.75, f"Some resistance analysis: {', '.join(found[:3])}"
        elif attack_mentions:
            return 0.6, "Mentions attacks but could explain resistance better"
        else:
            return 0.3, "Missing attack resistance analysis"

    def _check_false_positives(
        self,
        response: str,
        ground_truth: GroundTruth
    ) -> tuple[float, str]:
        """Check for false positive vulnerability claims."""
        if ground_truth.vulnerability_present:
            # If it's actually vulnerable, can't have false positives
            return 1.0, "N/A - code is actually vulnerable"

        response_lower = response.lower()

        # Strong vulnerability claims in secure code = false positive
        false_positive_indicators = [
            "vulnerability found", "is vulnerable", "can be exploited",
            "allows attacker", "critical vulnerability", "high severity"
        ]

        fp_claims = [ind for ind in false_positive_indicators if ind in response_lower]

        if fp_claims:
            return 0.0, f"False positive claims: {', '.join(fp_claims[:3])}"
        else:
            return 1.0, "No false positive vulnerability claims"

    def _generate_feedback(
        self,
        classification_score: float,
        property_score: float,
        ground_truth: GroundTruth
    ) -> str:
        """Generate feedback for negative knowledge phase."""
        feedback = []

        if classification_score < 0.5:
            if ground_truth.vulnerability_present:
                feedback.append("CRITICAL: Missed actual vulnerability")
            else:
                feedback.append("CRITICAL: False positive - code is actually secure")

        if property_score < 0.6 and not ground_truth.vulnerability_present:
            feedback.append("Explain WHY the code is secure, not just THAT it is")

        if not feedback:
            feedback.append("Good negative knowledge assessment")

        return "\n".join(feedback)


class VerificationGrader(PhaseGrader):
    """
    Grades verification/test phase.

    Criteria:
    - Test Validity: Test would actually work
    - Evidence Quality: Provides clear evidence
    - Conclusion Accuracy: Correct confirmed/refuted decision
    """

    def grade(
        self,
        response: str,
        ground_truth: GroundTruth,
        phase: Phase,
    ) -> GradingResult:
        criterion_scores = []

        # 1. Test Validity
        validity_score, validity_feedback = self._check_test_validity(response)
        criterion_scores.append(CriterionScore(
            name="test_validity",
            score=validity_score,
            weight=0.35,
            feedback=validity_feedback,
        ))

        # 2. Evidence Quality
        evidence_score, evidence_feedback = self._check_evidence(response)
        criterion_scores.append(CriterionScore(
            name="evidence_quality",
            score=evidence_score,
            weight=0.35,
            feedback=evidence_feedback,
        ))

        # 3. Conclusion Accuracy
        conclusion_score, conclusion_feedback = self._check_conclusion(response, ground_truth)
        criterion_scores.append(CriterionScore(
            name="conclusion_accuracy",
            score=conclusion_score,
            weight=0.30,
            feedback=conclusion_feedback,
        ))

        total_score = sum(cs.weighted_score for cs in criterion_scores)

        return GradingResult(
            phase_id=PhaseID.TEST,
            criterion_scores=criterion_scores,
            total_score=total_score,
            feedback=f"Verification phase: {total_score:.2f}",
        )

    def _check_test_validity(self, response: str) -> tuple[float, str]:
        """Check if the test methodology is valid."""
        response_lower = response.lower()

        # Look for concrete test tools/commands
        test_tools = [
            "adb", "frida", "burp", "mitmproxy", "drozer",
            "objection", "jadx", "apktool", "curl", "nc"
        ]
        found_tools = [t for t in test_tools if t in response_lower]

        # Look for specific test steps
        has_steps = bool(re.search(r'step \d|^\d\.|^-\s+', response, re.MULTILINE))

        # Look for expected results
        has_expected = any(
            term in response_lower
            for term in ["expected", "should", "will", "would show", "result"]
        )

        score = 0.3
        if found_tools:
            score += 0.3
        if has_steps:
            score += 0.2
        if has_expected:
            score += 0.2

        score = min(1.0, score)
        feedback = f"Tools: {', '.join(found_tools[:3])}" if found_tools else "Missing concrete test methodology"

        return score, feedback

    def _check_evidence(self, response: str) -> tuple[float, str]:
        """Check quality of evidence provided."""
        response_lower = response.lower()

        # Evidence indicators
        evidence_markers = [
            "output shows", "result:", "response:", "log shows",
            "confirmed", "observed", "screenshot", "proof"
        ]
        found = [m for m in evidence_markers if m in response_lower]

        # Look for actual output samples
        has_output = "```" in response or re.search(r'\n\s{4,}', response)

        score = 0.3
        if found:
            score += 0.3
        if has_output:
            score += 0.4

        score = min(1.0, score)

        return score, f"Evidence markers: {len(found)}, has output: {has_output}"

    def _check_conclusion(
        self,
        response: str,
        ground_truth: GroundTruth
    ) -> tuple[float, str]:
        """Check if conclusion matches ground truth."""
        response_lower = response.lower()

        # What does the response conclude?
        confirmed_indicators = ["confirmed", "verified", "vulnerability exists", "exploitable"]
        refuted_indicators = ["refuted", "not vulnerable", "false positive", "secure"]
        inconclusive_indicators = ["inconclusive", "unclear", "more testing needed"]

        concludes_confirmed = any(ind in response_lower for ind in confirmed_indicators)
        concludes_refuted = any(ind in response_lower for ind in refuted_indicators)
        concludes_inconclusive = any(ind in response_lower for ind in inconclusive_indicators)

        is_vulnerable = ground_truth.vulnerability_present

        if is_vulnerable:
            if concludes_confirmed:
                return 1.0, "Correct: vulnerability confirmed"
            elif concludes_refuted:
                return 0.0, "Incorrect: missed actual vulnerability"
            else:
                return 0.5, "Inconclusive on actual vulnerability"
        else:
            if concludes_refuted:
                return 1.0, "Correct: confirmed code is secure"
            elif concludes_confirmed:
                return 0.0, "Incorrect: false positive"
            else:
                return 0.5, "Inconclusive on secure code"


class ReasoningGrader:
    """
    Main grader class that orchestrates phase-specific graders.
    """

    def __init__(self, challenge: ChallengeV2):
        """
        Initialize grader for a specific challenge.

        Args:
            challenge: The V2 challenge to grade responses for
        """
        self.challenge = challenge

        # Combine all artifact content for hallucination detection
        artifact_content = "\n".join(a.content for a in challenge.artifacts)

        # Initialize phase-specific graders
        self.phase_graders: dict[PhaseID, PhaseGrader] = {
            PhaseID.OBSERVE: ObservationGrader(artifact_content),
            PhaseID.HYPOTHESIZE: HypothesisGrader(artifact_content),
            PhaseID.ANALYZE: RootCauseGrader(artifact_content),
            PhaseID.TEST: VerificationGrader(artifact_content),
        }

        # Special case: negative knowledge challenges use different grader
        if not challenge.ground_truth.vulnerability_present:
            self.phase_graders[PhaseID.ANALYZE] = NegativeKnowledgeGrader(artifact_content)

    def grade_phase(
        self,
        phase_id: PhaseID,
        response: str,
    ) -> GradingResult:
        """
        Grade a response for a specific phase.

        Args:
            phase_id: Which phase to grade
            response: The model's response text

        Returns:
            GradingResult with scores and feedback
        """
        # Find the phase definition
        phase = next(
            (p for p in self.challenge.phases if p.phase_id == phase_id),
            None
        )

        if not phase:
            raise ValueError(f"Phase {phase_id} not found in challenge")

        # Get appropriate grader
        grader = self.phase_graders.get(phase_id)

        if not grader:
            raise ValueError(f"No grader available for phase {phase_id}")

        return grader.grade(
            response=response,
            ground_truth=self.challenge.ground_truth,
            phase=phase,
        )

    def grade_full_chain(
        self,
        phase_responses: dict[PhaseID, str]
    ) -> tuple[list[GradingResult], ReasoningQuality]:
        """
        Grade a complete reasoning chain.

        Args:
            phase_responses: Dict mapping phase IDs to response text

        Returns:
            Tuple of (list of GradingResults, overall ReasoningQuality)
        """
        results = []

        for phase in self.challenge.phases:
            if phase.phase_id in phase_responses:
                result = self.grade_phase(
                    phase.phase_id,
                    phase_responses[phase.phase_id]
                )
                results.append(result)

        # Calculate overall reasoning quality
        quality = self._calculate_reasoning_quality(results, phase_responses)

        return results, quality

    def _calculate_reasoning_quality(
        self,
        results: list[GradingResult],
        phase_responses: dict[PhaseID, str]
    ) -> ReasoningQuality:
        """Calculate overall reasoning quality metrics."""
        if not results:
            return ReasoningQuality(
                completeness=0.0,
                accuracy=0.0,
                depth=0.0,
                transferability=0.0,
                coherence=0.0,
            )

        # Completeness: how many phases were completed well
        completeness = sum(1 for r in results if r.total_score >= 0.6) / len(self.challenge.phases)

        # Accuracy: average of accuracy-related scores
        accuracy_scores = []
        for r in results:
            for cs in r.criterion_scores:
                if "accuracy" in cs.name or "correct" in cs.name:
                    accuracy_scores.append(cs.score)
        accuracy = sum(accuracy_scores) / len(accuracy_scores) if accuracy_scores else 0.5

        # Depth: average of depth-related scores
        depth_scores = []
        for r in results:
            for cs in r.criterion_scores:
                if "depth" in cs.name or "generalization" in cs.name:
                    depth_scores.append(cs.score)
        depth = sum(depth_scores) / len(depth_scores) if depth_scores else 0.5

        # Transferability: check for pattern recognition
        transferability = 0.5
        all_responses = " ".join(phase_responses.values())
        if "pattern" in all_responses.lower() or "similar" in all_responses.lower():
            transferability = 0.7
        if "applies to" in all_responses.lower() or "generalizes" in all_responses.lower():
            transferability = 0.9

        # Coherence: check if conclusions follow from observations
        coherence = self._check_chain_coherence(phase_responses)

        return ReasoningQuality(
            completeness=completeness,
            accuracy=accuracy,
            depth=depth,
            transferability=transferability,
            coherence=coherence,
        )

    def _check_chain_coherence(self, phase_responses: dict[PhaseID, str]) -> float:
        """Check if reasoning chain is internally consistent."""
        if len(phase_responses) < 2:
            return 0.7  # Default for single phase

        # Simple coherence check: do later phases reference earlier ones?
        response_list = list(phase_responses.values())

        # Extract key terms from first response
        first_terms = set(
            w.lower() for w in response_list[0].split()
            if len(w) > 4 and w.isalpha()
        )

        # Check if later responses reference these terms
        reference_count = 0
        for response in response_list[1:]:
            response_lower = response.lower()
            refs = sum(1 for t in first_terms if t in response_lower)
            if refs > len(first_terms) * 0.2:
                reference_count += 1

        coherence = 0.5 + (reference_count / (len(response_list) - 1)) * 0.5

        return min(1.0, coherence)
