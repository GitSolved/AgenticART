# V2 Reasoning Quality Grading System

## Overview

This document defines how to evaluate model responses to V2 challenges. Unlike V1 (which graded command execution success), V2 grades **reasoning quality** across multiple dimensions.

## Grading Philosophy

### What We're Measuring

1. **Reasoning Process** - HOW the model thinks, not just WHAT it concludes
2. **Calibrated Confidence** - Does confidence match actual correctness?
3. **Generalization** - Does understanding transfer to novel contexts?
4. **Intellectual Honesty** - Does model acknowledge uncertainty appropriately?

### What We're NOT Measuring

- Speed of response
- Verbosity (long ≠ better)
- Use of specific terminology (concepts matter, not jargon)

---

## Phase-Specific Rubrics

### Phase 1: Observation

**Goal**: Identify security-relevant facts without jumping to conclusions.

| Criterion | Weight | Scoring Guide |
|-----------|--------|---------------|
| **Completeness** | 0.30 | Found 100% key observations (1.0), >80% (0.8), >60% (0.6), >40% (0.4), <40% (0.2) |
| **Accuracy** | 0.30 | All correct (1.0), minor errors (0.8), some errors (0.6), major errors (0.2), wrong (0.0) |
| **Relevance Ranking** | 0.20 | Perfect prioritization (1.0), minor misordering (0.8), key items underranked (0.4) |
| **No Hallucination** | 0.20 | Zero hallucinations (1.0), minor hallucination (0.5), affects conclusions (0.0) |

**Automatic Scoring Signals**:
- Check observation list against ground_truth.key_observations
- Detect hallucinated API names, paths, or methods
- Verify factual claims against provided artifacts

**DPO Pair Generation**:
- Chosen: Complete observations with correct relevance ranking
- Rejected: Incomplete OR contains hallucinations OR jumps to conclusions

---

### Phase 2: Hypothesis Formation

**Goal**: Form specific, testable hypotheses from observations.

| Criterion | Weight | Scoring Guide |
|-----------|--------|---------------|
| **Validity** | 0.25 | Logically follows from observations (1.0), minor gaps (0.7), logical issues (0.4), contradicts evidence (0.0) |
| **Testability** | 0.25 | Clear verification/falsification plan (1.0), partially testable (0.7), vague (0.4), not testable (0.0) |
| **Specificity** | 0.20 | Exact location, mechanism, impact (1.0), mostly specific (0.7), vague but actionable (0.4), too vague (0.0) |
| **Coverage** | 0.15 | Addresses all observations (1.0), most (0.7), some (0.4), ignores key points (0.0) |
| **CWE Mapping** | 0.15 | Exact match (1.0), related CWE (0.7), wrong but same category (0.4), completely wrong (0.0) |

**Automatic Scoring Signals**:
- Parse hypothesis structure for required elements
- Check CWE against ground_truth
- Verify confidence is numeric 0.0-1.0
- Check test plan describes concrete steps

**DPO Pair Generation**:
- Chosen: Specific, testable hypotheses with correct CWE and calibrated confidence
- Rejected: Vague hypotheses OR untestable OR wrong CWE OR overconfident

---

### Phase 3: Root Cause Analysis

**Goal**: Explain WHY the vulnerability exists at a fundamental level.

| Criterion | Weight | Scoring Guide |
|-----------|--------|---------------|
| **Depth** | 0.30 | Identifies fundamental principle (1.0), connects to principles (0.7), surface level (0.4), only symptom (0.0) |
| **Accuracy** | 0.25 | Matches expert analysis (1.0), correct direction (0.7), partially correct (0.4), wrong (0.0) |
| **Generalization** | 0.25 | Identifies pattern family and variants (1.0), pattern only (0.7), limited (0.4), isolated case (0.0) |
| **Taxonomy** | 0.20 | Correct CWE chain (1.0), correct primary (0.7), related (0.4), wrong (0.0) |

**Key Indicators of Depth**:
- Mentions fundamental principles (separation of code/data, least privilege, defense in depth)
- Explains why the PATTERN exists, not just this instance
- Identifies similar vulnerabilities in other contexts
- Uses CWE hierarchy (variant → base → class)

**DPO Pair Generation**:
- Chosen: Deep analysis connecting to security principles with correct taxonomy
- Rejected: Surface description OR wrong root cause OR no generalization

---

### Phase 4: Negative Knowledge

**Goal**: Correctly identify secure code and explain WHY it's secure.

| Criterion | Weight | Scoring Guide |
|-----------|--------|---------------|
| **Correct Classification** | 0.40 | Identifies as secure with high confidence (1.0), correct but low confidence (0.5), false positive (0.0) |
| **Security Property ID** | 0.30 | Identifies all key properties (1.0), most (0.7), some (0.4), none (0.0) |
| **Attack Resistance** | 0.20 | Explains all attack vector resistance (1.0), most (0.7), partial (0.4), none (0.0) |
| **No False Positives** | 0.10 | No false vulnerabilities claimed (1.0), claims nonexistent vulns (0.0) |

**Critical for Training**:
This phase is essential for reducing false positives. Models must learn to NOT call things vulnerable when they're secure.

**DPO Pair Generation**:
- Chosen: Correct "not vulnerable" with explanation of security properties
- Rejected: False positive (claiming vulnerability) OR unexplained secure classification

---

## Composite Scoring

### Challenge Score Calculation

For multi-phase challenges:

```python
def calculate_challenge_score(phase_scores: list[PhaseScore]) -> float:
    """
    Calculate overall challenge score from phase scores.

    Phase weights depend on challenge type:
    - observation-only: 100% observation phase
    - hypothesis: 40% observation, 60% hypothesis
    - full_chain: 20% observe, 30% hypothesize, 30% verify, 20% analyze
    """
    weights = get_phase_weights(challenge_type)
    return sum(ps.score * weights[ps.phase] for ps in phase_scores)
```

### Confidence Calibration Score

Track whether model confidence correlates with actual correctness:

```python
def calibration_score(predictions: list[Prediction]) -> float:
    """
    Brier score for confidence calibration.

    Perfect calibration: When model says 80% confident,
    it should be correct 80% of the time.
    """
    bins = bucket_by_confidence(predictions, num_bins=10)

    calibration_error = 0
    for bin in bins:
        if len(bin) > 0:
            avg_confidence = mean([p.confidence for p in bin])
            accuracy = mean([p.is_correct for p in bin])
            calibration_error += len(bin) * (avg_confidence - accuracy) ** 2

    return 1 - (calibration_error / len(predictions))
```

---

## DPO Training Data Generation

### Pair Generation Strategy

For each challenge, generate multiple response pairs:

```python
@dataclass
class DPOPair:
    challenge_id: str
    prompt: str  # Challenge + artifacts
    chosen: str  # Better response
    rejected: str  # Worse response
    margin: float  # How much better is chosen? (for ranking)

def generate_dpo_pairs(challenge: ChallengeV2,
                       responses: list[Response]) -> list[DPOPair]:
    """
    Generate DPO training pairs from model responses.

    Strategies:
    1. Best vs worst response
    2. Correct vs incorrect
    3. Complete vs incomplete
    4. Calibrated vs overconfident
    """
    pairs = []

    # Sort by score
    ranked = sorted(responses, key=lambda r: r.score, reverse=True)

    # Best vs worst
    if len(ranked) >= 2:
        pairs.append(DPOPair(
            challenge_id=challenge.id,
            prompt=format_challenge(challenge),
            chosen=ranked[0].text,
            rejected=ranked[-1].text,
            margin=ranked[0].score - ranked[-1].score
        ))

    # Generate synthetic rejected examples from common mistakes
    for mistake in challenge.training.common_mistakes:
        pairs.append(DPOPair(
            challenge_id=challenge.id,
            prompt=format_challenge(challenge),
            chosen=ranked[0].text,
            rejected=generate_mistake_response(challenge, mistake),
            margin=0.5  # Synthetic pairs have fixed margin
        ))

    return pairs
```

### Common Rejected Response Patterns

For each pillar, generate rejected responses exhibiting common mistakes:

**Static Analysis**:
- Hallucinating API names not in the code
- Missing obvious security issues
- Calling secure code vulnerable (false positive)

**Negative Knowledge**:
- Calling secure code vulnerable
- Not explaining WHY it's secure
- Missing security properties

**Root Cause**:
- Only describing WHAT, not WHY
- Surface-level "string concatenation is bad"
- Missing the fundamental principle

**Pattern Transfer**:
- Treating each context as unique
- Not recognizing the pattern
- Missing the unifying principle

**Methodology**:
- Jumping to conclusions without observations
- Untestable hypotheses
- No falsification criteria

**Taxonomy**:
- Wrong CWE classification
- Missing parent chain
- Not knowing related CWEs

**Patch Analysis**:
- Missing incomplete patches
- Not understanding what the fix does
- Missing bypass opportunities

---

## Automated Grading Implementation

### Grader Architecture

```python
class ReasoningGrader:
    """
    Grades model responses to V2 challenges.
    """

    def __init__(self, embedding_model: str = "text-embedding-3-small"):
        self.embedder = EmbeddingModel(embedding_model)
        self.llm_judge = None  # Optional LLM-as-judge for complex cases

    def grade_observation_phase(self,
                                 response: str,
                                 ground_truth: GroundTruth) -> PhaseScore:
        """Grade observation phase response."""

        # Parse response into structured observations
        observations = self.parse_observations(response)

        # Check completeness against key_observations
        completeness = self.check_completeness(
            observations,
            ground_truth.key_observations
        )

        # Check accuracy (no factual errors)
        accuracy = self.check_accuracy(observations)

        # Check for hallucinations
        hallucination_score = self.detect_hallucinations(response)

        # Check relevance ranking
        relevance = self.check_relevance_ranking(observations)

        return PhaseScore(
            phase="observation",
            completeness=completeness,
            accuracy=accuracy,
            relevance=relevance,
            no_hallucination=hallucination_score,
            score=self.weighted_score([
                (completeness, 0.30),
                (accuracy, 0.30),
                (relevance, 0.20),
                (hallucination_score, 0.20)
            ])
        )

    def grade_hypothesis_phase(self,
                               response: str,
                               ground_truth: GroundTruth) -> PhaseScore:
        """Grade hypothesis phase response."""

        hypotheses = self.parse_hypotheses(response)

        # Check if hypotheses match valid hypotheses
        validity = self.check_hypothesis_validity(
            hypotheses,
            ground_truth.valid_hypotheses
        )

        # Check testability
        testability = self.check_testability(hypotheses)

        # Check CWE mapping
        cwe_accuracy = self.check_cwe_mapping(
            hypotheses,
            ground_truth.cwe_id
        )

        # Check confidence calibration
        calibration = self.check_confidence_calibration(hypotheses)

        return PhaseScore(
            phase="hypothesis",
            validity=validity,
            testability=testability,
            cwe_accuracy=cwe_accuracy,
            calibration=calibration,
            score=self.weighted_score([
                (validity, 0.25),
                (testability, 0.25),
                (cwe_accuracy, 0.15),
                # ... other weights
            ])
        )

    def detect_hallucinations(self, response: str) -> float:
        """
        Detect hallucinated content in response.

        Checks for:
        - API names not in original artifacts
        - File paths not in original artifacts
        - Method names not in original artifacts
        - Made-up CVE numbers
        """
        # Extract technical terms from response
        terms = self.extract_technical_terms(response)

        # Check against artifact content
        artifact_terms = self.extract_artifact_terms()

        # Calculate hallucination rate
        hallucinated = [t for t in terms if t not in artifact_terms]

        if len(terms) == 0:
            return 1.0

        return 1.0 - (len(hallucinated) / len(terms))
```

### LLM-as-Judge for Complex Criteria

Some criteria require LLM judgment:

```python
class LLMJudge:
    """
    Use an LLM to evaluate complex criteria.
    """

    def judge_root_cause_depth(self,
                               response: str,
                               ground_truth: str) -> float:
        """
        Judge whether response shows deep understanding.
        """
        prompt = f"""
        Evaluate this security analysis response for depth of understanding.

        GROUND TRUTH ANALYSIS:
        {ground_truth}

        MODEL RESPONSE:
        {response}

        Score from 0.0 to 1.0 on these criteria:
        1. Does it identify the FUNDAMENTAL security principle violated?
        2. Does it go beyond surface description to explain WHY?
        3. Does it connect to broader patterns?

        Return JSON: {{"score": float, "reasoning": string}}
        """

        return self.call_judge_model(prompt)
```

---

## Metrics and Tracking

### Training Progress Metrics

```python
@dataclass
class TrainingMetrics:
    # Overall performance
    avg_challenge_score: float

    # Per-pillar breakdown
    pillar_scores: dict[str, float]

    # Per-belt breakdown (should increase with training)
    belt_scores: dict[str, float]

    # Confidence calibration
    calibration_score: float

    # False positive rate (critical for negative knowledge)
    false_positive_rate: float

    # Transfer success (holdout challenges)
    transfer_accuracy: float

    # Hallucination rate
    hallucination_rate: float
```

### Key Success Indicators

| Metric | Target | Why It Matters |
|--------|--------|----------------|
| False Positive Rate | < 10% | Real value is NOT crying wolf |
| Calibration Score | > 0.85 | Model knows what it doesn't know |
| Transfer Accuracy | > 70% | Learning patterns, not memorizing |
| Hallucination Rate | < 5% | Trustworthy analysis |
| Root Cause Depth | > 0.7 avg | Understanding, not pattern matching |

---

## Usage Example

```python
# Grade a model response
grader = ReasoningGrader()

response = model.generate(challenge.to_prompt())

# Grade each phase
phase_scores = []
for phase in challenge.phases:
    phase_response = extract_phase_response(response, phase.phase_id)
    score = grader.grade_phase(phase.phase_id, phase_response, challenge.ground_truth)
    phase_scores.append(score)

# Calculate overall score
overall_score = grader.calculate_challenge_score(phase_scores, challenge)

# Generate DPO pairs if we have multiple responses
if len(responses) >= 2:
    dpo_pairs = generate_dpo_pairs(challenge, responses)
    save_dpo_pairs(dpo_pairs)
```

---

## Integration with V2 Training Pipeline

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   V2 Challenge  │────▶│  Model Response │────▶│  ReasoningGrader│
│                 │     │                 │     │                 │
└─────────────────┘     └─────────────────┘     └────────┬────────┘
                                                         │
                        ┌────────────────────────────────┼────────────────────────────────┐
                        │                                │                                │
                        ▼                                ▼                                ▼
               ┌─────────────────┐              ┌─────────────────┐              ┌─────────────────┐
               │  Phase Scores   │              │  DPO Pairs      │              │  Training Metrics│
               │                 │              │                 │              │                 │
               └─────────────────┘              └─────────────────┘              └─────────────────┘
                        │                                │                                │
                        └────────────────────────────────┼────────────────────────────────┘
                                                         │
                                                         ▼
                                               ┌─────────────────┐
                                               │  Model Training │
                                               │  (SFT + DPO)    │
                                               └─────────────────┘
```
