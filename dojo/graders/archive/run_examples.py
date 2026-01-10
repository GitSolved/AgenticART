#!/usr/bin/env python3
"""
Run the reasoning grader on example challenges.

This script:
1. Loads V2 challenges from YAML
2. Generates sample model responses (simulating good and poor responses)
3. Runs the grader and displays results
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from dojo.graders.metrics import GradingMetrics
from dojo.graders.reasoning_grader import GradingResult, ReasoningGrader
from dojo.models import Belt
from dojo.models_v2 import (
    Artifact,
    ArtifactType,
    ChallengeType,
    ChallengeV2,
    EvaluationCriteria,
    GroundTruth,
    Phase,
    PhaseID,
    Pillar,
    TrainingMetadata,
    VerificationTask,
)

# ─────────────────────────────────────────────────────────────────────────────
# Challenge Loader
# ─────────────────────────────────────────────────────────────────────────────


def load_challenge_from_yaml(yaml_data: dict) -> ChallengeV2:
    """Convert YAML challenge data to ChallengeV2 object."""

    # Parse artifacts
    artifacts = []
    for art_data in yaml_data.get("artifacts", []):
        artifact_type = ArtifactType(art_data.get("type", "decompiled_code"))
        artifacts.append(Artifact(
            artifact_type=artifact_type,
            content=art_data.get("content", ""),
            context=art_data.get("context", ""),
        ))

    # Parse phases
    phases = []
    for phase_data in yaml_data.get("phases", []):
        phase_id_str = phase_data.get("phase_id", "observe")
        phase_id = PhaseID(phase_id_str)

        criteria = []
        for crit in phase_data.get("evaluation_criteria", []):
            criteria.append(EvaluationCriteria(
                name=crit.get("name", ""),
                weight=crit.get("weight", 0.25),
                description=crit.get("description", ""),
            ))

        phases.append(Phase(
            phase_id=phase_id,
            instruction=phase_data.get("instruction", ""),
            expected_output_schema=phase_data.get("expected_output_schema", {}),
            evaluation_criteria=criteria,
            max_tokens=phase_data.get("max_tokens", 1500),
        ))

    # Parse ground truth
    gt_data = yaml_data.get("ground_truth", {})
    ground_truth = GroundTruth(
        vulnerability_present=gt_data.get("vulnerability_present", True),
        vulnerability_type=gt_data.get("vulnerability_type"),
        cwe_id=gt_data.get("cwe_id"),
        root_cause=gt_data.get("root_cause", ""),
        key_observations=gt_data.get("key_observations", []),
        secure_properties=gt_data.get("secure_properties", []),
    )

    # Map belt string to enum
    belt_map = {
        "white": Belt.WHITE,
        "yellow": Belt.YELLOW,
        "orange": Belt.ORANGE,
        "green": Belt.GREEN,
        "blue": Belt.BLUE,
        "purple": Belt.PURPLE,
        "brown": Belt.BROWN,
        "black": Belt.BLACK,
    }
    belt = belt_map.get(yaml_data.get("belt", "white"), Belt.WHITE)

    # Map pillar string
    pillar_map = {
        "static_analysis": Pillar.STATIC_ANALYSIS,
        "negative_knowledge": Pillar.NEGATIVE_KNOWLEDGE,
        "root_cause": Pillar.ROOT_CAUSE,
        "pattern_transfer": Pillar.PATTERN_TRANSFER,
        "patch_analysis": Pillar.PATCH_ANALYSIS,
        "methodology": Pillar.METHODOLOGY,
        "taxonomy": Pillar.TAXONOMY,
    }
    pillar = pillar_map.get(yaml_data.get("pillar", "static_analysis"), Pillar.STATIC_ANALYSIS)

    # Map challenge type
    type_map = {
        "observation": ChallengeType.OBSERVATION,
        "hypothesis": ChallengeType.HYPOTHESIS,
        "synthesis": ChallengeType.SYNTHESIS,
        "negative": ChallengeType.NEGATIVE,
        "transfer": ChallengeType.TRANSFER,
    }
    challenge_type = type_map.get(yaml_data.get("type", "observation"), ChallengeType.OBSERVATION)

    # Parse verification_tasks from embedded YAML (Step 1 consolidation)
    verification_tasks = []
    for vt_data in yaml_data.get("verification_tasks", []):
        verification_tasks.append(VerificationTask(
            instruction=vt_data.get("instruction", ""),
            mcp_tool_call=vt_data.get("mcp_tool_call", {}),
            validation_rule=vt_data.get("validation_rule", {}),
        ))

    return ChallengeV2(
        id=yaml_data.get("id", "unknown"),
        name=yaml_data.get("name", "Unknown Challenge"),
        challenge_type=challenge_type,
        pillar=pillar,
        belt=belt,
        difficulty=yaml_data.get("difficulty", 5),
        description=yaml_data.get("description", ""),
        artifacts=artifacts,
        phases=phases,
        ground_truth=ground_truth,
        training_metadata=TrainingMetadata(),
        verification_tasks=verification_tasks,  # Now parsed from YAML
        cwe_tags=yaml_data.get("cwe_tags", []),
        tags=yaml_data.get("tags", []),
    )


def load_challenges_from_file(filepath: Path) -> list[ChallengeV2]:
    """Load all challenges from a YAML file."""
    with open(filepath) as f:
        data = yaml.safe_load(f)

    challenges = []
    for challenge_data in data.get("challenges", []):
        try:
            challenge = load_challenge_from_yaml(challenge_data)
            challenges.append(challenge)
        except Exception as e:
            print(f"Warning: Failed to load challenge {challenge_data.get('id', 'unknown')}: {e}")

    return challenges


# ─────────────────────────────────────────────────────────────────────────────
# Sample Responses
# ─────────────────────────────────────────────────────────────────────────────


SAMPLE_RESPONSES = {
    # Good response for static analysis observation
    "static_basic_white_001": {
        PhaseID.OBSERVE: """
## Section Analysis

### Section A: SharedPreferences Access
- **Is relevant**: Yes
- **Why**: Stores user data in SharedPreferences with MODE_PRIVATE. Security-relevant because this is where sensitive user identifiers are stored.
- **Category**: Data Storage

### Section B: WebView Configuration
- **Is relevant**: Yes
- **Why**: WebView with JavaScript enabled creates potential attack surface for XSS or JavaScript injection attacks.
- **Category**: UI/Attack Surface

### Section C: Intent Data Extraction
- **Is relevant**: Yes
- **Why**: Data from Intent extras (`amount`, `recipient`) comes from external sources. This is untrusted input that could be manipulated by other apps.
- **Category**: Input Handling

### Section D: Logging
- **Is relevant**: Yes
- **Why**: Logging user ID and transfer amount could expose sensitive financial information in logcat, accessible to other apps on rooted devices.
- **Category**: Information Disclosure

### Section E: Business Logic
- **Is relevant**: Yes
- **Why**: This is the core transfer initiation logic using external inputs. Any vulnerability in input handling flows directly into this business operation.
- **Category**: Business Logic / Input Validation

```json
{
    "section_analysis": [
        {"section": "A", "is_relevant": true, "why": "Sensitive data storage", "category": "data_storage"},
        {"section": "B", "is_relevant": true, "why": "WebView attack surface", "category": "ui_security"},
        {"section": "C", "is_relevant": true, "why": "External untrusted input", "category": "input_handling"},
        {"section": "D", "is_relevant": true, "why": "Sensitive data in logs", "category": "logging"},
        {"section": "E", "is_relevant": true, "why": "Business logic with external inputs", "category": "business_logic"}
    ]
}
```

**Key Insight**: ALL sections in this code are security-relevant. This is typical of financial applications where every component handles sensitive data or operations.
"""
    },

    # Good response for data flow analysis
    "static_dataflow_yellow_001": {
        PhaseID.OBSERVE: """
## Data Flow Analysis

### SOURCE Identification
- **Location**: `intent.getStringExtra("query")` at line 6
- **Data Type**: String from external Intent
- **Trust Level**: UNTRUSTED - Any app can send an Intent with arbitrary query content

### TRANSFORMATIONS Tracked

1. **Transformation 1: trim()**
   - Location: Line 9
   - Operation: Removes leading/trailing whitespace
   - Security Effect: NONE - does not sanitize SQL special characters

2. **Transformation 2: toLowerCase()**
   - Location: Line 12
   - Operation: Converts to lowercase
   - Security Effect: NONE - does not prevent injection

3. **Transformation 3: substring(0, 100)**
   - Location: Lines 15-17
   - Operation: Limits string length to 100 chars
   - Security Effect: PARTIAL - prevents DoS via extremely long input, but 100 chars is plenty for SQL injection

4. **Assignment: lastQuery field**
   - Location: Line 20
   - Operation: Stores for later use
   - Security Effect: NONE - just storage

### SINKS Identified

**SINK 1: UI Display**
- Location: Line 23 - `searchView.setText(normalized)`
- Sink Type: UI/TextView
- Data State: TAINTED (but safe for display)
- Risk Assessment: LOW - Android TextView handles text safely, no XSS in native views

**SINK 2: Database Query**
- Location: Lines 26-28 - `database.rawQuery(query, null)`
- Sink Type: SQL Execution
- Data State: TAINTED - reaches SQL concatenation unchanged
- Risk Assessment: **CRITICAL** - SQL injection vulnerability

### Key Finding
The data flows from untrusted Intent source directly to SQL rawQuery sink WITHOUT proper sanitization. The transformations (trim, toLowerCase, substring) provide NO SQL injection protection.

```json
{
    "source": {
        "location": "intent.getStringExtra(\"query\")",
        "data_type": "String",
        "trust_level": "untrusted"
    },
    "transformations": [
        {"location": "line 9", "operation": "trim()", "security_effect": "none"},
        {"location": "line 12", "operation": "toLowerCase()", "security_effect": "none"},
        {"location": "lines 15-17", "operation": "substring(0,100)", "security_effect": "partial_dos_only"}
    ],
    "sinks": [
        {"location": "line 23", "sink_type": "UI_display", "data_state": "tainted_safe", "risk_assessment": "low"},
        {"location": "lines 26-28", "sink_type": "SQL_execution", "data_state": "tainted", "risk_assessment": "critical"}
    ]
}
```
"""
    },

    # Good response for negative knowledge (secure code)
    "neg_secure_white_001": {
        PhaseID.OBSERVE: """
## Security Analysis

### Classification
**is_vulnerable**: false
**confidence**: 0.95

This code implements **secure password storage** following current best practices.

### Security Properties Identified

1. **PBKDF2 with HMAC-SHA256**
   - Status: SECURE
   - Reasoning: PBKDF2 is a NIST-approved key derivation function designed specifically for password hashing. SHA256 variant is modern and secure.

2. **100,000 Iterations**
   - Status: SECURE
   - Reasoning: High iteration count makes brute-force attacks computationally expensive. 100k meets OWASP 2023 recommendations.

3. **16-byte Random Salt**
   - Status: SECURE
   - Reasoning: Salt prevents rainbow table attacks. Generated with SecureRandom (CSPRNG), unique per password.

4. **256-bit Key Length**
   - Status: SECURE
   - Reasoning: Provides strong security margin, computationally infeasible to crack.

5. **Constant-Time Comparison**
   - Status: SECURE
   - Reasoning: `MessageDigest.isEqual()` prevents timing attacks that could leak hash information byte-by-byte.

### Attack Resistance Analysis

| Attack | Result | Why |
|--------|--------|-----|
| Rainbow Tables | BLOCKED | Unique random salt per password |
| Brute Force | IMPRACTICAL | 100k iterations = slow |
| Timing Attack | BLOCKED | Constant-time comparison |
| Dictionary Attack | IMPRACTICAL | PBKDF2 cost factor |

### What This Code Does NOT Have (And That's OK)
- Base64 is used for encoding the stored value, NOT for encryption - this is correct usage
- No plaintext password storage - passwords are properly hashed

```json
{
    "is_vulnerable": false,
    "confidence": 0.95,
    "security_properties": [
        {"property": "PBKDF2-HMAC-SHA256", "status": "secure", "reasoning": "NIST-approved KDF"},
        {"property": "100000 iterations", "status": "secure", "reasoning": "Meets OWASP recommendations"},
        {"property": "Random 16-byte salt", "status": "secure", "reasoning": "Prevents rainbow tables"},
        {"property": "Constant-time comparison", "status": "secure", "reasoning": "Prevents timing attacks"}
    ],
    "attempted_attacks": [
        {"attack": "Rainbow table", "result": "blocked", "why": "Unique salt per password"},
        {"attack": "Brute force", "result": "impractical", "why": "High iteration count"},
        {"attack": "Timing attack", "result": "blocked", "why": "MessageDigest.isEqual"}
    ]
}
```
"""
    },

    # Poor response for comparison
    "poor_static_basic_white_001": {
        PhaseID.OBSERVE: """
The code looks fine to me. I don't see any obvious vulnerabilities.

Section A just stores user preferences.
Section B has a WebView.
Section C gets some data.
Section D logs something.
Section E does the transfer.

I think this code is secure because it uses standard Android APIs.
"""
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# Main Runner
# ─────────────────────────────────────────────────────────────────────────────


def print_grading_result(result: GradingResult, challenge_name: str) -> None:
    """Pretty print a grading result."""
    print(f"\n{'═' * 70}")
    print(f"Challenge: {challenge_name}")
    print(f"Phase: {result.phase_id.value}")
    print(f"{'═' * 70}")

    print(f"\n📊 Total Score: {result.total_score:.1%}")

    print("\n📋 Criterion Scores:")
    for cs in result.criterion_scores:
        emoji = "✅" if cs.score >= 0.7 else "⚠️" if cs.score >= 0.5 else "❌"
        print(f"  {emoji} {cs.name}: {cs.score:.1%} (weight: {cs.weight})")
        if cs.feedback:
            print(f"      └─ {cs.feedback}")

    if result.hallucinations:
        print(f"\n⚠️  Hallucinations Detected: {len(result.hallucinations)}")
        for h in result.hallucinations[:5]:
            print(f"    - {h}")
        if len(result.hallucinations) > 5:
            print(f"    ... and {len(result.hallucinations) - 5} more")

    if result.missing_items:
        print(f"\n📝 Missing Items: {len(result.missing_items)}")
        for m in result.missing_items[:5]:
            print(f"    - {m}")

    if result.errors:
        print(f"\n❌ Errors: {len(result.errors)}")
        for e in result.errors:
            print(f"    - {e}")

    print(f"\n💬 Feedback:\n{result.feedback}")


def run_grader_on_challenges() -> None:
    """Main function to run grader on example challenges."""

    print("=" * 70)
    print("REASONING GRADER - EXAMPLE CHALLENGE EVALUATION")
    print("=" * 70)

    # Load challenges
    curriculum_dir = Path(__file__).parent.parent / "curriculum" / "v2" / "pillars"

    challenges_to_grade = []

    # Load static analysis challenges
    static_file = curriculum_dir / "static_analysis" / "challenges.yaml"
    if static_file.exists():
        challenges_to_grade.extend(load_challenges_from_file(static_file))
        print(f"\n✓ Loaded {len(challenges_to_grade)} challenges from static_analysis")

    # Load negative knowledge challenges
    neg_file = curriculum_dir / "negative_knowledge" / "challenges.yaml"
    if neg_file.exists():
        neg_challenges = load_challenges_from_file(neg_file)
        challenges_to_grade.extend(neg_challenges)
        print(f"✓ Loaded {len(neg_challenges)} challenges from negative_knowledge")

    print(f"\nTotal challenges loaded: {len(challenges_to_grade)}")

    # Initialize metrics
    metrics = GradingMetrics()

    # Grade challenges with sample responses
    graded_count = 0

    for challenge in challenges_to_grade:
        # Check if we have a sample response
        if challenge.id in SAMPLE_RESPONSES:
            print(f"\n{'─' * 70}")
            print(f"Grading: {challenge.name} [{challenge.belt.value}]")
            print(f"ID: {challenge.id}")
            print(f"Type: {challenge.challenge_type.value} | Pillar: {challenge.pillar.value}")

            # Initialize grader
            grader = ReasoningGrader(challenge)

            # Get sample response
            responses = SAMPLE_RESPONSES[challenge.id]

            # Grade each phase
            for phase_id, response_text in responses.items():
                try:
                    result = grader.grade_phase(phase_id, response_text)
                    print_grading_result(result, challenge.name)

                    # Add to metrics
                    is_vulnerable = challenge.ground_truth.vulnerability_present
                    predicted = "not vulnerable" not in response_text.lower() if not is_vulnerable else "vulnerable" in response_text.lower()

                    metrics.add_result(
                        challenge_id=challenge.id,
                        result=result,
                        pillar=challenge.pillar,
                        belt=challenge.belt,
                        actual_vulnerable=is_vulnerable,
                        predicted_vulnerable=predicted,
                        confidence=0.85,
                    )

                    graded_count += 1

                except Exception as e:
                    print(f"  ❌ Error grading {phase_id.value}: {e}")

    # Also grade a "poor" response for comparison
    if "poor_static_basic_white_001" in SAMPLE_RESPONSES:
        # Find the matching challenge
        for challenge in challenges_to_grade:
            if challenge.id == "static_basic_white_001":
                print(f"\n{'═' * 70}")
                print("COMPARISON: Grading POOR quality response")
                print(f"{'═' * 70}")

                grader = ReasoningGrader(challenge)
                poor_response = SAMPLE_RESPONSES["poor_static_basic_white_001"][PhaseID.OBSERVE]

                result = grader.grade_phase(PhaseID.OBSERVE, poor_response)
                print_grading_result(result, f"{challenge.name} (POOR RESPONSE)")
                break

    # Print summary
    print("\n" + "=" * 70)
    print("GRADING SUMMARY")
    print("=" * 70)
    print(f"\nChallenges graded: {graded_count}")
    print(metrics.summary())


if __name__ == "__main__":
    run_grader_on_challenges()
