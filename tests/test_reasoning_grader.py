"""
Tests for V2 Reasoning Grader system.

Tests cover:
- Phase-specific graders (Observation, Hypothesis, RootCause, NegativeKnowledge, Verification)
- Hallucination detection
- DPO pair generation
- Calibration and metrics tracking
- Full reasoning chain evaluation
"""

from __future__ import annotations

import pytest

from dojo.graders.dpo_generator import DPOPairGenerator
from dojo.graders.metrics import CalibrationTracker, GradingMetrics, Prediction
from dojo.graders.reasoning_grader import (
    GradingResult,
    HypothesisGrader,
    NegativeKnowledgeGrader,
    ObservationGrader,
    ReasoningGrader,
    RootCauseGrader,
    VerificationGrader,
)
from dojo.models import Belt
from dojo.models_v2 import (
    Artifact,
    ArtifactType,
    ChallengeType,
    ChallengeV2,
    EvaluationCriteria,
    GroundTruth,
    Phase,
    PhaseEvaluation,
    PhaseID,
    Pillar,
    ReasoningQuality,
    TrainingMetadata,
)

# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def vulnerable_code_artifact() -> Artifact:
    """Sample vulnerable code artifact for testing."""
    return Artifact(
        artifact_type=ArtifactType.DECOMPILED_CODE,
        content="""
public class SQLHandler {
    private Connection conn;

    public void executeQuery(String userInput) {
        String query = "SELECT * FROM users WHERE id = " + userInput;
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query);
        // Process results
    }

    public void getUserData(String userId) {
        String sql = "SELECT name, email FROM users WHERE user_id = '" + userId + "'";
        PreparedStatement ps = conn.prepareStatement(sql);
        ResultSet rs = ps.executeQuery();
    }
}
        """,
        context="Decompiled Java code from SQLHandler.class",
        source_file="com/app/data/SQLHandler.java",
    )


@pytest.fixture
def secure_code_artifact() -> Artifact:
    """Sample secure code artifact for testing."""
    return Artifact(
        artifact_type=ArtifactType.DECOMPILED_CODE,
        content="""
public class SecureSQLHandler {
    private Connection conn;

    public void executeQuery(String userInput) {
        String query = "SELECT * FROM users WHERE id = ?";
        PreparedStatement stmt = conn.prepareStatement(query);
        stmt.setString(1, userInput);
        ResultSet rs = stmt.executeQuery();
    }

    public void getUserData(int userId) {
        String sql = "SELECT name, email FROM users WHERE user_id = ?";
        PreparedStatement ps = conn.prepareStatement(sql);
        ps.setInt(1, userId);
        ResultSet rs = ps.executeQuery();
    }
}
        """,
        context="Decompiled Java code from SecureSQLHandler.class",
        source_file="com/app/data/SecureSQLHandler.java",
    )


@pytest.fixture
def vulnerable_ground_truth() -> GroundTruth:
    """Ground truth for vulnerable code challenge."""
    return GroundTruth(
        vulnerability_present=True,
        vulnerability_type="SQL Injection",
        cwe_id="CWE-89",
        cvss_score=9.8,
        root_cause="Direct string concatenation of user input violates separation of code and data principle",
        key_observations=[
            "String concatenation in SQL query",
            "User input directly inserted into query",
            "No parameterized queries used",
            "PreparedStatement misused with string concatenation",
        ],
        valid_hypotheses=[
            {"statement": "SQL injection via userId parameter", "testable": True},
        ],
        valid_tests=[
            {"name": "Single quote injection", "payload": "' OR '1'='1"},
        ],
    )


@pytest.fixture
def secure_ground_truth() -> GroundTruth:
    """Ground truth for secure code challenge."""
    return GroundTruth(
        vulnerability_present=False,
        vulnerability_type=None,
        cwe_id=None,
        cvss_score=None,
        root_cause=None,
        secure_properties=[
            "Uses parameterized queries",
            "PreparedStatement with placeholders",
            "Input bound via setString/setInt",
        ],
        key_observations=[
            "PreparedStatement used correctly",
            "Parameter binding via placeholders",
            "No string concatenation in SQL",
        ],
    )


@pytest.fixture
def observe_phase() -> Phase:
    """Observation phase definition."""
    return Phase(
        phase_id=PhaseID.OBSERVE,
        instruction="Identify all security-relevant observations in the provided code.",
        expected_output_schema={
            "type": "object",
            "properties": {
                "observations": {"type": "array"},
                "relevance_ranking": {"type": "array"},
            },
        },
        evaluation_criteria=[
            EvaluationCriteria(
                name="completeness",
                weight=0.30,
                description="Found all key observations",
            ),
            EvaluationCriteria(
                name="accuracy",
                weight=0.30,
                description="Observations are factually correct",
            ),
        ],
    )


@pytest.fixture
def hypothesize_phase() -> Phase:
    """Hypothesis phase definition."""
    return Phase(
        phase_id=PhaseID.HYPOTHESIZE,
        instruction="Form testable security hypotheses based on your observations.",
        expected_output_schema={
            "type": "object",
            "properties": {
                "hypotheses": {"type": "array"},
                "cwe_mapping": {"type": "string"},
            },
        },
        evaluation_criteria=[
            EvaluationCriteria(name="validity", weight=0.25, description="Logically sound"),
            EvaluationCriteria(name="testability", weight=0.25, description="Can be tested"),
        ],
    )


@pytest.fixture
def analyze_phase() -> Phase:
    """Analysis/root cause phase definition."""
    return Phase(
        phase_id=PhaseID.ANALYZE,
        instruction="Analyze the root cause of the vulnerability.",
        expected_output_schema={
            "type": "object",
            "properties": {
                "root_cause": {"type": "string"},
                "security_principle": {"type": "string"},
            },
        },
        evaluation_criteria=[
            EvaluationCriteria(name="depth", weight=0.30, description="Goes beyond surface"),
        ],
    )


@pytest.fixture
def test_phase() -> Phase:
    """Test/verification phase definition."""
    return Phase(
        phase_id=PhaseID.TEST,
        instruction="Design and execute tests to verify your hypothesis.",
        expected_output_schema={
            "type": "object",
            "properties": {
                "test_plan": {"type": "array"},
                "result": {"type": "string"},
            },
        },
        evaluation_criteria=[
            EvaluationCriteria(name="test_validity", weight=0.35, description="Test would work"),
        ],
    )


@pytest.fixture
def vulnerable_challenge(
    vulnerable_code_artifact: Artifact,
    vulnerable_ground_truth: GroundTruth,
    observe_phase: Phase,
    hypothesize_phase: Phase,
    analyze_phase: Phase,
    test_phase: Phase,
) -> ChallengeV2:
    """Complete vulnerable code challenge."""
    return ChallengeV2(
        id="test-sqli-001",
        name="SQL Injection in User Handler",
        challenge_type=ChallengeType.SYNTHESIS,
        pillar=Pillar.STATIC_ANALYSIS,
        belt=Belt.YELLOW,
        difficulty=3,
        description="Analyze the provided code for SQL injection vulnerabilities.",
        artifacts=[vulnerable_code_artifact],
        phases=[observe_phase, hypothesize_phase, analyze_phase, test_phase],
        ground_truth=vulnerable_ground_truth,
        training_metadata=TrainingMetadata(),
        verification_tasks=[],
        cwe_tags=["CWE-89"],
    )


@pytest.fixture
def secure_challenge(
    secure_code_artifact: Artifact,
    secure_ground_truth: GroundTruth,
    observe_phase: Phase,
    analyze_phase: Phase,
) -> ChallengeV2:
    """Complete secure code challenge for negative knowledge testing."""
    return ChallengeV2(
        id="test-secure-001",
        name="Secure SQL Handler Analysis",
        challenge_type=ChallengeType.NEGATIVE,
        pillar=Pillar.NEGATIVE_KNOWLEDGE,
        belt=Belt.GREEN,
        difficulty=4,
        description="Analyze the provided code and identify why it is secure.",
        artifacts=[secure_code_artifact],
        phases=[observe_phase, analyze_phase],
        ground_truth=secure_ground_truth,
        training_metadata=TrainingMetadata(),
        verification_tasks=[],
    )


# ─────────────────────────────────────────────────────────────────────────────
# Sample Responses
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def good_observation_response() -> str:
    """High-quality observation response."""
    return """
## Observations

1. **String Concatenation in SQL Query** (HIGH relevance)
   - Line 6: `String query = "SELECT * FROM users WHERE id = " + userInput;`
   - User input is directly concatenated into the SQL query string
   - No sanitization or validation applied

2. **PreparedStatement Misuse** (HIGH relevance)
   - Line 11: Although PreparedStatement is used, the SQL is constructed via string concatenation
   - This defeats the purpose of parameterized queries

3. **No Input Validation** (MEDIUM relevance)
   - The `userInput` parameter is used directly without any validation
   - No type checking or sanitization

```json
{
    "observations": [
        {"finding": "String concatenation in SQL", "severity": "critical"},
        {"finding": "PreparedStatement misuse", "severity": "high"},
        {"finding": "No input validation", "severity": "medium"}
    ],
    "relevance_ranking": ["high", "high", "medium"]
}
```
    """


@pytest.fixture
def poor_observation_response() -> str:
    """Low-quality observation response with hallucinations."""
    return """
## Observations

1. The code uses the DatabaseHelper class to execute queries
2. There's a potential buffer overflow in the processResults() method
3. The encryptData() function uses weak encryption
4. The validateInput() method is missing from the SecurityManager class

I noticed the code appears to be a standard data access layer.
    """


@pytest.fixture
def good_hypothesis_response() -> str:
    """High-quality hypothesis response."""
    return """
## Hypothesis

Based on my observations, I hypothesize that this code is **vulnerable to SQL injection (CWE-89)**.

**Statement**: The executeQuery and getUserData methods are vulnerable to SQL injection attacks because they concatenate user input directly into SQL query strings without proper sanitization.

**Supporting Observations**:
- String concatenation in SQL query construction
- No use of parameterized queries with bound parameters

**Test Plan**:
1. Input a single quote `'` to test for SQL syntax errors
2. Use payload `' OR '1'='1` to attempt authentication bypass
3. Use UNION-based injection to extract additional data

**CWE Mapping**: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)

This indicates a violation of the separation of code and data principle, where user-supplied data becomes executable SQL code.
    """


@pytest.fixture
def good_root_cause_response() -> str:
    """High-quality root cause analysis response."""
    return """
## Root Cause Analysis

### Fundamental Issue
The root cause is a violation of the **separation of code and data** principle. User-supplied input is treated as part of the SQL command structure rather than as data to be processed.

### Surface vs Root Cause
- **Surface level**: String concatenation in SQL queries
- **Root cause**: Failure to separate data from code by not using parameterized queries

### Security Principle Violated
This violates the fundamental principle that untrusted input should never influence program structure. The CWE-89 (SQL Injection) is part of the CWE-74 (Injection) pillar, which stems from CWE-707 (Improper Neutralization).

### Pattern Family
This belongs to the injection pattern family, which includes:
- SQL Injection (CWE-89)
- Command Injection (CWE-78)
- LDAP Injection (CWE-90)

Similar patterns appear in any context where user input is interpolated into structured language strings.
    """


@pytest.fixture
def good_verification_response() -> str:
    """High-quality verification/test response."""
    return """
## Verification

### Test Methodology
Using adb and burp proxy to intercept and modify requests.

**Step 1**: Test for SQL syntax error
```
Input: '
Expected: SQL error message or application error
```

**Step 2**: Boolean-based injection test
```
Input: 1 OR 1=1
Expected: Returns all users
```

**Step 3**: UNION-based extraction
```
Input: ' UNION SELECT username, password FROM admin--
```

### Evidence
```
Result: SQL Error - You have an error in your SQL syntax
Log shows: java.sql.SQLException at SQLHandler.executeQuery
```

### Conclusion
**Confirmed**: The vulnerability exists. The application is exploitable via SQL injection through the userInput parameter.
    """


@pytest.fixture
def good_secure_analysis_response() -> str:
    """High-quality response identifying secure code."""
    return """
## Security Analysis

### Classification
This code is **not vulnerable** to SQL injection.

### Security Properties
1. **Uses parameterized queries**: All SQL statements use `?` placeholders
2. **PreparedStatement with proper binding**: Parameters are bound via `setString()` and `setInt()`
3. **Type-safe parameter handling**: Integer userId is properly typed

### Attack Resistance
An injection attack would fail because:
- The query structure is defined separately from data
- User input is bound as a parameter, not concatenated
- The database driver escapes special characters automatically

### Conclusion
This implementation correctly follows the separation of code and data principle. SQL injection attacks would be blocked by the parameterized query mechanism.
    """


# ─────────────────────────────────────────────────────────────────────────────
# PhaseGrader Base Class Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestPhaseGraderBase:
    """Tests for PhaseGrader base class functionality."""

    def test_artifact_term_extraction(self, vulnerable_code_artifact: Artifact) -> None:
        """Test that artifact terms are correctly extracted."""
        grader = ObservationGrader(vulnerable_code_artifact.content)

        # Should extract method names (from method calls)
        assert "executequery" in grader.artifact_terms

        # Should extract string literals containing SQL
        assert any("select" in t for t in grader.artifact_terms)

    def test_hallucination_detection_finds_fake_terms(self, vulnerable_code_artifact: Artifact) -> None:
        """Test that hallucinations are detected when response mentions non-existent things."""
        grader = ObservationGrader(vulnerable_code_artifact.content)

        response_with_hallucinations = """
        The DatabaseHelper class uses the encryptData() method to secure queries.
        The FakeClassName is instantiated in the constructor.
        """

        hallucinations = grader.detect_hallucinations(response_with_hallucinations)

        # Should detect fake class names
        assert len(hallucinations) > 0
        assert any("DatabaseHelper" in h or "FakeClassName" in h for h in hallucinations)

    def test_hallucination_detection_allows_real_terms(self, vulnerable_code_artifact: Artifact) -> None:
        """Test that real artifact terms are not flagged as hallucinations."""
        grader = ObservationGrader(vulnerable_code_artifact.content)

        response_with_real_terms = """
        The SQLHandler class has an executeQuery method that concatenates user input.
        The conn Connection object is used to create statements.
        """

        hallucinations = grader.detect_hallucinations(response_with_real_terms)

        # Should not flag real terms
        assert "SQLHandler" not in hallucinations
        assert "executeQuery" not in hallucinations

    def test_parse_response_json(self) -> None:
        """Test JSON response parsing."""
        grader = ObservationGrader("")

        json_response = '{"observations": ["finding1", "finding2"], "score": 0.8}'
        parsed = grader.parse_response(json_response)

        assert parsed is not None
        assert parsed["observations"] == ["finding1", "finding2"]
        assert parsed["score"] == 0.8

    def test_parse_response_markdown_json(self) -> None:
        """Test parsing JSON from markdown code blocks."""
        grader = ObservationGrader("")

        markdown_response = """
        Here are my findings:

        ```json
        {"findings": ["SQL injection", "No validation"]}
        ```

        In conclusion, the code is vulnerable.
        """

        parsed = grader.parse_response(markdown_response)

        assert parsed is not None
        assert "findings" in parsed

    def test_check_key_terms_present(self) -> None:
        """Test key term checking with fuzzy matching."""
        grader = ObservationGrader("")

        response = "The code has sql injection vulnerabilities due to concatenation."
        required = ["SQL injection", "concatenation", "missing term"]

        found, missing = grader.check_key_terms_present(response, required)

        assert "SQL injection" in found or "sql injection" in [f.lower() for f in found]
        assert "concatenation" in found
        assert "missing term" in missing


# ─────────────────────────────────────────────────────────────────────────────
# ObservationGrader Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestObservationGrader:
    """Tests for ObservationGrader."""

    def test_good_observation_scores_high(
        self,
        vulnerable_code_artifact: Artifact,
        vulnerable_ground_truth: GroundTruth,
        observe_phase: Phase,
        good_observation_response: str,
    ) -> None:
        """Test that high-quality observations score well."""
        grader = ObservationGrader(vulnerable_code_artifact.content)

        result = grader.grade(
            response=good_observation_response,
            ground_truth=vulnerable_ground_truth,
            phase=observe_phase,
        )

        # Should have good overall score (completeness + accuracy + relevance)
        # Note: hallucination detection may flag common English words, which is a known limitation
        assert result.total_score >= 0.6
        assert result.phase_id == PhaseID.OBSERVE
        # Check that key criteria scored well
        completeness = next((cs.score for cs in result.criterion_scores if cs.name == "completeness"), 0)
        accuracy = next((cs.score for cs in result.criterion_scores if cs.name == "accuracy"), 0)
        assert completeness >= 0.8
        assert accuracy >= 0.8

    def test_poor_observation_scores_low(
        self,
        vulnerable_code_artifact: Artifact,
        vulnerable_ground_truth: GroundTruth,
        observe_phase: Phase,
        poor_observation_response: str,
    ) -> None:
        """Test that poor observations with hallucinations score low."""
        grader = ObservationGrader(vulnerable_code_artifact.content)

        result = grader.grade(
            response=poor_observation_response,
            ground_truth=vulnerable_ground_truth,
            phase=observe_phase,
        )

        # Should have lower score due to hallucinations and missing observations
        assert result.total_score < 0.7
        assert len(result.hallucinations) > 0

    def test_completeness_criterion(
        self,
        vulnerable_code_artifact: Artifact,
        vulnerable_ground_truth: GroundTruth,
        observe_phase: Phase,
    ) -> None:
        """Test that completeness is properly evaluated."""
        grader = ObservationGrader(vulnerable_code_artifact.content)

        # Response that mentions key observations
        complete_response = """
        I observed string concatenation in the SQL query.
        User input is directly inserted without parameterized queries.
        The PreparedStatement is misused with string concatenation.
        """

        result = grader.grade(complete_response, vulnerable_ground_truth, observe_phase)

        completeness_score = next(
            (cs.score for cs in result.criterion_scores if cs.name == "completeness"),
            0.0
        )
        assert completeness_score >= 0.5

    def test_accuracy_criterion_false_positive(
        self,
        secure_code_artifact: Artifact,
        secure_ground_truth: GroundTruth,
        observe_phase: Phase,
    ) -> None:
        """Test that claiming vulnerability in secure code is penalized."""
        grader = ObservationGrader(secure_code_artifact.content)

        false_positive_response = """
        The code is vulnerable to SQL injection.
        This vulnerability found in the executeQuery method.
        """

        result = grader.grade(false_positive_response, secure_ground_truth, observe_phase)

        accuracy_score = next(
            (cs.score for cs in result.criterion_scores if cs.name == "accuracy"),
            1.0
        )
        assert accuracy_score < 1.0


# ─────────────────────────────────────────────────────────────────────────────
# HypothesisGrader Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestHypothesisGrader:
    """Tests for HypothesisGrader."""

    def test_good_hypothesis_scores_high(
        self,
        vulnerable_code_artifact: Artifact,
        vulnerable_ground_truth: GroundTruth,
        hypothesize_phase: Phase,
        good_hypothesis_response: str,
    ) -> None:
        """Test that well-formed hypothesis scores high."""
        grader = HypothesisGrader(vulnerable_code_artifact.content)

        result = grader.grade(
            response=good_hypothesis_response,
            ground_truth=vulnerable_ground_truth,
            phase=hypothesize_phase,
        )

        assert result.total_score >= 0.7
        assert result.phase_id == PhaseID.HYPOTHESIZE

    def test_validity_requires_logical_connection(
        self,
        vulnerable_code_artifact: Artifact,
        vulnerable_ground_truth: GroundTruth,
        hypothesize_phase: Phase,
    ) -> None:
        """Test that validity criterion checks for logical reasoning."""
        grader = HypothesisGrader(vulnerable_code_artifact.content)

        # Response with logical connection words
        logical_response = "Because the code uses string concatenation, therefore it is vulnerable."
        result = grader.grade(logical_response, vulnerable_ground_truth, hypothesize_phase)

        validity_score = next(
            (cs.score for cs in result.criterion_scores if cs.name == "validity"),
            0.0
        )
        assert validity_score >= 0.7

    def test_testability_criterion(
        self,
        vulnerable_code_artifact: Artifact,
        vulnerable_ground_truth: GroundTruth,
        hypothesize_phase: Phase,
    ) -> None:
        """Test that testability criterion checks for test methodology."""
        grader = HypothesisGrader(vulnerable_code_artifact.content)

        testable_response = """
        Step 1: Use Frida to hook the method
        Step 2: Inject payload with Burp proxy
        Step 3: Verify with adb logcat output
        """

        result = grader.grade(testable_response, vulnerable_ground_truth, hypothesize_phase)

        testability_score = next(
            (cs.score for cs in result.criterion_scores if cs.name == "testability"),
            0.0
        )
        assert testability_score >= 0.7

    def test_cwe_mapping_correct(
        self,
        vulnerable_code_artifact: Artifact,
        vulnerable_ground_truth: GroundTruth,
        hypothesize_phase: Phase,
    ) -> None:
        """Test that correct CWE mapping is rewarded."""
        grader = HypothesisGrader(vulnerable_code_artifact.content)

        response_with_correct_cwe = "This is CWE-89 SQL injection vulnerability."
        result = grader.grade(response_with_correct_cwe, vulnerable_ground_truth, hypothesize_phase)

        cwe_score = next(
            (cs.score for cs in result.criterion_scores if cs.name == "cwe_mapping"),
            0.0
        )
        assert cwe_score == 1.0

    def test_cwe_mapping_wrong(
        self,
        vulnerable_code_artifact: Artifact,
        vulnerable_ground_truth: GroundTruth,
        hypothesize_phase: Phase,
    ) -> None:
        """Test that wrong CWE mapping is penalized."""
        grader = HypothesisGrader(vulnerable_code_artifact.content)

        response_with_wrong_cwe = "This is CWE-22 path traversal vulnerability."
        result = grader.grade(response_with_wrong_cwe, vulnerable_ground_truth, hypothesize_phase)

        cwe_score = next(
            (cs.score for cs in result.criterion_scores if cs.name == "cwe_mapping"),
            0.0
        )
        assert cwe_score < 0.5


# ─────────────────────────────────────────────────────────────────────────────
# RootCauseGrader Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestRootCauseGrader:
    """Tests for RootCauseGrader."""

    def test_good_root_cause_scores_high(
        self,
        vulnerable_code_artifact: Artifact,
        vulnerable_ground_truth: GroundTruth,
        analyze_phase: Phase,
        good_root_cause_response: str,
    ) -> None:
        """Test that deep root cause analysis scores high."""
        grader = RootCauseGrader(vulnerable_code_artifact.content)

        result = grader.grade(
            response=good_root_cause_response,
            ground_truth=vulnerable_ground_truth,
            phase=analyze_phase,
        )

        assert result.total_score >= 0.7

    def test_depth_criterion_requires_principles(
        self,
        vulnerable_code_artifact: Artifact,
        vulnerable_ground_truth: GroundTruth,
        analyze_phase: Phase,
    ) -> None:
        """Test that depth criterion checks for security principles."""
        grader = RootCauseGrader(vulnerable_code_artifact.content)

        shallow_response = "The code has SQL injection."
        deep_response = "The fundamental root cause is a violation of separation of code and data principle."

        shallow_result = grader.grade(shallow_response, vulnerable_ground_truth, analyze_phase)
        deep_result = grader.grade(deep_response, vulnerable_ground_truth, analyze_phase)

        shallow_depth = next(
            (cs.score for cs in shallow_result.criterion_scores if cs.name == "depth"),
            0.0
        )
        deep_depth = next(
            (cs.score for cs in deep_result.criterion_scores if cs.name == "depth"),
            0.0
        )

        assert deep_depth > shallow_depth

    def test_generalization_criterion(
        self,
        vulnerable_code_artifact: Artifact,
        vulnerable_ground_truth: GroundTruth,
        analyze_phase: Phase,
    ) -> None:
        """Test that generalization criterion rewards pattern identification."""
        grader = RootCauseGrader(vulnerable_code_artifact.content)

        generalizing_response = """
        This belongs to the injection pattern family.
        Similar patterns appear in command injection and LDAP injection.
        """

        result = grader.grade(generalizing_response, vulnerable_ground_truth, analyze_phase)

        gen_score = next(
            (cs.score for cs in result.criterion_scores if cs.name == "generalization"),
            0.0
        )
        assert gen_score >= 0.7


# ─────────────────────────────────────────────────────────────────────────────
# NegativeKnowledgeGrader Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestNegativeKnowledgeGrader:
    """Tests for NegativeKnowledgeGrader."""

    def test_correct_secure_classification(
        self,
        secure_code_artifact: Artifact,
        secure_ground_truth: GroundTruth,
        analyze_phase: Phase,
        good_secure_analysis_response: str,
    ) -> None:
        """Test that correctly identifying secure code scores high."""
        grader = NegativeKnowledgeGrader(secure_code_artifact.content)

        result = grader.grade(
            response=good_secure_analysis_response,
            ground_truth=secure_ground_truth,
            phase=analyze_phase,
        )

        assert result.total_score >= 0.7
        assert len(result.errors) == 0

    def test_false_positive_penalized(
        self,
        secure_code_artifact: Artifact,
        secure_ground_truth: GroundTruth,
        analyze_phase: Phase,
    ) -> None:
        """Test that false positive claims are heavily penalized."""
        grader = NegativeKnowledgeGrader(secure_code_artifact.content)

        false_positive_response = """
        This code is vulnerable to SQL injection.
        The vulnerability found allows attackers to bypass authentication.
        Critical vulnerability with high severity.
        """

        result = grader.grade(false_positive_response, secure_ground_truth, analyze_phase)

        assert result.total_score < 0.5
        assert any("false positive" in e.lower() for e in result.errors)

    def test_security_property_identification(
        self,
        secure_code_artifact: Artifact,
        secure_ground_truth: GroundTruth,
        analyze_phase: Phase,
    ) -> None:
        """Test that identifying security properties is rewarded."""
        grader = NegativeKnowledgeGrader(secure_code_artifact.content)

        property_response = """
        The code is not vulnerable because:
        - Uses parameterized queries with PreparedStatement
        - Parameters are bound via setString and setInt
        - No string concatenation in SQL construction
        """

        result = grader.grade(property_response, secure_ground_truth, analyze_phase)

        property_score = next(
            (cs.score for cs in result.criterion_scores if cs.name == "security_property_id"),
            0.0
        )
        # Score is calculated as found/total properties - accepting 0.65+ (2/3 properties)
        assert property_score >= 0.65


# ─────────────────────────────────────────────────────────────────────────────
# VerificationGrader Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestVerificationGrader:
    """Tests for VerificationGrader."""

    def test_good_verification_scores_high(
        self,
        vulnerable_code_artifact: Artifact,
        vulnerable_ground_truth: GroundTruth,
        test_phase: Phase,
        good_verification_response: str,
    ) -> None:
        """Test that complete verification scores high."""
        grader = VerificationGrader(vulnerable_code_artifact.content)

        result = grader.grade(
            response=good_verification_response,
            ground_truth=vulnerable_ground_truth,
            phase=test_phase,
        )

        assert result.total_score >= 0.7
        assert result.phase_id == PhaseID.TEST

    def test_test_validity_requires_tools(
        self,
        vulnerable_code_artifact: Artifact,
        vulnerable_ground_truth: GroundTruth,
        test_phase: Phase,
    ) -> None:
        """Test that valid tests mention concrete tools."""
        grader = VerificationGrader(vulnerable_code_artifact.content)

        with_tools = "Using Frida and adb, step 1: hook the method, step 2: inject payload."
        without_tools = "The vulnerability can be tested somehow."

        with_tools_result = grader.grade(with_tools, vulnerable_ground_truth, test_phase)
        without_tools_result = grader.grade(without_tools, vulnerable_ground_truth, test_phase)

        assert with_tools_result.total_score > without_tools_result.total_score

    def test_correct_conclusion_rewarded(
        self,
        vulnerable_code_artifact: Artifact,
        vulnerable_ground_truth: GroundTruth,
        test_phase: Phase,
    ) -> None:
        """Test that correct conclusion is rewarded."""
        grader = VerificationGrader(vulnerable_code_artifact.content)

        # Vulnerable code + confirmed vulnerable = correct
        correct_response = "Confirmed: The vulnerability exists and is exploitable."
        result = grader.grade(correct_response, vulnerable_ground_truth, test_phase)

        conclusion_score = next(
            (cs.score for cs in result.criterion_scores if cs.name == "conclusion_accuracy"),
            0.0
        )
        assert conclusion_score == 1.0

    def test_wrong_conclusion_penalized(
        self,
        vulnerable_code_artifact: Artifact,
        vulnerable_ground_truth: GroundTruth,
        test_phase: Phase,
    ) -> None:
        """Test that wrong conclusion is penalized."""
        grader = VerificationGrader(vulnerable_code_artifact.content)

        # Vulnerable code + refuted = wrong
        wrong_response = "Refuted: The code is not vulnerable, this was a false positive."
        result = grader.grade(wrong_response, vulnerable_ground_truth, test_phase)

        conclusion_score = next(
            (cs.score for cs in result.criterion_scores if cs.name == "conclusion_accuracy"),
            1.0
        )
        assert conclusion_score == 0.0


# ─────────────────────────────────────────────────────────────────────────────
# ReasoningGrader Orchestration Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestReasoningGrader:
    """Tests for main ReasoningGrader orchestration."""

    def test_initializes_appropriate_graders(self, vulnerable_challenge: ChallengeV2) -> None:
        """Test that appropriate graders are initialized for challenge."""
        grader = ReasoningGrader(vulnerable_challenge)

        assert PhaseID.OBSERVE in grader.phase_graders
        assert PhaseID.HYPOTHESIZE in grader.phase_graders
        assert PhaseID.ANALYZE in grader.phase_graders
        assert isinstance(grader.phase_graders[PhaseID.ANALYZE], RootCauseGrader)

    def test_uses_negative_grader_for_secure_challenge(self, secure_challenge: ChallengeV2) -> None:
        """Test that NegativeKnowledgeGrader is used for secure challenges."""
        grader = ReasoningGrader(secure_challenge)

        # For non-vulnerable challenges, ANALYZE phase should use NegativeKnowledgeGrader
        assert isinstance(grader.phase_graders[PhaseID.ANALYZE], NegativeKnowledgeGrader)

    def test_grade_phase_returns_result(
        self,
        vulnerable_challenge: ChallengeV2,
        good_observation_response: str,
    ) -> None:
        """Test that grade_phase returns proper result."""
        grader = ReasoningGrader(vulnerable_challenge)

        result = grader.grade_phase(PhaseID.OBSERVE, good_observation_response)

        assert isinstance(result, GradingResult)
        assert result.phase_id == PhaseID.OBSERVE
        assert 0 <= result.total_score <= 1

    def test_grade_phase_raises_for_invalid_phase(self, vulnerable_challenge: ChallengeV2) -> None:
        """Test that invalid phase raises error."""
        grader = ReasoningGrader(vulnerable_challenge)

        with pytest.raises(ValueError, match="not found"):
            grader.grade_phase(PhaseID.SYNTHESIZE, "some response")

    def test_grade_full_chain(
        self,
        vulnerable_challenge: ChallengeV2,
        good_observation_response: str,
        good_hypothesis_response: str,
    ) -> None:
        """Test grading a full reasoning chain."""
        grader = ReasoningGrader(vulnerable_challenge)

        phase_responses = {
            PhaseID.OBSERVE: good_observation_response,
            PhaseID.HYPOTHESIZE: good_hypothesis_response,
        }

        results, quality = grader.grade_full_chain(phase_responses)

        assert len(results) == 2
        assert isinstance(quality, ReasoningQuality)
        assert 0 <= quality.overall <= 1

    def test_reasoning_quality_calculation(
        self,
        vulnerable_challenge: ChallengeV2,
        good_observation_response: str,
        good_hypothesis_response: str,
        good_root_cause_response: str,
    ) -> None:
        """Test reasoning quality metrics calculation."""
        grader = ReasoningGrader(vulnerable_challenge)

        phase_responses = {
            PhaseID.OBSERVE: good_observation_response,
            PhaseID.HYPOTHESIZE: good_hypothesis_response,
            PhaseID.ANALYZE: good_root_cause_response,
        }

        _, quality = grader.grade_full_chain(phase_responses)

        # All quality dimensions should be set
        assert quality.completeness > 0
        assert quality.accuracy > 0
        assert quality.depth > 0
        assert quality.coherence > 0

    def test_grading_result_to_phase_evaluation(
        self,
        vulnerable_challenge: ChallengeV2,
        good_observation_response: str,
    ) -> None:
        """Test converting GradingResult to PhaseEvaluation."""
        grader = ReasoningGrader(vulnerable_challenge)

        result = grader.grade_phase(PhaseID.OBSERVE, good_observation_response)
        evaluation = result.to_phase_evaluation()

        assert isinstance(evaluation, PhaseEvaluation)
        assert evaluation.phase_id == PhaseID.OBSERVE
        assert evaluation.score == result.total_score


# ─────────────────────────────────────────────────────────────────────────────
# DPO Generator Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestDPOPairGenerator:
    """Tests for DPO pair generation."""

    def test_generate_from_responses_creates_pairs(
        self,
        vulnerable_challenge: ChallengeV2,
        good_observation_response: str,
        poor_observation_response: str,
    ) -> None:
        """Test generating DPO pairs from response comparisons."""
        generator = DPOPairGenerator(min_margin=0.1)

        # Create mock grading results
        good_result = GradingResult(
            phase_id=PhaseID.OBSERVE,
            criterion_scores=[],
            total_score=0.85,
            feedback="Good",
        )
        poor_result = GradingResult(
            phase_id=PhaseID.OBSERVE,
            criterion_scores=[],
            total_score=0.45,
            feedback="Poor",
        )

        responses = [
            (good_observation_response, good_result),
            (poor_observation_response, poor_result),
        ]

        pairs = generator.generate_from_responses(
            challenge=vulnerable_challenge,
            responses=responses,
            phase_id=PhaseID.OBSERVE,
        )

        assert len(pairs) >= 1
        # DPO generator now adds <thinking> tags, so check for inclusion
        assert good_observation_response.strip() in pairs[0].chosen
        assert pairs[0].rejected == poor_observation_response
        assert pairs[0].margin >= 0.1

    def test_min_margin_filtering(self, vulnerable_challenge: ChallengeV2) -> None:
        """Test that pairs below min_margin are filtered out."""
        generator = DPOPairGenerator(min_margin=0.5)

        # Create responses with small score difference
        result1 = GradingResult(PhaseID.OBSERVE, [], 0.75, "")
        result2 = GradingResult(PhaseID.OBSERVE, [], 0.70, "")  # Only 0.05 difference

        responses = [
            ("response1", result1),
            ("response2", result2),
        ]

        pairs = generator.generate_from_responses(
            challenge=vulnerable_challenge,
            responses=responses,
            phase_id=PhaseID.OBSERVE,
        )

        # Should not generate pair due to small margin
        assert len(pairs) == 0

    def test_synthetic_pair_generation(
        self,
        vulnerable_challenge: ChallengeV2,
        good_observation_response: str,
    ) -> None:
        """Test synthetic rejected response generation."""
        generator = DPOPairGenerator()

        pairs = generator.generate_synthetic_pairs(
            challenge=vulnerable_challenge,
            good_response=good_observation_response,
            good_score=0.85,
            phase_id=PhaseID.OBSERVE,
            num_pairs=2,
        )

        assert len(pairs) == 2
        for pair in pairs:
            # DPO generator now adds <thinking> tags, so check for inclusion
            assert good_observation_response.strip() in pair.chosen
            assert pair.rejected != good_observation_response
            assert len(pair.rejection_reasons) > 0


# ─────────────────────────────────────────────────────────────────────────────
# Calibration and Metrics Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestCalibrationTracker:
    """Tests for calibration tracking."""

    def _make_prediction(self, confidence: float, actual: bool, predicted: bool | None = None) -> Prediction:
        if predicted is None:
            predicted = actual
        return Prediction(
            confidence=confidence,
            actual_vulnerable=actual,
            predicted_vulnerable=predicted,
            challenge_id="test",
            phase_id=PhaseID.OBSERVE,
            score=0.0  # Default score
        )

    def check_prediction(self, predicted: bool | None = None):
        pass

    def test_add_predictions(self) -> None:
        """Test adding predictions to calibration tracker."""
        tracker = CalibrationTracker()

        tracker.add_prediction(self._make_prediction(confidence=0.9, actual=True))
        tracker.add_prediction(self._make_prediction(confidence=0.8, actual=True))
        tracker.add_prediction(self._make_prediction(confidence=0.3, actual=False))

        assert len(tracker.predictions) == 3

    def test_expected_calibration_error_perfect(self) -> None:
        """Test ECE is low for well-calibrated predictions."""
        tracker = CalibrationTracker()

        # Well calibrated: 80% confident, ~80% correct
        for _ in range(8):
            tracker.add_prediction(self._make_prediction(confidence=0.8, actual=True))
        for _ in range(2):
            tracker.add_prediction(self._make_prediction(confidence=0.8, actual=True, predicted=False))

        ece = tracker.expected_calibration_error()

        # Should be relatively low (allowing for bin effects)
        assert ece < 0.3

    def test_expected_calibration_error_overconfident(self) -> None:
        """Test ECE is high for overconfident predictions."""
        tracker = CalibrationTracker()

        # Overconfident: 90% confident but only 50% correct
        for _ in range(5):
            tracker.add_prediction(self._make_prediction(confidence=0.9, actual=True))
        for _ in range(5):
            tracker.add_prediction(self._make_prediction(confidence=0.9, actual=True, predicted=False))

        ece = tracker.expected_calibration_error()

        # Should have high ECE (confidence 0.9 but accuracy 0.5)
        assert ece > 0.3

    def test_brier_score(self) -> None:
        """Test Brier score calculation."""
        tracker = CalibrationTracker()

        # Perfect predictions: high confidence when actually vulnerable
        tracker.add_prediction(self._make_prediction(confidence=1.0, actual=True))
        tracker.add_prediction(self._make_prediction(confidence=0.0, actual=False))

        brier = tracker.brier_score()

        # Perfect predictions should have Brier score of 0
        assert brier == 0.0


class TestGradingMetrics:
    """Tests for grading metrics tracking."""

    def test_add_result_updates_metrics(
        self,
        vulnerable_challenge: ChallengeV2,
        good_observation_response: str,
    ) -> None:
        """Test that adding results updates metrics."""
        metrics = GradingMetrics()

        result = GradingResult(
            phase_id=PhaseID.OBSERVE,
            criterion_scores=[],
            total_score=0.85,
            feedback="Good",
        )

        metrics.add_result(
            challenge_id=vulnerable_challenge.id,
            result=result,
            pillar=vulnerable_challenge.pillar,
            belt=vulnerable_challenge.belt,
            actual_vulnerable=True,
            predicted_vulnerable=True,
            confidence=0.9,
        )

        # Check that results were added
        assert len(metrics.grading_results) == 1
        assert Pillar.STATIC_ANALYSIS.value in metrics.pillar_scores

    def test_confusion_matrix_metrics(self) -> None:
        """Test precision, recall, F1 calculations."""
        metrics = GradingMetrics()

        result = GradingResult(PhaseID.OBSERVE, [], 0.8, "")

        # Add true positive
        metrics.add_result("c1", result, Pillar.STATIC_ANALYSIS, Belt.WHITE, True, True, 0.9)
        # Add false positive
        metrics.add_result("c2", result, Pillar.STATIC_ANALYSIS, Belt.WHITE, False, True, 0.8)
        # Add false negative
        metrics.add_result("c3", result, Pillar.STATIC_ANALYSIS, Belt.WHITE, True, False, 0.7)
        # Add true negative
        metrics.add_result("c4", result, Pillar.STATIC_ANALYSIS, Belt.WHITE, False, False, 0.6)

        assert metrics.true_positives == 1
        assert metrics.false_positives == 1
        assert metrics.false_negatives == 1
        assert metrics.true_negatives == 1

        # Precision = TP / (TP + FP) = 1/2 = 0.5
        assert metrics.precision == 0.5
        # Recall = TP / (TP + FN) = 1/2 = 0.5
        assert metrics.recall == 0.5

    def test_summary_generation(self) -> None:
        """Test metrics summary generation."""
        metrics = GradingMetrics()

        result = GradingResult(PhaseID.OBSERVE, [], 0.8, "")
        metrics.add_result("c1", result, Pillar.STATIC_ANALYSIS, Belt.WHITE, True, True, 0.9)

        summary = metrics.summary()

        assert isinstance(summary, str)
        assert "Challenges" in summary or "Total" in summary

    def test_to_dict_serialization(self) -> None:
        """Test metrics can be serialized to dict."""
        metrics = GradingMetrics()

        result = GradingResult(PhaseID.OBSERVE, [], 0.8, "")
        metrics.add_result("c1", result, Pillar.STATIC_ANALYSIS, Belt.WHITE, True, True, 0.9)

        data = metrics.to_dict()

        assert isinstance(data, dict)
        # Check for expected keys in the nested structure
        assert "summary" in data
        assert "scores" in data
        assert "by_pillar" in data["scores"]


# ─────────────────────────────────────────────────────────────────────────────
# Integration Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestIntegration:
    """Integration tests for the complete grading pipeline."""

    def test_full_grading_pipeline(
        self,
        vulnerable_challenge: ChallengeV2,
        good_observation_response: str,
        good_hypothesis_response: str,
        good_root_cause_response: str,
        good_verification_response: str,
    ) -> None:
        """Test complete grading pipeline from responses to metrics."""
        # Initialize components
        grader = ReasoningGrader(vulnerable_challenge)
        metrics = GradingMetrics()

        # Grade all phases
        phase_responses = {
            PhaseID.OBSERVE: good_observation_response,
            PhaseID.HYPOTHESIZE: good_hypothesis_response,
            PhaseID.ANALYZE: good_root_cause_response,
            PhaseID.TEST: good_verification_response,
        }

        results, quality = grader.grade_full_chain(phase_responses)

        # Add results to metrics
        for result in results:
            metrics.add_result(
                challenge_id=vulnerable_challenge.id,
                result=result,
                pillar=vulnerable_challenge.pillar,
                belt=vulnerable_challenge.belt,
                actual_vulnerable=True,
                predicted_vulnerable=True,
                confidence=0.85,
            )

        # Verify metrics updated
        assert len(metrics.grading_results) == len(results)

        # Verify quality assessment
        assert quality.overall > 0.5

    def test_negative_challenge_pipeline(
        self,
        secure_challenge: ChallengeV2,
        good_secure_analysis_response: str,
    ) -> None:
        """Test grading pipeline for negative knowledge challenges."""
        grader = ReasoningGrader(secure_challenge)

        result = grader.grade_phase(PhaseID.ANALYZE, good_secure_analysis_response)

        # Should score well for correctly identifying secure code
        assert result.total_score >= 0.7
        assert len(result.errors) == 0
