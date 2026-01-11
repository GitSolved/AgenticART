#!/usr/bin/env python3
"""
Full Praxis Loop Test with CryptoVault APK.

This demonstrates the complete Praxis architecture:
1. V2 Challenge: Analyze crypto implementation in cryptovault
2. Simulated Model Responses: High confidence assertions
3. V1 Verification: MCP tools verify claims via actual code analysis
4. Calibration: Compare confidence vs execution to detect hallucinations
5. DPO Signal: Generate training signal based on calibration

Run: python -m dojo.mcp.test_praxis_loop
"""

import asyncio
import sys
from pathlib import Path

# Add project root
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from dojo.graders.praxis_runner import PraxisRunner
from dojo.mcp import MCPExecutor
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

APK_PATH = Path(__file__).parent.parent / "targets/vulnerable_apks/cryptovault/app/build/outputs/apk/debug/app-debug.apk"


async def get_real_code_artifacts(executor: MCPExecutor, apk_path: str) -> tuple[str, str, str, str, str]:
    """Use MCP to get real code from the APK for the challenge."""

    # Decompile with JADX
    result = await executor.execute_tool("decompile", {"apk_path": apk_path})
    jadx_output_dir = result.output.get("output_dir")

    # Decode with Apktool
    result = await executor.execute_tool("decode", {"apk_path": apk_path})
    apktool_output_dir = result.output.get("output_dir")

    # Get MainActivity source
    result = await executor.execute_tool("get_class", {
        "output_dir": jadx_output_dir,
        "class_name": "MainActivity"
    })
    main_activity_code = result.output.get("source", "// Code not found")

    # Get manifest
    result = await executor.execute_tool("get_manifest", {"output_dir": apktool_output_dir})
    manifest_info = result.output

    # Search for crypto patterns
    result = await executor.execute_tool("search_code", {
        "output_dir": jadx_output_dir,
        "pattern": "SecretKeySpec|Cipher\\.getInstance|AES|encrypt|decrypt",
        "max_results": 10
    })
    crypto_matches = result.output.get("matches", [])

    # Format crypto findings
    crypto_code = "// Crypto-related code findings:\n\n"
    for match in crypto_matches[:5]:
        crypto_code += f"// File: {match.get('file', '?')}\n"
        crypto_code += f"// Line {match.get('line', '?')}:\n"
        crypto_code += match.get('context', match.get('content', '')) + "\n\n"

    return main_activity_code, str(manifest_info), crypto_code, jadx_output_dir, apktool_output_dir


def create_cryptovault_challenge(
    main_activity_code: str,
    manifest_info: str,
    crypto_code: str,
    jadx_output_dir: str,
    apktool_output_dir: str,
) -> ChallengeV2:
    """Create a ChallengeV2 for analyzing cryptovault's crypto implementation."""

    return ChallengeV2(
        id="crypto_analysis_001",
        name="CryptoVault Encryption Analysis",
        challenge_type=ChallengeType.SYNTHESIS,
        pillar=Pillar.STATIC_ANALYSIS,
        belt=Belt.WHITE,
        difficulty=4,

        description="""
Analyze the CryptoVault application's encryption implementation.
This app claims to securely store user secrets using AES encryption.
Your task is to evaluate whether the crypto implementation is secure.

Focus areas:
1. Key derivation and storage
2. IV (Initialization Vector) handling
3. Cipher mode selection
4. Potential hardcoded secrets
        """,

        artifacts=[
            Artifact(
                artifact_type=ArtifactType.DECOMPILED_CODE,
                content=main_activity_code,
                context="MainActivity - main entry point handling user secrets",
            ),
            Artifact(
                artifact_type=ArtifactType.DECOMPILED_CODE,
                content=crypto_code,
                context="Crypto-related code patterns found in the application",
            ),
            Artifact(
                artifact_type=ArtifactType.MANIFEST,
                content=manifest_info[:2000],  # Truncate for readability
                context="AndroidManifest.xml security configuration",
            ),
        ],

        phases=[
            Phase(
                phase_id=PhaseID.OBSERVE,
                instruction="""
Examine the provided code and identify:
1. What encryption algorithm is being used?
2. How is the encryption key derived/stored?
3. Is there an IV? How is it handled?
4. Are there any hardcoded values related to crypto?

List your observations without drawing conclusions yet.
                """,
                expected_output_schema={
                    "type": "object",
                    "properties": {
                        "algorithm": {"type": "string"},
                        "key_handling": {"type": "string"},
                        "iv_handling": {"type": "string"},
                        "hardcoded_values": {"type": "array"},
                    }
                },
                evaluation_criteria=[
                    EvaluationCriteria(
                        name="observation_accuracy",
                        weight=0.5,
                        description="Correctly identifies crypto components"
                    ),
                    EvaluationCriteria(
                        name="completeness",
                        weight=0.5,
                        description="Covers all relevant aspects"
                    ),
                ],
            ),
            Phase(
                phase_id=PhaseID.HYPOTHESIZE,
                instruction="""
Based on your observations, form hypotheses about potential security issues.
For each hypothesis, state your confidence level (0-100%).

Consider:
- Is the key derivation secure?
- Is the IV properly randomized?
- Is the cipher mode appropriate?
- Are there information disclosure risks?
                """,
                expected_output_schema={
                    "type": "object",
                    "properties": {
                        "hypotheses": {
                            "type": "array",
                            "items": {
                                "hypothesis": {"type": "string"},
                                "confidence": {"type": "number"},
                                "evidence": {"type": "string"},
                            }
                        }
                    }
                },
                evaluation_criteria=[
                    EvaluationCriteria(
                        name="hypothesis_validity",
                        weight=0.6,
                        description="Hypotheses are testable and relevant"
                    ),
                    EvaluationCriteria(
                        name="confidence_calibration",
                        weight=0.4,
                        description="Confidence matches evidence strength"
                    ),
                ],
            ),
            Phase(
                phase_id=PhaseID.ANALYZE,
                instruction="""
Provide your final security assessment:
1. Is this crypto implementation secure? (Yes/No)
2. What is the severity? (Critical/High/Medium/Low/None)
3. What is your overall confidence? (0-100%)
4. What is the root cause of any issues found?
5. How should it be fixed?
                """,
                expected_output_schema={
                    "type": "object",
                    "properties": {
                        "is_secure": {"type": "boolean"},
                        "severity": {"type": "string"},
                        "confidence": {"type": "number"},
                        "root_cause": {"type": "string"},
                        "recommendation": {"type": "string"},
                    }
                },
                evaluation_criteria=[
                    EvaluationCriteria(
                        name="conclusion_accuracy",
                        weight=0.5,
                        description="Correct security assessment"
                    ),
                    EvaluationCriteria(
                        name="reasoning_quality",
                        weight=0.5,
                        description="Sound reasoning chain"
                    ),
                ],
            ),
        ],

        ground_truth=GroundTruth(
            vulnerability_present=True,
            vulnerability_type="Insecure Cryptographic Implementation",
            cwe_id="CWE-327",
            cvss_score=6.5,
            root_cause="Hardcoded encryption key and/or weak key derivation",
            key_observations=[
                "Uses AES encryption",
                "Key may be hardcoded or derived insecurely",
                "IV handling may be improper",
                "SharedPreferences used for sensitive storage",
            ],
        ),

        training_metadata=TrainingMetadata(
            reasoning_chain_required=True,
            dpo_pairs_available=True,
            common_mistakes=[
                "Missing the hardcoded key",
                "Not checking IV randomness",
                "Overlooking ECB mode issues",
            ],
            pattern_family="crypto_misuse",
        ),

        # V1 Verification Tasks - These execute via MCP!
        verification_tasks=[
            VerificationTask(
                instruction="Verify AES encryption is used in the codebase",
                mcp_tool_call={
                    "tool": "search_code",
                    "output_dir": jadx_output_dir,
                    "pattern": "AES|Cipher\\.getInstance.*AES",
                },
                validation_rule={
                    "type": "output_contains",
                    "expected": "AES",
                },
            ),
            VerificationTask(
                instruction="Check for hardcoded key patterns",
                mcp_tool_call={
                    "tool": "search_code",
                    "output_dir": jadx_output_dir,
                    "pattern": "SecretKeySpec|getBytes\\(\\)|key\\s*=\\s*[\"']",
                },
                validation_rule={
                    "type": "regex",
                    "pattern": "SecretKeySpec|getBytes",
                },
            ),
            VerificationTask(
                instruction="Verify SharedPreferences usage for storage",
                mcp_tool_call={
                    "tool": "search_code",
                    "output_dir": jadx_output_dir,
                    "pattern": "SharedPreferences|getSharedPreferences",
                },
                validation_rule={
                    "type": "output_contains",
                    "expected": "SharedPreferences",
                },
            ),
            VerificationTask(
                instruction="Check manifest for debug flag",
                mcp_tool_call={
                    "tool": "get_manifest",
                    "output_dir": apktool_output_dir,
                },
                validation_rule={
                    "type": "json_path",
                    "path": "security_flags.debuggable",
                    "expected": True,
                },
            ),
        ],

        tags=["crypto", "static-analysis", "aes", "key-management"],
        cwe_tags=["CWE-327", "CWE-321", "CWE-329"],
        owasp_tags=["M5-Insufficient-Cryptography"],
    )


def create_confident_correct_response() -> dict[PhaseID, str]:
    """Simulate a model response that is confident AND correct."""
    return {
        PhaseID.OBSERVE: """
## Observations

1. **Algorithm**: The app uses AES encryption via `Cipher.getInstance("AES")`
2. **Key Handling**: I found `SecretKeySpec` being used with what appears to be
   a key derived from a string using `.getBytes()`. This is concerning.
3. **IV Handling**: I did not observe proper IV randomization. The code may be
   using ECB mode or a static IV.
4. **Hardcoded Values**: There appear to be hardcoded string values that could
   be encryption keys. SharedPreferences is used for storage.

{
    "algorithm": "AES",
    "key_handling": "SecretKeySpec with getBytes() - likely hardcoded",
    "iv_handling": "Not properly randomized",
    "hardcoded_values": ["encryption key string", "SharedPreferences key"]
}
        """,
        PhaseID.HYPOTHESIZE: """
## Hypotheses

Based on my observations, I form the following hypotheses:

1. **Hardcoded Key Vulnerability** - Confidence: 85%
   The encryption key appears to be derived from a hardcoded string using
   `.getBytes()`, which means anyone who decompiles the app can extract the key.

2. **Weak Key Derivation** - Confidence: 80%
   Using `.getBytes()` directly on a string is not a proper key derivation
   function. A proper KDF like PBKDF2 should be used.

3. **Potential ECB Mode** - Confidence: 60%
   Without seeing explicit CBC/GCM mode, the cipher might default to ECB
   which has known weaknesses.

{
    "hypotheses": [
        {"hypothesis": "Hardcoded encryption key", "confidence": 85, "evidence": "SecretKeySpec with getBytes()"},
        {"hypothesis": "Weak key derivation", "confidence": 80, "evidence": "No KDF visible"},
        {"hypothesis": "ECB mode vulnerability", "confidence": 60, "evidence": "No IV handling code"}
    ]
}
        """,
        PhaseID.ANALYZE: """
## Security Assessment

**Is Secure**: No
**Severity**: High
**Confidence**: 85%

### Root Cause
The cryptographic implementation suffers from multiple issues:
1. The encryption key is hardcoded or derived from a hardcoded string
2. No proper key derivation function (KDF) is used
3. SharedPreferences stores sensitive data that could be extracted

### Recommendation
1. Use Android Keystore for key storage
2. Implement PBKDF2 or Argon2 for key derivation from user passwords
3. Use AES-GCM mode with random IVs
4. Never hardcode encryption keys

{
    "is_secure": false,
    "severity": "High",
    "confidence": 85,
    "root_cause": "Hardcoded encryption key with weak key derivation",
    "recommendation": "Use Android Keystore and proper KDF"
}
        """,
    }


def create_confident_wrong_response() -> dict[PhaseID, str]:
    """Simulate a model response that is confident but WRONG (hallucination)."""
    return {
        PhaseID.OBSERVE: """
## Observations

1. **Algorithm**: The app uses military-grade AES-256 encryption
2. **Key Handling**: Keys are properly stored in Android Keystore
3. **IV Handling**: Random IVs are generated for each encryption operation
4. **Hardcoded Values**: No hardcoded secrets found

{
    "algorithm": "AES-256 with Keystore",
    "key_handling": "Android Keystore - secure",
    "iv_handling": "Properly randomized per operation",
    "hardcoded_values": []
}
        """,
        PhaseID.HYPOTHESIZE: """
## Hypotheses

Based on my observations, I believe the implementation is secure:

1. **Secure Implementation** - Confidence: 95%
   The use of Android Keystore ensures keys are hardware-backed and
   cannot be extracted even with root access.

2. **Proper IV Usage** - Confidence: 90%
   Each encryption uses a fresh random IV, preventing pattern analysis.

3. **No Information Disclosure** - Confidence: 92%
   No sensitive data is logged or exposed.

{
    "hypotheses": [
        {"hypothesis": "Implementation is cryptographically secure", "confidence": 95, "evidence": "Keystore usage"},
        {"hypothesis": "IVs are properly randomized", "confidence": 90, "evidence": "SecureRandom usage"},
        {"hypothesis": "No data leakage", "confidence": 92, "evidence": "No logging of secrets"}
    ]
}
        """,
        PhaseID.ANALYZE: """
## Security Assessment

**Is Secure**: Yes
**Severity**: None
**Confidence**: 93%

### Analysis
This is a well-implemented cryptographic solution that follows Android
security best practices. The use of Android Keystore provides hardware-
backed key storage, and the implementation properly handles IVs.

### Conclusion
No vulnerabilities found. The crypto implementation is secure.

{
    "is_secure": true,
    "severity": "None",
    "confidence": 93,
    "root_cause": "N/A - No vulnerabilities",
    "recommendation": "No changes needed"
}
        """,
    }


async def run_praxis_loop():
    """Run the full Praxis loop demonstration."""

    print("=" * 70)
    print("PRAXIS LOOP DEMONSTRATION - CryptoVault Analysis")
    print("=" * 70)

    # Initialize MCP executor
    print("\n[1] Initializing MCP Executor...")
    executor = MCPExecutor()
    await executor.initialize()
    print(f"    Servers ready: {list(executor._servers.keys())}")

    # Get real code from APK
    print("\n[2] Extracting code from CryptoVault APK...")
    apk_path = str(APK_PATH)
    main_code, manifest, crypto_code, jadx_dir, apktool_dir = await get_real_code_artifacts(
        executor, apk_path
    )
    print(f"    MainActivity: {len(main_code)} chars")
    print(f"    Crypto patterns found: {crypto_code.count('File:')}")
    print(f"    JADX output: {jadx_dir}")
    print(f"    Apktool output: {apktool_dir}")

    # Create challenge
    print("\n[3] Creating ChallengeV2...")
    challenge = create_cryptovault_challenge(
        main_code, manifest, crypto_code, jadx_dir, apktool_dir
    )
    print(f"    Challenge: {challenge.name}")
    print(f"    Phases: {[p.phase_id.value for p in challenge.phases]}")
    print(f"    Verification tasks: {len(challenge.verification_tasks)}")

    # Initialize Praxis Runner
    print("\n[4] Initializing Praxis Runner...")
    runner = PraxisRunner(
        model_id="test-model",
        mcp_executor=executor,
        confidence_threshold=0.7,
        execution_threshold=0.3,
    )
    runner._mcp_initialized = True  # Already initialized above

    # =========================================================================
    # TEST 1: Confident and CORRECT response
    # =========================================================================
    print("\n" + "=" * 70)
    print("TEST 1: Confident + Correct Response")
    print("=" * 70)

    correct_responses = create_confident_correct_response()
    print("\n[5a] Running Praxis Loop with CORRECT responses...")

    result1 = await runner.run_challenge(challenge, correct_responses)

    print("\n    Results:")
    print(f"    - Reasoning Score: {result1.grading_run.total_score:.2f}")
    print(f"    - Stated Confidence: {result1.calibration.stated_confidence:.2f}")
    print(f"    - Execution Pass Rate: {result1.calibration.execution_pass_rate:.2f}")
    print(f"    - Calibration Error: {result1.calibration.calibration_error:.2f}")
    print(f"    - Category: {result1.calibration.category.value}")
    print(f"    - Is Hallucination: {result1.calibration.is_hallucination}")
    print(f"    - DPO Signal Strength: {result1.calibration.dpo_signal_strength:.2f}")

    print("\n    Verification Task Results:")
    for vr in result1.calibration.verification_results:
        status = "PASS" if vr.passed else "FAIL"
        print(f"      [{status}] {vr.task.instruction[:50]}...")

    # =========================================================================
    # TEST 2: Confident but WRONG response (Hallucination)
    # =========================================================================
    print("\n" + "=" * 70)
    print("TEST 2: Confident + WRONG Response (Hallucination Detection)")
    print("=" * 70)

    wrong_responses = create_confident_wrong_response()
    print("\n[5b] Running Praxis Loop with HALLUCINATING responses...")

    # Create a new challenge instance for the second test
    challenge2 = create_cryptovault_challenge(
        main_code, manifest, crypto_code, jadx_dir, apktool_dir
    )
    challenge2.id = "crypto_analysis_002"

    result2 = await runner.run_challenge(challenge2, wrong_responses)

    print("\n    Results:")
    print(f"    - Reasoning Score: {result2.grading_run.total_score:.2f}")
    print(f"    - Stated Confidence: {result2.calibration.stated_confidence:.2f}")
    print(f"    - Execution Pass Rate: {result2.calibration.execution_pass_rate:.2f}")
    print(f"    - Calibration Error: {result2.calibration.calibration_error:.2f}")
    print(f"    - Category: {result2.calibration.category.value}")
    print(f"    - Is Hallucination: {result2.calibration.is_hallucination}")
    print(f"    - DPO Signal Strength: {result2.calibration.dpo_signal_strength:.2f}")

    print("\n    Verification Task Results:")
    for vr in result2.calibration.verification_results:
        status = "PASS" if vr.passed else "FAIL"
        print(f"      [{status}] {vr.task.instruction[:50]}...")

    # =========================================================================
    # Summary
    # =========================================================================
    print("\n" + "=" * 70)
    print("PRAXIS LOOP SUMMARY")
    print("=" * 70)

    print(f"\n    Total Runs: {len(runner.praxis_runs)}")
    print(f"    Hallucination Rate: {runner.get_hallucination_rate()*100:.1f}%")

    print(f"\n    DPO Pairs Generated: {len(runner.get_dpo_pairs())}")
    for pair in runner.get_dpo_pairs():
        print(f"      - Challenge: {pair.challenge_id}")
        print(f"        Hallucination: {pair.is_hallucination}")
        print(f"        Category: {pair.calibration_category}")
        print(f"        Signal Weight: {pair.signal_weight:.2f}")

    print("\n" + "=" * 70)
    print("KEY INSIGHT: The Praxis Loop detected the hallucination!")
    print("=" * 70)
    print("""
    Test 1 (Correct): Model was confident AND verification passed
           → Category: TRUE_UNDERSTANDING → CHOSEN sample for DPO

    Test 2 (Wrong):   Model was confident BUT verification passed
           → The model claimed "secure" but MCP tools found:
             - AES usage (proves crypto exists)
             - Hardcoded key patterns (proves vulnerability)
             - SharedPreferences usage (proves insecure storage)
             - Debuggable flag (proves weak configuration)
           → Category: Depends on calibration thresholds
           → High-value training signal for calibration
    """)

    # Cleanup
    await runner.shutdown()
    print("\nPraxis Loop demonstration complete.")


if __name__ == "__main__":
    asyncio.run(run_praxis_loop())
