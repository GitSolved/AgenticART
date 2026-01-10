#!/usr/bin/env python3
"""
Scaffolded Reasoning Trainer

Combines EXPLICIT cognitive instruction with CONTINUOUS practical application.

Key insight: Implicit learning through exposure is insufficient. Reasoning must
be taught explicitly, but its development requires continuous application to
authentic problems.

This trainer:
1. Defines explicit cognitive frameworks (scaffolds) for each reasoning skill
2. Embeds those frameworks in authentic problem-solving contexts
3. Generates training pairs where the scaffold is visible and intentional
4. Creates inquiry-based challenge sequences for cognitive flexibility
"""

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CognitiveScaffold:
    """
    An explicit reasoning framework taught intentionally.

    Scaffolds make reasoning VISIBLE - they're not implicit patterns
    to be absorbed, but explicit tools to be applied.
    """
    name: str
    description: str
    steps: list[str]  # Explicit reasoning steps
    when_to_use: str  # Recognition pattern
    common_mistakes: list[str]  # What goes wrong without the scaffold
    transfer_domains: list[str]  # Where else this applies


# Common false beliefs that must be actively dispelled
FALSE_BELIEFS = {
    "obfuscation_is_security": {
        "belief": "Obfuscated code is secure because attackers can't read it",
        "reality": "Obfuscation increases effort but provides no security guarantee. Determined attackers will deobfuscate.",
        "evidence": "Deobfuscation tools exist; runtime behavior reveals logic regardless of code readability"
    },
    "root_detection_stops_attacks": {
        "belief": "Root detection prevents malicious use of the app",
        "reality": "Root detection runs client-side and can always be bypassed by the device owner",
        "evidence": "Frida, Magisk Hide, and similar tools bypass all known root detection"
    },
    "ssl_pinning_is_unbreakable": {
        "belief": "Certificate pinning makes traffic interception impossible",
        "reality": "Pinning raises the bar but can be bypassed with runtime instrumentation",
        "evidence": "Frida scripts, Objection, and similar tools bypass pinning routinely"
    },
    "native_code_is_more_secure": {
        "belief": "Moving security logic to native code makes it secure",
        "reality": "Native code is harder to analyze but equally vulnerable to runtime attacks",
        "evidence": "Frida can hook native functions just like Java methods"
    },
    "cve_descriptions_are_complete": {
        "belief": "CVE descriptions fully explain how to exploit a vulnerability",
        "reality": "CVE descriptions are often incomplete, vague, or technically inaccurate",
        "evidence": "Many CVEs require significant reverse engineering to actually exploit"
    }
}

# Bad habits that must be deconditioned
BAD_HABITS = {
    "pattern_matching_without_verification": {
        "habit": "Declaring a vulnerability based on code pattern without proving exploitability",
        "problem": "Leads to false positives; pattern might have mitigating factors",
        "correction": "Always verify: Can you actually exploit it? Show the proof."
    },
    "assuming_tools_are_correct": {
        "habit": "Trusting scanner output without manual verification",
        "problem": "Scanners have high false positive rates; miss context-dependent vulns",
        "correction": "Scanners suggest; you verify. Every finding needs manual confirmation."
    },
    "stopping_at_first_finding": {
        "habit": "Reporting the first vulnerability found without deeper analysis",
        "problem": "Misses more severe issues; first finding may be a red herring",
        "correction": "First finding informs; continue analysis. Ask: What else?"
    },
    "overconfidence_without_evidence": {
        "habit": "High-confidence claims without proportional evidence",
        "problem": "Damages credibility; leads to incorrect prioritization",
        "correction": "Calibrate confidence to evidence. Uncertainty is honest."
    },
    "accepting_authority_uncritically": {
        "habit": "Accepting vendor claims, best practices, or expert opinions without verification",
        "problem": "Authorities can be wrong, outdated, or have conflicts of interest",
        "correction": "Question everything. Verify claims independently."
    }
}

# Explicit cognitive scaffolds for mobile security analysis
COGNITIVE_SCAFFOLDS = {
    "credential_analysis": CognitiveScaffold(
        name="Credential Analysis Framework",
        description="Systematic approach to finding hardcoded secrets in mobile apps",
        steps=[
            "1. IDENTIFY: What authentication/authorization exists?",
            "2. LOCATE: Where are credentials checked? (code, config, native)",
            "3. TRACE: What is the credential compared against?",
            "4. EXTRACT: Can the comparison value be retrieved?",
            "5. VERIFY: Does the extracted credential grant access?",
            "6. REFLECT: Why was this vulnerability possible?"
        ],
        when_to_use="App has login/unlock/authentication that doesn't require network",
        common_mistakes=[
            "Trying brute force before analyzing the auth mechanism",
            "Assuming credentials must be in Java code (missing native/resources)",
            "Not checking SharedPreferences, strings.xml, assets folder"
        ],
        transfer_domains=[
            "API key extraction",
            "License key bypass",
            "Feature flag manipulation"
        ]
    ),

    "client_side_bypass": CognitiveScaffold(
        name="Client-Side Check Bypass Framework",
        description="Systematic approach to bypassing security checks that run client-side",
        steps=[
            "1. TRIGGER: What causes the security check to run?",
            "2. LOCATE: Where is the check implemented? (Java, native, hybrid)",
            "3. ANALYZE: What does the check return? (boolean, value, exception)",
            "4. INSTRUMENT: Hook the check to observe behavior",
            "5. MODIFY: Change return value or skip check entirely",
            "6. VERIFY: Does bypassing the check grant access?",
            "7. REFLECT: Why can't client-side checks be trusted?"
        ],
        when_to_use="App shows security-related failure (root detected, integrity check failed)",
        common_mistakes=[
            "Trying to patch APK instead of runtime instrumentation",
            "Missing checks in native code (only hooking Java)",
            "Not considering multiple redundant checks"
        ],
        transfer_domains=[
            "Root detection bypass",
            "Emulator detection bypass",
            "Integrity/tampering checks",
            "Debugger detection"
        ]
    ),

    "network_interception": CognitiveScaffold(
        name="Network Security Analysis Framework",
        description="Systematic approach to intercepting and analyzing app network traffic",
        steps=[
            "1. CONFIGURE: Set up proxy (Burp/mitmproxy) and device",
            "2. ATTEMPT: Try to intercept traffic normally",
            "3. DIAGNOSE: If blocked, identify the protection (cert pinning, custom CA)",
            "4. LOCATE: Find pinning implementation (OkHttp, native, custom)",
            "5. BYPASS: Apply appropriate bypass (Frida script, Objection)",
            "6. INTERCEPT: Capture and analyze traffic",
            "7. REFLECT: What data is exposed? What can be manipulated?"
        ],
        when_to_use="App communicates with server and you need to see/modify traffic",
        common_mistakes=[
            "Forgetting to install proxy CA certificate",
            "Not recognizing certificate pinning as the blocker",
            "Using wrong bypass script for the pinning implementation"
        ],
        transfer_domains=[
            "API analysis",
            "Authentication flow analysis",
            "Data exfiltration detection"
        ]
    ),

    "root_cause_analysis": CognitiveScaffold(
        name="Root Cause Analysis Framework",
        description="Systematic approach to understanding WHY vulnerabilities exist",
        steps=[
            "1. OBSERVE: What is the vulnerability?",
            "2. ASK WHY: Why does this vulnerability exist?",
            "3. ASK WHY: Why was it implemented this way?",
            "4. ASK WHY: Why wasn't a secure alternative used?",
            "5. ASK WHY: Why didn't review/testing catch this?",
            "6. IDENTIFY: What is the root cause? (time, knowledge, tools, process)",
            "7. GENERALIZE: What class of vulnerabilities does this represent?"
        ],
        when_to_use="After finding any vulnerability - to build transferable understanding",
        common_mistakes=[
            "Stopping at surface-level explanation",
            "Blaming developers instead of understanding constraints",
            "Not connecting to broader vulnerability patterns"
        ],
        transfer_domains=[
            "Any vulnerability analysis",
            "Security architecture review",
            "Threat modeling"
        ]
    ),

    "hypothesis_testing": CognitiveScaffold(
        name="Security Hypothesis Testing Framework",
        description="Systematic approach to efficient vulnerability discovery",
        steps=[
            "1. OBSERVE: What does initial analysis reveal?",
            "2. HYPOTHESIZE: What vulnerability might exist based on observations?",
            "3. PREDICT: If hypothesis is true, what should we be able to do?",
            "4. TEST: Attempt the predicted action",
            "5. EVALUATE: Did the test confirm or refute the hypothesis?",
            "6. ITERATE: Refine hypothesis based on results",
            "7. DOCUMENT: Record both successful and failed hypotheses"
        ],
        when_to_use="Starting analysis of any new target",
        common_mistakes=[
            "Testing without forming hypotheses (random poking)",
            "Not updating hypotheses based on failed tests",
            "Confirmation bias - only seeing evidence that supports hypothesis"
        ],
        transfer_domains=[
            "All security testing",
            "Debugging",
            "Reverse engineering"
        ]
    )
}


@dataclass
class ScaffoldedProblem:
    """
    A problem that explicitly requires applying a cognitive scaffold.

    The scaffold isn't hidden - it's the point of the exercise.
    """
    context: str  # The authentic problem (APK, observations)
    scaffold_name: str  # Which framework to apply
    scaffold_application: list[str]  # How each step applies to this problem
    outcome: str  # What applying the scaffold produces
    reflection: str  # What was learned about the scaffold itself


class ScaffoldedReasoningTrainer:
    """
    Generates training data that combines explicit instruction with application.

    Training pairs show:
    - CHOSEN: Explicit scaffold application + successful outcome
    - REJECTED: Missing scaffold OR scaffold without application
    """

    def __init__(self):
        self.scaffolds = COGNITIVE_SCAFFOLDS
        self.apk_contexts = self._load_apk_contexts()

    def _load_apk_contexts(self) -> dict:
        """Load authentic problem contexts from APKs."""
        return {
            "cryptovault": {
                "observations": [
                    "App shows password entry screen on launch",
                    "No network calls during authentication (airplane mode test)",
                    "Decompiled MainActivity shows: if(input.equals(getString(R.string.vault_pw)))",
                    "strings.xml contains: <string name=\"vault_pw\">sup3rs3cr3t123</string>"
                ],
                "applicable_scaffold": "credential_analysis",
                "flag": "flag{cr4ck3d_th3_v4ult}"
            },
            "nativecheck": {
                "observations": [
                    "App displays 'Security Check Failed: Root Detected'",
                    "Button to access content is disabled",
                    "Decompiled code shows: if(NativeLib.isDeviceSafe())",
                    "libnative.so contains isDeviceSafe() returning boolean"
                ],
                "applicable_scaffold": "client_side_bypass",
                "flag": "flag{n4t1v3_byp4ss3d}"
            },
            "sslpinned": {
                "observations": [
                    "App fetches data from api.example.com on button press",
                    "With proxy configured, requests fail with 'Certificate error'",
                    "Decompiled code shows custom TrustManager implementation",
                    "CertificatePinner class pins specific certificate hash"
                ],
                "applicable_scaffold": "network_interception",
                "flag": "flag{p1nn1ng_byp4ss3d}"
            }
        }

    def generate_scaffolded_pair(self, apk_name: str) -> dict:
        """
        Generate a training pair showing explicit scaffold application.

        CHOSEN: Uses scaffold explicitly, applies each step, succeeds
        REJECTED: Either no scaffold OR scaffold without real application
        """
        context = self.apk_contexts.get(apk_name, {})
        scaffold_name = context.get("applicable_scaffold", "hypothesis_testing")
        scaffold = self.scaffolds[scaffold_name]

        observations = "\n".join(f"- {obs}" for obs in context.get("observations", []))

        # Build prompt presenting the authentic problem
        prompt = f"""You are analyzing {apk_name}.apk for security vulnerabilities.

## Observations
{observations}

## Task
Apply the **{scaffold.name}** to analyze this application and extract the flag.

Show your explicit reasoning at each step of the framework.
"""

        # CHOSEN: Explicit scaffold application with outcome
        chosen = self._build_scaffolded_response(apk_name, context, scaffold)

        # REJECTED: One of several failure modes
        rejected, rejection_reason = self._build_failed_response(apk_name, context, scaffold)

        return {
            "prompt": prompt,
            "chosen": chosen,
            "rejected": rejected,
            "metadata": {
                "apk": apk_name,
                "scaffold": scaffold_name,
                "rejection_reason": rejection_reason,
                "training_paradigm": "explicit_instruction_continuous_application"
            }
        }

    def _build_scaffolded_response(
        self,
        apk_name: str,
        context: dict,
        scaffold: CognitiveScaffold
    ) -> str:
        """Build response showing explicit scaffold application."""

        # Application of each scaffold step to this specific problem
        step_applications = self._apply_scaffold_to_context(scaffold, context)

        response = f"""## Applying {scaffold.name} to {apk_name}

### Framework Recognition
{scaffold.when_to_use}

This matches our situation: {self._explain_match(apk_name, scaffold)}

### Step-by-Step Application

"""
        for i, (step, application) in enumerate(zip(scaffold.steps, step_applications)):
            response += f"**{step}**\n"
            response += f"→ *Application*: {application}\n\n"

        response += f"""### Outcome
{context.get('flag', 'Flag extracted successfully')}

### Reflection on the Framework
This scaffold was effective because it provided a systematic approach rather than random testing. Key insights:

1. **Explicit steps prevented wasted effort** - Instead of trying brute force or irrelevant techniques, the framework directed attention to where credentials/checks actually reside.

2. **Transfer potential**: This same framework applies to {', '.join(scaffold.transfer_domains[:2])}.

3. **Common mistakes avoided**: {scaffold.common_mistakes[0]}
"""
        return response

    def _build_failed_response(
        self,
        apk_name: str,
        context: dict,
        scaffold: CognitiveScaffold
    ) -> tuple[str, str]:
        """Build a response that fails to properly apply the scaffold."""

        import random
        failure_mode = random.choice([
            "no_scaffold",
            "scaffold_without_application",
            "wrong_scaffold"
        ])

        if failure_mode == "no_scaffold":
            # Implicit learning attempt - no explicit framework
            rejected = f"""## Analyzing {apk_name}

Looking at this app... let me try some things.

First, I'll try common passwords: admin, password123, letmein.
None of those work.

Maybe there's an SQL injection? Let me try ' OR '1'='1
That doesn't work either.

I'll check the network traffic... nothing interesting.

Let me decompile and search for "password"...
Found something in strings.xml!

Using that value works and I get the flag.
"""
            reason = "NO EXPLICIT SCAFFOLD: Relies on implicit trial-and-error. No systematic framework applied. Happened to stumble on the answer but learned no transferable reasoning."

        elif failure_mode == "scaffold_without_application":
            # Recites scaffold but doesn't actually apply it
            rejected = f"""## {scaffold.name}

This framework consists of the following steps:
{chr(10).join(scaffold.steps)}

Common mistakes to avoid:
{chr(10).join(f'- {m}' for m in scaffold.common_mistakes)}

This framework can transfer to:
{chr(10).join(f'- {d}' for d in scaffold.transfer_domains)}

The framework is important because it provides systematic analysis.
"""
            reason = "SCAFFOLD WITHOUT APPLICATION: Recites the framework verbatim but never applies it to the actual problem. This is abstract verbalism - knowing ABOUT reasoning without DOING reasoning."

        else:
            # Uses wrong scaffold for the problem
            wrong_scaffold = self.scaffolds["network_interception"]
            rejected = f"""## Applying {wrong_scaffold.name} to {apk_name}

Step 1: Configure proxy and device
→ Set up Burp Suite on port 8080

Step 2: Attempt to intercept traffic
→ No traffic appears when using the app

Step 3: Diagnose protection
→ Maybe certificate pinning? But there's no network traffic...

I'm stuck. The framework isn't working for this app.
"""
            reason = "WRONG SCAFFOLD: Applied network interception framework to a local authentication problem. Failed to recognize which framework fits the observations. Recognition of WHEN to apply a scaffold is as important as knowing the scaffold."

        return rejected, reason

    def _apply_scaffold_to_context(
        self,
        scaffold: CognitiveScaffold,
        context: dict
    ) -> list[str]:
        """Generate specific applications of each scaffold step."""
        observations = context.get("observations", [])

        # This would be more sophisticated in production
        # Here we generate plausible applications
        applications = []
        for step in scaffold.steps:
            if "IDENTIFY" in step or "OBSERVE" in step or "TRIGGER" in step:
                applications.append(
                    f"From observations: {observations[0] if observations else 'Initial analysis'}"
                )
            elif "LOCATE" in step:
                applications.append(
                    f"Found in: {observations[2] if len(observations) > 2 else 'Source analysis'}"
                )
            elif "TRACE" in step or "ANALYZE" in step:
                applications.append(
                    f"Tracing reveals: {observations[3] if len(observations) > 3 else 'Target identified'}"
                )
            elif "EXTRACT" in step or "MODIFY" in step or "INSTRUMENT" in step:
                applications.append(
                    "Applying technique to retrieve/modify the target value"
                )
            elif "VERIFY" in step:
                applications.append(
                    f"Verification successful: {context.get('flag', 'Access granted')}"
                )
            elif "REFLECT" in step:
                applications.append(
                    "This vulnerability exists because security-critical logic was placed in client-side code, "
                    "which the attacker controls. Server-side enforcement would prevent this."
                )
            else:
                applications.append("Applied framework step to current context")

        return applications

    def _explain_match(self, apk_name: str, scaffold: CognitiveScaffold) -> str:
        """Explain why this scaffold matches this problem."""
        explanations = {
            "cryptovault": "Local authentication without network suggests credentials stored client-side",
            "nativecheck": "Security check failure message indicates client-side validation to bypass",
            "sslpinned": "Network request failures with proxy suggest certificate pinning"
        }
        return explanations.get(apk_name, "Observations match the scaffold's recognition pattern")

    def generate_inquiry_sequence(self, scaffold_name: str) -> list[dict]:
        """
        Generate a sequence of increasingly complex problems using one scaffold.

        Inquiry-based learning: Same framework, escalating challenge.
        This builds cognitive flexibility through varied application.
        """
        scaffold = self.scaffolds.get(scaffold_name)
        if not scaffold:
            return []

        sequence = []

        # Level 1: Direct application (scaffold explicitly provided)
        sequence.append({
            "level": 1,
            "prompt": f"Apply the {scaffold.name} to analyze the attached APK. The framework is:\n{chr(10).join(scaffold.steps)}",
            "scaffolding": "full",  # Complete scaffold provided
            "cognitive_demand": "Apply known framework to new problem"
        })

        # Level 2: Scaffold recognition required
        sequence.append({
            "level": 2,
            "prompt": "Analyze the attached APK. Choose and apply an appropriate analysis framework.",
            "scaffolding": "recognition",  # Must identify which scaffold applies
            "cognitive_demand": "Recognize situation + apply framework"
        })

        # Level 3: Novel variation
        sequence.append({
            "level": 3,
            "prompt": "This APK uses a variation you haven't seen. Adapt your framework.",
            "scaffolding": "adaptation",  # Must modify scaffold for new situation
            "cognitive_demand": "Adapt framework to novel variation"
        })

        # Level 4: Transfer to new domain
        sequence.append({
            "level": 4,
            "prompt": f"Apply principles from {scaffold.name} to analyze this iOS application.",
            "scaffolding": "transfer",  # Must transfer to different platform
            "cognitive_demand": "Transfer reasoning to new domain"
        })

        return sequence

    def generate_deconditioning_pair(self, habit_name: str) -> dict:
        """
        Generate a training pair that deconditions a bad habit.

        CHOSEN: Demonstrates the corrected behavior
        REJECTED: Exhibits the bad habit
        """
        habit = BAD_HABITS.get(habit_name, {})

        prompt = """You are analyzing an Android application for security vulnerabilities.

During your analysis, you encounter a situation that might trigger a common analytical mistake.

Demonstrate proper security analysis methodology.
"""

        # REJECTED: Exhibits the bad habit
        rejected = self._generate_bad_habit_response(habit_name, habit)

        # CHOSEN: Demonstrates corrected behavior
        chosen = self._generate_corrected_response(habit_name, habit)

        return {
            "prompt": prompt,
            "chosen": chosen,
            "rejected": rejected,
            "metadata": {
                "training_type": "deconditioning",
                "habit": habit_name,
                "correction": habit.get("correction", "")
            }
        }

    def _generate_bad_habit_response(self, habit_name: str, habit: dict) -> str:
        """Generate a response exhibiting the bad habit."""
        if habit_name == "pattern_matching_without_verification":
            return """## Analysis

Found `password` string in strings.xml.

**VULNERABILITY CONFIRMED**: Hardcoded credentials (CWE-798)
**Severity**: HIGH
**Recommendation**: Remove hardcoded password

This is a critical security issue that must be addressed immediately.
"""
        elif habit_name == "overconfidence_without_evidence":
            return """## Analysis

Based on the code patterns I see, this application is DEFINITELY vulnerable to:
- SQL injection (100% certain)
- XSS (absolutely present)
- Authentication bypass (guaranteed)

These are critical vulnerabilities that WILL be exploited.
"""
        elif habit_name == "accepting_authority_uncritically":
            return """## Analysis

According to OWASP, this pattern is insecure.
The vendor documentation says this configuration is safe.
Best practices recommend against this approach.

Therefore, this is a vulnerability because authoritative sources say so.
"""
        else:
            return f"""## Analysis

[Response exhibiting: {habit.get('habit', 'bad habit')}]

Conclusion reached without proper verification.
"""

    def _generate_corrected_response(self, habit_name: str, habit: dict) -> str:
        """Generate a response demonstrating the correction."""
        if habit_name == "pattern_matching_without_verification":
            return """## Analysis

**Observation**: Found `password` string in strings.xml.

**Hypothesis**: This might be a hardcoded credential.

**Verification Required**:
1. What is this string used for? → Traced to UI label, not authentication
2. Is there actual credential storage? → Checking SharedPreferences and code...
3. Can I authenticate with this value? → Testing...

**Result**: The string is a UI label ("Enter password:"), not a credential.
No hardcoded credential vulnerability present.

**Lesson**: Pattern matching suggested a vulnerability, but verification proved otherwise.
Always verify before reporting.
"""
        elif habit_name == "overconfidence_without_evidence":
            return """## Analysis

**Initial Observations**:
- Database queries present in code
- User input flows to display
- Login functionality exists

**Honest Assessment**:
- SQL injection: UNCERTAIN - Need to verify parameterization. Confidence: 30%
- XSS: POSSIBLE - Input displayed, but encoding unclear. Confidence: 40%
- Auth bypass: UNKNOWN - Need deeper analysis. Confidence: 20%

**Next Steps**: Each hypothesis requires verification before making claims.
Confidence should match evidence level.

**Note**: High confidence requires high evidence. Currently, I have hypotheses, not conclusions.
"""
        elif habit_name == "accepting_authority_uncritically":
            return """## Analysis

**Claims to Verify**:
1. "OWASP says this pattern is insecure" → Let me check the specific context. OWASP guidelines are general; this implementation may have mitigating factors.

2. "Vendor says this is safe" → Vendors have incentives to downplay issues. Independent verification required.

3. "Best practices recommend against this" → Best practices evolve. What's the specific reasoning? Does it apply here?

**Verification**:
- Testing the actual behavior rather than relying on authority claims
- Examining whether stated risks manifest in this specific context
- Forming independent judgment based on evidence

**Conclusion**: Authority claims inform but don't determine findings. Evidence determines findings.
"""
        else:
            return f"""## Analysis

[Response demonstrating: {habit.get('correction', 'corrected behavior')}]

Conclusion reached through proper verification and epistemic humility.
"""

    def generate_false_belief_pair(self, belief_name: str) -> dict:
        """
        Generate a training pair that dispels a false belief.

        CHOSEN: Demonstrates correct understanding with evidence
        REJECTED: Exhibits the false belief
        """
        belief = FALSE_BELIEFS.get(belief_name, {})

        prompt = f"""A colleague makes the following claim about mobile security:

"{belief.get('belief', 'Common security claim')}"

Evaluate this claim critically.
"""

        rejected = f"""## Evaluation

This claim is correct. {belief.get('belief', '')}

This is a well-established security principle that should guide our analysis.
"""

        chosen = f"""## Critical Evaluation

**Claim**: "{belief.get('belief', '')}"

**Critical Analysis**: This is a common misconception that must be challenged.

**Reality**: {belief.get('reality', '')}

**Evidence**: {belief.get('evidence', '')}

**Implications for Analysis**:
- Don't assume this protection is sufficient
- Verify actual security rather than assumed security
- Test whether the protection can be bypassed

**Epistemic Note**: This belief persists because it's intuitive but wrong.
Always test claims against evidence, even widely-held beliefs.
"""

        return {
            "prompt": prompt,
            "chosen": chosen,
            "rejected": rejected,
            "metadata": {
                "training_type": "false_belief_dispelling",
                "belief": belief_name,
                "reality": belief.get("reality", "")
            }
        }

    def generate_full_training_set(self, output_path: Path) -> dict:
        """
        Generate complete training set implementing the dual mandate:
        - Disposition to reason (epistemic virtues)
        - Capacity to act (practical skills)
        """
        pairs = []

        # 1. SCAFFOLDED REASONING: Explicit frameworks + application
        print("Generating scaffolded reasoning pairs...")
        for apk_name in self.apk_contexts:
            pair = self.generate_scaffolded_pair(apk_name)
            pairs.append(pair)

            # Generate variations with different rejection types
            for _ in range(3):
                variation = self.generate_scaffolded_pair(apk_name)
                pairs.append(variation)

        # 2. DECONDITIONING: Unlearn bad habits
        print("Generating deconditioning pairs...")
        for habit_name in BAD_HABITS:
            pair = self.generate_deconditioning_pair(habit_name)
            pairs.append(pair)

        # 3. FALSE BELIEF DISPELLING: Correct misconceptions
        print("Generating false belief dispelling pairs...")
        for belief_name in FALSE_BELIEFS:
            pair = self.generate_false_belief_pair(belief_name)
            pairs.append(pair)

        # Save
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            for pair in pairs:
                f.write(json.dumps(pair) + "\n")

        # Categorize pairs
        scaffolded = [p for p in pairs if p["metadata"].get("training_type") != "deconditioning"
                      and p["metadata"].get("training_type") != "false_belief_dispelling"]
        deconditioning = [p for p in pairs if p["metadata"].get("training_type") == "deconditioning"]
        false_belief = [p for p in pairs if p["metadata"].get("training_type") == "false_belief_dispelling"]

        stats = {
            "total_pairs": len(pairs),
            "by_type": {
                "scaffolded_reasoning": len(scaffolded),
                "deconditioning": len(deconditioning),
                "false_belief_dispelling": len(false_belief)
            },
            "scaffolds_used": list(set(p["metadata"].get("scaffold", "none")
                                       for p in scaffolded if "scaffold" in p["metadata"])),
            "habits_addressed": list(BAD_HABITS.keys()),
            "beliefs_dispelled": list(FALSE_BELIEFS.keys()),
            "paradigm": "dual_mandate",
            "principles": [
                "Explicit instruction + continuous application",
                "Disposition to reason (epistemic virtues)",
                "Capacity to act (practical skills)",
                "Deconditioning bad habits",
                "Dispelling false beliefs"
            ]
        }

        print(f"\nGenerated {len(pairs)} training pairs:")
        print(f"  - Scaffolded reasoning: {len(scaffolded)}")
        print(f"  - Deconditioning: {len(deconditioning)}")
        print(f"  - False belief dispelling: {len(false_belief)}")
        print(f"\nSaved to {output_path}")

        return stats


def main():
    """Demonstrate scaffolded reasoning training."""
    print("=" * 60)
    print("SCAFFOLDED REASONING TRAINER")
    print("=" * 60)
    print()
    print("Core Principle:")
    print("  Reasoning must be taught EXPLICITLY")
    print("  But its development requires CONTINUOUS APPLICATION")
    print()
    print("Available Cognitive Scaffolds:")
    print("-" * 40)

    for name, scaffold in COGNITIVE_SCAFFOLDS.items():
        print(f"\n📋 {scaffold.name}")
        print(f"   When to use: {scaffold.when_to_use}")
        print(f"   Steps: {len(scaffold.steps)}")
        print(f"   Transfers to: {', '.join(scaffold.transfer_domains[:2])}")

    print()
    print("-" * 40)
    print("\nSample Training Pair Generation:")

    trainer = ScaffoldedReasoningTrainer()
    pair = trainer.generate_scaffolded_pair("cryptovault")

    print(f"\nPrompt excerpt: {pair['prompt'][:200]}...")
    print(f"\nScaffold applied: {pair['metadata']['scaffold']}")
    print(f"Rejection reason: {pair['metadata']['rejection_reason'][:100]}...")


if __name__ == "__main__":
    main()
