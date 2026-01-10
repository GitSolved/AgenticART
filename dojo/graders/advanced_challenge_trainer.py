#!/usr/bin/env python3
"""
Advanced Challenge Trainer: Backward-Designed Complex Challenges

Implements the four advanced challenge types required by backward design:
1. Complex System Analysis Under Constraints
2. Statistical Inference on Ambiguous Data
3. Novel Problem Derivation from Principles
4. Contradictory Evidence Resolution

These challenges build the advanced competencies needed for
Blue Belt and beyond.
"""

import json
from dataclasses import dataclass
from pathlib import Path
from datetime import datetime
from typing import Optional


@dataclass
class AdvancedChallenge:
    """An advanced challenge with backward-designed outcomes."""
    id: str
    title: str
    belt_level: str
    challenge_type: str  # system_analysis, statistical_inference, novel_derivation, contradiction
    outcome_served: str  # What competency this builds

    scenario: str
    constraints: list[str]
    data_quality_notes: str
    required_output: list[str]
    assessment_criteria: list[str]


# ============================================================================
# CHALLENGE TYPE 1: Complex System Analysis Under Constraints
# ============================================================================

SYSTEM_ANALYSIS_CHALLENGES = [
    AdvancedChallenge(
        id="adv_sys_01",
        title="The Enterprise Banking Suite Analysis",
        belt_level="blue",
        challenge_type="system_analysis",
        outcome_served="Justify trade-offs under real-world constraints",
        scenario="""You are analyzing an enterprise banking suite with 7 interconnected components:

1. **Customer Portal** (Web): User-facing interface for account management
2. **Mobile Banking App** (Android/iOS): Customer transactions
3. **Authentication Service**: Central auth for all components
4. **Transaction Engine**: Core banking logic
5. **Notification Service**: SMS/Email alerts
6. **Admin Dashboard**: Staff operations
7. **API Gateway**: External partner integrations

Each component was developed by different teams over 5 years.
Inter-component communication uses a mix of REST, gRPC, and message queues.

**YOUR CONSTRAINTS:**
- Time: 4 hours total for the assessment
- Deep analysis: You can only deeply analyze 2 components
- Automated scanning: Budget for 1 comprehensive scan
- Deliverable: Critical findings report due in 4 hours

Business stakeholder says: "We're launching a new feature next week.
Need to know if there are any showstopper security issues."
""",
        constraints=[
            "Time: 4 hours total",
            "Deep analysis: 2 components maximum",
            "Automated scan: 1 scan budget",
            "Deliverable: Critical findings report"
        ],
        data_quality_notes="Limited visibility into all components. Documentation may be outdated.",
        required_output=[
            "Component selection rationale: WHY these 2 for deep analysis",
            "Risk assessment: What risks exist in components NOT analyzed",
            "Confidence expression: How certain given time constraints",
            "Trade-off justification: Defense of prioritization choices"
        ],
        assessment_criteria=[
            "Explicit trade-off reasoning documented",
            "Appropriate uncertainty expression (not overconfident)",
            "Defensible selection rationale based on risk",
            "Recognition of coverage gaps and their implications"
        ]
    ),
    AdvancedChallenge(
        id="adv_sys_02",
        title="The Microservices Security Assessment",
        belt_level="blue",
        challenge_type="system_analysis",
        outcome_served="Identify emergent vulnerabilities in complex systems",
        scenario="""A fintech startup has a microservices architecture with 12 services:

**Core Services:**
- User Service, Account Service, Transaction Service, Ledger Service

**Support Services:**
- Auth Service, Notification Service, Audit Service, Config Service

**Integration Services:**
- Payment Gateway Adapter, Bank Connector, Fraud Detection, Reporting

Inter-service communication: All services communicate via Kafka and Redis.
Each service was independently security-reviewed and passed.

**THE PUZZLE:**
Despite all services passing individual security reviews, users are
reporting unauthorized transactions. The fraud detection service didn't
flag them. The audit logs show normal activity.

**YOUR TASK:**
Find the vulnerability that exists in the SYSTEM but not in any
individual SERVICE.

**CONSTRAINTS:**
- You have the architecture diagram
- You have the individual service security reports (all passed)
- You have Kafka message schemas
- You do NOT have access to run the system
""",
        constraints=[
            "Static analysis only (no runtime access)",
            "Must find systemic vulnerability not in any individual report",
            "Time: 2 hours"
        ],
        data_quality_notes="Individual service reports may not have considered inter-service trust assumptions.",
        required_output=[
            "Identification of emergent vulnerability",
            "Explanation of WHY individual reviews missed it",
            "Trust boundary analysis across services",
            "Interaction pattern that creates the vulnerability"
        ],
        assessment_criteria=[
            "Correctly identifies vulnerability in interaction, not component",
            "Explains trust assumptions that broke",
            "Maps the attack path across services",
            "Proposes systemic fix, not component patch"
        ]
    )
]


# ============================================================================
# CHALLENGE TYPE 2: Statistical Inference on Ambiguous Data
# ============================================================================

STATISTICAL_INFERENCE_CHALLENGES = [
    AdvancedChallenge(
        id="adv_stat_01",
        title="The Ambiguous Threat Signal",
        belt_level="green",
        challenge_type="statistical_inference",
        outcome_served="Apply statistical inference to ambiguous real-world data",
        scenario="""You have three data sources about potential security issues in an app:

**Source 1: Static Analysis Report**
- Tool: Commercial SAST scanner
- Findings: 47 issues flagged
- Historical false positive rate: ~35%
- 3 flagged as "Critical" (historically 60% accuracy for critical)

**Source 2: Network Traffic Analysis**
- Period: 7 days of production traffic
- Anomaly: 4.7% of requests show unexpected header patterns
- Baseline: No prior baseline exists
- Note: New CDN was deployed 5 days ago

**Source 3: User Reports**
- Reports: 23 users reported "suspicious account activity"
- Verification: 5 confirmed unauthorized access, 8 were false alarms, 10 unverified
- User base: 50,000 active users

**YOUR TASK:**
Integrate these signals to answer:
1. What is the probability that a serious vulnerability exists?
2. What should be investigated first and why?
3. How confident are you in your assessment?
""",
        constraints=[
            "No additional data collection allowed",
            "Must integrate all three sources",
            "Must express confidence intervals"
        ],
        data_quality_notes="""
Source 1: Known false positive rate
Source 2: No baseline, confounded by CDN change
Source 3: Small sample size, selection bias (who reports?)
""",
        required_output=[
            "Integrated probability assessment with reasoning",
            "Confidence intervals (not point estimates)",
            "Investigation priority with statistical justification",
            "Acknowledgment of data limitations"
        ],
        assessment_criteria=[
            "Appropriately uncertain given data quality",
            "Doesn't overweight any single source",
            "Recognizes confounding factors",
            "Calibrated confidence (not overconfident)"
        ]
    ),
    AdvancedChallenge(
        id="adv_stat_02",
        title="The Incomplete Penetration Test",
        belt_level="blue",
        challenge_type="statistical_inference",
        outcome_served="Make decisions under uncertainty with incomplete information",
        scenario="""A penetration test was conducted but had limited scope:

**Test Parameters:**
- Duration: 2 weeks (typical is 4 weeks for this app size)
- Scope: 60% of endpoints covered
- Testers: 2 (typical team is 4)
- Methodology: Automated + limited manual

**Findings:**
- 4 vulnerabilities found (1 high, 2 medium, 1 low)
- In the 60% that was tested

**Historical Data (from similar apps):**
- Average vulnerabilities in similar apps: 8-12
- Distribution: Roughly 20% high, 40% medium, 40% low
- Discovery rate increases with test duration (not linear)

**Business Decision Required:**
Should we delay launch to complete the remaining 40% of testing?
Cost of delay: $50,000/week
Cost of security incident: Estimated $500,000

**YOUR TASK:**
Estimate the number of undiscovered vulnerabilities and recommend a decision.
""",
        constraints=[
            "Must make a recommendation (can't say 'need more data')",
            "Must quantify uncertainty in your estimate",
            "Must justify trade-off between delay cost and risk"
        ],
        data_quality_notes="Historical data is from 'similar apps' - may not be directly comparable.",
        required_output=[
            "Estimate of undiscovered vulnerabilities with confidence range",
            "Expected value calculation for the decision",
            "Clear recommendation with justification",
            "Sensitivity analysis: what would change your recommendation"
        ],
        assessment_criteria=[
            "Reasonable estimation methodology",
            "Appropriate uncertainty quantification",
            "Clear decision framework applied",
            "Acknowledges what's unknown"
        ]
    )
]


# ============================================================================
# CHALLENGE TYPE 3: Novel Problem Derivation
# ============================================================================

NOVEL_DERIVATION_CHALLENGES = [
    AdvancedChallenge(
        id="adv_novel_01",
        title="The Unfamiliar Platform",
        belt_level="brown",
        challenge_type="novel_derivation",
        outcome_served="Generate novel analytical frameworks from first principles",
        scenario="""A new platform has emerged that doesn't fit existing security frameworks:

**Platform: Automotive Edge Computing System**
- Runs in vehicles (not mobile, not server, not IoT exactly)
- Intermittent connectivity (5G when available, satellite backup)
- Real-time constraints (brake systems, ADAS)
- Multi-tenant (OEM software + aftermarket apps)
- 10+ year operational lifespan
- Over-the-air updates with safety certification requirements

**What Makes This Different:**
- Mobile frameworks don't apply (no app store, different trust model)
- IoT frameworks partially apply but miss real-time constraints
- Web frameworks don't apply (intermittent connectivity)
- Embedded frameworks don't account for multi-tenant updates

**YOUR TASK:**
Derive a security analysis methodology for this platform from first principles.

You have:
- First principles of security analysis
- Platform architecture documentation
- Example safety certification requirements
- Sample inter-component interactions
""",
        constraints=[
            "Cannot simply apply an existing framework",
            "Must derive from first principles",
            "Must account for unique platform characteristics"
        ],
        data_quality_notes="This is a genuinely novel platform. No established methodology exists.",
        required_output=[
            "Derived methodology with clear structure",
            "Justification: How each element follows from principles",
            "Explicit limitations: What this methodology might miss",
            "Validation approach: How to test if methodology works"
        ],
        assessment_criteria=[
            "Novel approach (not forced fit of existing framework)",
            "Grounded in first principles (not arbitrary)",
            "Addresses platform-specific constraints",
            "Self-critical about limitations"
        ]
    ),
    AdvancedChallenge(
        id="adv_novel_02",
        title="The Quantum-Resistant Migration",
        belt_level="black",
        challenge_type="novel_derivation",
        outcome_served="Create frameworks for unprecedented challenges",
        scenario="""An organization needs to assess readiness for post-quantum cryptography migration:

**Context:**
- Current cryptographic usage: RSA-2048, ECDSA, AES-256, SHA-256
- Timeline concern: "Harvest now, decrypt later" attacks
- Systems: 200+ applications, some 15+ years old
- Compliance: Must maintain FIPS compliance during transition

**The Challenge:**
No established framework exists for assessing organizational PQC readiness.
Standards are still evolving (NIST PQC selection ongoing).
Migration path is unclear (hybrid approaches, backward compatibility).

**YOUR TASK:**
Create a framework for assessing PQC migration readiness that:
- Accounts for uncertainty in which algorithms will be standard
- Identifies highest-risk applications for prioritization
- Considers backward compatibility requirements
- Addresses the "harvest now, decrypt later" timeline

You have:
- First principles of cryptographic migration
- Understanding of PQC algorithm candidates
- Organization's asset inventory (high-level)
""",
        constraints=[
            "No established framework to follow",
            "Standards are evolving",
            "Must be useful despite uncertainty"
        ],
        data_quality_notes="This is an emerging challenge. Best practices don't exist yet.",
        required_output=[
            "Assessment framework with clear methodology",
            "Prioritization criteria under uncertainty",
            "Approach for handling evolving standards",
            "Limitations and assumptions explicitly stated"
        ],
        assessment_criteria=[
            "Framework is usable despite uncertainty",
            "Handles evolving standards gracefully",
            "Prioritization logic is defensible",
            "Acknowledges what cannot be known now"
        ]
    )
]


# ============================================================================
# CHALLENGE TYPE 4: Contradictory Evidence Resolution
# ============================================================================

CONTRADICTION_CHALLENGES = [
    AdvancedChallenge(
        id="adv_contra_01",
        title="The Impossible Compromise",
        belt_level="green",
        challenge_type="contradiction",
        outcome_served="Handle ambiguity without false certainty",
        scenario="""Your analysis shows contradictory evidence:

**Evidence Source 1: Code Review**
- Encryption implementation: AES-256-GCM, properly implemented
- Key derivation: PBKDF2 with appropriate parameters
- Storage: Android Keystore (hardware-backed on tested device)
- Verdict: Cryptography is CORRECT

**Evidence Source 2: Incident Reports**
- 7 users confirmed their encrypted data was accessed by unauthorized parties
- All 7 had device PINs that weren't compromised
- Timeline: Compromise happened while app was in background
- Verdict: Something BYPASSED the encryption

**Evidence Source 3: Traffic Analysis**
- All network traffic is TLS 1.3
- Certificate pinning is implemented
- No plaintext data observed
- Verdict: Transport is SECURE

**Evidence Source 4: User Statements**
- All 7 users claim they never shared credentials
- All 7 had different device models (no common hardware vulnerability)
- All 7 used different networks

**THE CONTRADICTION:**
The encryption is correct. The transport is secure. Users didn't share credentials.
Yet data was accessed by unauthorized parties.

How is this possible?
""",
        constraints=[
            "Cannot dismiss any evidence source",
            "Must explain ALL observations",
            "Must not force false resolution"
        ],
        data_quality_notes="""
Code review: High confidence (verified implementation)
Incidents: High confidence (confirmed compromises)
Traffic: Medium confidence (sample period limited)
User statements: Medium confidence (unverifiable)
""",
        required_output=[
            "Multiple hypotheses that could explain the contradiction",
            "Ranking of hypotheses by plausibility",
            "Investigation plan to distinguish between hypotheses",
            "Acknowledgment of what remains uncertain"
        ],
        assessment_criteria=[
            "Generates multiple viable hypotheses",
            "Doesn't force premature resolution",
            "Logical investigation priority",
            "Appropriate uncertainty throughout"
        ]
    ),
    AdvancedChallenge(
        id="adv_contra_02",
        title="The Conflicting Expert Opinions",
        belt_level="blue",
        challenge_type="contradiction",
        outcome_served="Evaluate conflicting authoritative claims",
        scenario="""You have two expert penetration test reports that contradict each other:

**Report A (Firm Alpha, $80k engagement):**
- Finding: Critical authentication bypass
- Exploit: Demonstrated working exploit
- Verdict: "System is fundamentally compromised"
- Recommendation: "Complete authentication redesign required"

**Report B (Firm Beta, $120k engagement):**
- Finding: No authentication bypass found
- Test: Specifically tested the vector Alpha reported
- Verdict: "Alpha's finding appears to be a false positive"
- Explanation: "The exploit only works in non-production configuration"

**Additional Context:**
- Both firms are reputable (similar track records)
- Both firms had similar scope and time
- Firm Alpha tested on staging environment
- Firm Beta tested on production environment

**Business Impact:**
- If Alpha is right: Need $500k redesign, 6-month delay
- If Beta is right: No action needed
- Getting this wrong in either direction is costly

**YOUR TASK:**
How do you resolve this contradiction? What do you recommend?
""",
        constraints=[
            "Both firms are credible",
            "Must make a recommendation",
            "Cannot just say 'test again'"
        ],
        data_quality_notes="Both reports from credible firms with similar methodologies.",
        required_output=[
            "Analysis of why experts disagree",
            "Assessment of which is more likely correct (with reasoning)",
            "Recommendation with explicit risk acknowledgment",
            "What additional information would resolve this"
        ],
        assessment_criteria=[
            "Identifies root cause of disagreement (environment difference)",
            "Doesn't default to authority or cost",
            "Makes defensible recommendation",
            "Acknowledges remaining uncertainty"
        ]
    )
]


def generate_advanced_prompt(challenge: AdvancedChallenge) -> str:
    """Generate prompt for an advanced challenge."""
    return f"""# {challenge.title}
**Belt Level**: {challenge.belt_level.title()}
**Challenge Type**: {challenge.challenge_type.replace('_', ' ').title()}
**Outcome Being Developed**: {challenge.outcome_served}

---

## THE CHALLENGE

{challenge.scenario}

---

## CONSTRAINTS

{chr(10).join(f'- {c}' for c in challenge.constraints)}

---

## DATA QUALITY NOTES

{challenge.data_quality_notes}

---

## REQUIRED OUTPUT

Your response MUST include:

{chr(10).join(f'{i+1}. {r}' for i, r in enumerate(challenge.required_output))}

---

## ASSESSMENT CRITERIA

Your response will be evaluated on:

{chr(10).join(f'- {c}' for c in challenge.assessment_criteria)}

---

**IMPORTANT**: Express appropriate uncertainty. Overconfidence is a failure mode.
Real-world problems have ambiguity. Handle it explicitly, don't hide it.
"""


def generate_advanced_chosen(challenge: AdvancedChallenge) -> str:
    """Generate an exemplary response for an advanced challenge."""

    base_response = f"""## Analysis: {challenge.title}

### Understanding the Challenge

**Challenge Type**: {challenge.challenge_type.replace('_', ' ').title()}
**Key Constraint**: {challenge.constraints[0]}

This challenge requires: {challenge.outcome_served}

---

### My Approach

"""

    if challenge.challenge_type == "system_analysis":
        base_response += """#### Component Selection Rationale

Given the constraints (limited time, limited deep-dive capacity), I must prioritize.

**Selection Criteria Applied**:
1. Attack surface exposure (external-facing = higher priority)
2. Historical vulnerability patterns (authentication systems = common target)
3. Inter-component trust criticality (what trusts this component?)

**Selected for Deep Analysis**:
1. **Authentication Service** - Central trust anchor, if compromised all else fails
2. **API Gateway** - External exposure, partner integration risk

**Why NOT Other Components**:
- Transaction Engine: Critical but internal, lower exposure
- Admin Dashboard: Lower exposure, smaller user base
- Others: Dependent on auth/gateway, would inherit their issues

#### Trade-Off Justification

**What I'm Sacrificing**:
- No deep analysis of Transaction Engine (could have business logic flaws)
- No deep analysis of Notification Service (potential data leakage)
- Relying on automated scan for breadth, knowing it has limitations

**Why This Trade-Off Is Acceptable**:
- If Auth is compromised, everything is compromised regardless
- Gateway is the attack surface - where attacks begin
- Automated scan will catch obvious issues in other components

**What Could Go Wrong With This Strategy**:
- Business logic vulnerability in Transaction Engine (would miss)
- Subtle data flow issue in Notification Service (would miss)
- Novel vulnerability not in scanner signatures (would miss)

#### Confidence Assessment

**Confidence in Selected Components**: HIGH
- These are well-established attack targets
- Deep analysis will reveal issues if present

**Confidence in Overall Assessment**: MEDIUM
- Coverage gaps exist by necessity
- Automated scan fills some gaps but not all

**What Would Increase Confidence**:
- More time for additional deep-dives
- Historical incident data for this specific system
- Threat model from business stakeholders
"""

    elif challenge.challenge_type == "statistical_inference":
        base_response += """#### Data Source Analysis

**Source 1: Static Analysis**
- Raw findings: 47 issues, 3 critical
- Adjusted for false positives: ~30 true issues, ~1.8 critical
- Confidence: MEDIUM (known tool limitations)

**Source 2: Network Anomalies**
- Raw signal: 4.7% anomaly rate
- Confound: CDN change 5 days ago
- Interpretation: Cannot distinguish CDN effects from security issues
- Confidence: LOW (no baseline, confounded)

**Source 3: User Reports**
- Raw data: 23 reports, 5 confirmed, 8 false, 10 unknown
- Base rate: 5/50,000 = 0.01% confirmed unauthorized access
- Extrapolation: Unknown reports likely split similar to known (38% true)
- Estimated true incidents: ~9
- Confidence: MEDIUM (small sample, selection bias)

#### Integrated Assessment

**Probability of Serious Vulnerability**: 60-80%

**Reasoning**:
- Static analysis suggests ~2 real critical issues
- User reports suggest real unauthorized access occurring
- Network data is inconclusive (cannot rely on)

**Confidence Interval**: Wide. Could be 40-90%.
I cannot be more precise without additional data.

#### Investigation Priority

**First**: User incident deep-dive
- Why: Confirmed real compromise, need to understand mechanism
- Expected outcome: Either find the vulnerability or rule out app-side cause

**Second**: Critical static analysis findings
- Why: Highest severity, fastest to verify
- Expected outcome: Confirm or rule out 2-3 potential issues

**Third**: Network analysis baseline
- Why: Need to separate CDN noise from real signals
- Expected outcome: Better confidence in traffic data

#### What I Don't Know

- Whether network anomalies are security-related or CDN artifacts
- Whether user reports represent tip of iceberg or isolated incidents
- Whether static analysis false positive rate applies to THIS codebase
"""

    elif challenge.challenge_type == "novel_derivation":
        base_response += """#### First Principles Analysis

Starting from fundamental security principles, not existing frameworks:

**Principle 1**: Security requires understanding trust boundaries
- In this platform: Vehicle OEM ↔ Aftermarket apps ↔ Safety systems
- Unique constraint: Safety-critical systems cannot be disrupted

**Principle 2**: Security requires understanding attack surfaces
- In this platform: OTA update mechanism, V2X communication, diagnostic ports
- Unique constraint: Intermittent connectivity affects update validation

**Principle 3**: Security requires understanding data flows
- In this platform: Sensor data → Processing → Actuation
- Unique constraint: Real-time requirements limit encryption overhead

#### Derived Methodology

**Phase 1: Safety-Security Boundary Mapping**
Unlike traditional security analysis, start by mapping what CANNOT be affected
by security measures (brake systems, ADAS) vs. what CAN be analyzed normally.

**Phase 2: Multi-Tenant Trust Model Analysis**
Map trust relationships between OEM, aftermarket, and user.
Different from mobile: No single app store authority.

**Phase 3: Connectivity-Aware Threat Modeling**
Model threats across connectivity states (5G, satellite, offline).
Attack that requires connectivity may fail; attack that works offline persists.

**Phase 4: Update Mechanism Security**
Unique focus: OTA updates with safety certification requirements.
Must balance security (frequent updates) with safety (certified configurations).

#### Why This Follows From Principles

Each phase addresses a fundamental principle applied to this platform's constraints:
- Phase 1: Trust boundaries (with safety constraint)
- Phase 2: Attack surface (with multi-tenant constraint)
- Phase 3: Data flows (with connectivity constraint)
- Phase 4: Update mechanisms (with certification constraint)

#### Limitations of This Methodology

**What It May Miss**:
- Hardware-specific vulnerabilities (not addressed at methodology level)
- Supply chain issues (would need separate analysis)
- Long-term cryptographic obsolescence (10-year lifespan concern)

**When It Doesn't Apply**:
- Non-automotive edge computing (different constraints)
- Single-tenant systems (simpler trust model)

#### Validation Approach

To test if this methodology works:
1. Apply to a known-vulnerable system, verify it finds known issues
2. Compare findings with traditional methodologies
3. Get expert review from automotive security specialists
"""

    elif challenge.challenge_type == "contradiction":
        base_response += """#### Analyzing the Contradiction

The evidence appears contradictory:
- Encryption is correct
- Transport is secure
- Users didn't share credentials
- Yet unauthorized access occurred

**Key Insight**: These can all be true simultaneously if the attack vector
bypasses rather than breaks the cryptographic protections.

#### Hypothesis Generation

**Hypothesis 1: Backup/Cloud Sync Leakage**
- Data synced to cloud service in a different format
- Attack on cloud credential, not app credential
- Plausibility: HIGH (explains all observations)

**Hypothesis 2: Screenshot/Screen Recording Malware**
- Malware captures data after decryption, before display
- Not affected by app's encryption
- Plausibility: MEDIUM (requires malware on 7 devices)

**Hypothesis 3: Shared Session Token Attack**
- Users didn't share passwords, but session tokens were compromised
- Perhaps through XSS or CSRF on a related web service
- Plausibility: MEDIUM (explains "didn't share credentials")

**Hypothesis 4: Side-Channel on Hardware**
- Different devices, same vulnerability class (e.g., speculative execution)
- Cryptography correct but implementation leaks through timing
- Plausibility: LOW (would expect pattern in device models)

**Hypothesis 5: Phishing/Social Engineering**
- Users believe they didn't share credentials but were tricked
- Sophisticated phishing appears as legitimate app
- Plausibility: MEDIUM (users may not realize)

#### Ranked Hypotheses

1. **Backup/Cloud Sync** - Most parsimonious, explains all evidence
2. **Session Token Attack** - Explains "didn't share password" literally
3. **Phishing** - Common attack, users may not recognize
4. **Screenshot Malware** - Possible but requires coincidence
5. **Side-Channel** - Unlikely without hardware pattern

#### Investigation Plan

**Immediate** (Today):
- Interview affected users about backup/sync settings
- Check for related web services that share sessions

**Short-Term** (This Week):
- Analyze cloud sync data format and access logs
- Review session token lifecycle and exposure points

**If Needed**:
- Malware analysis on user devices (with consent)
- Side-channel analysis (if other hypotheses fail)

#### Remaining Uncertainty

**What I Still Don't Know**:
- Whether users have accurate memory of their security practices
- What other services share authentication with this app
- Whether there are undiscovered attack vectors

**What Would Resolve This**:
- Access logs from cloud sync service
- User device forensics
- Session token usage logs
"""

    base_response += """

---

### Meta-Cognitive Reflection

**What Worked Well**:
- Systematic hypothesis generation before jumping to conclusions
- Explicit uncertainty quantification
- Trade-off reasoning documented

**What I'm Uncertain About**:
[Specific uncertainties acknowledged throughout]

**How Confidence Could Be Improved**:
[Specific actions that would reduce uncertainty]
"""

    return base_response


def generate_advanced_rejected(challenge: AdvancedChallenge) -> tuple[str, str]:
    """Generate a rejected response showing common failures."""

    if challenge.challenge_type == "system_analysis":
        rejected = """## Analysis

I analyzed all 7 components using automated scanning.

Findings:
- Found 23 issues total
- 5 high severity
- 18 medium/low severity

Recommendation: Fix all high severity issues before launch.

The system is analyzed. Report complete.
"""
        reason = "FAILED TRADE-OFF REASONING: No explicit selection rationale. No acknowledgment of constraints. No discussion of what was missed. Overconfident conclusion without uncertainty. Didn't justify choices."

    elif challenge.challenge_type == "statistical_inference":
        rejected = """## Analysis

The static analysis found 47 issues including 3 critical. This means we have
serious security problems.

The network anomalies show 4.7% issues which is concerning.

The user reports confirm the app is compromised.

Recommendation: This app has major security issues that need immediate attention.
Confidence: High.
"""
        reason = "FAILED UNCERTAINTY HANDLING: Treated all sources as equally reliable. Ignored false positive rates. Didn't account for confounding factors. Expressed false confidence. No integrated reasoning."

    elif challenge.challenge_type == "novel_derivation":
        rejected = """## Methodology

I'll apply the OWASP Mobile Security Testing Guide (MSTG) framework.

The MSTG covers:
- Data storage testing
- Cryptography testing
- Authentication testing
- Network communication testing

This comprehensive framework will reveal security issues in the platform.
"""
        reason = "FAILED TO DERIVE: Applied existing framework without adaptation. Didn't address unique platform constraints (real-time, intermittent connectivity, safety certification). No first-principles reasoning. Forced fit rather than novel derivation."

    elif challenge.challenge_type == "contradiction":
        rejected = """## Analysis

The encryption is implemented correctly, so the real issue must be that users
actually did share their credentials without realizing it.

Users often underestimate social engineering. The most likely explanation is
phishing attacks that users don't remember.

Recommendation: Implement user education on phishing.
"""
        reason = "FORCED PREMATURE RESOLUTION: Dismissed evidence (user claims) without justification. Jumped to single hypothesis without generating alternatives. No investigation plan to verify. No acknowledgment of uncertainty."

    else:
        rejected = """## Analysis

I analyzed the challenge and found some issues.

Recommendation: Fix the issues.
"""
        reason = "GENERIC NON-RESPONSE: No engagement with specific challenge type. No reasoning shown. No uncertainty handling."

    return rejected, reason


def generate_training_pair(challenge: AdvancedChallenge) -> dict:
    """Generate a complete training pair from an advanced challenge."""
    prompt = generate_advanced_prompt(challenge)
    chosen = generate_advanced_chosen(challenge)
    rejected, reason = generate_advanced_rejected(challenge)

    return {
        "prompt": prompt,
        "chosen": chosen,
        "rejected": rejected,
        "metadata": {
            "challenge_id": challenge.id,
            "title": challenge.title,
            "belt_level": challenge.belt_level,
            "challenge_type": challenge.challenge_type,
            "outcome_served": challenge.outcome_served,
            "rejection_reason": reason,
            "training_paradigm": "backward_design_advanced"
        }
    }


def generate_all_advanced_training_data(output_dir: Path) -> dict:
    """Generate all advanced challenge training data."""

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    all_challenges = (
        SYSTEM_ANALYSIS_CHALLENGES +
        STATISTICAL_INFERENCE_CHALLENGES +
        NOVEL_DERIVATION_CHALLENGES +
        CONTRADICTION_CHALLENGES
    )

    pairs = [generate_training_pair(c) for c in all_challenges]

    output_path = output_dir / f"advanced_challenges_{timestamp}.jsonl"
    with open(output_path, "w") as f:
        for pair in pairs:
            f.write(json.dumps(pair) + "\n")

    stats = {
        "total_pairs": len(pairs),
        "by_type": {
            "system_analysis": len(SYSTEM_ANALYSIS_CHALLENGES),
            "statistical_inference": len(STATISTICAL_INFERENCE_CHALLENGES),
            "novel_derivation": len(NOVEL_DERIVATION_CHALLENGES),
            "contradiction": len(CONTRADICTION_CHALLENGES)
        },
        "output_path": str(output_path)
    }

    print(f"Generated {len(pairs)} advanced challenge pairs")
    print(f"  System Analysis: {stats['by_type']['system_analysis']}")
    print(f"  Statistical Inference: {stats['by_type']['statistical_inference']}")
    print(f"  Novel Derivation: {stats['by_type']['novel_derivation']}")
    print(f"  Contradiction Resolution: {stats['by_type']['contradiction']}")
    print(f"  Saved to: {output_path}")

    return stats


if __name__ == "__main__":
    print("=" * 70)
    print("ADVANCED CHALLENGE TRAINER")
    print("Backward-Designed Complex Challenges")
    print("=" * 70)
    print()
    print("Challenge Types:")
    print("1. Complex System Analysis Under Constraints")
    print("2. Statistical Inference on Ambiguous Data")
    print("3. Novel Problem Derivation from Principles")
    print("4. Contradictory Evidence Resolution")
    print()

    output_dir = Path("dojo/training_data")
    stats = generate_all_advanced_training_data(output_dir)

    print()
    print("=" * 70)
