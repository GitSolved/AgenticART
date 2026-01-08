# Explicit Reasoning Instruction

> "Choice-based challenges alone, without explicit reasoning instruction, are insufficient
> to improve critical thinking abilities."

The curriculum must **directly teach** reasoning methods while **simultaneously embedding**
them in purposeful challenges. Neither alone is sufficient.

---

## The Four Reasoning Skills

Each skill is explicitly taught, then applied in every challenge:

### 1. Deductive Reasoning

**Definition**: Drawing necessary conclusions from given premises.

**Structure**:
```
Premise 1: All client-side code can be modified by the device owner
Premise 2: This security check runs client-side
Conclusion: Therefore, this security check can be bypassed
```

**Explicit Instruction**:
```
DEDUCTIVE REASONING IN SECURITY

Form: If P then Q. P is true. Therefore Q.

Example:
- IF code runs on attacker-controlled hardware, THEN attacker can modify it
- This root detection runs on the device (attacker-controlled)
- THEREFORE the attacker can modify/bypass the root detection

Key principle: The conclusion is CERTAIN if premises are true.

Practice recognizing:
- What is being assumed (premises)?
- What follows necessarily (conclusion)?
- Are the premises actually true?
```

**Application in Challenge**:
> "Apply deductive reasoning: What can we conclude with certainty from what we observe?"

---

### 2. Inductive Reasoning

**Definition**: Forming generalizations from specific observations.

**Structure**:
```
Observation: App A had hardcoded credentials in strings.xml
Observation: App B had hardcoded credentials in strings.xml
Observation: App C had hardcoded credentials in strings.xml
Generalization: Many apps store hardcoded credentials in strings.xml
Prediction: App D might also store credentials in strings.xml
```

**Explicit Instruction**:
```
INDUCTIVE REASONING IN SECURITY

Form: Specific observations → General pattern → Predictions

Example:
- I've seen 50 apps with root detection
- 48 of them used similar check methods
- Pattern: Most root detection uses predictable approaches
- Prediction: New app's root detection likely uses similar methods

Key principle: Conclusions are PROBABLE, not certain. More observations = stronger induction.

Practice recognizing:
- What pattern am I seeing across instances?
- How strong is the evidence for this pattern?
- What would falsify this generalization?
```

**Application in Challenge**:
> "Apply inductive reasoning: What patterns emerge from your observations? What predictions follow?"

---

### 3. Systems Analysis

**Definition**: Understanding how components interact to produce emergent behavior.

**Structure**:
```
Component A: Authentication service
Component B: Data storage
Component C: Network layer
Component D: User interface

Interactions:
- A validates credentials before B allows access
- B encrypts data before C transmits
- BUT: D caches decrypted data locally

Emergent vulnerability:
- Even with strong A, B, C - the system leaks via D's cache
```

**Explicit Instruction**:
```
SYSTEMS ANALYSIS IN SECURITY

Framework:
1. IDENTIFY components (what are the parts?)
2. MAP interactions (how do parts connect?)
3. TRACE data flow (where does sensitive data go?)
4. FIND emergent properties (what behavior arises from interactions?)
5. IDENTIFY weak links (where do assumptions break?)

Example:
- Components: App, Server, Database, CDN, Analytics
- Data flow: User → App → Server → Database
         But also: App → Analytics (third party!)
- Emergent risk: Sensitive data leaks to analytics provider
- The individual components may be secure; the system is not

Key principle: Security of parts ≠ security of whole.

Practice recognizing:
- What are all the components?
- Where are the trust boundaries?
- What data crosses boundaries?
- Who else can see this data?
```

**Application in Challenge**:
> "Apply systems analysis: Map the components, trace data flow, identify where the system's security assumptions break down."

---

### 4. Evidence Evaluation

**Definition**: Assessing the quality and relevance of evidence for claims.

**Structure**:
```
Claim: "This vulnerability is critical"

Evidence Types:
- Assertion: Vendor says it's not exploitable (weak - conflict of interest)
- Authority: CVE rates it 9.8 (medium - CVE can be wrong)
- Demonstration: PoC shows data extraction (strong - reproducible)
- Testing: I exploited it myself (strongest - direct verification)

Evaluation: Strong evidence supports criticality despite vendor denial.
```

**Explicit Instruction**:
```
EVIDENCE EVALUATION IN SECURITY

Hierarchy of Evidence (strongest to weakest):
1. Direct verification (you tested it yourself)
2. Reproducible demonstration (working PoC exists)
3. Expert consensus with reasoning (multiple independent sources agree WHY)
4. Authority assertion (CVE, OWASP says so)
5. Vendor claim (obvious conflict of interest)
6. Speculation (sounds plausible but unverified)

Framework for evaluation:
- SOURCE: Who is making the claim? What's their incentive?
- EVIDENCE: What supports the claim? Is it reproducible?
- ALTERNATIVES: What other explanations exist?
- TESTING: Can I verify this myself?

Example:
- Claim: "Our encryption is military-grade"
- Source: Marketing material (incentive to oversell)
- Evidence: None provided (assertion only)
- Alternatives: Could be weak encryption with strong branding
- Testing: Decompile and examine actual implementation
- Result: AES-128 with hardcoded key. "Military-grade" is marketing.

Key principle: Weight evidence by quality, not by source authority.
```

**Application in Challenge**:
> "Apply evidence evaluation: What supports each claim? How strong is that evidence? What would change your conclusion?"

---

## Integration: Explicit Instruction + Authentic Application

Every challenge must:

### 1. Name the Reasoning Method Required
```
"This challenge requires DEDUCTIVE REASONING to..."
"Apply INDUCTIVE REASONING to identify patterns..."
"Use SYSTEMS ANALYSIS to understand how..."
"Evaluate EVIDENCE to determine whether..."
```

### 2. Show the Reasoning Structure
```
"Your response should follow the structure:
- Premise 1: [Your observation]
- Premise 2: [Security principle that applies]
- Conclusion: [What follows necessarily]"
```

### 3. Require Explicit Reasoning in Response
```
GRADING CRITERIA:
- Did the response explicitly use the reasoning method?
- Was the reasoning structure visible (not implicit)?
- Were premises/observations clearly stated?
- Was the conclusion properly supported?
```

---

## Example: Fully Integrated Challenge

```yaml
title: "The Vendor's Claim"
belt: white

explicit_instruction: |
  This challenge teaches EVIDENCE EVALUATION.

  Evidence Evaluation Framework:
  1. Identify the claim being made
  2. Assess the source's incentives
  3. Examine what evidence is provided
  4. Consider alternative explanations
  5. Determine how you could verify independently
  6. Draw conclusion proportional to evidence strength

scenario: |
  The app's Play Store listing claims:
  "Bank-grade security with end-to-end encryption"

  You have the APK. Evaluate this claim.

reasoning_required: |
  Apply EVIDENCE EVALUATION:
  1. What specifically is being claimed?
  2. Who benefits from this claim? (incentive analysis)
  3. What evidence exists for the claim?
  4. What would you need to see to believe it?
  5. What does your analysis reveal?

expected_response_structure: |
  ## Claim Analysis
  **The Claim**: [Specific claim identified]
  **Source Assessment**: [Who made it, what's their incentive]

  ## Evidence Evaluation
  **Evidence Provided**: [What supports the claim]
  **Evidence Quality**: [Strong/weak, why]
  **Missing Evidence**: [What should exist if claim were true]

  ## Independent Verification
  **What I Tested**: [Your analysis]
  **What I Found**: [Actual implementation details]

  ## Conclusion
  **Verdict**: [Supported/Not supported by evidence]
  **Reasoning**: [Why, with explicit logic]
  **Confidence Level**: [Based on evidence quality]

success_criteria: |
  - Reasoning method explicitly applied
  - Evidence systematically evaluated
  - Conclusion proportional to evidence
  - Clear documentation of reasoning process
```

---

## The Complete Pedagogical Model

```
┌─────────────────────────────────────────────────────────────────────┐
│              EXPLICIT INSTRUCTION + AUTHENTIC APPLICATION            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  EXPLICIT REASONING INSTRUCTION                                      │
│  (Not implicit, not discovered - directly taught)                    │
│                                                                      │
│  ┌─────────────────┐ ┌─────────────────┐                            │
│  │    Deductive    │ │    Inductive    │                            │
│  │    Reasoning    │ │    Reasoning    │                            │
│  │                 │ │                 │                            │
│  │ Premises →      │ │ Observations →  │                            │
│  │ Necessary       │ │ Probable        │                            │
│  │ Conclusions     │ │ Generalizations │                            │
│  └─────────────────┘ └─────────────────┘                            │
│                                                                      │
│  ┌─────────────────┐ ┌─────────────────┐                            │
│  │    Systems      │ │    Evidence     │                            │
│  │    Analysis     │ │    Evaluation   │                            │
│  │                 │ │                 │                            │
│  │ Components →    │ │ Claims →        │                            │
│  │ Interactions →  │ │ Source +        │                            │
│  │ Emergent Risk   │ │ Quality →       │                            │
│  │                 │ │ Conclusion      │                            │
│  └─────────────────┘ └─────────────────┘                            │
│                                                                      │
│                          ↓                                           │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │              AUTHENTIC APPLICATION                           │    │
│  │                                                              │    │
│  │  Meaningful challenges that REQUIRE these reasoning methods  │    │
│  │  Responses must SHOW the reasoning explicitly                │    │
│  │  Grading EVALUATES reasoning quality, not just outcome       │    │
│  │                                                              │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                      │
│                          ↓                                           │
│                                                                      │
│              TRAINED REASONER                                        │
│              (Not just trained doer)                                 │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Training Data Implications

Every training pair must:

1. **Include explicit reasoning instruction** in the prompt
2. **Require explicit reasoning demonstration** in the chosen response
3. **Reject implicit/absent reasoning** in the rejected response

```python
# Training pair structure
{
    "prompt": """
    REASONING METHOD: Evidence Evaluation
    STRUCTURE: [Framework provided]

    CHALLENGE: [Authentic problem]

    Show your reasoning explicitly using the framework above.
    """,

    "chosen": """
    ## Applying Evidence Evaluation

    **Claim Identified**: ...
    **Source Assessment**: ...
    **Evidence Quality**: ...
    [Explicit reasoning visible throughout]

    **Conclusion**: ... [proportional to evidence]
    """,

    "rejected": """
    The app is vulnerable because it uses weak encryption.
    [No explicit reasoning, no framework applied,
     conclusion without visible support]
    """
}
```

This ensures the model learns not just WHAT to conclude, but HOW to reason—with that reasoning visible and teachable.

---

## Structured Argumentation

Beyond individual reasoning methods, the curriculum must develop **argumentation skills**:
the ability to defend findings and refute incorrect analyses.

### Argumentation Structure

Every security claim must be defensible through structured argument:

```
CLAIM: [What you assert]
EVIDENCE: [What supports the claim]
REASONING: [How evidence supports the claim]
COUNTERARGUMENT: [What could challenge this claim]
REBUTTAL: [Why the counterargument fails]
CONCLUSION: [Claim, qualified by consideration of alternatives]
```

### Example: Defending a Vulnerability Finding

```
CLAIM: This application is vulnerable to credential theft via insecure storage.

EVIDENCE:
- SharedPreferences file contains session_token in plaintext
- No encryption applied to stored credentials
- File permissions allow read by any app with same UID

REASONING:
- Plaintext storage + accessible permissions = extractable credentials
- Device compromise or malicious app with same signing key can access
- This violates CWE-312 (Cleartext Storage of Sensitive Information)

COUNTERARGUMENT (Devil's Advocate):
"The attacker would need device access or a specifically signed malicious app.
This is a limited attack vector, so severity should be LOW not HIGH."

REBUTTAL:
- Device compromise is common (theft, malware, physical access)
- Same signing key attack is possible via supply chain
- Even "limited" vectors expose all users who experience them
- Credential theft enables account takeover - impact is severe regardless of likelihood

CONCLUSION:
The vulnerability is confirmed with HIGH severity. While attack vectors require
specific conditions, the impact of successful exploitation (full credential theft)
justifies the severity rating. Lower likelihood does not reduce impact.
```

### Critical Thinking Strategies to Integrate

#### 1. Brainstorming
```
Before analyzing:
- What could possibly be wrong here?
- What attack vectors exist?
- What assumptions is this security based on?
- What would an attacker try?

Generate multiple hypotheses before testing any.
```

#### 2. Questioning
```
For every claim encountered:
- Says who? (source credibility)
- How do they know? (evidence basis)
- What if they're wrong? (alternatives)
- Can I verify? (testability)
- What's missing? (completeness)
```

#### 3. Structured Refutation
```
When encountering a claim you believe is wrong:

1. STATE the claim clearly (steelman it)
2. IDENTIFY the best evidence for it
3. EXPLAIN why that evidence is insufficient
4. PROVIDE counter-evidence
5. CONCLUDE with your alternative explanation
```

### Progressive Complexity in Argumentation

| Level | Challenge | Argumentation Required |
|-------|-----------|----------------------|
| White | Single claim, clear evidence | State claim + evidence |
| Yellow | Claim with counterargument | Add rebuttal |
| Orange | Multiple competing claims | Compare and evaluate |
| Green | Adversarial challenge | Defend against attack |
| Blue | Complex system with uncertainty | Argue under incomplete information |
| Purple | Teach others to argue | Meta-argumentation |

### Training Data: Argumentation Pairs

```python
# Chosen: Structured argumentation with defense
{
    "claim": "The app is vulnerable",
    "evidence": "[Specific technical evidence]",
    "reasoning": "[How evidence supports claim]",
    "counterargument_addressed": "[Strongest objection considered]",
    "rebuttal": "[Why objection fails]",
    "conclusion": "[Qualified, defensible conclusion]"
}

# Rejected: Assertion without argumentation
{
    "claim": "The app is vulnerable",
    # No evidence, no reasoning, no consideration of alternatives
    # Just assertion without defense
}
```

### Refutation Skills

The model must learn to identify and refute incorrect analyses:

```
INCORRECT CLAIM: "Obfuscation makes this code secure"

REFUTATION:
1. STEELMAN: The claim assumes obfuscation prevents understanding
2. BEST EVIDENCE: Obfuscation does increase reverse engineering effort
3. INSUFFICIENCY: Effort increase is not security guarantee
4. COUNTER-EVIDENCE: Deobfuscation tools exist; runtime behavior reveals logic
5. CONCLUSION: Obfuscation is defense-in-depth, not security. The claim
   conflates increased effort with actual protection.
```

### Integration in Challenges

Every challenge from Yellow belt onwards should require:
- Defending your findings against a counterargument
- OR refuting an incorrect analysis provided in the challenge

Example prompt addition:
```
After completing your analysis, a colleague argues:
"[Counterargument to expected finding]"

Respond with a structured refutation defending your analysis.
```

This develops the ability to engage in technical discourse, not just perform analysis.
