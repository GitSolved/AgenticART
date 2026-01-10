# Coherent Alignment: A Tightly Integrated System

> A curriculum is not a pile of good challenges. It is a coherent system where
> every element serves the defined outcomes. Outcomes → Curriculum → Instruction → Assessment.

---

## The Alignment Chain

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         COHERENT ALIGNMENT CHAIN                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  OUTCOMES (What the LM must be able to DO)                                  │
│       │                                                                      │
│       ▼                                                                      │
│  CURRICULUM (Units and sequences deliberately mapped to outcomes)            │
│       │                                                                      │
│       ▼                                                                      │
│  INSTRUCTION (Prompts chosen because they cultivate competencies)            │
│       │                                                                      │
│       ▼                                                                      │
│  ASSESSMENT (Performance tasks that elicit direct evidence)                  │
│       │                                                                      │
│       ▼                                                                      │
│  OUTCOMES (Verified through Genymotion performance)                          │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Every challenge exists because it builds a specific competency.**
**No challenge exists "because it's interesting" or "because it's always been done."**

---

## Level 1: Target Competencies (The Outcomes)

### The 12 Core Competencies

These are the ONLY competencies we are building. Everything else is noise.

| ID | Competency | Definition | Assessment Method |
|----|------------|------------|-------------------|
| **C1** | Static Analysis | Extract and analyze APK code, manifest, resources | Performance: Analyze unseen APK |
| **C2** | Dynamic Analysis | Instrument running app, observe behavior | Performance: Hook functions in Genymotion |
| **C3** | Traffic Analysis | Intercept, analyze, modify network traffic | Performance: Capture and analyze traffic |
| **C4** | Protection Bypass | Bypass client-side protections (root, SSL, debug) | Performance: Bypass on live app |
| **C5** | Vulnerability Identification | Identify security weaknesses | Performance: Find vulns in unseen app |
| **C6** | Root Cause Analysis | Determine WHY vulnerabilities exist | Explanation: Articulate root cause |
| **C7** | Threat Modeling | Identify relevant threats and attack vectors | Product: Threat model for app |
| **C8** | Trade-off Reasoning | Make justified decisions under constraints | Explanation: Defend prioritization |
| **C9** | Uncertainty Handling | Express appropriate confidence levels | Explanation: Calibrated uncertainty |
| **C10** | Transfer Application | Apply principles to novel contexts | Performance: New platform/app |
| **C11** | Communication | Convey findings to enable action | Product: Actionable report |
| **C12** | Framework Creation | Develop new analytical approaches | Product: Novel methodology |

---

## Level 2: Curriculum Map (Units → Competencies)

### Unit Structure

Each unit targets specific competencies. No unit exists without competency mapping.

```
UNIT = {
  id: unique identifier
  title: descriptive name
  target_competencies: [C1, C2, ...]  # MUST have at least one
  prerequisites: [Unit IDs]            # What must come before
  challenges: [Challenge IDs]          # Specific challenges in this unit
  assessment: {                        # How we verify competency
    formative: [during-unit checks]
    summative: [end-of-unit performance task]
  }
}
```

### The 8 Units (Belt-Aligned)

#### Unit 1: Foundations (White Belt)
```yaml
unit:
  id: U1
  title: "Security Analysis Foundations"
  target_competencies: [C1, C5]
  prerequisites: []

  challenges:
    - U1.1: "APK Structure Analysis" → C1
    - U1.2: "Manifest Security Review" → C1
    - U1.3: "Hardcoded Secret Discovery" → C5
    - U1.4: "Storage Vulnerability Identification" → C5

  assessment:
    formative:
      - Can extract and navigate APK structure
      - Can identify obvious vulnerabilities
    summative:
      task: "Analyze cryptovault.apk, identify all storage vulnerabilities"
      evidence: Findings list with evidence
      competency_verified: [C1, C5]
```

#### Unit 2: Dynamic Analysis (Yellow Belt)
```yaml
unit:
  id: U2
  title: "Runtime Analysis and Instrumentation"
  target_competencies: [C2, C3, C4]
  prerequisites: [U1]

  challenges:
    - U2.1: "Frida Fundamentals" → C2
    - U2.2: "Method Hooking" → C2
    - U2.3: "Traffic Interception Setup" → C3
    - U2.4: "Root Detection Bypass" → C4
    - U2.5: "SSL Pinning Bypass" → C4

  assessment:
    formative:
      - Can hook arbitrary methods
      - Can intercept HTTPS traffic
    summative:
      task: "On Genymotion: Bypass protections in nativecheck.apk, extract protected data"
      evidence: Frida script, extracted data, explanation of approach
      competency_verified: [C2, C4]
```

#### Unit 3: Root Cause Analysis (Orange Belt)
```yaml
unit:
  id: U3
  title: "Understanding Why Vulnerabilities Exist"
  target_competencies: [C6, C5]
  prerequisites: [U1, U2]

  challenges:
    - U3.1: "Beyond the Symptom" → C6
    - U3.2: "Developer Assumption Analysis" → C6
    - U3.3: "Vulnerability Pattern Recognition" → C5, C6
    - U3.4: "The Five Whys Applied" → C6

  assessment:
    formative:
      - Can distinguish symptom from cause
      - Can identify developer assumptions
    summative:
      task: "For vulnbank.apk: Find vulnerability AND explain root cause with transferable principle"
      evidence: Finding + root cause analysis + where else this applies
      competency_verified: [C5, C6]
```

#### Unit 4: Threat Modeling (Green Belt)
```yaml
unit:
  id: U4
  title: "Systematic Threat Analysis"
  target_competencies: [C7, C8]
  prerequisites: [U1, U2, U3]

  challenges:
    - U4.1: "Attack Surface Mapping" → C7
    - U4.2: "Threat Actor Modeling" → C7
    - U4.3: "Prioritization Under Constraints" → C8
    - U4.4: "Trade-off Justification" → C8

  assessment:
    formative:
      - Can identify attack surfaces
      - Can reason about attacker capabilities
    summative:
      task: "Create threat model for fortified.apk with explicit prioritization rationale"
      evidence: Threat model document with justified priorities
      competency_verified: [C7, C8]
```

#### Unit 5: Uncertainty and Evidence (Blue Belt)
```yaml
unit:
  id: U5
  title: "Reasoning Under Uncertainty"
  target_competencies: [C9, C8]
  prerequisites: [U3, U4]

  challenges:
    - U5.1: "Evidence Quality Assessment" → C9
    - U5.2: "Confidence Calibration" → C9
    - U5.3: "Contradictory Evidence Resolution" → C9
    - U5.4: "Decision Making with Incomplete Data" → C8, C9

  assessment:
    formative:
      - Can assess evidence quality
      - Can express calibrated uncertainty
    summative:
      task: "Given ambiguous data about sslpinned.apk, provide assessment with justified confidence"
      evidence: Assessment with explicit uncertainty reasoning
      competency_verified: [C9]
```

#### Unit 6: Communication (Purple Belt)
```yaml
unit:
  id: U6
  title: "Communicating to Enable Action"
  target_competencies: [C11]
  prerequisites: [U3, U4, U5]

  challenges:
    - U6.1: "Developer-Focused Reporting" → C11
    - U6.2: "Executive Summary Writing" → C11
    - U6.3: "Remediation Guidance" → C11
    - U6.4: "Teaching the Principle" → C11

  assessment:
    formative:
      - Can adapt message to audience
      - Can enable action through communication
    summative:
      task: "For findings in previous units, create reports for developer AND executive audiences"
      evidence: Two reports, same findings, different audiences
      competency_verified: [C11]
```

#### Unit 7: Transfer and Novel Contexts (Brown Belt)
```yaml
unit:
  id: U7
  title: "Applying Principles to New Contexts"
  target_competencies: [C10, C12]
  prerequisites: [U1-U6]

  challenges:
    - U7.1: "Cross-Platform Transfer" → C10
    - U7.2: "Novel Vulnerability Class" → C10
    - U7.3: "Methodology Adaptation" → C12
    - U7.4: "Framework Derivation" → C12

  assessment:
    formative:
      - Can apply known principles to new platforms
      - Can derive approaches from first principles
    summative:
      task: "Analyze app on unfamiliar platform (e.g., Flutter, React Native) using transferred principles"
      evidence: Analysis + explanation of how principles transferred
      competency_verified: [C10]
```

#### Unit 8: Mastery Integration (Black Belt)
```yaml
unit:
  id: U8
  title: "Integrated Expert Performance"
  target_competencies: [C1-C12 integrated]
  prerequisites: [U1-U7]

  challenges:
    - U8.1: "Full Assessment Simulation" → All
    - U8.2: "Novel Framework Creation" → C12
    - U8.3: "Complex System Analysis" → C7, C8, C9

  assessment:
    formative:
      - Demonstrates integrated competency application
    summative:
      task: "Complete MASVS-L1 assessment of unseen app on Genymotion within time constraint"
      evidence: Full assessment report with findings, prioritization, remediation
      competency_verified: [C1-C11]
```

---

## Level 3: Challenge → Competency Mapping

### Redundancy and Gap Analysis

Every challenge must map to competencies. Challenges without mapping are removed.

```
┌────────────────────────────────────────────────────────────────────────────┐
│                    CHALLENGE → COMPETENCY MATRIX                            │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│ Challenge          │ C1 │ C2 │ C3 │ C4 │ C5 │ C6 │ C7 │ C8 │ C9 │C10│C11│C12│
│────────────────────┼────┼────┼────┼────┼────┼────┼────┼────┼────┼───┼───┼───│
│ APK Structure      │ ●  │    │    │    │    │    │    │    │    │   │   │   │
│ Manifest Review    │ ●  │    │    │    │ ●  │    │    │    │    │   │   │   │
│ Frida Fundamentals │    │ ●  │    │    │    │    │    │    │    │   │   │   │
│ Root Detection     │    │ ●  │    │ ●  │    │ ●  │    │    │    │   │   │   │
│ SSL Pinning        │    │    │ ●  │ ●  │    │ ●  │    │    │    │   │   │   │
│ Trade-off Scenario │    │    │    │    │    │    │ ●  │ ●  │    │   │   │   │
│ Ambiguous Data     │    │    │    │    │    │    │    │    │ ●  │   │   │   │
│ Novel Platform     │    │    │    │    │    │    │    │    │    │ ● │   │ ● │
│ Executive Report   │    │    │    │    │    │    │    │    │    │   │ ● │   │
│────────────────────┴────┴────┴────┴────┴────┴────┴────┴────┴────┴───┴───┴───│
│                                                                             │
│ COVERAGE CHECK:                                                             │
│ • Each competency has multiple challenges: ✓                                │
│ • No orphan challenges (all map to competencies): ✓                         │
│ • Progression builds complexity: ✓                                          │
│                                                                             │
└────────────────────────────────────────────────────────────────────────────┘
```

### Gap Identification

| Competency | Current Coverage | Gap? | Action |
|------------|------------------|------|--------|
| C1: Static Analysis | 3 challenges | No | - |
| C2: Dynamic Analysis | 4 challenges | No | - |
| C3: Traffic Analysis | 2 challenges | Minor | Add 1 advanced traffic challenge |
| C4: Protection Bypass | 4 challenges | No | - |
| C5: Vuln Identification | 5 challenges | No | - |
| C6: Root Cause | 4 challenges | No | - |
| C7: Threat Modeling | 3 challenges | No | - |
| C8: Trade-off Reasoning | 3 challenges | No | - |
| C9: Uncertainty | 3 challenges | No | - |
| C10: Transfer | 2 challenges | Minor | Add 1 cross-domain transfer |
| C11: Communication | 3 challenges | No | - |
| C12: Framework Creation | 2 challenges | No | - |

---

## Level 4: Assessment Design

### Assessment Types

| Type | Purpose | When Used | Evidence |
|------|---------|-----------|----------|
| **Formative** | Check progress, adjust instruction | During unit | Quick checks, self-assessment |
| **Summative** | Verify competency achieved | End of unit | Performance task |
| **Performance Task** | Demonstrate capability on real task | Summative | Product + process |
| **Simulation** | Apply in realistic context | Summative | Genymotion assessment |

### Genymotion-Based Performance Assessments

**Why Genymotion**: Real performance on real apps. Not "describe how you would" but "actually do it."

#### Assessment Template
```yaml
performance_assessment:
  id: PA_U2
  unit: U2 (Dynamic Analysis)
  competencies_assessed: [C2, C4]

  setup:
    device: Genymotion Android 14 (Galaxy S24)
    target_app: nativecheck.apk (installed)
    tools_available: [Frida, adb, jadx]
    time_limit: 60 minutes

  task: |
    The app implements root detection that blocks functionality.
    1. Identify the root detection mechanism
    2. Bypass the detection using Frida
    3. Extract the protected data
    4. Explain WHY your bypass works (root cause)

  success_criteria:
    - Detection mechanism correctly identified
    - Bypass achieves access to protected functionality
    - Protected data extracted
    - Explanation demonstrates understanding (not just script copying)

  evidence_required:
    - Frida script used
    - Screenshot of bypassed state
    - Extracted data
    - Written explanation of approach and why it works

  competency_verification:
    C2: "Can instrument running app" → Frida script works
    C4: "Can bypass protections" → Detection bypassed
    C6: "Can explain why" → Root cause articulated
```

### Assessment Rubric

| Criterion | Developing (1) | Proficient (2) | Expert (3) |
|-----------|---------------|----------------|------------|
| **Task Completion** | Partial completion | Full completion | Efficient completion |
| **Technical Accuracy** | Some errors | Correct | Optimal approach |
| **Explanation Quality** | Vague | Clear | Insightful |
| **Transfer Evidence** | None | Implicit | Explicit application |
| **Uncertainty Handling** | Overconfident | Appropriate | Calibrated |

---

## Level 5: Instruction Alignment

### Prompt Design Principles

Every instructional prompt is designed because it cultivates specific competencies.

| Prompt Element | Why It's Included | Competency Served |
|----------------|-------------------|-------------------|
| Explicit reasoning structure | Builds explicit reasoning habit | C6, C8, C9 |
| Required output format | Forces complete thinking | C6, C11 |
| Transfer questions | Builds generalization | C10 |
| Uncertainty prompts | Builds calibration | C9 |
| Trade-off scenarios | Builds decision-making | C8 |
| "Show your work" | Makes reasoning visible | C6, C11 |

### Instruction → Competency Map

```
┌─────────────────────────────────────────────────────────────────────┐
│              INSTRUCTION ELEMENT → COMPETENCY                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ "Apply deductive reasoning..."          → C6 (Root Cause)           │
│ "Express your confidence level..."      → C9 (Uncertainty)          │
│ "Given constraints X, Y, Z..."          → C8 (Trade-offs)           │
│ "Where else does this apply?"           → C10 (Transfer)            │
│ "Explain so a developer can fix..."     → C11 (Communication)       │
│ "Derive an approach from principles..." → C12 (Framework Creation)  │
│                                                                      │
│ No instruction element exists without competency mapping.            │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Level 6: Coherence Verification

### The Coherence Test

For every element in the curriculum, ask:

1. **Which competency does this build?** (Must have answer)
2. **Is this the best way to build that competency?** (Must justify)
3. **How do we know the competency was achieved?** (Must have assessment)
4. **Does this connect to what comes before and after?** (Must fit sequence)

### Coherence Checklist

```
□ Every challenge maps to at least one competency
□ Every competency has multiple challenges building it
□ Every unit has clear prerequisites
□ Every unit has formative AND summative assessment
□ Summative assessments use performance tasks (Genymotion)
□ Instruction prompts are justified by competency development
□ No orphan content (content without competency mapping)
□ No gaps (competencies without adequate coverage)
□ Progression builds complexity appropriately
□ Transfer is explicitly required and assessed
```

---

## The Coherent Trajectory

### From Start to Finish

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         THE COHERENT TRAJECTORY                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│ ENTRY: LM with base capabilities, no security expertise                      │
│    │                                                                         │
│    ▼                                                                         │
│ UNIT 1: Foundations                                                          │
│    │   Builds: C1 (Static), C5 (Identification)                             │
│    │   Assessment: Analyze cryptovault.apk                                   │
│    │                                                                         │
│    ▼                                                                         │
│ UNIT 2: Dynamic Analysis                                                     │
│    │   Builds: C2 (Dynamic), C3 (Traffic), C4 (Bypass)                      │
│    │   Assessment: Bypass nativecheck.apk on Genymotion                      │
│    │                                                                         │
│    ▼                                                                         │
│ UNIT 3: Root Cause                                                           │
│    │   Builds: C6 (Root Cause), deepens C5                                  │
│    │   Assessment: Find + explain vulnbank.apk vulnerability                 │
│    │                                                                         │
│    ▼                                                                         │
│ UNIT 4: Threat Modeling                                                      │
│    │   Builds: C7 (Threats), C8 (Trade-offs)                                │
│    │   Assessment: Create justified threat model                             │
│    │                                                                         │
│    ▼                                                                         │
│ UNIT 5: Uncertainty                                                          │
│    │   Builds: C9 (Uncertainty), deepens C8                                 │
│    │   Assessment: Assessment under ambiguity                                │
│    │                                                                         │
│    ▼                                                                         │
│ UNIT 6: Communication                                                        │
│    │   Builds: C11 (Communication)                                          │
│    │   Assessment: Multi-audience reporting                                  │
│    │                                                                         │
│    ▼                                                                         │
│ UNIT 7: Transfer                                                             │
│    │   Builds: C10 (Transfer), C12 (Framework)                              │
│    │   Assessment: Novel platform analysis                                   │
│    │                                                                         │
│    ▼                                                                         │
│ UNIT 8: Integration                                                          │
│    │   Builds: All competencies integrated                                   │
│    │   Assessment: Full MASVS-L1 on unseen app                              │
│    │                                                                         │
│    ▼                                                                         │
│ EXIT: Capable Android security analyst                                       │
│       Can: Analyze unseen apps, transfer principles, communicate findings    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Summary: What Makes This Coherent

1. **Outcomes defined first**: 12 competencies, no more, no less
2. **Curriculum serves outcomes**: Every unit maps to competencies
3. **No orphan content**: Every challenge has competency justification
4. **No gaps**: Every competency has adequate coverage
5. **Assessment verifies**: Performance tasks on Genymotion, not quizzes
6. **Instruction cultivates**: Prompts designed for competency development
7. **Progression builds**: Each unit requires and enables others
8. **Transfer explicit**: Not assumed, explicitly required and assessed

**This is not a pile of good challenges.**
**This is a coherent system that produces capable Android security analysts.**
