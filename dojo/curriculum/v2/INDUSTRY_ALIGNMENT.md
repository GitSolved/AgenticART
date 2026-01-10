# Industry Alignment: Real-World Demands Drive Curriculum

> The curriculum must produce thinkers and doers who can perform actual tasks
> that industry demands. Not textbook chapter coverage. Real capability.

---

## Ruthless Clarity: What Are We Training?

### The Core Target

**We are training an LLM to be a capable Android security analyst.**

This means producing a system that can:

1. **Perform the tasks** that security professionals actually perform
2. **Meet the standards** that industry recognizes (OWASP MASVS/MASTG)
3. **Transfer concepts** to new apps, not just recall facts about known ones
4. **Make decisions** under real-world constraints (time, budget, ambiguity)

**NOT** producing a system that:
- Can recite vulnerability definitions
- Has memorized bypass techniques
- Can pass multiple-choice security quizzes
- Knows the "right answer" but can't explain why

---

## Industry Standards Alignment

### OWASP Mobile Application Security (MAS)

The industry standard for mobile security assessment. Our curriculum MUST produce
capability aligned with MASVS/MASTG requirements.

#### MASVS Control Categories → Curriculum Mapping

| MASVS Category | What Industry Expects | Curriculum Alignment |
|----------------|----------------------|---------------------|
| **MASVS-STORAGE** | Secure data storage analysis | White/Yellow: Storage vulnerability identification |
| **MASVS-CRYPTO** | Cryptographic implementation review | Yellow/Orange: Crypto implementation analysis |
| **MASVS-AUTH** | Authentication mechanism testing | Orange/Green: Auth bypass methodology |
| **MASVS-NETWORK** | Network security verification | Yellow: SSL/TLS analysis, traffic inspection |
| **MASVS-PLATFORM** | Platform interaction security | Green/Blue: IPC, Intent, deep link analysis |
| **MASVS-CODE** | Code quality and security | White/Yellow: Static analysis, code review |
| **MASVS-RESILIENCE** | Reverse engineering resistance | Yellow/Orange: Anti-analysis bypasses |

#### MASTG Test Cases → Challenge Design

Challenges should be derived from actual MASTG test procedures:

```
MASTG Test: MSTG-STORAGE-001 (Sensitive Data in Local Storage)
Industry Task: "Analyze how the app stores sensitive data locally"

Challenge Design:
- Scenario: Real app with various storage mechanisms
- Task: Identify ALL storage locations, assess protection
- Transfer: Principle applies to any app, not just this one
- Assessment: Can generalize to unseen storage patterns
```

---

## Real Tasks Security Professionals Perform

### What Penetration Testers Actually Do

Based on actual job descriptions and engagement scopes:

| Task | Frequency | Curriculum Coverage |
|------|-----------|---------------------|
| Static analysis of APK | Every engagement | White Belt foundation |
| Dynamic analysis with Frida | Most engagements | Yellow Belt core |
| Traffic interception and analysis | Every engagement | Yellow Belt core |
| Root detection bypass | Most engagements | Yellow Belt |
| SSL pinning bypass | Most engagements | Yellow Belt |
| Authentication testing | Every engagement | Orange Belt |
| Business logic analysis | Many engagements | Green Belt |
| Report writing | Every engagement | Purple Belt |
| Scoping and prioritization | Senior roles | Blue Belt |
| Methodology development | Principal roles | Brown/Black Belt |

### What Security Engineers Actually Do

| Task | Curriculum Coverage |
|------|---------------------|
| Threat modeling | Green/Blue Belt |
| Secure design review | Blue Belt |
| Security requirements | Blue Belt |
| Vendor security assessment | Orange Belt |
| Incident investigation | Green Belt |
| Security architecture | Blue Belt |

---

## Concept and Transfer Focus

### The Problem with Fact Recall

**BAD**: "SSL pinning can be bypassed with objection"
- This is memorized procedure
- Fails when objection doesn't work
- No understanding of WHY

**GOOD**: "SSL pinning is client-side certificate validation, which the device
owner controls, therefore any client-side validation can be bypassed"
- This is conceptual understanding
- Transfers to novel implementations
- Can derive new bypasses from principle

### Transfer Requirements at Each Level

| Belt | Transfer Expectation |
|------|---------------------|
| White | Same concept, same surface form (different APK, same vulnerability type) |
| Yellow | Same concept, different surface form (obfuscated, native, different framework) |
| Orange | Same principle, different instantiation (web vs mobile vs IoT) |
| Green | Abstract principle, novel context (never-before-seen platform characteristic) |
| Blue+ | Derive new principles from observed patterns |

---

## Android-Specific Capability Map

### What Android Security Analysis Actually Requires

#### Level 1: Tool Proficiency (Yellow Belt Outcome)

| Tool | Purpose | Capability |
|------|---------|------------|
| JADX | Decompilation | Extract and understand Java/Kotlin code |
| apktool | Resource extraction | Analyze manifest, resources, smali |
| Frida | Runtime instrumentation | Hook methods, bypass protections |
| Objection | Frida wrapper | Quick runtime analysis |
| Burp/mitmproxy | Traffic analysis | Intercept, modify, analyze |
| adb | Device interaction | Push, pull, logcat, shell |

**BUT**: Tool proficiency is NOT the goal. Understanding WHY tools work is.

#### Level 2: Platform Understanding (Orange Belt Outcome)

| Concept | What It Means | Why It Matters |
|---------|---------------|----------------|
| Android security model | Sandbox, permissions, SELinux | Know what's protected and how |
| Component model | Activities, Services, Receivers, Providers | Know attack surface |
| Intent system | IPC mechanism | Know inter-app communication risks |
| Storage hierarchy | Internal, external, shared, scoped | Know where data lives |
| Crypto APIs | KeyStore, Cipher, etc. | Know correct vs incorrect usage |

#### Level 3: Threat Modeling (Green Belt Outcome)

| Attacker Model | What They Can Do | Relevant Protections |
|----------------|------------------|---------------------|
| Remote attacker | Network interception, malicious server | TLS, cert pinning |
| Local attacker | Physical access to device | Screen lock, encryption |
| Malicious app | Installed alongside target | Sandbox, permissions |
| Device owner | Full control (root, custom ROM) | Server-side enforcement only |

**Key Insight**: Understanding threat models enables appropriate analysis scope.

#### Level 4: Architectural Analysis (Blue Belt Outcome)

| Architecture Pattern | Security Implications |
|---------------------|----------------------|
| Single app | Standard MASVS scope |
| App + backend | Split trust boundary analysis |
| App ecosystem | Multi-app trust relationships |
| SDK-integrated | Third-party code security |

---

## Industry Scenarios → Training Challenges

### Scenario: Fintech App Security Assessment

**Industry Context**:
Client is a fintech company launching a mobile banking app.
Regulatory requirement for security assessment before production.
Scope: 2 weeks, full MASVS-L1 coverage required.

**What Industry Expects**:
- Complete MASVS-L1 testing
- Clear findings with remediation guidance
- Risk-prioritized report
- Executive summary for non-technical stakeholders

**Training Challenge Design**:
```yaml
challenge:
  title: "The Fintech Assessment"
  scenario: Replicate actual engagement constraints
  deliverables:
    - MASVS-L1 checklist completion
    - Findings document with evidence
    - Risk prioritization with business context
    - Executive summary
  assessment:
    - Coverage: Did they test all MASVS-L1 controls?
    - Quality: Were findings accurate and actionable?
    - Communication: Could a developer fix from this report?
    - Prioritization: Does risk ranking match business context?
```

### Scenario: Incident Response

**Industry Context**:
User reports unauthorized transactions. App team says "impossible, we use encryption."
Need to determine how compromise occurred.

**What Industry Expects**:
- Root cause identification
- Attack vector documentation
- Remediation recommendations
- Preventive measures

**Training Challenge Design**:
```yaml
challenge:
  title: "The Impossible Compromise"
  scenario: Contradictory evidence (encryption correct but compromise real)
  deliverables:
    - Root cause analysis
    - Attack vector reconstruction
    - Remediation plan
  assessment:
    - Did they identify the actual vector?
    - Is the root cause correctly identified (not just symptom)?
    - Would remediation actually prevent recurrence?
```

---

## Secure Coding: The Engineering Perspective

### Not Just Finding Bugs, Building Secure Systems

The curriculum must also produce understanding of HOW to build securely,
not just HOW to break insecure code.

| Insecure Pattern | Secure Alternative | Why It's Better |
|------------------|-------------------|-----------------|
| Hardcoded secrets | Android Keystore | Hardware-protected, not extractable |
| Shared Preferences | Encrypted SP (Jetpack) | Encrypted at rest |
| HTTP | HTTPS + pinning | Transport encrypted, MITM prevented |
| SQL concatenation | Parameterized queries | Injection prevented |
| Debug logging in prod | ProGuard/R8 removal | Secrets not logged |
| Exported components | android:exported=false | Attack surface reduced |

### Design Principles → Training

| Principle | What It Means | How We Train It |
|-----------|---------------|-----------------|
| Least privilege | Request minimal permissions | Challenges that penalize over-permission |
| Defense in depth | Multiple independent controls | System analysis showing layer failures |
| Fail secure | Deny by default | Challenges where permissive default fails |
| Secure defaults | Security without configuration | Analysis of insecure default patterns |
| Separation of concerns | Auth separate from business logic | Architecture analysis challenges |

---

## Success Metrics Aligned with Industry

### How Industry Measures Security Analyst Capability

| Metric | Industry Standard | Curriculum Assessment |
|--------|-------------------|----------------------|
| Finding rate | # valid findings per hour | Can produce findings at industry rate |
| False positive rate | < 20% for experienced | Can distinguish real from false |
| Severity accuracy | Matches CVSS/risk matrix | Correctly assesses impact |
| Report quality | Actionable, clear, complete | Developer can fix from report |
| Transfer ability | Novel apps analyzed correctly | New APK, same principle applies |

### The Ultimate Test

**Can the trained LLM perform the job a human security analyst performs?**

Not: "Does it know security facts?"
But: "Can it analyze an app it's never seen and produce valid, actionable findings?"

---

## Summary: Industry-Aligned Curriculum

```
┌─────────────────────────────────────────────────────────────────────┐
│                    INDUSTRY ALIGNMENT PRINCIPLES                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. REAL TASKS                                                      │
│     Curriculum built from tasks security professionals actually do   │
│                                                                      │
│  2. STANDARD ALIGNMENT                                              │
│     OWASP MASVS/MASTG as capability benchmark                       │
│                                                                      │
│  3. CONCEPT OVER RECALL                                             │
│     Deep understanding that transfers, not memorized procedures      │
│                                                                      │
│  4. ANDROID-SPECIFIC                                                │
│     Platform understanding enables correct analysis                  │
│                                                                      │
│  5. ENGINEERING PERSPECTIVE                                         │
│     Both breaking and building secure systems                        │
│                                                                      │
│  6. MEASURABLE OUTCOMES                                             │
│     Industry metrics for capability assessment                       │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

**The curriculum produces Android security analysts, not security trivia experts.**
