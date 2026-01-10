# Big Driving Questions

> Purpose-based learning frames curriculum around big driving questions addressing
> real-world challenges, leading to improved outcomes and engagement.

Every challenge exists to investigate a driving question. The question gives purpose.
Without purpose, challenges become arbitrary exercises. With purpose, they become
meaningful investigations that build knowledge and foster critical thinking.

---

## The Big Questions of Mobile Security

### BQ1: "Why do security measures fail despite good intentions?"

**The Real-World Issue**: Developers implement security features, yet apps remain vulnerable. Why?

**What We're Really Investigating**:
- The gap between security intent and security implementation
- How assumptions break down in adversarial contexts
- Why "secure by design" often isn't

**Challenges That Investigate This Question**:

| Challenge | Investigation | Knowledge Built |
|-----------|---------------|-----------------|
| "The Secure App" | Verify vendor's security claims | Claims ≠ reality; verification is essential |
| "The Best Practice" | Test if following best practices = secure | Best practices are context-dependent |
| "Defense in Depth" | Analyze layered security | Layers can have gaps; depth ≠ completeness |

**Driving Sub-Questions**:
- What assumptions do security implementations make?
- Where do those assumptions break?
- What's the difference between security intent and security reality?

---

### BQ2: "How can we protect anything on hardware we don't control?"

**The Real-World Issue**: Mobile apps run on user devices. The user IS the attacker. How is security possible?

**What We're Really Investigating**:
- The fundamental limits of client-side security
- What CAN and CANNOT be protected client-side
- The role of server-side enforcement

**Challenges That Investigate This Question**:

| Challenge | Investigation | Knowledge Built |
|-----------|---------------|-----------------|
| "Root Detection Bypass" | Can device owner bypass device checks? | Device owner controls device |
| "The Client-Side Check" | What checks can be trusted client-side? | Answer: None, fundamentally |
| "Server vs Client" | Where should security logic live? | Enforcement must be server-side |

**Driving Sub-Questions**:
- What does "client-side" really mean for security?
- What can never be secured client-side?
- How should security architecture account for untrusted clients?

---

### BQ3: "What separates security theater from actual security?"

**The Real-World Issue**: Many security measures look impressive but provide no real protection. How do we tell the difference?

**What We're Really Investigating**:
- The difference between appearance and substance
- How to evaluate security claims critically
- What makes security actually effective

**Challenges That Investigate This Question**:

| Challenge | Investigation | Knowledge Built |
|-----------|---------------|-----------------|
| "Obfuscation Analysis" | Does obfuscation = security? | Obscurity increases effort, not security |
| "The Security Checkbox" | Do compliance features = security? | Compliance and security are different goals |
| "Threat Model Mismatch" | Do protections match actual threats? | Security must address real threats |

**Driving Sub-Questions**:
- How do we evaluate if a security measure actually works?
- What makes security effective vs. theatrical?
- How do we avoid false confidence from security theater?

---

### BQ4: "How do complex systems create unexpected vulnerabilities?"

**The Real-World Issue**: Individual components may be secure, but their interaction creates vulnerabilities. Why?

**What We're Really Investigating**:
- Emergent behavior in complex systems
- How secure components can combine insecurely
- Systems thinking in security

**Challenges That Investigate This Question**:

| Challenge | Investigation | Knowledge Built |
|-----------|---------------|-----------------|
| "The App Ecosystem" | How do multiple apps create risk? | Security of parts ≠ security of whole |
| "Third-Party Integration" | How do dependencies affect security? | Trust boundaries are complex |
| "The Side Channel" | What unexpected paths exist? | Systems have unintended behaviors |

**Driving Sub-Questions**:
- What emerges from component interactions?
- Where are the trust boundaries?
- How do we think about systems, not just components?

---

### BQ5: "How do we communicate security findings to drive action?"

**The Real-World Issue**: Finding vulnerabilities is useless if no one acts on the findings. How do we communicate effectively?

**What We're Really Investigating**:
- The gap between technical findings and organizational action
- How to communicate risk to different audiences
- What makes security communication effective

**Challenges That Investigate This Question**:

| Challenge | Investigation | Knowledge Built |
|-----------|---------------|-----------------|
| "The Executive Summary" | How do we explain risk to non-technical leaders? | Translate technical to business impact |
| "The Developer Report" | How do we enable remediation? | Actionable guidance > technical detail |
| "The Teaching Moment" | How do we build organizational capability? | Communication builds capability |

**Driving Sub-Questions**:
- What does each audience need to act?
- How do we translate technical findings to business risk?
- What makes communication drive action vs. collect dust?

---

## Curriculum Structure: Questions Drive Challenges

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        PURPOSE-BASED CURRICULUM                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   BIG DRIVING QUESTION                                                       │
│   "Why do security measures fail despite good intentions?"                   │
│                          │                                                   │
│                          ▼                                                   │
│   ┌──────────────────────────────────────────────────────────────────────┐  │
│   │                     INVESTIGATION CHALLENGES                          │  │
│   │                                                                       │  │
│   │  Challenge 1: Analyze "secure" app → Discover: claims ≠ reality      │  │
│   │  Challenge 2: Test best practices → Discover: context matters        │  │
│   │  Challenge 3: Examine defense layers → Discover: gaps exist          │  │
│   │                                                                       │  │
│   └──────────────────────────────────────────────────────────────────────┘  │
│                          │                                                   │
│                          ▼                                                   │
│   KNOWLEDGE CONSTRUCTED                                                      │
│   "Security fails when assumptions about context are wrong"                  │
│                          │                                                   │
│                          ▼                                                   │
│   COGNITIVE FLEXIBILITY DEVELOPED                                            │
│   Can now analyze NEW situations for assumption failures                     │
│                          │                                                   │
│                          ▼                                                   │
│   TRANSFER TO REAL WORLD                                                     │
│   Apply this understanding to apps never seen in training                    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Inquiry-Based Instruction Model

Each challenge follows the inquiry cycle:

### 1. ENGAGE (The Question)
```
Present the driving question in concrete form:
"This app claims to be secure. The developers followed all the best practices.
Yet users are being compromised. Why?"

Purpose: Create cognitive dissonance that motivates investigation.
```

### 2. EXPLORE (The Investigation)
```
Provide the authentic context (APK, environment, tools).
Let the learner investigate without predetermined answers.
Multiple paths are valid. Discovery is personal.

Purpose: Build knowledge through active investigation.
```

### 3. EXPLAIN (The Reasoning)
```
Require explicit reasoning about findings:
- What did you discover?
- WHY does this vulnerability exist? (root cause)
- What principle does this illustrate?

Purpose: Transform observations into understanding.
```

### 4. ELABORATE (The Transfer)
```
Apply the discovered principle to new situations:
- Where else does this pattern appear?
- How would you recognize this in an app you've never seen?
- What other vulnerabilities share this root cause?

Purpose: Develop cognitive flexibility through transfer.
```

### 5. EVALUATE (The Reflection)
```
Assess both the outcome and the process:
- Did you answer the driving question?
- What would you do differently?
- How has your understanding changed?

Purpose: Metacognition - thinking about thinking.
```

---

## Challenge Template: Purpose-Based

```yaml
challenge:
  id: challenge_001
  title: "The Secure App Paradox"

  # PURPOSE - Why this challenge matters
  driving_question: "Why do security measures fail despite good intentions?"
  real_world_relevance: |
    Every day, apps with security features get compromised.
    Understanding WHY teaches us more than memorizing HOW.

  # ENGAGE - Create cognitive dissonance
  scenario: |
    cryptovault.apk was built by a security-conscious team.
    They implemented: encryption, secure storage, input validation.
    Yet the app was compromised within a week of release.

    Investigate: Why did their security measures fail?

  # EXPLORE - Provide authentic context
  materials:
    - cryptovault.apk
    - Developer's security checklist (all items checked ✓)
    - Incident report: "Credentials stolen from app"

  tools_available:
    - jadx (decompilation)
    - frida (runtime analysis)
    - adb (device interaction)

  # EXPLAIN - Required reasoning
  reasoning_required:
    - Identify WHAT failed
    - Explain WHY it failed (root cause, not just symptom)
    - Connect to the driving question

  # ELABORATE - Transfer requirement
  transfer_questions:
    - What other apps might have this same vulnerability?
    - How would you recognize this pattern in a new app?
    - What would actually fix this (not just patch the symptom)?

  # EVALUATE - Reflection prompts
  reflection:
    - What assumption did the developers make that was wrong?
    - How does this change how you think about "secure" apps?
    - What would YOU do differently if building this app?

  # SUCCESS CRITERIA
  success:
    knowledge_built: "Security fails when assumptions about attacker capabilities are wrong"
    flexibility_demonstrated: "Can identify assumption failures in novel contexts"
    question_answered: "Why did good intentions lead to failure?"
```

---

## Cognitive Flexibility Through Active Training

Cognitive flexibility = ability to adapt thinking to new situations.

Developed through:

### 1. Multiple Approaches to Same Problem
```
"Solve this three different ways"
- Forces consideration of alternatives
- Builds repertoire of approaches
- Develops judgment about when to use what
```

### 2. Transfer Challenges
```
"You solved X. Now solve Y, which is superficially different but structurally similar"
- Separates surface features from deep structure
- Builds pattern recognition across domains
- Develops abstract principle extraction
```

### 3. Contradictory Evidence
```
"Your analysis says X. This evidence says Y. Reconcile them."
- Forces reconsideration of conclusions
- Develops intellectual humility
- Builds nuanced thinking
```

### 4. Novel Contexts
```
"Apply what you learned to this domain you haven't seen"
- Tests true understanding vs. memorization
- Reveals gaps in principle comprehension
- Develops genuine transfer ability
```

---

## The Anti-Pattern: Purposeless Challenges

Challenges WITHOUT driving questions become:
- Arbitrary exercises
- "Do this because we say so"
- Tasks without meaning
- Skills without understanding

Signs of purposeless challenges:
- No "why" - just "what" and "how"
- No connection to real-world issues
- No transfer requirement
- Success = task completion, not understanding

**Every challenge must answer: "Why does this matter?"**

---

## Assessment: Did Learning Happen?

True assessment asks:

1. **Can they answer the driving question?**
   - Not just solve the specific challenge
   - But articulate the underlying principle

2. **Can they transfer to novel situations?**
   - Same principle, different surface features
   - Recognizing patterns across contexts

3. **Do they ask better questions?**
   - Inquiry improves inquiry
   - Learning to learn

4. **Has their thinking changed?**
   - Before: "I need to find vulnerabilities"
   - After: "I need to understand why security fails"

---

## Conclusion: Purpose Transforms Practice

Without driving questions:
- Challenges are tasks
- Learning is accumulation
- Flexibility is limited
- Transfer is weak

With driving questions:
- Challenges are investigations
- Learning is construction
- Flexibility is developed
- Transfer is natural

**The question "Why do security measures fail?" teaches more than a thousand "Find the vulnerability" challenges.**
