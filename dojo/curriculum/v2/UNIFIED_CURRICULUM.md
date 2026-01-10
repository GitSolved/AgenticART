# Unified Curriculum Architecture

> This document synthesizes the pedagogical framework into a practical training system
> that creates truly impactful learning data for local LLMs.

---

## The Core Insight: Why Most Training Fails

Most training data fails to produce capable models because it:
1. Shows **answers** instead of **reasoning processes**
2. Teaches **techniques** instead of **principles**
3. Uses **artificial contexts** instead of **authentic stakes**
4. Expects **implicit absorption** instead of **explicit instruction**
5. Measures **task completion** instead of **understanding transfer**

**The solution**: Training data that embodies praxis - the inseparable unity of
critical thought and purposeful action.

---

## Architecture: The Four Pillars

### Pillar 1: Explicit Reasoning Instruction

Training data must **explicitly teach** reasoning methods, not expect implicit learning.

```
WHAT TO INCLUDE IN EVERY PROMPT:
┌─────────────────────────────────────────────────────────────────────┐
│ 1. Named reasoning method with definition                          │
│ 2. Explicit structure to follow                                    │
│ 3. Worked example showing the structure applied                    │
│ 4. Key questions to ask                                            │
│ 5. Common errors to avoid                                          │
│ 6. Required response structure (enforces application)              │
└─────────────────────────────────────────────────────────────────────┘

WHAT TO INCLUDE IN EVERY CHOSEN RESPONSE:
┌─────────────────────────────────────────────────────────────────────┐
│ 1. Explicit application of the named structure                     │
│ 2. Each step labeled and visible                                   │
│ 3. Reasoning made explicit, not implicit                           │
│ 4. Transfer principle extracted and stated                         │
│ 5. Meta-cognitive reflection on the process                        │
└─────────────────────────────────────────────────────────────────────┘

WHAT MAKES A REJECTED RESPONSE:
┌─────────────────────────────────────────────────────────────────────┐
│ 1. Correct answer but implicit reasoning                           │
│ 2. Pattern matching without understanding                          │
│ 3. No explicit structure followed                                  │
│ 4. Missing transfer - can't generalize                             │
│ 5. Bad habits (stopping at first finding, overconfidence, etc.)    │
└─────────────────────────────────────────────────────────────────────┘
```

### Pillar 2: Authentic Application Contexts

Every challenge must have **authentic stakes** that make learning meaningful.

```
AUTHENTIC CONTEXT REQUIREMENTS:
┌─────────────────────────────────────────────────────────────────────┐
│ NOT: "Find the vulnerability in this APK"                          │
│ YES: "Users are losing money despite security claims. Why?"        │
│                                                                     │
│ NOT: "Bypass the root detection"                                   │
│ YES: "The bank believes this check protects users. Does it?"       │
│                                                                     │
│ NOT: "Analyze the encryption"                                      │
│ YES: "The developer followed best practices but got hacked. Why?"  │
└─────────────────────────────────────────────────────────────────────┘

Every context must answer:
- Why does this matter?
- Who is affected?
- What decision depends on this analysis?
```

### Pillar 3: Complete Investigation Trajectories

Training data must show **the journey**, not just the destination.

```
TRAJECTORY STRUCTURE:
┌─────────────────────────────────────────────────────────────────────┐
│ PHASE 1: ENGAGE - Question and cognitive dissonance                │
│    "This should be secure, but it's not. What's wrong?"            │
│                                                                     │
│ PHASE 2: EXPLORE - Investigation with multiple paths               │
│    "Let me examine... This path shows X, this path shows Y..."     │
│    CRITICAL: Show branching, dead ends, revisions                  │
│                                                                     │
│ PHASE 3: EXPLAIN - Explicit reasoning about findings               │
│    "The evidence shows... Using [REASONING METHOD]..."             │
│    Apply the explicit reasoning framework                          │
│                                                                     │
│ PHASE 4: ELABORATE - Transfer to new contexts                      │
│    "This principle applies to X, Y, Z because..."                  │
│    Demonstrate cognitive flexibility                               │
│                                                                     │
│ PHASE 5: EVALUATE - Meta-cognitive reflection                      │
│    "What worked? What would I do differently? How has my           │
│     understanding changed?"                                        │
└─────────────────────────────────────────────────────────────────────┘
```

### Pillar 4: Praxis Through Problem-Posing

Training must facilitate praxis - not banking education.

```
BANKING MODEL (WRONG):
┌─────────────────────────────────────────────────────────────────────┐
│ Prompt: "Here's what you need to know about X. Apply it to Y."     │
│ Response: "Applied X to Y. Done."                                  │
│                                                                     │
│ Problem: Passive recipient, no critical consciousness              │
└─────────────────────────────────────────────────────────────────────┘

PROBLEM-POSING MODEL (RIGHT):
┌─────────────────────────────────────────────────────────────────────┐
│ Prompt: "This situation contradicts what we expect. Investigate."  │
│ Response:                                                          │
│   - "I notice a contradiction..."                                  │
│   - "Let me investigate using [METHOD]..."                         │
│   - "This reveals a deeper principle..."                           │
│   - "This raises new questions about..."                           │
│   - "I would investigate further by..."                            │
│                                                                     │
│ Result: Active investigator, generates new questions               │
└─────────────────────────────────────────────────────────────────────┘
```

---

## The Five Required Components in Every Training Pair

### Component 1: Driving Question (Purpose)

Every pair must connect to a Big Driving Question:

| Question | Purpose |
|----------|---------|
| BQ1: "Why do security measures fail despite good intentions?" | Root cause analysis |
| BQ2: "How can we protect anything on hardware we don't control?" | Fundamental limits |
| BQ3: "What separates security theater from actual security?" | Critical evaluation |
| BQ4: "How do complex systems create unexpected vulnerabilities?" | Systems thinking |
| BQ5: "How do we communicate findings to drive action?" | Effective reporting |

### Component 2: Explicit Reasoning Method (Instruction)

Every pair must explicitly teach one primary reasoning method:

| Method | When Used | Structure |
|--------|-----------|-----------|
| Deductive | Deriving conclusions from principles | Premise → Premise → Conclusion |
| Inductive | Building principles from observations | Observation → Pattern → Hypothesis → Test |
| Systems Analysis | Understanding emergent behavior | Components → Interactions → Emergent Properties |
| Evidence Evaluation | Assessing claims | Claim → Source → Evidence → Verification → Conclusion |

### Component 3: Structured Argumentation (Defense)

Every chosen response must include structured argumentation:

```
CLAIM: [What I assert based on analysis]
EVIDENCE: [What specifically supports this claim]
REASONING: [How the evidence connects to the claim]
COUNTERARGUMENT: [What could challenge this claim]
REBUTTAL: [Why the counterargument fails, or how it qualifies the claim]
CONCLUSION: [Final position, appropriately nuanced]
```

### Component 4: Transfer Principle (Generalization)

Every chosen response must extract a transferable principle:

```
TRANSFER PRINCIPLE REQUIREMENTS:
- Must be abstract enough to apply beyond this specific case
- Must be concrete enough to guide future analysis
- Must explicitly state where else it applies
- Must include recognition criteria (how to spot when it applies)
```

### Component 5: Meta-Cognitive Reflection (Learning to Learn)

Every chosen response must include explicit meta-cognition:

```
META-COGNITIVE REFLECTION:
- What reasoning process did I use?
- What worked well? What didn't?
- What assumption did I make? Was it valid?
- What would I do differently next time?
- How has my understanding changed?
- What new questions does this raise?
```

---

## Deconditioning: Bad Habits and False Beliefs

### False Beliefs to Dispel

Each belief must have explicit training pairs showing:
1. The common misconception
2. Why it seems reasonable
3. Evidence that disproves it
4. The correct understanding

| False Belief | Correction |
|--------------|------------|
| "Obfuscation = Security" | Obscurity increases effort, not security |
| "Root detection stops attacks" | Device owner controls device |
| "SSL pinning is unbreakable" | Implementation > concept |
| "Native code is more secure" | Complexity ≠ security |
| "CVE descriptions are complete" | Documentation ≠ reality |

### Bad Habits to Decondition

Each habit must have explicit training pairs showing:
1. The problematic behavior
2. Why it leads to wrong conclusions
3. The better approach
4. Why the better approach works

| Bad Habit | Better Approach |
|-----------|-----------------|
| Pattern matching without verification | Test assumptions with evidence |
| Assuming tools are correct | Verify tool output manually |
| Stopping at first finding | Continue comprehensive analysis |
| Overconfidence without evidence | Calibrate confidence to evidence |
| Accepting authority uncritically | Demand verification regardless of source |

---

## Belt Progression: Scaffolded Complexity

### White Belt: Foundation
- Single reasoning method per challenge
- Explicit scaffolding provided
- Focus: Learn the reasoning structures

### Yellow Belt: Application
- Single reasoning method, less scaffolding
- Authentic stakes introduced
- Focus: Apply structures independently

### Orange Belt: Integration
- Two reasoning methods combined
- Transfer explicitly required
- Focus: Integrate methods

### Green Belt: Flexibility
- Multiple valid approaches
- Novel contexts
- Focus: Cognitive flexibility

### Blue Belt: Synthesis
- Create new approaches from principles
- Complex systems analysis
- Focus: Synthesis

### Purple Belt: Transfer
- Cross-domain application
- Teaching others (requires deep understanding)
- Focus: Far transfer

### Brown Belt: Mastery
- Novel problem types
- Method selection judgment
- Focus: Expert judgment

### Black Belt: Creation
- Generate new frameworks
- Advance the field
- Focus: Knowledge creation

---

## Training Data Generation Requirements

### Minimum Requirements Per Challenge

```yaml
required_elements:
  driving_question: true           # Connection to BQ1-5
  explicit_reasoning_method: true  # Named method with structure
  authentic_context: true          # Real stakes, not artificial
  investigation_trajectory: true   # Show the process
  structured_argumentation: true   # Claim-Evidence-Reasoning
  transfer_principle: true         # Generalization extracted
  meta_cognition: true            # Reflection on process

chosen_response_requirements:
  explicit_structure_followed: true
  reasoning_visible: true
  principle_extracted: true
  transfer_demonstrated: true
  reflection_included: true

rejected_response_characteristics:
  - implicit_reasoning           # Correct but unexplained
  - pattern_matching            # No understanding
  - no_transfer                 # Can't generalize
  - bad_habit_exhibited         # Any of the 5 bad habits
  - false_belief_held           # Any of the 5 false beliefs
```

### Variation Axes for Amplification

To amplify training data while maintaining pedagogical value:

1. **Surface Variation**: Same principle, different APK/context
2. **Reasoning Method Variation**: Same challenge, different reasoning approach
3. **Complexity Variation**: Same principle, different belt level
4. **Transfer Variation**: Same principle, different application domain
5. **Error Variation**: Different ways to get it wrong (bad habits, false beliefs)

---

## Quality Metrics

### Training Pair Quality Checklist

```
□ Does the prompt explicitly teach a reasoning method?
□ Is the context authentic with real stakes?
□ Does the chosen response follow the explicit structure?
□ Is all reasoning visible (not implicit)?
□ Is a transfer principle extracted and explained?
□ Is meta-cognitive reflection included?
□ Does the rejected response demonstrate a specific failure mode?
□ Is the rejection reason explicit and educational?
```

### Curriculum Coverage Matrix

Ensure training data covers:

|              | BQ1 | BQ2 | BQ3 | BQ4 | BQ5 |
|--------------|-----|-----|-----|-----|-----|
| Deductive    |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |
| Inductive    |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |
| Systems      |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |
| Evidence     |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |

At each belt level:

|              | White | Yellow | Orange | Green | Blue | Purple | Brown | Black |
|--------------|-------|--------|--------|-------|------|--------|-------|-------|
| Minimum Pairs|  20   |   20   |   20   |   20  |  20  |   20   |  20   |  20   |

---

## Integration: The Master Training Generator

The master training generator must:

1. **Accept Challenge Definition** with:
   - Driving question
   - Belt level
   - Primary reasoning method
   - Authentic context
   - APK/materials reference

2. **Generate Complete Trajectory** showing:
   - Engage phase (cognitive dissonance)
   - Explore phase (investigation with branches)
   - Explain phase (explicit reasoning)
   - Elaborate phase (transfer)
   - Evaluate phase (meta-cognition)

3. **Produce Chosen/Rejected Pairs** with:
   - Chosen: Full trajectory with all 5 components
   - Rejected: Specific failure mode (bad habit or implicit reasoning)
   - Metadata: Why rejected, what would fix it

4. **Validate Quality** against:
   - All required elements present
   - Explicit reasoning visible
   - Transfer principle actionable
   - Rejection reason educational

---

## Conclusion: The Unified Vision

Training data that transforms a local LLM must embody praxis:

**Reflection without action = Abstract verbalism**
(Reasoning methods taught without application)

**Action without reflection = Blind activism**
(Techniques memorized without understanding)

**Praxis = Authentic union of critical thought and purposeful action**
(Explicit reasoning applied to meaningful challenges, building transferable understanding)

Every training pair must be an investigation that:
- Starts with a question that matters
- Teaches reasoning explicitly
- Shows the complete journey
- Extracts transferable principles
- Reflects on the learning process

This is not training data. This is **curriculum as code**.
