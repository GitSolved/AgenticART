# AgenticART Curriculum Summary

> Complete pedagogical framework for training local LLMs in mobile security analysis

---

## Training Data Overview

### High-Quality Pedagogical Data (Recommended for DPO)

| File | Pairs | Purpose |
|------|-------|---------|
| `pedagogical_combined_*.jsonl` | 89 | Combined pedagogical curriculum |
| `unified_amplified_*.jsonl` | 56 | Quality-amplified with transfer contexts |
| `phase_0_foundations_*.jsonl` | 4 | Explicit reasoning method instruction |
| `unified_complete_*.jsonl` | 24 | Complete unified curriculum challenges |
| `inquiry_based.jsonl` | 10 | Purpose-driven inquiry challenges |
| `dual_mandate_training.jsonl` | 22 | Reasoning + application integration |
| `meaningful_challenges.jsonl` | 15 | 4C competency challenges |
| `integrated_reasoning.jsonl` | 8 | Explicit instruction + application |
| `deconditioning_*.jsonl` | 5 | Bad habit deconditioning |
| `false_beliefs_*.jsonl` | 5 | False belief dispelling |

**Total High-Quality Pedagogical Pairs: ~238**

### Technique Variation Data

| File | Pairs | Purpose |
|------|-------|---------|
| `dpo_amplified_*.jsonl` | 1,640 | Technique variations from original curriculum |

---

## Curriculum Architecture

### The Four Pillars

```
┌─────────────────────────────────────────────────────────────────────┐
│                    UNIFIED CURRICULUM ARCHITECTURE                   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  PILLAR 1: EXPLICIT REASONING INSTRUCTION                           │
│  ├── Deductive Reasoning (certain conclusions from premises)        │
│  ├── Inductive Reasoning (patterns from observations)               │
│  ├── Evidence Evaluation (assessing claims against evidence)        │
│  └── Systems Analysis (emergent properties from interactions)       │
│                                                                      │
│  PILLAR 2: AUTHENTIC APPLICATION CONTEXTS                           │
│  ├── Real stakes (not artificial puzzles)                           │
│  ├── Driving questions (purpose-based learning)                     │
│  └── Cognitive dissonance (motivates investigation)                 │
│                                                                      │
│  PILLAR 3: COMPLETE INVESTIGATION TRAJECTORIES                      │
│  ├── ENGAGE: Question and dissonance                                │
│  ├── EXPLORE: Investigation with branches and dead ends             │
│  ├── EXPLAIN: Explicit reasoning applied                            │
│  ├── ELABORATE: Transfer to new contexts                            │
│  └── EVALUATE: Meta-cognitive reflection                            │
│                                                                      │
│  PILLAR 4: PRAXIS (Union of Thought and Action)                     │
│  ├── Problem-posing education (not banking model)                   │
│  ├── Structured argumentation (defense and rebuttal)                │
│  └── Knowledge construction (not accumulation)                      │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Learning Sequence (Critical for Effectiveness)

```
Phase 0: FOUNDATIONS (Must come first)
├── Explicit instruction in each reasoning method
├── No challenges yet - just understanding the methods
└── Enables: All subsequent challenges

Phase 1: WHITE BELT (Heavy scaffolding)
├── Single reasoning method per challenge
├── Prerequisites: Phase 0
└── Enables: Phase 2

Phase 2: YELLOW BELT (Less scaffolding)
├── Same methods, increasing independence
├── Prerequisites: All Phase 1
└── Enables: Phase 3

Phase 3: ORANGE BELT (Integration)
├── Two methods combined
├── False beliefs applied in context
├── Prerequisites: All Phase 2
└── Enables: Phase 4

Phase 4: GREEN BELT (Flexibility)
├── Method selection required
├── Novel contexts
├── Prerequisites: All Phase 3
└── Enables: Phase 5

Phase 5+: BLUE through BLACK
├── Synthesis, teaching, mastery, creation
├── Each builds on previous
└── Full cognitive flexibility required
```

---

## Key Pedagogical Innovations

### 1. Explicit Reasoning Instruction

Every prompt explicitly teaches the reasoning method:
- Definition and structure provided
- Worked example included
- Key questions to ask
- Common errors to avoid
- Required response structure

**Why**: Implicit instruction is significantly less effective than explicit.

### 2. Investigation Trajectories (Not Just Answers)

Every chosen response shows the journey:
- Dead ends and revisions
- How discoveries connect
- Why certain approaches work
- What would change conclusions

**Why**: Showing process builds transferable skills.

### 3. Structured Argumentation

Every conclusion includes:
- CLAIM: What is asserted
- EVIDENCE: What supports it
- REASONING: How evidence connects to claim
- COUNTERARGUMENT: What could challenge it
- REBUTTAL: Why counterargument fails
- CONCLUSION: Final position, appropriately nuanced

**Why**: Argumentation forces explicit reasoning and builds communication skills.

### 4. Transfer Principle Extraction

Every challenge extracts transferable knowledge:
- Abstract enough to generalize
- Concrete enough to guide action
- Recognition criteria for when to apply
- Where else it applies listed

**Why**: Transfer is the test of true understanding.

### 5. Deconditioning Bad Habits

Explicit training pairs showing:
- The bad habit in action
- Why it leads to wrong conclusions
- The better approach
- Why the better approach works

**Why**: Bad habits must be explicitly corrected, not implicitly trained over.

### 6. Dispelling False Beliefs

Explicit training pairs showing:
- The common misconception
- Why it seems reasonable
- Evidence that disproves it
- The correct understanding

**Why**: False beliefs persist unless explicitly addressed.

---

## The Five Bad Habits to Decondition

| Habit | Problem | Correction |
|-------|---------|------------|
| Pattern matching without verification | Surface similarity ≠ deep structure | Always verify assumptions |
| Assuming tools are correct | Tools have blind spots | Verify critical findings manually |
| Stopping at first finding | Missing the full picture | Complete comprehensive analysis |
| Overconfidence without evidence | Confidence > evidence | Calibrate to evidence quality |
| Accepting authority uncritically | Authority ≠ correctness | Demand verification regardless of source |

---

## The Five False Beliefs to Dispel

| Belief | Reality |
|--------|---------|
| Obfuscation = Security | Obscurity increases effort, not security |
| Root detection stops attacks | Device owner controls device |
| SSL pinning is unbreakable | Implementation > concept |
| Native code is more secure | Complexity ≠ security |
| CVE descriptions are complete | Documentation ≠ reality |

---

## The Five Big Driving Questions

| # | Question | What It Teaches |
|---|----------|-----------------|
| BQ1 | Why do security measures fail despite good intentions? | Root cause analysis |
| BQ2 | How can we protect anything on hardware we don't control? | Fundamental limits |
| BQ3 | What separates security theater from actual security? | Critical evaluation |
| BQ4 | How do complex systems create unexpected vulnerabilities? | Systems thinking |
| BQ5 | How do we communicate findings to drive action? | Effective reporting |

---

## Using the Training Data

### For DPO Training

**Recommended approach**:

1. **Use sequenced data first**: Start with `phase_0_foundations_*.jsonl`
2. **Add pedagogical combined**: Include `pedagogical_combined_*.jsonl`
3. **Add amplified variations**: Include `unified_amplified_*.jsonl`
4. **Optional technique variations**: Add `dpo_amplified_*.jsonl` for technique breadth

### Training Order Matters

```python
# Suggested dataset composition
training_data = []

# 1. Phase 0 foundations (explicit instruction) - weighted 2x
training_data.extend(load_jsonl("phase_0_foundations_*.jsonl") * 2)

# 2. Pedagogical combined (integrated curriculum)
training_data.extend(load_jsonl("pedagogical_combined_*.jsonl"))

# 3. Amplified variations (transfer and reasoning alternatives)
training_data.extend(load_jsonl("unified_amplified_*.jsonl"))

# 4. Optional: Technique variations for breadth
training_data.extend(load_jsonl("dpo_amplified_*.jsonl"))

# Shuffle within phases, but maintain phase order weighting
```

### Evaluation Criteria

True learning is demonstrated by:
1. ✓ Can construct valid deductive arguments
2. ✓ Can build hypotheses from observations
3. ✓ Can evaluate evidence quality (not source authority)
4. ✓ Can identify emergent system properties
5. ✓ Can transfer principles to novel contexts
6. ✓ Can defend conclusions with structured argumentation
7. ✓ Doesn't exhibit the 5 bad habits
8. ✓ Doesn't hold the 5 false beliefs

---

## Summary

This curriculum represents:
- **Explicit instruction** over implicit absorption
- **Investigation trajectories** over final answers
- **Authentic application** over artificial exercises
- **Transfer principles** over memorized techniques
- **Praxis** - the authentic union of critical thought and purposeful action

The training data is not a collection of examples.
It is **curriculum as code**.

---

## Files Reference

### Curriculum Documentation
- `UNIFIED_CURRICULUM.md` - Complete architecture
- `LEARNING_SEQUENCE.md` - Sequencing and prerequisites
- `DRIVING_QUESTIONS.md` - Purpose-based learning framework
- `PRAXIS_PHILOSOPHY.md` - Pedagogical foundation
- `REASONING_INSTRUCTION.md` - Explicit reasoning methods
- `MEANINGFUL_CHALLENGES.md` - 4C competency framework

### Training Generators
- `unified_curriculum_trainer.py` - Master training generator
- `sequenced_curriculum_trainer.py` - Phase 0 foundations
- `pedagogical_amplifier.py` - Quality-preserving amplification
- `inquiry_based_trainer.py` - Purpose-driven challenges
- `integrated_reasoning_trainer.py` - Explicit instruction + application
- `scaffolded_reasoning_trainer.py` - Deconditioning and belief dispelling
