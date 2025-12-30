# Research Methodology

How AgenticART validates AI security capabilities.

## Core Hypothesis

> Automated execution verification can replace human oversight in LLM-powered security testing.

## Triangulated Verification

Results are validated through three independent systems:

```
      LLM                    OS/ADB                  Grader
       │                       │                       │
generates valid         executes on real        checks output
   command               device, returns         against challenge
       │                 real stdout/rc              criteria
       │                       │                       │
       └───────────────────────┴───────────────────────┘
                               │
                          All three must
                            agree for
                             PASS
```

### Why Hallucination is Prevented

1. **Truth Source Separation:** The LLM generates commands, but the "truth" comes from the OS process buffer via `subprocess.run()`, not from the model.

2. **Hard Failure on No Device:** If no Android device is connected, ADB returns a hard error. There is no path to a "pass" without real hardware execution.

3. **Independent Grading:** The Grader evaluates actual execution output against challenge-defined validation patterns.

## Experimental Design

### Variables

| Variable | Control | Experimental |
|----------|---------|--------------|
| Model size | 70B (teacher) | 7B (student) |
| Training data | None | Verified traces |
| Verification | Human review | Automated |

### Metrics

- **Pass rate:** Challenges completed successfully
- **Grade distribution:** Quality of solutions
- **Efficiency:** Attempts needed per challenge

## Baseline Experiment Results

From Android 11 milestone:

| Condition | Pass Rate | Notes |
|-----------|-----------|-------|
| 7B baseline | 20% | Hallucinations, wrong syntax |
| 70B teacher | 100% | Gold standard |
| 7B fine-tuned | 100% | After 10 verified examples |

## Limitations

- Small sample size (5 white belt challenges)
- Single model pair tested
- Not replicated across belt levels

## Future Work

- Scale to full curriculum
- Test multiple model families
- Compare verification methods
