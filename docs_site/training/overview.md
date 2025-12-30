# Training Overview

How AgenticART creates training data for fine-tuning security LLMs.

## The Training Loop

```
┌─────────────────────────────────────────────────────────────┐
│                    AgenticART Training Loop                   │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│   Challenge ──► LLM ──► Command ──► Device ──► Grader       │
│       │                                           │          │
│       │                                           ▼          │
│       │                                    Training Data     │
│       │                                           │          │
│       └───────────── Next Challenge ◄─────────────┘          │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

## Why Execution Verification Matters

Traditional approach:

```
LLM generates command → Assume it works → Train on it
❌ Problem: Hallucinated commands become training data
```

AgenticART approach:

```
LLM generates command → Run on device → Verify output → Train only on successes
✅ Result: Training data contains only working commands
```

## Training Data Quality

| Grade | Meaning | Use in Training |
|-------|---------|-----------------|
| A | Perfect execution | Positive example |
| B | Good with minor issues | Positive example |
| C | Functional but flawed | Borderline |
| D | Poor execution | Negative example |
| F | Complete failure | Negative example |

## Export Formats

AgenticART exports training data in multiple formats:

| Format | Use Case | File |
|--------|----------|------|
| JSONL | Generic fine-tuning | `*_raw.jsonl` |
| Alpaca | Instruction tuning | `*_alpaca.json` |
| ShareGPT | Chat fine-tuning | `*_sharegpt.json` |
| DPO | Preference learning | `*_dpo.json` |

## Next Steps

- [Fine-tuning with LoRA](finetuning.md) - Train your model
- [Exporting Data](exporting.md) - Package training data
