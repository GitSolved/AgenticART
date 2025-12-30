# Exporting Training Data

Package execution-verified traces for model training.

## Export Command

```bash
python3 scripts/package_finetune.py
```

## Output Formats

### JSONL (Raw)

```json
{"instruction": "...", "input": "...", "output": "...", "metadata": {...}}
```

Use for: Custom training pipelines

### Alpaca Format

```json
[
  {
    "instruction": "Write an ADB command to list packages",
    "input": "Device: emulator-5554",
    "output": "shell pm list packages"
  }
]
```

Use for: Instruction fine-tuning (most common)

### ShareGPT Format

```json
{
  "conversations": [
    {"from": "human", "value": "..."},
    {"from": "gpt", "value": "..."}
  ]
}
```

Use for: Chat model fine-tuning

### DPO Format

```json
{
  "prompt": "...",
  "chosen": "correct command",
  "rejected": "failed command"
}
```

Use for: Preference optimization (RLHF alternative)

## Filtering by Grade

Export only high-quality examples:

```python
from dojo.finetune.packager import TrainingPackager

packager = TrainingPackager()
packager.export(
    min_grade="B",  # Only A and B grades
    formats=["alpaca", "dpo"]
)
```

## Validation

Verify exported data:

```bash
python3 scripts/validate_training_data.py
```

Checks:

- JSON syntax validity
- Required fields present
- No empty outputs
- Metadata integrity
