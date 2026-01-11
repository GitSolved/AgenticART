# Baseline Comparison Experiment

**Purpose**: Determine if AgenticART's complexity is justified by comparing against simpler alternatives.

## The Core Question

Does the full AgenticART pipeline (7 LoRA adapters + Best-of-N + CoT enforcement) outperform:
1. Claude with good prompting?
2. Qwen 2.5 7B with good prompting (no fine-tuning)?
3. Qwen 2.5 7B with a single general adapter?

## Decision Framework

After running this experiment, use these thresholds:

| Result | Decision |
|--------|----------|
| Full pipeline < Claude baseline | **Stop**. Use Claude with good prompts. |
| Full pipeline ≈ Claude (±5pp) | **Simplify**. The complexity isn't worth it. |
| Full pipeline > Claude (>10pp), Expert Mixture insignificant | **Simplify** to single adapter. |
| Full pipeline > Claude (>10pp), Expert Mixture significant | **Keep** Expert Mixture, evaluate Best-of-N. |
| All components significant | **Keep** full pipeline. |

**pp = percentage points**

## Running the Experiment

### 1. Create Holdout Test Set (DO THIS FIRST)

```bash
python create_test_set.py
```

This creates `test_challenges/` with stratified samples. **Never train on these challenges.**

### 2. Train the Single General Adapter

Before running arm C, you need a single general-purpose adapter:

```bash
# Combine training data from all pillars
cat adapters/*/training_data.jsonl > adapters/qwen_general_lora/training_data.jsonl

# Train
./adapters/train_adapter.sh general --epochs 1000
```

### 3. Run the Experiment

```bash
python experiment_runner.py
```

This takes several hours. Progress is saved incrementally.

### 4. Analyze Results

```bash
python statistical_analysis.py results/results_TIMESTAMP.json
```

### 5. Human Evaluation (Critical)

Automated metrics only measure "did it work" not "is the reasoning correct."

```bash
# Generate evaluation set (blinded)
python -c "
from human_evaluation import HumanEvaluationProtocol
from pathlib import Path
protocol = HumanEvaluationProtocol(Path('results/responses_TIMESTAMP.jsonl'))
protocol.create_evaluation_set(Path('human_eval/eval_set.json'))
"

# Have 2 evaluators independently rate items using the rubric
# Then analyze inter-rater reliability and unblind
```

## Interpreting Results

### Example Output

```
ABLATION ANALYSIS
----------------------------------------
  fine_tuning          +12.3%  (h=0.34) ***
    → Fine-tuning adds 12.3pp
  expert_mixture       +3.2%   (h=0.11)
    → Expert Mixture adds 3.2pp
  best_of_n_cot        +5.1%   (h=0.18) ***
    → Best-of-N + CoT adds 5.1pp

KEY FINDINGS
----------------------------------------
  ✓ Full pipeline OUTPERFORMS Claude (statistically significant)
  ✗ Expert Mixture does NOT provide meaningful improvement
    → Consider simplifying to single adapter
  ✓ Best-of-N + CoT provides meaningful improvement
```

**Interpretation**: In this example, you should:
1. Keep fine-tuning (significant 12pp gain)
2. Remove Expert Mixture (only 3pp, not significant)
3. Keep Best-of-N + CoT (significant 5pp gain)

### Effect Size Guidelines (Cohen's h)

| h value | Interpretation |
|---------|----------------|
| < 0.20 | Negligible - probably not worth the complexity |
| 0.20-0.50 | Small - consider if complexity is low |
| 0.50-0.80 | Medium - likely worth it |
| > 0.80 | Large - definitely worth it |

## Files

```
experiments/baseline_comparison/
├── README.md                    # This file
├── experiment_config.py         # Arm definitions, hyperparameters
├── experiment_runner.py         # Main experiment execution
├── statistical_analysis.py      # Significance tests, effect sizes
├── human_evaluation.py          # Blind human evaluation protocol
├── create_test_set.py          # Generate holdout set
├── test_challenges/            # Holdout test set (DO NOT TRAIN ON)
│   ├── holdout_white/
│   ├── holdout_yellow/
│   ├── holdout_green/
│   ├── holdout_brown/
│   ├── holdout_black/
│   ├── holdout_novel/
│   └── manifest.json
└── results/                    # Experiment outputs
    ├── results_TIMESTAMP.json
    └── responses_TIMESTAMP.jsonl
```

## Cost Estimation

| Arm | Cost Factor | Notes |
|-----|-------------|-------|
| Claude baseline | ~$5-10 for 100 challenges | API costs |
| Qwen (all variants) | $0 | Local inference on M3 Max |

Running all 5 arms on 100 challenges: ~$5-10 total (Claude API only)

## Validity Threats

1. **Selection bias**: Test set might not represent real-world pentesting tasks
2. **Emulator ceiling**: Performance on Genymotion ≠ performance on real devices
3. **Grading limitations**: Rule-based verification can't capture reasoning quality
4. **Human evaluation bias**: Evaluators might have implicit preferences

Mitigations:
- Include "novel" tier with unseen vulnerability patterns
- Human evaluation with inter-rater reliability checks
- Blind evaluation protocol
