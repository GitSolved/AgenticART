# Fine-tuning with LoRA

Train a specialized security agent using Low-Rank Adaptation.

## Prerequisites

- Completed challenges with graded outputs
- MLX (Apple Silicon) or PyTorch (CUDA)
- Base model (e.g., Llama 3.1 8B, Qwen 2.5 7B)

## Step 1: Generate Training Data

Run challenges to generate verified traces:

```bash
python3 dojo/test_end_to_end.py \
  --mode live \
  --model llama3.1:70b \
  --belt white \
  --belt yellow
```

## Step 2: Package for Fine-tuning

```bash
python3 scripts/package_finetune.py
```

This creates:

```
dojo_output/training_data/
├── model_timestamp_alpaca.json    # Instruction format
├── model_timestamp_sharegpt.json  # Chat format
└── model_timestamp_dpo.json       # Preference pairs
```

## Step 3: Fine-tune with MLX (Apple Silicon)

```bash
python3 dojo/custom_train.py
```

Configuration in `custom_train.py`:

```python
model_path = "models/your-base-model-4bit"
data_source = "dojo_output/training_data/..._alpaca.json"
iterations = 500
batch_size = 1
learning_rate = 1e-5
```

## Step 4: Test Fine-tuned Model

```bash
python3 dojo/test_end_to_end.py \
  --mode live \
  --model ./models/your-adapters \
  --belt white
```

## Expected Results

From the Android 11 milestone experiment:

| Model | Pass Rate |
|-------|-----------|
| Base 7B (before) | 20% |
| Teacher 70B | 100% |
| Fine-tuned 7B (after) | 100% |

**Key insight:** 10 high-quality traces achieved 80pp improvement.

## Troubleshooting

### Out of memory

- Reduce batch size to 1
- Use 4-bit quantization
- Reduce sequence length

### Loss not converging

- Check data format matches model's expected template
- Verify prompt delimiters (e.g., `### Response:`)
