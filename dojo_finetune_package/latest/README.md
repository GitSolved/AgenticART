# AgenticART Dojo - Fine-Tuning Package (MLX Edition)

This package contains everything needed to fine-tune WhiteRabbitNeo on ADB command data using **Apple Silicon (MLX)**.

## Contents

- `data/training_data.json` - Training data in Alpaca format
- `train.py` - Main training script (uses `mlx_lm.lora`)
- `config.json` - Training configuration
- `requirements.txt` - Python dependencies (MLX)
- `Modelfile` - Ollama Modelfile (lightweight alternative)

## Requirements

- **Hardware:** Apple Silicon Mac (M1/M2/M3)
- **OS:** macOS 13.3+
- **Python:** 3.10+
- **RAM:** 16GB+ recommended

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Run Training

This will use the Neural Engine / GPU on your Mac.

```bash
# Standard run (default settings)
python train.py

# Custom settings
python train.py --iters 1000 --batch-size 8 --learning-rate 1e-5
```

### 3. Test Your Model

After training, adapters are saved to `mlx_adapters/`. Test them in the Dojo:

```bash
cd ../..
python -m dojo.test_end_to_end --mode mlx --adapter dojo_finetune_package/finetune_package_<timestamp>/mlx_adapters
```

## Configuration

Default settings in `config.json`:

| Setting | Value |
|---------|-------|
| Base Model | WhiteRabbitNeo/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B |
| LoRA Rank | 16 |
| LoRA Alpha | 32 |
| Epochs/Iters | 3 (converted to iters) |
| Batch Size | 4 |

## Alternative: Ollama

If you prefer to run the base model in Ollama without fine-tuning:

```bash
ollama create whiterabbit-adb-dojo -f Modelfile
ollama run whiterabbit-adb-dojo
```
