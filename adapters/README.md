# Expert Mixture LoRA Adapters

Specialized LoRA adapters for the AgenticART Android security dojo.

## Architecture

```
Base Model: Qwen 2.5 7B Instruct (~14GB)
     │
     └── LoRA Adapters (~100MB each)
         ├── qwen_static_lora      → Static code analysis
         ├── qwen_negative_lora    → Secure pattern recognition
         ├── qwen_rootcause_lora   → Root cause analysis
         ├── qwen_transfer_lora    → Pattern transfer learning
         ├── qwen_methodology_lora → Discovery methodology
         ├── qwen_taxonomy_lora    → CWE/OWASP classification
         └── qwen_patch_lora       → Patch completeness analysis
```

## M3 Max Unified Memory Optimization

The base model remains resident in Unified Memory while only the small
LoRA delta weights are swapped. This enables near-instant (~50-200ms)
expert switching compared to 30+ seconds for full model reloads.

## Adapter Structure

Each adapter directory contains:
- `adapter_config.json` - LoRA hyperparameters (rank, alpha, target modules)
- `adapters.safetensors` - Trained LoRA weights
- `README.md` - Training details and usage notes

## Training New Adapters

Use the dojo training pipeline to generate adapter-specific training data:

```bash
# Generate training data for a specific pillar
python -m dojo.train_adapter --pillar static_analysis --output adapters/qwen_static_lora

# Fine-tune with MLX
mlx_lm.lora \
    --model models/qwen2.5-7b-instruct \
    --train \
    --data adapters/qwen_static_lora/training_data.jsonl \
    --adapter-path adapters/qwen_static_lora \
    --iters 1000
```

## Configuration

Environment variables:
- `MLX_BASE_MODEL` - Path to base Qwen model
- `MLX_ADAPTER_DIR` - Base directory for adapters (default: `adapters/`)

## Pillar Descriptions

| Pillar | Focus Area | Key Training Signals |
|--------|------------|---------------------|
| STATIC_ANALYSIS | Decompiled code review | API patterns, data flow, taint analysis |
| NEGATIVE_KNOWLEDGE | Secure code recognition | False positive avoidance, defense patterns |
| ROOT_CAUSE | Deep "why" analysis | Vulnerability origins, design flaws |
| PATTERN_TRANSFER | Cross-context application | Pattern families, generalization |
| METHODOLOGY | Systematic discovery | Observation→hypothesis→test flow |
| TAXONOMY | Classification accuracy | CWE hierarchy, OWASP mapping |
| PATCH_ANALYSIS | Fix completeness | Bypass detection, incomplete patches |
