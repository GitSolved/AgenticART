# AgenticART Dojo

A training framework for security LLMs that uses structured challenges, automated grading, and fine-tuning to improve ADB command generation.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              DOJO FRAMEWORK                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Phase 1-3: Challenge & Grade (This Machine)      Phase 4: Train (GPU)      │
│  ┌─────────────────────────────────────────┐     ┌───────────────────────┐  │
│  │                                         │     │                       │  │
│  │  ┌─────────┐    ┌─────────┐            │     │  ┌─────────────────┐  │  │
│  │  │Curriculum│───▶│Challenger│            │     │  │   train.py      │  │  │
│  │  │ (YAML)  │    │         │            │     │  │                 │  │  │
│  │  └─────────┘    └────┬────┘            │     │  └────────┬────────┘  │  │
│  │                      │                  │     │           │          │  │
│  │                      ▼                  │     │           ▼          │  │
│  │               ┌──────────┐             │     │  ┌─────────────────┐  │  │
│  │               │ Executor │             │     │  │ PyTorch + CUDA  │  │  │
│  │               │  (ADB)   │             │     │  │    Unsloth      │  │  │
│  │               └────┬─────┘             │     │  └────────┬────────┘  │  │
│  │                    │                    │     │           │          │  │
│  │                    ▼                    │     │           ▼          │  │
│  │  ┌─────────┐  ┌─────────┐              │     │  ┌─────────────────┐  │  │
│  │  │ Sensei  │◀─│ Ollama  │              │     │  │  Fine-tuned     │  │  │
│  │  │(Grader) │  │  (LLM)  │              │     │  │    Model        │  │  │
│  │  └────┬────┘  └─────────┘              │     │  └─────────────────┘  │  │
│  │       │                                 │     │                       │  │
│  │       ▼                                 │     │                       │  │
│  │  ┌──────────────┐                      │     │                       │  │
│  │  │Training Data │──────────────────────┼────▶│                       │  │
│  │  │(Alpaca/DPO)  │                      │     │                       │  │
│  │  └──────────────┘                      │     │                       │  │
│  │                                         │     │                       │  │
│  │  Requirements:                          │     │  Requirements:        │  │
│  │  - Python 3.10+                        │     │  - NVIDIA GPU 16GB+   │  │
│  │  - Ollama                              │     │  - PyTorch + CUDA     │  │
│  │  - ADB                                 │     │  - Unsloth/TRL/PEFT   │  │
│  │  - NO PyTorch                          │     │                       │  │
│  └─────────────────────────────────────────┘     └───────────────────────┘  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Phases

| Phase | Name | Purpose | PyTorch? |
|-------|------|---------|----------|
| 1 | Models | Data structures, Belt/Grade enums | No |
| 2 | Curriculum | Load challenges, execute on device, retry logic | No |
| 3 | Sensei | Grade results, extract training examples, export | No |
| 4 | Fine-tune | Train model on collected data | **Yes** |

## Dependencies

### Phases 1-3 (This Machine)

```bash
# Python packages
pip install pyyaml

# Ollama (LLM runtime - NOT PyTorch)
# Windows: https://ollama.com/download/windows
ollama pull hf.co/bartowski/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B-GGUF:Q4_K_M

# Android SDK (for ADB)
# Set ADB_PATH or ensure 'adb' is in PATH
```

### Phase 4 (GPU Machine)

```bash
# Full ML stack
pip install torch transformers datasets trl peft unsloth bitsandbytes
```

## Why Ollama vs PyTorch?

| Ollama | PyTorch |
|--------|---------|
| **Inference only** - runs pre-trained models | **Training** - modifies model weights |
| Optimized for CPU/consumer GPU | Requires CUDA GPU |
| Simple CLI: `ollama run model` | Complex: dataloaders, optimizers, loss |
| Can't change the model | Can fine-tune the model |

The Dojo uses Ollama to **run** challenges against the model and collect data.
Fine-tuning uses PyTorch to **train** the model on that data.

## Quick Start

```bash
# Run challenges (no GPU needed)
python -m dojo.test_end_to_end --mode live --belt white

# Package for fine-tuning (transfer to GPU machine)
python -c "
from dojo.finetune import TrainingPackager
from pathlib import Path
packager = TrainingPackager()
packager.create_package(Path('dojo_output/training_data/combined/combined_all_*.json'))
"
```

## File Structure

```
dojo/
├── __init__.py              # v0.3.0
├── requirements.txt         # Dojo deps (no PyTorch)
├── models.py                # Belt, Grade, Challenge, etc.
├── config.py                # DojoConfig
├── exceptions.py            # Error types
├── curriculum/              # Phase 2
│   ├── loader.py            # YAML challenge loading
│   ├── executor.py          # ADB command execution
│   ├── error_extractor.py   # Parse error output
│   ├── context_injector.py  # Build retry prompts
│   └── challenger.py        # Orchestrate attempts
├── sensei/                  # Phase 3
│   ├── grader.py            # Score sessions
│   ├── training_extractor.py
│   ├── exporter.py          # JSONL, Alpaca, DPO
│   └── progress_tracker.py
├── finetune/                # Phase 4
│   ├── config.py            # FinetuneConfig
│   └── packager.py          # Create portable package
└── test_end_to_end.py       # Full pipeline test
```
