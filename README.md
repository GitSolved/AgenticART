<div align="center">

# AgenticART

### The Android Security Dojo

*Train LLMs to generate exploits that actually work*

[![arXiv](https://img.shields.io/badge/arXiv-2509.07933-b31b1b.svg)](https://arxiv.org/abs/2509.07933)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/GitSolved/AgenticART/actions/workflows/ci.yml/badge.svg)](https://github.com/GitSolved/AgenticART/actions)

[Quick Start](#quick-start) · [How It Works](#how-it-works) · [Belt System](#belt-progression) · [Documentation](docs/)

</div>

---

## The Problem

You ask an LLM to generate Android exploit code. It produces something that **looks correct** — proper structure, confident comments, plausible function names.

Then you run it. Nothing works.

```
❌  Uses APIs that don't exist         →  frida.hooks.Hook (fabricated)
❌  Wrong vulnerability details        →  "audio driver" for a cmdq exploit
❌  Invented kernel structures         →  Fake ioctl codes and syscalls
❌  No execution feedback              →  Model never learns what actually runs
```

The root cause: **LLMs have seen exploit code in training, but never received feedback on whether it executed successfully.** They pattern-match syntax without understanding ground truth.

---

## The Solution

AgenticART creates a **feedback loop** between the model and a real Android device. Generated code is executed, failures are captured with context, and the model regenerates until it works.

Everything — successes, failures, and corrections — becomes training data.

```
                                     FEEDBACK LOOP
┌────────────────────────────────────────────────────────────────────────────────┐
│                                                                                │
│  ┌───────────┐     ┌───────────┐     ┌───────────┐     ┌─────────────┐        │
│  │           │     │           │     │           │     │             │        │
│  │ CHALLENGE │────▶│ GENERATE  │────▶│  EXECUTE  │────▶│  SUCCESS ?  │        │
│  │           │     │   (LLM)   │     │   (AVD)   │     │             │        │
│  └───────────┘     └─────▲─────┘     └───────────┘     └──────┬──────┘        │
│                          │                                    │               │
│                          │                             YES ───┴─── NO         │
│                          │                              │          │          │
│                          │                              │          ▼          │
│                          │                              │   ┌────────────┐    │
│                          │                              │   │  EXTRACT   │    │
│                          │                              │   │   ERROR    │    │
│                          │                              │   │            │    │
│                          │                              │   │  • What    │    │
│                          │                              │   │  • Why     │    │
│                          │                              │   │  • Context │    │
│                          │                              │   └─────┬──────┘    │
│                          │                              │         │           │
│                          │                              │         ▼           │
│                          │                              │   ┌────────────┐    │
│                          │        RETRY WITH CONTEXT    │   │   INJECT   │    │
│                          └──────────────────────────────────│   CONTEXT  │    │
│                                                         │   │            │    │
│                            "Your script failed because  │   │ "Try this  │    │
│                             [error]. Regenerate with    │   │  instead"  │    │
│                             this fix: [suggestion]"     │   └────────────┘    │
│                                                         │                     │
└─────────────────────────────────────────────────────────┴─────────────────────┘
                                                          │
                                                          ▼
                                               ┌─────────────────────┐
                                               │    TRAINING DATA    │
                                               │                     │
                                               │  ✓ Working scripts  │
                                               │  ✓ Error → Fix pairs│
                                               └──────────┬──────────┘
                                                          │
                                                          ▼
                                               ┌─────────────────────┐
                                               │      FINE-TUNE      │
                                               └──────────┬──────────┘
                                                          │
                                                          ▼
                                               ┌─────────────────────┐
                                               │   IMPROVED MODEL    │
                                               └─────────────────────┘
```

**This is the core insight:** failures are training data. When a script crashes, we capture exactly what went wrong and how to fix it. The model learns both what works and how to recover from what doesn't.

---

## Quick Start

```bash
# Clone and setup
git clone https://github.com/GitSolved/AgenticART.git
cd AgenticART && pip install -r dojo/requirements.txt

# Pull a base model
ollama pull hf.co/bartowski/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B-GGUF:Q4_K_M

# Start Android emulator
emulator -avd <your_avd_name>

# Run challenges (collects training data)
python -m dojo.test_end_to_end --mode live --belt white

# Package for fine-tuning (transfer to GPU machine)
python -c "
from dojo.finetune import TrainingPackager
from pathlib import Path
packager = TrainingPackager()
data = Path('dojo_output/training_data/combined/combined_all_*_alpaca.json')
packager.create_package(list(data.parent.glob(data.name))[0])
"
```

---

## How It Works

### 1. Challenge the Model

```bash
python -m dojo.test_end_to_end --mode live --belt white
python -m dojo.test_end_to_end --mode live --belt yellow
python -m dojo.test_end_to_end --mode live --belt orange
```

The model receives structured challenges with device context and constraints. Progress through belts as the model improves.

### 2. Execute on Real Device

Generated code runs against an Android emulator. No simulations — real ADB, real Frida, real failures.

### 3. Grade and Correct

The **Sensei** evaluates output:

```
Challenge: green_001_frida_hook
Score: 68/100
Grade: C

Issues Found:
  ✗ Used frida.hooks.Hook (does not exist)
  ✗ Missing Java.perform() wrapper

Correction Generated:
  → Replaced with valid Java.use() pattern
  → Added proper Frida boilerplate
```

### 4. Capture Everything

| What's Captured | Training Purpose |
|-----------------|------------------|
| Working scripts | Positive examples — "do this" |
| Failed + corrected | Error recovery — "when X fails, fix with Y" |
| Retry sequences | Iterative improvement patterns |

### 5. Fine-Tune

Fine-tuning requires a GPU. The Dojo packages everything for transfer to a GPU machine:

```bash
# Training data is auto-saved to: dojo_output/training_data/
# Package is created at: dojo_output/finetune_package_*/

# On GPU machine:
cd finetune_package_*/
pip install -r requirements.txt
python train.py --epochs 3

# Or use Google Colab (free T4 GPU):
# Upload finetune_colab.ipynb and training_data.json
```

**Note:** Data collection (Phases 1-3) uses Ollama and runs on any machine. Fine-tuning (Phase 4) uses PyTorch and requires a GPU.

### 6. Improved Model

After training, import the fine-tuned model back to Ollama:

```bash
ollama create whiterabbit-adb-dojo -f Modelfile
python -m dojo.test_end_to_end --mode live --belt white  # Re-test
```

The model now generates correct ADB commands because it learned from execution feedback, not just text patterns.

---

## Belt Progression

Models advance through structured difficulty levels:

| | Belt | Focus | Challenges |
|-|------|-------|------------|
| ⬜ | **White** | Fundamentals | ADB commands, device enumeration |
| 🟨 | **Yellow** | Reconnaissance | App analysis, permission mapping |
| 🟧 | **Orange** | Vulnerability | CVE matching, version fingerprinting |
| 🟩 | **Green** | Scripting | Frida hooks, Python exploit scaffolds |
| 🟦 | **Blue** | Exploitation | Known CVE reproduction |
| 🟪 | **Purple** | Evasion | SELinux bypass, detection avoidance |
| 🟫 | **Brown** | Chaining | Multi-phase attack orchestration |
| ⬛ | **Black** | Novel | Zero-day pattern generation |

Promotion requires passing challenges at 80%+ accuracy. Each belt unlocks harder challenges and captures more sophisticated training data.

---

## Validated Results

Tested against Android 7.0 (API 24) emulator:

| Capability | Status |
|------------|--------|
| CVE Detection | ✓ CVE-2020-0069 identified (CVSS 9.8) |
| Device Fingerprinting | ✓ Full profile via ADB |
| NVD Integration | ✓ 205 CVEs matched |
| Feedback Loop | ✓ Error extraction and retry working |
| Governance | ✓ 5-tier approval system |

---

## Architecture

```
AgenticART/
├── dojo/                   # Training framework
│   ├── models.py           # Core data models (Belt, Challenge, Assessment)
│   ├── config.py           # Configuration management
│   ├── curriculum/         # Phase 2: Challenge execution, retry logic
│   ├── sensei/             # Phase 3: Grading, training data export
│   └── finetune/           # Phase 4: Package for GPU training
├── agent/                  # LLM interface
│   ├── llm_client.py       # Multi-provider support
│   ├── script_generator.py # Code generation
│   └── prompts/            # System prompts
├── core/                   # Exploitation modules
│   ├── reconnaissance/     # Device enumeration
│   ├── scanning/           # CVE matching
│   └── exploitation/       # Attack techniques
└── dojo_output/            # Generated outputs
    ├── training_data/      # Alpaca, ShareGPT, DPO formats
    ├── progress/           # Model progress tracking
    └── finetune_package_*/ # Portable training packages
```

---

## Export Formats

| Format | Use Case | Command |
|--------|----------|---------|
| Alpaca | LLaMA-Factory, Axolotl | `--format alpaca` |
| ShareGPT | OpenAI-style | `--format sharegpt` |
| DPO | Preference tuning | `--format dpo` |
| MLX | Apple Silicon | `--format mlx` |

---

## Governance

All actions are risk-classified and require appropriate approval:

| Level | Example | Approval |
|-------|---------|----------|
| INFO | `getprop ro.build.version` | Auto |
| LOW | `pm list packages` | Auto |
| MEDIUM | File reads | Prompt |
| HIGH | `su -c 'id'` | Required |
| CRITICAL | Exploit execution | Required |

---

## Requirements

### Data Collection (Phases 1-3) — Any Machine
- Python 3.10+
- Android emulator (AVD or Genymotion)
- [Ollama](https://ollama.ai) for local inference
- 16GB+ RAM recommended
- **No GPU required** — Ollama handles inference

### Fine-Tuning (Phase 4) — GPU Machine
- NVIDIA GPU with 16GB+ VRAM (or 8GB with QLoRA)
- PyTorch 2.0+ with CUDA
- Unsloth, TRL, PEFT libraries
- **Or use Google Colab** (free T4 GPU) with the included notebook

---

## Research

Based on: [**"Breaking Android with AI: A Deep Dive into LLM-Powered Exploitation"**](https://arxiv.org/abs/2509.07933)

The paper introduces the feedback loop methodology that AgenticART implements.

---

## License

MIT — See [LICENSE](LICENSE)

---

<div align="center">

**For authorized security testing only.**

*The dojo is open. Train your model.*

⬜ → 🟨 → 🟧 → 🟩 → 🟦 → 🟪 → 🟫 → ⬛

</div>
