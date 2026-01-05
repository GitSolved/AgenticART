<div align="center">

# AgenticART

### Train LLMs to Generate Exploits That Actually Work

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/GitSolved/AgenticART/actions/workflows/ci.yml/badge.svg)](https://github.com/GitSolved/AgenticART/actions)

[Quick Start](#quick-start) · [How It Works](#how-it-works) · [Belt System](#belt-progression) · [Docs](docs/)

</div>

<img width="1344" height="768" alt="image" src="https://github.com/user-attachments/assets/60b8fcb5-c581-4459-b325-6a416ff3b5c4" />

---

## The Problem

LLMs generate exploit code that **looks correct** but doesn't run:

- Uses APIs that don't exist (`frida.hooks.Hook`)
- Invents kernel structures and syscalls
- Never receives execution feedback

**Root cause:** Models pattern-match syntax without knowing what actually executes.

---

## The Solution

AgenticART creates a **feedback loop** between the model and a real Android device:

```
```
```

    ┌──────────────┐      ┌──────────────┐      ┌──────────────┐      ┌──────────────┐
    │  CHALLENGE   │─────>│   GENERATE   │─────>│   EXECUTE    │─────>│   SUCCESS?   │
    └──────────────┘      └──────┬───────┘      └──────────────┘      └────────┬─────┘
                                 │                                             │
                                 │                                             │
                                 │                      ┌──────────────────────┤
                                 │                      │                      │
                                 │                      │ No                   │ Yes
                                 │                      │                      │
                                 │             ┌────────▼────────┐             │
                                 │             │ EXTRACT ERROR & │             │
                                 │             │ INJECT CONTEXT  │             │
                                 │             └────────┬────────┘             │
                                 │                      │                      │
                          ┌──────▼──────┐               │                      │
                          │    RETRY    │<──────────────┘                      │         
                          └─────────────┘                                      │
                                                                               │
                                                                               │
                                                                               │
                                                                      ┌────────▼─────────┐
                                                                      │ TRAINING DATA    | 
                                                                      │                  |
                                                                      │ ✓ Working        |
                                                                      │   scripts        |
                                                                      │ ✓ Error-Fix      |
                                                                      │   pairs          |
                                                                      └──────────────────┘

``````
```

**Failures become training data.** The model learns what works and how to recover from what doesn't.

AgenticART targets **Android** devices, with testing focused on Samsung, Xiaomi, and Google Pixel phones.  

---

## Quick Start

```bash
# Clone and install
git clone https://github.com/GitSolved/AgenticART.git
cd AgenticART
pip install -r dojo/requirements.txt

# Start Android emulator
emulator -avd <your_avd_name>

# Run challenges (generates training data)
python -m dojo.test_end_to_end

# Package for fine-tuning
python -m dojo.finetune.packager
```

> **Note:** Data collection runs on any machine with Ollama. Fine-tuning requires a GPU.

---

## How It Works

1. **Challenge** → Model receives structured task with device context
2. **Generate** → LLM produces exploit script
3. **Execute** → Code runs against real Android emulator
4. **Grade** → Sensei evaluates output, extracts errors
5. **Capture** → Working scripts + error→fix pairs become training data
6. **Fine-tune** → Train improved model on collected data

---

## Belt Progression

Models advance through structured difficulty levels:

| Belt | Focus | Belt | Focus |
|------|-------|------|-------|
| ⬜ White | ADB fundamentals | 🟦 Blue | CVE exploitation |
| 🟨 Yellow | Reconnaissance | 🟪 Purple | Evasion |
| 🟧 Orange | Vulnerability mapping | 🟫 Brown | Attack chaining |
| 🟩 Green | Scripting (Frida, Python) | ⬛ Black | Advanced Proficiency Test |

---

## Requirements

| Data Collection (any machine) | Fine-Tuning (GPU machine) |
|------------------------------|---------------------------|
| Python 3.10+ | NVIDIA GPU 16GB+ VRAM |
| Android emulator | PyTorch 2.0+ with CUDA |
| [Ollama](https://ollama.ai) | Or use Google Colab (free T4) |

---

## Documentation

| Doc | Description |
|-----|-------------|
| [Architecture](docs/architecture.md) | System design and components |
| [Dojo Framework](docs/DOJO_FRAMEWORK.md) | Training methodology |
| [Setup Guide](docs/SETUP.md) | Detailed installation |
| [Governance](docs/GOVERNANCE.md) | Safety controls and approval tiers |
| [Tools](docs/TOOLS.md) | Available security tools |

---

## Research

Based on [**"LLM-Powered Android Exploitation"**](https://arxiv.org/abs/2509.07933) which introduces the feedback loop methodology.

---

## License

MIT — See [LICENSE](LICENSE)

---

<div align="center">

**For authorized security testing only.**

⬜ → 🟨 → 🟧 → 🟩 → 🟦 → 🟪 → 🟫 → ⬛

</div>
