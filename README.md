<div align="center">

# AgenticART

**Agentic Android Red Team**

*Train LLMs to Master Android Exploitation*

[![CI Status](https://github.com/GitSolved/AgenticART/actions/workflows/ci.yml/badge.svg)](https://github.com/GitSolved/AgenticART/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)

[Paper](https://arxiv.org/abs/2509.07933) • [Issues](https://github.com/GitSolved/AgenticART/issues)

</div>

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Training Pipeline](#training-pipeline)
- [Model Recommendations](#model-recommendations)
- [Configuration](#configuration)
- [Project Structure](#project-structure)
- [Governance & Safety](#governance--safety)
- [Credits](#credits)
- [License](#license)

---

## Overview

AgenticART is an automated Android exploitation framework that:

1. **Generates** exploits using LLMs
2. **Executes** against real/emulated devices
3. **Captures** rich training data (scripts, reasoning, errors)
4. **Fine-tunes** your chosen model to improve over time

> **The Loop:** Template exploits → Execute → Capture → Train → Advanced exploits

Based on the research paper: ["Breaking Android with AI: A Deep Dive into LLM-Powered Exploitation"](https://arxiv.org/abs/2509.07933)

---

## Features

| Feature | Description |
|---------|-------------|
| **Model Training** | Fine-tune any LLM on real exploitation trajectories |
| **Data Capture** | Log scripts, reasoning, errors, and recovery actions |
| **NL to Code** | Convert natural language objectives to executable scripts |
| **CVE Matching** | Match device fingerprint to applicable vulnerabilities |
| **Attack Chains** | Orchestrated Recon → Scan → Exploit → Verify workflow |
| **Governance** | Human-in-the-loop approval with risk-based triage |

---

## Architecture

<details>
<summary>System Overview (click to expand)</summary>

```
┌─────────────────────────────────────────────────────────────────┐
│                        Web Application                          │
│                    (Streamlit Interface)                        │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│                       Agent Layer                               │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────┐    │
│  │   Planner   │◄─┤  Summarizer  │◄─┤  Script Generator   │    │
│  └─────────────┘  └──────────────┘  └─────────────────────┘    │
│                                                                  │
│  ┌───────────────────────────────────────────────────────┐      │
│  │                    Memory System                       │      │
│  │              (Working + Vector Store)                  │      │
│  └───────────────────────────────────────────────────────┘      │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│                      Core Modules                               │
│  ┌──────────────┐  ┌─────────────┐  ┌────────────────────┐     │
│  │Reconnaissance│  │  Scanning   │  │   Exploitation     │     │
│  │ (Device Enum)│  │ (CVE Match) │  │ (Magisk, Kernel)   │     │
│  └──────────────┘  └─────────────┘  └────────────────────┘     │
└─────────────────────────────────────────────────────────────────┘
```

</details>

<details>
<summary>Training Loop (click to expand)</summary>

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Run Exploit │────▶│ Capture Data │────▶│  Fine-tune   │
│    Chains    │     │   (JSON)     │     │  Your Model  │
└──────────────┘     └──────────────┘     └──────────────┘
       ▲                                         │
       └─────────────────────────────────────────┘
              Model produces better exploits
```

</details>

---

## Quick Start

### Prerequisites

- Python 3.10+
- Docker (optional)
- Genymotion or Android Emulator

### Installation

```bash
# Clone
git clone https://github.com/GitSolved/AgenticART.git
cd AgenticART

# Setup
./scripts/setup.sh
source activate.sh

# Configure
cp config/.env.example config/.env

# Run
streamlit run webapp/app.py
```

### Verify Installation

```bash
./scripts/check-tools.sh
python demo.py
```

---

## Training Pipeline

The core innovation: **learn from real exploitation attempts**.

### How It Works

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Run Chains  │────▶│ Capture Data │────▶│  Fine-tune   │
│  (Emulator)  │     │ (Trajectories)│    │  Your Model  │
└──────────────┘     └──────────────┘     └──────────────┘
       ▲                                         │
       └─────────────────────────────────────────┘
                   Better exploits
```

### What Gets Captured

| Data | Training Purpose |
|------|------------------|
| Generated scripts | Learn working exploit code |
| Phase outcomes | Learn which approaches succeed |
| Error messages | Learn failure patterns |
| Device context | Match exploits to targets |

### Generate Training Data

```bash
# Run exploitation chains (data auto-saved to output/attack_chains/)
python exploit_demo.py

# Export to Alpaca format for fine-tuning
./scripts/export-training-data.py --format alpaca --output training.jsonl

# Or ShareGPT format
./scripts/export-training-data.py --format sharegpt --output training.jsonl
```

### Fine-tune Your Model

Use your preferred training framework and model:

```bash
# Example with Axolotl
axolotl train config.yaml

# Example with Unsloth (faster, less VRAM)
python train.py --model your-model --data training.jsonl
```

<details>
<summary>Training Progression (click to expand)</summary>

| Cycle | Model State | Exploit Quality |
|-------|-------------|-----------------|
| 0 | Base model | Template/generic exploits |
| 1 | +100 trajectories | Learns basic patterns |
| 2 | +500 trajectories | Context-aware exploitation |
| 3+ | Ongoing data | Increasingly sophisticated |

</details>

---

## Model Recommendations

AgenticART works with any LLM. Choose based on your resources and needs:

| Model | VRAM | Strengths |
|-------|------|-----------|
| Qwen2.5-Coder | 8-48GB | Strong code generation |
| DeepSeek-Coder | 16-48GB | Security-aware coding |
| CodeLlama | 16-48GB | Code understanding |
| Llama 3.1 | 8-48GB | General reasoning |
| Mistral | 8-24GB | Fast inference |

**For fine-tuning:** Start with a 7B parameter model, generate data, train, and iterate. Larger models can be used once you have sufficient training data.

**Local inference:** Use [Ollama](https://ollama.ai) to run models locally without API keys.

---

## Configuration

<details>
<summary>Environment Variables (click to expand)</summary>

```bash
# LLM Provider
LLM_PROVIDER=ollama          # ollama, openai, anthropic
OLLAMA_MODEL=codellama       # Model to use with Ollama

# API Keys (if using cloud providers)
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...

# Device
TARGET_DEVICE=192.168.56.101:5555
ANDROID_SDK=/path/to/android-sdk

# Safety
DRY_RUN=true                 # Don't execute, just generate
REQUIRE_APPROVAL=true        # Human approval for dangerous commands
```

</details>

---

## Project Structure

```
AgenticART/
├── agent/                  # Agent layer
│   ├── llm_client.py      # Multi-provider LLM interface
│   ├── planner.py         # Strategic planning
│   ├── summarizer.py      # Result analysis
│   ├── script_generator.py # Code generation
│   └── memory/            # Working + vector memory
├── core/                   # Core modules
│   ├── reconnaissance/    # Device enumeration
│   ├── scanning/          # CVE matching
│   ├── exploitation/      # Exploit techniques
│   └── governance.py      # Approval system
├── webapp/                 # Streamlit UI
├── scripts/               # Utilities
│   └── export-training-data.py
├── output/                # Results & training data
│   └── attack_chains/     # Captured trajectories
└── tests/                 # Test suite
```

---

## Governance & Safety

Actions are classified by risk level:

| Level | Example Commands | Approval |
|-------|------------------|----------|
| INFO | `getprop ro.build.version.release` | Auto-approved |
| LOW | `pm list packages` | Auto-approved |
| MEDIUM | `cat /data/local/tmp/file` | Prompted |
| HIGH | `su -c 'id'`, `frida -U` | Required |
| CRITICAL | Exploit execution, `rm -rf` | Required + confirmation |

All actions are logged for audit purposes.

---

## Credits

Built on research and patterns from:

| Project | Contribution |
|---------|--------------|
| [PentestGPT](https://github.com/GreyDGL/PentestGPT) | Pentest methodology, prompts |
| [PentAGI](https://github.com/vxcontrol/pentagi) | Multi-agent architecture |
| [HackSynth](https://github.com/aielte-research/HackSynth) | Planner/Summarizer pattern |

Paper: ["Breaking Android with AI: A Deep Dive into LLM-Powered Exploitation"](https://arxiv.org/abs/2509.07933)

---

## License

MIT License - See [LICENSE](LICENSE) for details.

---

<div align="center">

**For authorized security testing only.**

Only test devices you own or have explicit permission to test.

</div>
