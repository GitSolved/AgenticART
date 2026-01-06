# AgenticART

**Train LLMs to Generate Exploits That Actually Work**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/GitSolved/AgenticART/blob/main/LICENSE)
[![CI](https://github.com/GitSolved/AgenticART/actions/workflows/ci.yml/badge.svg)](https://github.com/GitSolved/AgenticART/actions)
[![arXiv](https://img.shields.io/badge/arXiv-2509.07933-b31b1b.svg)](https://arxiv.org/abs/2509.07933)

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

```mermaid
flowchart LR
    A[Challenge] --> B[Generate]
    B --> C[Execute]
    C --> D{Success?}
    D -->|No| E[Extract Error]
    E --> F[Inject Context]
    F --> B
    D -->|Yes| G[Training Data]
```

**Failures become training data.** The model learns what works and how to recover from what doesn't.

AgenticART targets **Android** devices, with testing focused on Samsung, Xiaomi, and Google Pixel phones.

---

## Key Results

| Metric | Result |
|--------|--------|
| Distillation improvement | **+80 percentage points** |
| Model compression | 70B → 7B parameters |
| Challenge curriculum | 192 structured challenges |

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

## Research

Inspired by [**"LLM-Powered Android Exploitation"**](https://arxiv.org/abs/2509.07933) which introduces the feedback loop methodology.

---

<div align="center">

**For authorized security testing only.**

⬜ → 🟨 → 🟧 → 🟩 → 🟦 → 🟪 → 🟫 → ⬛

</div>
