# AgenticART

**Framework for creating AI security agents through execution-verified training**

---

## What is AgenticART?

AgenticART is a research framework that trains Large Language Models (LLMs) on Android security tasks through:

- **Execution-verified feedback** - Commands run on real devices, not just generated
- **Structured curriculum** - Progressive difficulty from reconnaissance to kernel analysis
- **Training data pipeline** - Export verified traces for fine-tuning

## The Research Question

> Can automated execution verification replace human oversight in LLM-powered security testing?

The original research ([arXiv:2509.07933](https://arxiv.org/abs/2509.07933)) showed LLMs can automate Android pentesting but need human oversight for accuracy. AgenticART tests whether automated verification can achieve the same goal.

## Quick Links

- [Quick Start](getting-started/quickstart.md) - Get running in 5 minutes
- [Training Guide](training/overview.md) - Fine-tune your own model
- [Scoring System](reference/scoring.md) - Understand grading and metrics

## Key Results

| Metric | Value |
|--------|-------|
| Distillation improvement | 20% → 100% (+80pp) |
| Model compression | 70B → 7B |
| Training examples needed | 10 verified traces |
| Curriculum size | 192 challenges |

## Installation

```bash
git clone https://github.com/GitSolved/AgenticART.git
cd AgenticART
pip install -r requirements.txt
```

See [Installation Guide](getting-started/installation.md) for detailed setup.
