# AgenticART: Android Red Team Training Dojo for Security LLMs

A research framework for training Large Language Models (LLMs) on Android security tasks through structured challenges, execution-verified feedback, and curriculum-based skill progression.

---

## Why AgenticART?

### The Problem

Most LLMs can *talk* about security but can't *do* security. They hallucinate commands, misunderstand Android internals, and fail when execution matters. Training data for security tasks is scarce, outdated, or synthetic.

### The Solution

AgenticART creates **AI agents that can actually perform security assessments** by:

- Training on **real CVEs** from Android Security Bulletins (not textbook examples)
- Using **execution-verified feedback** (did the command actually work?)
- Providing **structured progression** from beginner to advanced (belt system)

### Who Is This For?

| Audience | Why AgenticART? |
|----------|-----------------|
| **Learning AI Red Teaming** | Hands-on environment to understand how AI agents perform security tasks. See what works, what fails, and why. |
| **AI Security Researchers** | Study curriculum-based training for security tasks. Benchmark improvements with real execution data. |
| **Air-Gapped / Compliance Teams** | Train once, deploy offline forever. No cloud API dependencies in production. |
| **Teams Building Security Agents** | Create a personalized Android security agent fine-tuned on your own verified execution traces. |

### Why Does This Exist?

**Where else do you get this?**

There is no other public source combining:
- Hundreds of Android security challenges (CVE-based + foundational skills)
- Real CVEs from NIST NVD and Android Security Bulletins
- Execution verification against live Android devices
- Structured prompts optimized for security task performance
- Training data export pipeline (JSONL/Alpaca/ShareGPT/DPO)
- Belt-based curriculum with measurable progression
- Scoring system for tracking improvement and comparing models

### The Compound Effect

The framework creates a virtuous cycle:

```
┌─────────────────────────────────────────────────────────────────┐
│                    How AgenticART Compounds                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. PROMPT ENGINEERING                                           │
│     ReAct patterns, error context injection, structured          │
│     challenge prompts → Better LLM performance out of the box    │
│                                                                  │
│  2. EXECUTION VERIFICATION                                       │
│     Commands run on real devices → Only working solutions        │
│     become training data                                         │
│                                                                  │
│  3. CURRICULUM STRUCTURE                                         │
│     Progressive difficulty → Model learns fundamentals before    │
│     advanced techniques                                          │
│                                                                  │
│  4. FINE-TUNING                                                  │
│     Verified traces → Personalized local model that actually     │
│     works for YOUR environment                                   │
│                                                                  │
│  Result: Each layer improves the next                            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Measurable Progress

| Layer | What It Does | Measurable Outcome |
|-------|--------------|-------------------|
| **Prompt Engineering** | Structured prompts, ReAct reasoning, error recovery | Higher pass rate vs naive prompting |
| **Execution Verification** | Filter to only working commands | Training data quality improvement |
| **Curriculum Progression** | White → Black belt ordering | Track pass rate improvement per belt |
| **Fine-tuning** | Train on verified traces | Before/after benchmark comparison |

---

## Building Penetration Testing Agents

AgenticART provides the foundation for Android pentest agents:

| Component | What You Get |
|-----------|--------------|
| **Training Data** | Fine-tune a model on verified security tasks |
| **Prompt Patterns** | ReAct reasoning proven to work for multi-step attacks |
| **Execution Infrastructure** | ADB/Frida execution with automatic error recovery |
| **Verification Loop** | Know when exploitation succeeded vs failed |

This is training infrastructure, not a finished agent. You use it to create a model that's better at Android security tasks, then build your agent on top.

---

## Scoring & Model Comparison

### Grading System

Every challenge attempt receives a grade:

| Grade | Meaning | Training Value |
|-------|---------|----------------|
| **A** | Perfect execution | Positive example |
| **B** | Good with minor issues | Positive example |
| **C** | Functional but needs improvement | Borderline |
| **D** | Poor, correction needed | Negative example (with correction) |
| **F** | Failed completely | Negative example (with correction) |

### Point System

Points scale with belt difficulty:

```
White Belt:  10 pts/challenge    Purple Belt: 70 pts/challenge
Yellow Belt: 20 pts/challenge    Black Belt:  80 pts/challenge
...progressive scaling...
```

Bonus points for:
- First-try success (no retries)
- Fast execution (< 30 seconds)
- Grade A (perfect score)

### Tracking Model Progress

```python
from dojo.scoring import ModelScorer
from dojo.sensei import ProgressTracker

# Track across sessions
tracker = ProgressTracker(storage_path="./progress")
progress = tracker.get_progress("llama3.1-8b")

print(f"Belt: {progress.current_belt}")
print(f"Pass Rate: {progress.pass_rate}%")
print(f"Total Score: {progress.total_score}")

# Compare models
scorer = ModelScorer()
report = scorer.generate_report()
```

### Metrics Collection

Track granular performance data:

```python
from dojo.challenge_value import MetricsCollector

collector = MetricsCollector()
# Records per-challenge: attempts, success rate, execution time,
# error types, token usage, grade distribution
```

### Comparing Models

Use `compare_challengers.py` to benchmark:

```bash
# Compare Basic vs ReAct prompting
python dojo/compare_challengers.py --model llama3.1:8b

# Output:
#   Basic Challenger:  60% pass rate, avg 3.2 steps
#   ReAct Challenger:  78% pass rate, avg 2.1 steps
```

### Prompt Engineering Approaches

| Approach | File | When to Use |
|----------|------|-------------|
| **Basic** | `curriculum/challenger.py` | Simple challenges, fast iteration |
| **ReAct** | `react_challenger.py` | Multi-step reasoning, error recovery |
| **Hybrid** | `hybrid_challenger.py` | Auto-select based on challenge complexity |

ReAct prompt structure:
```
THOUGHT: [Reasoning about the situation]
HYPOTHESIS: [What I expect to happen]
ACTION: [Exact command to execute]
OBSERVATION: [What actually happened]
... iterate until success or max attempts ...
```

Error context injection (`context_injector.py`):
```
[FAILED_COMMAND] shell pm list packages -3
[ERROR] Type: permission_denied | Message: requires android.permission.QUERY_ALL_PACKAGES
[SUGGESTIONS] Try using 'dumpsys package' or limit query scope
[INSTRUCTIONS] Modify your approach based on this error
```

---

## How It Works

AgenticART implements a "Dojo" training system where AI agents learn Android vulnerability assessment through a continuous improvement loop:

```
┌─────────────────────────────────────────────────────────────────┐
│                      AgenticART Architecture                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐ │
│   │   NVD    │───▶│ Challenge│───▶│  Agent   │───▶│ Android  │ │
│   │   API    │    │ Generator│    │ Executor │    │ Emulator │ │
│   └──────────┘    └──────────┘    └──────────┘    └──────────┘ │
│                                          │              │       │
│                                          ▼              ▼       │
│                                   ┌──────────┐   ┌──────────┐  │
│                                   │  Grader  │◀──│Exec Trace│  │
│                                   └──────────┘   └──────────┘  │
│                                          │                      │
│                                          ▼                      │
│                                   ┌──────────┐                  │
│                                   │ Training │                  │
│                                   │   Data   │                  │
│                                   └──────────┘                  │
└─────────────────────────────────────────────────────────────────┘
```

**The Loop:**
1. **Challenge Generation** - Pull real CVEs from NVD, classify by difficulty
2. **Agent Execution** - LLM attempts the challenge on a live Android device
3. **Grading** - Verify if the output achieved the objective
4. **Training Data** - Successful attempts become "gold" training examples
5. **Model Refinement** - Fine-tune models on verified execution traces
6. **Repeat** - Progressively harder challenges, continuously improving agents

---

## Curriculum Statistics

**Last Updated:** December 2025 (after value-based pruning)

| Belt | Challenges | Skill Level | Focus Area |
|------|------------|-------------|------------|
| White | 5 | Beginner | Device reconnaissance, basic ADB |
| Yellow | 11 | Novice | Information disclosure, simple DoS |
| Orange | 30 | Intermediate | Permission bypass, logic bugs |
| Green | 43 | Intermediate+ | IPC, content providers, intents |
| Blue | 24 | Advanced | Buffer overflows, high-severity EoP |
| Brown | 47 | Expert | UAF, race conditions, memory corruption |
| Purple | 16 | Elite | Qualcomm critical, RCE vectors |
| Black | 16 | Master | Kernel exploits, zero-click analysis |
| **Total** | **192** | | |

**CVE Sources:** NIST National Vulnerability Database, Android Security Bulletins (2019-2025)

*91 low-value challenges pruned using automated value scoring (see `scripts/evaluate_curriculum.py`)*

---

## Execution Capabilities & Design Choices

### What Agents CAN Do (Full Execution)

| Domain | Status | Description |
|--------|--------|-------------|
| **ADB/Shell** | ✅ Full | Device reconnaissance, package analysis, system probing |
| **Frida** | ✅ Full | Runtime hooking, API interception, memory inspection |
| **Content Providers** | ✅ Full | Query/exploit exposed data interfaces |
| **Intent Attacks** | ✅ Full | IPC manipulation, deep link exploitation |
| **Logcat Analysis** | ✅ Full | Sensitive data leakage detection |

### Intentional Constraints (Realistic Training)

#### 🔒 Non-Rooted Environment (By Design)

**Why:** ~95% of real Android devices are NOT rooted. Training agents on rooted emulators would teach unrealistic techniques that fail in the real world.

```
┌─────────────────────────────────────────────────────────────────┐
│              REALISTIC CONSTRAINT TRAINING                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ❌ If we trained on rooted emulators:                          │
│     Agent learns: "su -c cat /data/data/com.app/secrets.db"     │
│     Real world:   "su: not found" → FAILS on 95% of devices     │
│                                                                  │
│  ✅ Current approach (non-rooted):                              │
│     Agent learns: Exploit logic bugs, misconfigurations         │
│     Agent learns: "run-as com.debuggable.app cat databases/*"   │
│     Agent learns: Chain low-privilege vulnerabilities           │
│     Real world:   Actually works on real targets                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Result:** Agents learn to hack like real attackers, not like someone who already owns the device.

#### ⚠️ C/Native Code (Syntax Validation Only)

**Current State:** C exploit code is validated for syntax but NOT compiled or executed on device.

**Why this limitation exists:**
- Requires NDK cross-compilation (ARM toolchain)
- Binary must be pushed to device and executed
- Most native exploits target specific kernel versions/builds
- Not yet implemented (contribution welcome!)

**Impact:** Black/Purple belt kernel challenges are **detection-focused** - agents analyze vulnerabilities but cannot execute native exploits.

**Fixable?** Yes - NDK integration would enable full native execution. See [Contributing](#contributing).

#### 📱 Emulator vs Physical Device

| Aspect | Emulator | Physical Device |
|--------|----------|-----------------|
| Reproducibility | ✅ Consistent | ❌ Varies |
| Hardware features | ❌ Limited | ✅ Full |
| Kernel | Generic | Vendor-specific |
| TEE/TrustZone | ❌ No | ✅ Yes |
| Baseband/Radio | ❌ No | ✅ Yes |

**Current approach:** Emulators for reproducible training. Physical devices for validation.

---

## Supported Android Versions

Persona configurations exist for:

| Version | API Level | Codename | Persona File |
|---------|-----------|----------|--------------|
| Android 11 | 30 | R | `android_11_user.yaml` |
| Android 14 | 34 | U | `android_14_user.yaml` |
| Android 15 | 35 | V | `android_15_user.yaml` |
| Android 16 | 36 | Baklava | `android_16_user.yaml` |

Each persona includes realistic user data (contacts, SMS, files, apps) to enable meaningful security assessments.

---

## Installation

### Prerequisites

- Python 3.10+
- Android SDK / Platform Tools (ADB)
- Android Emulator or physical device
- Ollama (for local LLM inference)
- MLX / MLX-LM (optional, for Apple Silicon optimization)

### Setup

```bash
# Clone repository
git clone https://github.com/GitSolved/AgenticART.git
cd AgenticART

# Install dependencies
pip install -r requirements.txt

# Install as editable package (optional)
pip install -e .

# Set up environment variables
cp .env.example .env
# Edit .env with your NVD API key (optional, for CVE generation)
```

---

## Usage

### 1. Generate Challenges from NVD

```bash
python3 scripts/generate_nvd_challenges.py
```

Fetches recent Android CVEs and generates challenge templates.

### 2. Run Agent Training

```bash
python3 dojo/test_end_to_end.py --mode live --model <model_name> --belt <target_belt>
```

### 3. Package Training Data

```bash
python3 scripts/package_finetune.py
```

### 4. Fine-tune with MLX (Apple Silicon)

```bash
python3 dojo/custom_train.py
```

---

## Project Structure

```
AgenticART/
├── dojo/
│   ├── curriculum/           # Challenge execution engine
│   │   ├── white_belt/       # Challenge definitions by belt
│   │   ├── yellow_belt/
│   │   ├── ...
│   │   ├── black_belt/
│   │   ├── challenger.py     # Basic challenge executor
│   │   ├── executor.py       # ADB/Frida/C execution engine
│   │   └── loader.py         # Challenge loading utilities
│   ├── sensei/               # Grading and training data pipeline
│   │   ├── grader.py         # Output validation and scoring
│   │   ├── exporter.py       # Training data export (JSONL/Alpaca)
│   │   └── sensei.py         # Main orchestrator
│   ├── personas/             # Android device configurations
│   ├── device/               # Device management and setup
│   ├── targets/              # Vulnerable app configurations
│   ├── tools/                # NVD generator, utilities
│   ├── react_challenger.py   # ReAct (Reason+Act) executor
│   └── models.py             # Data models (Belt, Challenge, etc.)
├── scripts/
│   ├── generate_nvd_challenges.py
│   ├── package_finetune.py
│   ├── evaluate_curriculum.py
│   └── validate_training_data.py
├── webapp/                   # Streamlit dashboard
└── tests/
```

---

## Challenge Execution Modes

Challenges specify their execution capability:

| Mode | Description |
|------|-------------|
| `full_execution` | Agent can complete the entire challenge |
| `detection_analysis` | Agent analyzes/detects but cannot exploit |
| `detection_only` | Vulnerability assessment only |
| `simulation` | Simulates behavior patterns |
| `syntax_only` | C code validated locally, not executed |
| `try_harder` | Aspirational challenge with partial credit |

---

## Evaluation Metrics

The framework tracks:

- **Pass Rate:** Percentage of challenges completed successfully
- **Syntax Accuracy:** Valid code generation rate
- **Execution Success:** Commands that run without errors
- **Objective Achievement:** Goal completion rate

---

## Scope & Boundaries

### What AgenticART IS

- ✅ Training framework for Android security assessment agents
- ✅ Growing curriculum of CVE-based and foundational security challenges
- ✅ Execution-verified feedback loop for model improvement
- ✅ Realistic non-rooted environment matching real targets
- ✅ Research prototype for studying AI security capabilities

### What AgenticART is NOT

- ❌ Production-ready pentesting tool
- ❌ Zero-day discovery engine (aspirational, not demonstrated)
- ❌ Magic "hack any phone" solution
- ❌ Replacement for human security researchers

### Technical Boundaries

| Capability | Status | Reason |
|------------|--------|--------|
| **Zero-Click Exploits** | Analysis only | Requires months of dedicated 0-day research, memory corruption expertise |
| **Kernel Exploitation** | Detection only | Needs specific kernel builds, not generalizable |
| **Baseband/Radio** | Not supported | Requires physical device with cellular hardware |
| **TrustZone/TEE** | Not supported | Hardware security module not emulated |
| **Bootloader Attacks** | Not supported | Requires unlocked bootloader, physical access |

### Honest Expectations

```
What you SHOULD expect:
───────────────────────
• Agents that can perform systematic Android reconnaissance
• Automated vulnerability assessment against known CVEs
• High-quality training data for security-focused LLMs
• Foundation for building more advanced security tools

What you should NOT expect:
───────────────────────────
• Agents discovering novel 0-days autonomously
• "Push button, hack phone" capability
• Replacement for skilled penetration testers
• Production-grade security scanner
```

---

## Research Goals

AgenticART explores testable hypotheses:

| Hypothesis | How to Test | Status |
|------------|-------------|--------|
| **Capability Transfer** | Fine-tune 7B model on 70B teacher traces, compare performance | Untested |
| **Execution Verification** | Compare models trained on verified vs unverified data | Untested |
| **Curriculum Learning** | Benchmark before/after belt-progressive training | Untested |
| **Failure Patterns** | Analyze error types across belt levels | Infrastructure exists |

**This framework provides the infrastructure to test these hypotheses, not proven results.**

---

## Contributing

Contributions welcome! Areas of interest:

- Additional CVE challenge templates
- New Android version personas
- Improved grading heuristics
- NDK integration for native execution
- Additional execution domains (e.g., Magisk, Xposed)

---

## License

MIT License - See [LICENSE](LICENSE)

---

## Disclaimer

This framework is for **authorized security research only**. Use only on devices you own or have explicit permission to test. The authors are not responsible for misuse.

---

## Inspired By

This project builds on research demonstrating that LLMs can automate Android security testing:

> **Breaking Android with AI: A Deep Dive into LLM-Powered Exploitation**
> Wanni Vidulige Ishan Perera, Xing Liu, Fan Liang, Junyi Zhang
> arXiv:2509.07933
> [https://arxiv.org/abs/2509.07933](https://arxiv.org/abs/2509.07933)

The paper showed that LLMs can significantly streamline exploitation workflows when given proper guidance. AgenticART extends this by providing:
- **Structured curriculum** instead of ad-hoc prompting
- **Execution verification** to ensure commands actually work
- **Training data pipeline** to improve models over time

---

## Contact

- **Repository:** [github.com/GitSolved/AgenticART](https://github.com/GitSolved/AgenticART)
- **Research Portfolio:** [secureyourgear.com](https://secureyourgear.com)

---

*Last updated: December 30, 2025*
