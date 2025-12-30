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

### Value Proposition

| For | Value |
|-----|-------|
| **AI Researchers** | High-quality training data for security-focused LLMs |
| **Security Teams** | Foundation for automated vulnerability assessment |
| **Red Teams** | AI-assisted Android penetration testing capabilities |
| **Educators** | Structured, real-world security curriculum |

### Key Differentiators

```
┌─────────────────────────────────────────────────────────────────┐
│                    What Makes AgenticART Different               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ❌ Traditional LLM Training    ✅ AgenticART Approach           │
│  ─────────────────────────────  ─────────────────────────────── │
│  • Static text datasets         • Execution-verified traces     │
│  • Synthetic examples           • Real CVEs from NVD (166+)     │
│  • No difficulty scaling        • 8-tier belt progression       │
│  • Generic security knowledge   • Android-specific expertise    │
│  • Cloud-dependent              • 100% offline capable          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
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
│   ├── curriculum/           # Challenge definitions by belt
│   │   ├── white_belt/
│   │   ├── yellow_belt/
│   │   ├── ...
│   │   └── black_belt/
│   ├── personas/             # Android device configurations
│   ├── tools/                # NVD generator, utilities
│   ├── challenger.py         # Basic challenge executor
│   ├── react_challenger.py   # ReAct (Reason+Act) executor
│   ├── executor.py           # ADB/Frida/C execution engine
│   ├── grader.py             # Output validation
│   └── models.py             # Data models (Belt, Challenge, etc.)
├── scripts/
│   ├── generate_nvd_challenges.py
│   ├── package_finetune.py
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
- ✅ Curriculum of 283 real-world CVE challenges
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

AgenticART explores:

1. **Capability Transfer:** Can security skills be distilled from large models (70B) to smaller ones (7B)?
2. **Execution-Verified Learning:** Does training on verified execution traces improve reliability?
3. **Curriculum Learning:** Does progressive difficulty (belt system) accelerate skill acquisition?
4. **Failure Analysis:** What patterns emerge in AI security task failures?

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

## Contact

- **Repository:** [github.com/GitSolved/AgenticART](https://github.com/GitSolved/AgenticART)
- **Research Portfolio:** [secureyourgear.com](https://secureyourgear.com)

---

*Last updated: December 30, 2025*
