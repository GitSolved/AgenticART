# LLM-AndroidPentest

**LLM-Powered Android Penetration Testing Framework**

An automated Android exploitation framework that uses Large Language Models to generate and execute penetration testing scripts. Converts natural language commands into executable exploits.

> Based on: ["Breaking Android with AI: A Deep Dive into LLM-Powered Exploitation"](https://arxiv.org/abs/2509.07933) (arXiv:2509.07933)

## Key Features

| Feature | Description |
|---------|-------------|
| **NL to Code** | Convert "root this device" into executable Python/Bash scripts |
| **CVE Matching** | Automatically match device fingerprint to applicable vulnerabilities |
| **Attack Chains** | Orchestrated Recon -> Scan -> Exploit -> Verify workflow |
| **Local LLM** | Runs entirely on Ollama - no API keys required |
| **Genymotion** | Integrated Android emulator for safe testing |

## How It Works

```
User: "Root this Android 11 Pixel 7"
                    |
                    v
    +---------------+---------------+
    |            AGENT              |
    |   Planner -> Generator ->     |
    |          Summarizer           |
    +---------------+---------------+
                    |
                    v
    +---------------+---------------+
    |      GENERATED SCRIPT         |
    |   adb shell su -c 'id'        |
    |   if uid=0: root achieved     |
    +---------------+---------------+
                    |
                    v
    +---------------+---------------+
    |         EXECUTION             |
    |   Genymotion Emulator         |
    |   Android 11 / API 30         |
    +-------------------------------+
```

## Architecture

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
│  │ (Strategy)  │  │  (Analysis)  │  │  (Code Generation)  │    │
│  └─────────────┘  └──────────────┘  └─────────────────────┘    │
│         │                                      │                │
│  ┌──────▼──────────────────────────────────────▼──────┐        │
│  │                    Memory System                    │        │
│  │         (Working + Vector Store)                    │        │
│  └─────────────────────────────────────────────────────┘        │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│                      Core Modules                               │
│  ┌──────────────┐  ┌─────────────┐  ┌────────────────────┐     │
│  │ Reconnaissance│  │  Scanning   │  │   Exploitation     │     │
│  │ (Device Enum) │  │  (Vulns)    │  │ (Magisk, Kernel)   │     │
│  └──────────────┘  └─────────────┘  └────────────────────┘     │
│                                      ┌────────────────────┐     │
│                                      │   Verification     │     │
│                                      │   (Root Check)     │     │
│                                      └────────────────────┘     │
└─────────────────────────────────────────────────────────────────┘
```

## Features

- **Dual-Module Architecture**: HackSynth-inspired Planner + Summarizer for iterative exploitation
- **Multi-Provider LLM Support**: OpenAI, Anthropic Claude, or local models (Ollama)
- **Automated Script Generation**: Convert natural language to executable Python/Bash scripts
- **Android-Focused**: Genymotion emulator integration, ADB automation, Magisk rooting
- **Memory System**: Persistent context with vector embeddings for semantic search
- **Safety Controls**: Dry-run mode, script validation, confirmation prompts

## Live Exploitation Demo

Run the exploitation demo against a connected Android device:

```bash
python3 exploit_demo.py
```

**Real Output (Genymotion Android 11):**

```
╔══════════════════════════════════════════════════════════════════════╗
║         LLM-AndroidPentest: LIVE EXPLOITATION DEMO                   ║
╚══════════════════════════════════════════════════════════════════════╝

══════════════════════════════════════════════════════════════════════
  PHASE 1: RECONNAISSANCE
══════════════════════════════════════════════════════════════════════
  [+] Device: Pixel 7
  [+] Android: 11 (API 30)
  [+] Security Patch: 2021-01-05
  [!] VULNERABLE: Device is debuggable!

══════════════════════════════════════════════════════════════════════
  PHASE 2: VULNERABILITY ASSESSMENT
══════════════════════════════════════════════════════════════════════
  [+] Matched 12 potential CVEs
  [!] VULNERABLE: 3 CRITICAL vulnerabilities found!
      • CVE-2024-0031: Bluetooth remote code execution...
      • CVE-2021-0968: System UI heap buffer overflow...

══════════════════════════════════════════════════════════════════════
  PHASE 3: EXPLOITATION
══════════════════════════════════════════════════════════════════════
  [!] VULNERABLE: ADB ROOT ACHIEVED!
  [!] VULNERABLE: Package Permissions accessible!
  [!] VULNERABLE: System partition remountable!

══════════════════════════════════════════════════════════════════════
  EXPLOITATION REPORT
══════════════════════════════════════════════════════════════════════
  Success Rate: 2/3 attacks succeeded
  [!] DEVICE COMPROMISED
```

## Framework Demo

Run the methodology validation demo:

```bash
python3 demo.py
```

**Sample Output:**

```
╔══════════════════════════════════════════════════════════════════════╗
║          LLM-AndroidPentest Framework Demo                           ║
║          Based on: 'Breaking Android with AI'                        ║
╚══════════════════════════════════════════════════════════════════════╝

══════════════════════════════════════════════════════════════════════
  DEMO 1: Device Reconnaissance
══════════════════════════════════════════════════════════════════════
  ┌─────────────────────────────────────────┐
  │  Device Information                     │
  │  Model:          Pixel 7                │
  │  Android:        11                     │
  │  API Level:      30                     │
  │  Security Patch: 2021-01-05             │
  └─────────────────────────────────────────┘

══════════════════════════════════════════════════════════════════════
  DEMO 2: CVE Matching
══════════════════════════════════════════════════════════════════════
  Found 12 applicable CVEs:

  1. CVE-2024-0031
     Severity: CRITICAL (CVSS: 9.8)
     Bluetooth remote code execution vulnerability

  2. CVE-2021-0968
     Severity: CRITICAL (CVSS: 9.8)
     System UI heap buffer overflow allows remote code execution
     ⚠️  Exploit: poc_available

══════════════════════════════════════════════════════════════════════
  DEMO 3: LLM Script Generation
══════════════════════════════════════════════════════════════════════
  → Input: "Enumerate installed packages and check for root indicators"
  → Target: Android 11 @ 192.168.56.101

  ┌─ Generated: recon_packages_root_check.py ─────────────────────
  │  1: #!/usr/bin/env python3
  │  2: import subprocess
  │  3: def run_adb(cmd):
  │  4:     result = subprocess.run(["adb", "-s", "192.168.56.101:5555"...
  └──────────────────────────────────────────────────

  Validation: ✓ PASSED
  Quality Check:
    - Hallucinated tools: 0
    - Hallucinated paths: 0

══════════════════════════════════════════════════════════════════════
  DEMO 4: Feedback Loop (Error Recovery)
══════════════════════════════════════════════════════════════════════
  ⚠️  Error: device '192.168.56.101:5555' not found

  Error Analysis:
    Type: device_offline
    Suggestions:
      • Reconnect ADB: adb connect <ip>:<port>
      • Restart ADB server: adb kill-server && adb start-server

  ✓ Feedback loop architecture: Validated

══════════════════════════════════════════════════════════════════════
  DEMO 5: Governance & Triage
══════════════════════════════════════════════════════════════════════
  Command                                             Level  Action
  getprop ro.build.version.release                        1  ✓ Auto-approve
  pm list packages                                        2  ✓ Auto-approve
  su -c 'id'                                              4  🛑 Block
  frida -U -n com.target.app                              4  🛑 Block
  rm -rf /data/local/tmp/*                                5  🛑 Block
```

The demo validates all six phases from the research paper methodology.

---

## Quick Start

### 1. Install Dependencies

```bash
# Clone the repository
git clone https://github.com/GitSolved/LLM-AndroidPentest.git
cd LLM-AndroidPentest

# Run setup (installs system tools + creates venv)
./scripts/setup.sh

# Activate environment
source activate.sh
```

### 2. Configure Environment

```bash
# Copy example configuration
cp config/.env.example config/.env

# Edit with your API keys
nano config/.env
```

### 3. Verify Installation

```bash
# Check all tools are installed
./scripts/check-tools.sh

# Run the demo
python demo.py
```

### 4. Run Web Application

```bash
streamlit run webapp/app.py
```

Open http://localhost:8501 in your browser.

## Usage

### Interactive Chat

Use the chat interface to get penetration testing guidance:

```
You: How do I extract the boot image from a Pixel 7 running Android 13?

PentestGPT: To extract the boot image, follow these steps...
```

### Script Generation

1. Describe the action in natural language
2. Select script type (Python/Bash/ADB)
3. Review generated script
4. Execute in dry-run or live mode

### Automated Chain

Run the full exploitation chain:

1. Configure target device (IP, Android version)
2. Set objective (e.g., "Achieve root access")
3. Start chain execution
4. Monitor progress through phases:
   - Reconnaissance → Scanning → Exploitation → Privilege Escalation → Verification

## Project Structure

```
LLM-AndroidPentest/
├── config/                 # Configuration layer
│   ├── .env.example       # Environment template
│   ├── settings.yaml      # Application settings
│   └── emulator/          # Genymotion profiles
├── agent/                  # Agent layer (the "engine")
│   ├── llm_client.py      # Multi-provider LLM interface
│   ├── planner.py         # Strategic planning (HackSynth-style)
│   ├── summarizer.py      # Result analysis
│   ├── script_generator.py # Code generation
│   ├── prompts/           # Phase-specific prompt templates
│   ├── chains/            # Orchestration workflows
│   └── memory/            # Working + vector memory
├── core/                   # Exploitation modules
│   ├── reconnaissance/    # Device enumeration
│   ├── scanning/          # Vulnerability scanning
│   ├── exploitation/      # Exploit techniques
│   └── verification/      # Root verification
├── webapp/                 # Streamlit application
│   └── app.py             # Main web interface
├── scripts/               # Generated scripts
│   ├── generated/         # AI-generated automation
│   └── manual/            # Reference scripts
├── output/                # Results
│   ├── logs/             # Execution logs
│   └── reports/          # Assessment reports
└── tests/                 # Test suite
```

## Novel Contributions

This project implements several key innovations:

| Component | Innovation |
|-----------|------------|
| **Script Generator** | Converts natural language to validated, executable exploit code |
| **CVE Pipeline** | Device fingerprint -> CVE matching -> Exploit selection |
| **Attack Chain** | State machine with retry logic and phase transitions |
| **Prompt Templates** | Android-specific prompts for each exploitation phase |

See [docs/architecture.md](docs/architecture.md) for detailed diagrams.

## Technology Stack

- **LLM**: Ollama (local), OpenAI, Anthropic
- **Framework**: Python 3.11+, Streamlit
- **Android**: Genymotion (QEMU), ADB
- **Storage**: ChromaDB (vectors)
- **Container**: Docker, Docker Compose

## Inspiration & Credits

This project combines patterns from:

| Project | Contribution |
|---------|--------------|
| [PentestGPT](https://github.com/GreyDGL/PentestGPT) | Core pentest methodology, prompt engineering |
| [PentAGI](https://github.com/vxcontrol/pentagi) | Multi-agent architecture, memory system |
| [HackSynth](https://github.com/aielte-research/HackSynth) | Planner/Summarizer dual-module pattern |

Research paper: ["Breaking Android with AI: A Deep Dive into LLM-Powered Exploitation"](https://arxiv.org/abs/2509.07933) by Perera et al.

## Disclaimer

This tool is for **authorized security testing only**. Usage guidelines:

- Only test devices you own or have explicit permission to test
- Comply with all applicable laws and regulations
- Use the dry-run mode for learning and experimentation
- Never use for malicious purposes

## License

MIT License - See [LICENSE](LICENSE) for details.
