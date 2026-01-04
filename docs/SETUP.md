# AgenticART Setup Guide

Complete guide for setting up the LLM-powered Android penetration testing environment.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start](#quick-start)
3. [Ollama Setup](#ollama-setup)
4. [Genymotion Setup](#genymotion-setup)
5. [Docker Setup](#docker-setup)
6. [Local Development Setup](#local-development-setup)
7. [Configuration](#configuration)
8. [Verification](#verification)
9. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required Software

| Software | Version | Purpose |
|----------|---------|---------|
| Python | 3.10+ | Core runtime |
| Docker | 20.10+ | Containerization |
| Docker Compose | 2.0+ | Multi-container orchestration |
| Genymotion | Latest | Android emulator |
| ADB | Latest | Android Debug Bridge |
| **Ollama** | Latest | Local LLM inference (default provider) |

### LLM Provider Options

AgenticART supports multiple LLM providers. **Ollama is the default** (free, local, private):

| Provider | Cost | Setup | Best For |
|----------|------|-------|----------|
| **Ollama** (default) | Free | Local install | Privacy, no API limits |
| OpenAI | Paid | API key | GPT-4 quality |
| Anthropic | Paid | API key | Claude models |

> **Note:** You only need ONE provider. Ollama requires no API key.

---

## Quick Start

```bash
# Clone repository
git clone https://github.com/GitSolved/AgenticART.git
cd AgenticART

# Option 1: Quick start with Ollama (recommended)
# Install Ollama first: https://ollama.ai/download
ollama pull qwen2.5-coder:32b
pip install -r requirements.txt
streamlit run webapp/app.py

# Option 2: Run setup script
./scripts/setup.sh

# Option 3: Use Docker
cp config/.env.example config/.env
docker-compose up webapp

# Open http://localhost:8501
```

---

## Ollama Setup

Ollama is the recommended LLM provider - free, private, and runs locally.

### Step 1: Install Ollama

**macOS:**
```bash
brew install ollama
```

**Linux:**
```bash
curl -fsSL https://ollama.ai/install.sh | sh
```

**Windows:**
Download from https://ollama.ai/download

### Step 2: Start Ollama Service

```bash
ollama serve
# Runs on http://localhost:11434
```

### Step 3: Pull a Model

```bash
# Recommended for exploit generation (requires 20GB+ RAM):
ollama pull qwen2.5-coder:32b

# Smaller alternative (8GB RAM):
ollama pull qwen2.5-coder:14b

# Uncensored option (won't refuse security prompts):
ollama pull dolphin-mistral:7b
```

### Step 4: Verify

```bash
ollama list
# Should show your pulled model(s)

curl http://localhost:11434/api/tags
# Should return JSON with models
```

> **Model Notes:** Standard Llama models have safety filters that may refuse exploit generation. Use Qwen-coder or Dolphin variants for security research.

---

## Genymotion Setup

Genymotion is the recommended Android emulator for penetration testing.

### Step 1: Install Genymotion

1. Go to https://www.genymotion.com/download/
2. Download Genymotion Desktop (free tier available)
3. Install the application
4. Create a Genymotion account and log in

### Step 2: Install VirtualBox (if needed)

Genymotion requires VirtualBox for emulation:
- **macOS**: VirtualBox is bundled with Genymotion
- **Windows/Linux**: Install VirtualBox from https://www.virtualbox.org/

### Step 3: Create a Virtual Device

1. Open Genymotion
2. Click **+** to add a new device
3. Recommended devices for testing:
   - **Samsung Galaxy S23 - Android 14** (modern target)
   - **Samsung Galaxy S23 Rooted - Android 14** (for root testing)
4. Download and create the device

### Step 4: Configure Networking

For ADB connectivity from Docker or external tools:

1. In Genymotion, go to **Settings > Network**
2. Choose one of:
   - **NAT** (default): Device gets IP like `192.168.56.101`
   - **Bridge**: Device gets IP on your local network

3. Start the virtual device

### Step 5: Enable ADB over Network

1. In the running emulator, go to **Settings**
2. **About Phone** > Tap **Build Number** 7 times to enable Developer Options
3. Go to **Developer Options**
4. Enable **USB Debugging**
5. Enable **ADB over network** (if available)
6. Note the IP address shown (e.g., `192.168.56.101:5555`)

### Step 6: Connect via ADB

```bash
# Connect to emulator
adb connect 192.168.56.101:5555

# Verify connection
adb devices
# Should show: 192.168.56.101:5555    device

# Test shell access
adb shell id
# Should show: uid=2000(shell) gid=2000(shell)
```

---

## Docker Setup

### Option 1: Production (Recommended)

```bash
# Build and start the web application
docker-compose up -d webapp

# View logs
docker-compose logs -f webapp

# Stop
docker-compose down
```

Access the web interface at http://localhost:8501

### Option 2: Development

```bash
# Start development container with live code mounting
docker-compose --profile dev up -d cli

# Attach to container
docker exec -it llm-pentest-cli bash

# Inside container, you have access to:
# - All Python packages
# - Frida tools
# - Full source code at /app
```

### Option 3: Full Stack (with ADB bridge)

```bash
# Start all services including ADB bridge
docker-compose --profile full up -d

# The ADB bridge container will automatically connect to Genymotion
```

### Option 4: With Containerized Ollama

```bash
# If you prefer Ollama in Docker instead of host install
docker-compose --profile ollama up -d
```

---

## Local Development Setup

For development without Docker:

### Step 1: Create Virtual Environment

```bash
cd AgenticART
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### Step 2: Install Dependencies

```bash
# Core dependencies
pip install -r requirements.txt

# For dojo training system
pip install -r dojo/requirements.txt

# For development (tests, linting)
pip install pytest ruff mypy
```

### Step 3: Configure Environment

```bash
cp config/.env.example config/.env
# Edit config/.env if needed (defaults work with Ollama)
```

### Step 4: Run Application

```bash
# Start Streamlit web app
streamlit run webapp/app.py

# Or run CLI tools
python scripts/run-scan.py --ip 192.168.56.101

# Or run dojo training
python -m dojo.test_end_to_end
```

---

## Configuration

### Environment Variables

Edit `config/.env`:

```bash
# LLM Provider (default: ollama)
LLM_PROVIDER=ollama

# Ollama Configuration (default provider - no API key needed)
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=qwen2.5-coder:32b
OLLAMA_TEMPERATURE=0.7
OLLAMA_CONTEXT_LENGTH=32768

# Alternative: OpenAI (requires API key)
# LLM_PROVIDER=openai
# OPENAI_API_KEY=sk-your-key-here

# Alternative: Anthropic (requires API key)
# LLM_PROVIDER=anthropic
# ANTHROPIC_API_KEY=sk-ant-your-key-here

# Android Emulator
EMULATOR_IP=192.168.56.101
EMULATOR_PORT=5555
```

### Application Settings

Edit `config/settings.yaml` for:
- LLM parameters (temperature, max tokens)
- Exploitation technique preferences
- Output and logging settings
- Safety controls

### Emulator Profiles

Edit `config/emulator/genymotion.yaml` to define target profiles.

---

## Verification

### Test Ollama Connection

```bash
curl http://localhost:11434/api/tags
# Should return JSON with your models
```

### Test ADB Connection

```bash
./scripts/test-connection.sh
```

Expected output:
```
[OK] Connected to 192.168.56.101:5555
[OK] Shell access confirmed

DEVICE INFORMATION
------------------
  Model:          SM-S911B (Galaxy S23)
  Android:        14 (API 34)
  Security Patch: 2023-11-01
  SELinux:        Enforcing
```

### Run Quick Scan

```bash
python scripts/run-scan.py --ip 192.168.56.101 --quick
```

### Test Web Interface

1. Start the application: `docker-compose up webapp` or `streamlit run webapp/app.py`
2. Open http://localhost:8501
3. Navigate to **Chat** tab
4. Ask: "What vulnerabilities should I look for on Android 14?"
5. Verify LLM responds with Android-specific guidance

### Run Tests

```bash
# Run unit tests
python -m pytest tests/ -v
```

---

## Troubleshooting

### Ollama not responding

```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# Start Ollama service
ollama serve

# Check if model is pulled
ollama list

# Pull model if missing
ollama pull qwen2.5-coder:32b
```

### Cannot connect to emulator

```bash
# Restart ADB server
adb kill-server
adb start-server
adb connect 192.168.56.101:5555

# Check if emulator is running
# - Genymotion window should be open
# - Device should be fully booted

# Check network mode in Genymotion
# - NAT mode uses 192.168.56.x subnet
# - Bridge mode uses your local network
```

### Docker cannot reach emulator

```bash
# On macOS/Windows, use special hostname
GENYMOTION_HOST=host.docker.internal docker-compose up webapp

# Verify from inside container
docker exec llm-pentest-webapp ping host.docker.internal
```

### Docker cannot reach Ollama

```bash
# Ollama must be running on host
ollama serve

# Docker uses host.docker.internal to reach host services
# This is configured automatically in docker-compose.yml
```

### LLM refuses to generate exploits

```bash
# Standard Llama models have safety filters
# Use uncensored/code-focused models instead:
ollama pull qwen2.5-coder:32b    # Code-focused, fewer refusals
ollama pull dolphin-mistral:7b   # Explicitly uncensored
```

### Port 8501 already in use

```bash
# Find and kill process
lsof -i :8501
kill -9 <PID>

# Or use different port
streamlit run webapp/app.py --server.port 8502
```

---

## Architecture Overview

```
+-------------------------------------------------------------------+
|                     HOST MACHINE                                  |
|                                                                   |
|  +-----------------+       +-------------------------------+      |
|  |   Genymotion    |       |     Docker Environment        |      |
|  |                 |       |                               |      |
|  |  +-----------+  |  ADB  |  +-------------------------+  |      |
|  |  |  Android  |<-+-------+--|  llm-pentest-webapp     |  |      |
|  |  |  Emulator |  |       |  |  (Streamlit + Python)   |  |      |
|  |  +-----------+  |       |  +------------+------------+  |      |
|  |                 |       |               |               |      |
|  |  192.168.56.101 |       |               v               |      |
|  +-----------------+       |  +-------------------------+  |      |
|                            |  | Ollama (host or Docker) |  |      |
|  +-----------------+       |  | http://localhost:11434  |  |      |
|  |     Ollama      |<------+--|                         |  |      |
|  |  (recommended)  |       |  +-------------------------+  |      |
|  +-----------------+       +-------------------------------+      |
|                                                                   |
|  Browser ------------------------> http://localhost:8501          |
+-------------------------------------------------------------------+
```

---

## Next Steps

After setup is complete:

1. **Explore the Web UI**: Chat with the LLM about Android exploitation
2. **Run a Scan**: Use the Script Generator to create reconnaissance scripts
3. **Try the Dojo**: Run `python -m dojo.test_end_to_end` to generate training data
4. **Check Logs**: See `output/logs/` for execution logs
