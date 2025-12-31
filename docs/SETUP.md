# AgenticART Setup Guide

Complete guide for setting up the LLM-powered Android penetration testing environment.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start](#quick-start)
3. [Genymotion Setup](#genymotion-setup)
4. [Docker Setup](#docker-setup)
5. [Local Development Setup](#local-development-setup)
6. [Configuration](#configuration)
7. [Verification](#verification)
8. [Troubleshooting](#troubleshooting)

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

### LLM API Keys (at least one required)

- **OpenAI**: Get from https://platform.openai.com/api-keys
- **Anthropic**: Get from https://console.anthropic.com/

---

## Quick Start

```bash
# Clone repository
git clone https://github.com/your-username/llm-android-pentest.git
cd AgenticART

# Run setup script
./scripts/setup.sh

# Or manually:
cp config/.env.example config/.env
# Edit config/.env to add your API key

# Start with Docker
docker-compose up webapp

# Open http://localhost:8501
```

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

### Running Tests

```bash
docker-compose --profile test run --rm test
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
pip install -r requirements.txt

# For development (tests, linting)
pip install pytest pytest-cov black ruff mypy
```

### Step 3: Configure Environment

```bash
cp config/.env.example config/.env
# Edit config/.env with your API keys
```

### Step 4: Run Application

```bash
# Start Streamlit web app
streamlit run webapp/app.py

# Or run CLI tools
python scripts/run-scan.py --ip 192.168.56.101
```

---

## Configuration

### Environment Variables

Edit `config/.env`:

```bash
# LLM Provider (required)
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-your-key-here

# Alternative: Anthropic
# LLM_PROVIDER=anthropic
# ANTHROPIC_API_KEY=sk-ant-your-key-here

# Android Emulator
EMULATOR_IP=192.168.56.101
EMULATOR_PORT=5555

# Safety settings
AUTO_EXECUTE_SCRIPTS=false  # Require confirmation before running scripts
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

### Test ADB Connection

```bash
./scripts/test-connection.sh
```

Expected output:
```
[✓] Connected to 192.168.56.101:5555
[✓] Shell access confirmed

DEVICE INFORMATION
━━━━━━━━━━━━━━━━━━
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

1. Start the application: `docker-compose up webapp`
2. Open http://localhost:8501
3. Navigate to **Chat** tab
4. Ask: "What vulnerabilities should I look for on Android 14?"
5. Verify LLM responds with Android-specific guidance

---

## Troubleshooting

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

### LLM API errors

```bash
# Check API key is set
echo $OPENAI_API_KEY

# Test API directly
curl https://api.openai.com/v1/models \
  -H "Authorization: Bearer $OPENAI_API_KEY"
```

### ADB inside Docker fails

```bash
# Start the ADB bridge service
docker-compose --profile full up -d adb-bridge

# Check ADB bridge logs
docker-compose logs adb-bridge
```

### Port 8501 already in use

```bash
# Find and kill process
lsof -i :8501
kill -9 <PID>

# Or use different port
docker-compose run -p 8502:8501 webapp
```

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     HOST MACHINE                            │
│                                                             │
│  ┌─────────────────┐       ┌─────────────────────────────┐ │
│  │   Genymotion    │       │     Docker Environment      │ │
│  │                 │       │                             │ │
│  │  ┌───────────┐  │ ADB   │  ┌───────────────────────┐ │ │
│  │  │  Android  │◄─┼───────┼──│  llm-pentest-webapp   │ │ │
│  │  │  Emulator │  │       │  │  (Streamlit + Python) │ │ │
│  │  └───────────┘  │       │  └───────────────────────┘ │ │
│  │                 │       │            │               │ │
│  │  192.168.56.101 │       │            ▼               │ │
│  └─────────────────┘       │  ┌───────────────────────┐ │ │
│                            │  │   OpenAI / Anthropic  │ │ │
│                            │  │      API Calls        │ │ │
│                            │  └───────────────────────┘ │ │
│                            └─────────────────────────────┘ │
│                                                             │
│  Browser ──────────────────► http://localhost:8501          │
└─────────────────────────────────────────────────────────────┘
```

---

## Next Steps

After setup is complete:

1. **Explore the Web UI**: Chat with the LLM about Android exploitation
2. **Run a Scan**: Use the Script Generator to create reconnaissance scripts
3. **Try the Chain Runner**: Execute an automated pentest chain
4. **Review Reports**: Check `output/reports/` for generated reports
