# Installation

Complete setup guide for AgenticART.

## System Requirements

| Component | Requirement |
|-----------|-------------|
| Python | 3.10+ |
| OS | macOS, Linux, Windows (WSL) |
| RAM | 16GB+ recommended |
| GPU | Optional (Apple Silicon or CUDA) |

## Step 1: Clone Repository

```bash
git clone https://github.com/GitSolved/AgenticART.git
cd AgenticART
```

## Step 2: Install Python Dependencies

```bash
pip install -r requirements.txt

# Optional: Install as editable package
pip install -e .
```

## Step 3: Android SDK Setup

### Option A: Android Studio

1. Download [Android Studio](https://developer.android.com/studio)
2. Install Android SDK via SDK Manager
3. Create an AVD (Android Virtual Device)

### Option B: Command Line Only

```bash
# Download command-line tools
# Add to PATH:
export ANDROID_HOME=$HOME/Android/Sdk
export PATH=$PATH:$ANDROID_HOME/platform-tools
```

Verify:

```bash
adb version
# Android Debug Bridge version 1.0.41
```

## Step 4: Ollama Setup

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull a model
ollama pull llama3.1:8b
```

## Step 5: Environment Variables

```bash
cp .env.example .env
```

Edit `.env`:

```
NVD_API_KEY=your_key_here  # Optional, for CVE generation
```

## Step 6: Verify Installation

```bash
python3 -c "from dojo import Belt, Challenge; print('OK')"
```

## Troubleshooting

### ADB not found

```bash
export PATH=$PATH:$ANDROID_HOME/platform-tools
```

### Ollama connection refused

```bash
ollama serve  # Start Ollama server
```

### Emulator not detected

```bash
adb kill-server && adb start-server
```
