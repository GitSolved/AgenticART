# Quick Start

Get AgenticART running in 5 minutes.

## Prerequisites

- Python 3.10+
- Android SDK / ADB
- Android Emulator or physical device
- Ollama (for local LLM inference)

## Step 1: Clone and Install

```bash
git clone https://github.com/GitSolved/AgenticART.git
cd AgenticART
pip install -r requirements.txt
```

## Step 2: Start Android Emulator

```bash
emulator -avd Your_AVD_Name
```

Verify connection:

```bash
adb devices
# Should show: emulator-5554 device
```

## Step 3: Run Your First Challenge

```bash
python3 dojo/test_end_to_end.py --mode live --model llama3.1:8b --belt white
```

This will:

1. Load white belt challenges
2. Send each challenge to your LLM
3. Execute generated commands on the emulator
4. Grade the results

## Step 4: View Results

Results are saved to `dojo_output/`. View the dashboard:

```bash
streamlit run webapp/dashboard.py
```

## Next Steps

- [Full Installation Guide](installation.md) - Configure all options
- [Training Overview](../training/overview.md) - Fine-tune your own model
- [Scoring System](../reference/scoring.md) - Understand the grading
