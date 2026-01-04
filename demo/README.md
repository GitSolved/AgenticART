# Demo Scripts

Runnable demonstrations of the AgenticART framework.

## Available Demos

### framework.py - Framework Showcase
Comprehensive demonstration of all framework capabilities with mock/simulated execution.

```bash
python -m demo.framework
```

**Shows:**
- Device reconnaissance (mock or real)
- CVE matching against device profile
- LLM-driven script generation
- Iterative feedback loop on failure
- Human-in-the-loop governance
- Quality/hallucination detection

### live_exploit.py - Live Exploitation
Real exploitation against a connected Android device. **Not a simulation.**

```bash
python -m demo.live_exploit [device_ip]
```

**Requirements:**
- Connected Android device (Genymotion emulator or physical)
- ADB access to the device
- Ollama running with a model loaded

### cve_2025_36896.py - CVE-Specific Test
Demonstrates the framework's approach to 1-day exploit testing against a specific CVE (Google Pixel WLAN vulnerability).

```bash
python -m demo.cve_2025_36896
```

**Methodology:**
1. Device fingerprinting - Confirm target is vulnerable
2. CVE analysis - Feed CVE description to LLM
3. Exploit generation - LLM generates attack script
4. Execution - Run against target
5. Verification - Confirm exploitation success

## Running Demos

All demos can be run as modules from the project root:

```bash
# Framework showcase (safe, uses mocks)
python -m demo.framework

# Live exploitation (requires device)
python -m demo.live_exploit 192.168.56.101

# CVE-specific test
python -m demo.cve_2025_36896
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `LLM_PROVIDER` | LLM backend (ollama, openai, anthropic, mock) | ollama |
| `OLLAMA_MODEL` | Model to use with Ollama | qwen2.5:72b |
| `EMULATOR_DEVICE` | Default device IP for demos | 192.168.56.101 |
