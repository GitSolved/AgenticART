#!/usr/bin/env python3
"""
End-to-End Test - Run Phase 2 (Curriculum) and Phase 3 (Sensei) together.

Usage:
    python -m dojo.test_end_to_end --mode mock    # Test with mock LLM
    python -m dojo.test_end_to_end --mode live    # Test with Ollama
"""

from __future__ import annotations

import os

# Suppress tokenizer parallelism warnings to avoid deadlocks in forked processes
os.environ["TOKENIZERS_PARALLELISM"] = "false"

import argparse
import os
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import json

from dojo import (
    # Phase 2
    Belt,
    ChallengeLoader,
    Challenger,
    ChallengeSession,
    ContextInjector,
    ErrorExtractor,
    Executor,
    ExportFormat,
    # Phase 3
    Sensei,
)


# --- ENGINE STATE UTILS ---
def set_engine_state(status: str):
    """Update the engine state file for the dashboard."""
    output_dir = Path(project_root) / "dojo_output"
    state_path = output_dir / "engine_state.json"
    output_dir.mkdir(parents=True, exist_ok=True)

    current = {"status": "idle", "accumulated_seconds": 0, "start_time": None}
    if state_path.exists():
        try:
            with open(state_path, "r") as f:
                current = json.load(f)
        except Exception:
            pass

    now = datetime.now()
    start_time_str = current.get("start_time")
    accumulated = current.get("accumulated_seconds", 0)

    if status == "running":
        start_time_str = now.isoformat()
    else:
        if current.get("status") == "running" and start_time_str:
            try:
                start_dt = datetime.fromisoformat(str(start_time_str))
                raw_acc = current.get("accumulated_seconds", 0.0)
                # Ensure it's a float
                accumulated = (
                    float(raw_acc) if isinstance(raw_acc, (int, float, str)) else 0.0
                )
                accumulated += (now - start_dt).total_seconds()
            except Exception:
                pass
        start_time_str = None

    with open(state_path, "w") as f:
        json.dump(
            {
                "status": status,
                "start_time": start_time_str,
                "accumulated_seconds": accumulated,
                "last_update": now.isoformat(),
            },
            f,
        )


# ============================================================================
# ADB Path Detection (from test_phase2.py)
# ============================================================================


def find_adb_path() -> str:
    """Find the ADB executable path."""
    adb_path = os.environ.get("ADB_PATH")
    if adb_path and os.path.exists(adb_path):
        return adb_path

    adb_in_path = shutil.which("adb")
    if adb_in_path:
        return adb_in_path

    if sys.platform == "win32":
        common_paths = [
            os.path.expandvars(r"%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe"),
            os.path.expandvars(
                r"%USERPROFILE%\AppData\Local\Android\Sdk\platform-tools\adb.exe"
            ),
        ]
        for path in common_paths:
            if os.path.exists(path):
                return path

    return "adb"


# ============================================================================
# LLM Clients (from test_phase2.py)
# ============================================================================


class MockLLMClient:
    """Mock LLM that returns expected answers for testing."""

    ANSWERS = {
        # White belt
        "white_001": "shell getprop ro.build.version.release",
        "white_002": "shell pm list packages",
        "white_003": "shell getprop ro.product.model",
        "white_004": "shell ps",
        "white_005": "shell cat /data/system/packages.xml",
        # Yellow belt
        "yellow_001": "shell dumpsys package com.android.settings | grep permission",
        "yellow_002": "shell am start -n com.android.settings/.Settings",
        "yellow_003": "shell ip addr",
        "yellow_004": "shell logcat -d ActivityManager:E *:S",
        "yellow_005": "shell dumpsys activity services",
        "yellow_006": "shell pm path com.android.calculator2",
        "yellow_007": "shell am broadcast -a android.net.conn.CONNECTIVITY_CHANGE",
        "yellow_008": "shell screencap -p /sdcard/screenshot.png",
        "yellow_009": "shell input text hello",
        "yellow_010": "shell cat /proc/cpuinfo",
        # Orange belt
        "orange_001": "shell run-as com.android.settings ls /data/data/com.android.settings/",
        "orange_002": "shell sqlite3 /data/data/com.android.providers.contacts/databases/contacts2.db '.tables'",
        "orange_003": "shell netstat -an",
        "orange_004": "shell content query --uri content://settings/system",
        "orange_005": "shell cat /proc/$(pidof system_server)/maps",
        "orange_006": "shell dumpsys package com.android.browser | grep -A 100 'Activity Resolver Table'",
        "orange_007": "shell getprop | grep -iE 'security|selinux'",
        "orange_008": "shell am force-stop com.android.calculator2",
        "orange_009": "shell input keyevent 3",
        "orange_010": "forward tcp:8080 tcp:8080",
        "orange_011": "backup -f settings_backup.ab com.android.settings",
        "orange_012": "shell uiautomator dump /sdcard/window_dump.xml",
        "orange_013": "shell df -h /data",
        "orange_014": "shell settings put global adb_enabled 1",
        "orange_015": "shell printenv",
    }

    RETRY_ANSWERS = {
        "white_005": "shell su -c 'cat /data/system/packages.xml'",
        "orange_001": "shell ls /data/data/com.android.settings/",
        "orange_002": "shell cat /data/data/com.android.providers.contacts/databases/contacts2.db",
    }

    CHALLENGE_IDENTIFIERS = [
        # White belt
        ("white_005", ["packages.xml", "/data/system", "protected file"]),
        ("white_004", ["running processes", "process enumeration", "process id"]),
        ("white_003", ["device model", "model name", "marketing name"]),
        ("white_002", ["installed packages", "package manager", "pm list"]),
        ("white_001", ["android version", "version number", "version of"]),
        # Yellow belt
        (
            "yellow_001",
            ["app permission", "permissions requested", "com.android.settings"],
        ),
        ("yellow_002", ["launch activity", "start activity", "settings app"]),
        ("yellow_003", ["network interface", "network configuration", "ip address"]),
        ("yellow_004", ["logcat", "error level", "activitymanager"]),
        ("yellow_005", ["running services", "active service", "dumpsys activity"]),
        ("yellow_006", ["apk path", "apk file path", "calculator"]),
        ("yellow_007", ["broadcast intent", "connectivity_change", "send broadcast"]),
        ("yellow_008", ["screenshot", "screen capture", "screencap"]),
        ("yellow_009", ["simulate text", "text input", "input text"]),
        ("yellow_010", ["cpu architecture", "processor info", "cpuinfo"]),
        # Orange belt
        ("orange_001", ["app data directory", "data/data", "run-as"]),
        ("orange_002", ["sqlite", "database", "contacts2.db"]),
        ("orange_003", ["network connections", "netstat", "listening ports"]),
        ("orange_004", ["content provider", "content query", "settings/system"]),
        ("orange_005", ["memory map", "proc/", "/maps"]),
        ("orange_006", ["package component", "activity resolver", "browser"]),
        ("orange_007", ["security properties", "selinux", "crypto"]),
        ("orange_008", ["force stop", "force-stop", "terminate"]),
        ("orange_009", ["keyevent", "home button", "keycode"]),
        ("orange_010", ["port forward", "tcp:8080", "localhost"]),
        ("orange_011", ["backup", "application data", ".ab"]),
        ("orange_012", ["window hierarchy", "ui hierarchy", "uiautomator"]),
        ("orange_013", ["disk usage", "storage space", "df -h"]),
        ("orange_014", ["modify setting", "settings put", "adb_enabled"]),
        ("orange_015", ["environment variable", "printenv", "shell environment"]),
    ]

    def __init__(self):
        self.call_count = 0
        self.last_challenge_id = None

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        self.call_count += 1
        prompt_lower = prompt.lower()

        if (
            "previous attempt failed" in prompt_lower
            or "your previous command failed" in prompt_lower
        ):
            if self.last_challenge_id and self.last_challenge_id in self.RETRY_ANSWERS:
                return self.RETRY_ANSWERS[self.last_challenge_id]

        for cid in self.ANSWERS:
            if cid in prompt:
                self.last_challenge_id = cid
                return self.ANSWERS[cid]

        for cid, keywords in self.CHALLENGE_IDENTIFIERS:
            if any(kw in prompt_lower for kw in keywords):
                self.last_challenge_id = cid
                return self.ANSWERS[cid]

        return "shell echo 'unknown challenge'"


class MLXLLMClient:
    """Native MLX client for high-performance benchmarking on Apple Silicon."""

    def __init__(self, model_path: str):
        from mlx_lm import load

        print(f"🚀 Loading Native MLX Brain: {model_path}...")
        # Capture all returned values to be version-agnostic
        results = load(model_path)
        self.model = results[0]
        self.tokenizer = results[1]

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:

        from mlx_lm import generate

        full_instruction = f"{system_prompt}\n{prompt}" if system_prompt else prompt
        formatted_prompt = (
            f"### Instruction:\n{full_instruction}\n\n### Response: shell "
        )

        response = generate(
            self.model,
            self.tokenizer,
            prompt=formatted_prompt,
            max_tokens=100,
        )
        # Prepend the 'shell ' we forced
        return f"shell {response.strip()}"


class OllamaLLMClient:
    """Real LLM client using Ollama HTTP API."""

    def __init__(
        self,
        model: str = "hf.co/bartowski/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B-GGUF:Q4_K_M",
    ):
        self.model = model
        self.api_url = "http://localhost:11434/api/generate"
        self._check_ollama()

    def _check_ollama(self):
        import requests

        try:
            response = requests.get("http://localhost:11434/api/tags", timeout=5)
            if response.status_code != 200:
                raise RuntimeError("Ollama server not responding")
        except Exception:
            raise RuntimeError(
                "Ollama server not running. Start it with 'ollama serve'"
            )

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:

        import requests

        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": system_prompt if system_prompt else "",
            "stream": False,
            "options": {"temperature": 0.1, "top_p": 0.9, "num_ctx": 4096},
        }

        try:
            response = requests.post(self.api_url, json=payload, timeout=120)
            if response.status_code == 200:
                result = response.json()
                return result.get("response", "").strip()
            else:
                return f"[ERROR: API Status {response.status_code}]"
        except Exception as e:
            return f"[ERROR: {e}]"


# ============================================================================
# End-to-End Runner
# ============================================================================


def run_end_to_end(
    mode: str = "mock",
    device_id: str = "emulator-5554",
    belt: str = "white",
    model: Optional[str] = None,
) -> int:
    """Run the complete Phase 2 + Phase 3 pipeline."""
    set_engine_state("running")
    belt_enum = Belt.from_string(belt)

    print("\n" + "=" * 70)
    print("END-TO-END TEST - AgenticART Dojo")
    print("Phase 2 (Curriculum) + Phase 3 (Sensei)")
    print("=" * 70 + "\n")

    start_time = datetime.now()

    # ========================================================================
    # Setup
    # ========================================================================

    print(f"Mode: {mode.upper()}")
    print(f"Belt: {belt_enum.display}")
    print(f"Device: {device_id}")

    adb_path = find_adb_path()
    print(f"ADB: {adb_path}")

    # Create LLM client
    llm: Any
    if mode == "mock":
        llm = MockLLMClient()
        print("LLM: Mock (returns expected answers)")
    elif mode == "mlx":
        try:
            model_path = model or "models/whiterabbit-7b-dojo-4bit"
            llm = MLXLLMClient(model_path=model_path)
            print(f"LLM: Native MLX ({model_path})")
        except Exception as e:
            print(f"ERROR: {e}")
            return 1
    elif mode == "live":
        try:
            model_name = (
                model
                or "hf.co/bartowski/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B-GGUF:Q4_K_M"
            )
            llm = OllamaLLMClient(model=model_name)
            print(f"LLM: Ollama ({model_name})")
        except RuntimeError as e:
            print(f"ERROR: {e}")
            print("Falling back to mock mode")
            llm = MockLLMClient()
    else:
        print(f"Unknown mode: {mode}")
        set_engine_state("idle")
        return 1

    print()

    # ========================================================================
    # Phase 2: Run Challenges
    # ========================================================================

    print("-" * 70)
    print("PHASE 2: CURRICULUM - Running Challenges")
    print("-" * 70 + "\n")

    # Create Phase 2 components
    executor = Executor(device_id=device_id, adb_path=adb_path)

    # Check device connection
    if not executor.check_device_connected():
        print("ERROR: Device not connected. Is the emulator running?")
        set_engine_state("idle")
        return 1

    device_info = executor.get_device_info()
    print(f"Connected: {device_id} (Android {device_info.get('android_version', '?')})")
    print()

    loader = ChallengeLoader()
    error_extractor = ErrorExtractor(executor)
    context_injector = ContextInjector(max_attempts=3)

    def on_attempt(attempt):
        status = "OK" if attempt.execution_result.success else "FAIL"
        print(f"  Attempt {attempt.attempt_number}: {status}")

    challenger = Challenger(
        llm_client=llm,
        executor=executor,
        error_extractor=error_extractor,
        context_injector=context_injector,
        max_retries=3,
        on_attempt=on_attempt,
    )

    # Run challenges for selected belt
    challenges = loader.load_belt(belt_enum)
    print(f"Loaded {len(challenges)} {belt} belt challenges\n")

    sessions: list[ChallengeSession] = []
    for challenge in challenges:
        print(f"Challenge: {challenge.id} - {challenge.name}")
        session = challenger.run_challenge(challenge)
        sessions.append(session)

        status = "PASS" if session.final_success else "FAIL"
        print(f"  Result: {status} ({session.total_attempts} attempts)")
        print()

    # Phase 2 summary
    passed = sum(1 for s in sessions if s.final_success)
    print(f"Phase 2 Complete: {passed}/{len(sessions)} challenges passed")
    print()

    # ========================================================================
    # Phase 3: Grade and Export
    # ========================================================================

    print("-" * 70)
    print("PHASE 3: SENSEI - Grading and Training Data Export")
    print("-" * 70 + "\n")

    # Create output directory
    output_dir = Path("./dojo_output")
    sensei = Sensei(output_dir=output_dir)

    # Sanitize model name for ID
    if model:
        safe_model_name = model.split("/")[-1].replace(":", "-")
    else:
        safe_model_name = f"{mode}_model"
    model_id = f"{safe_model_name}-{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    # Run training cycle
    print(f"Model ID: {model_id}")
    print("Running training cycle...")
    print()

    result = sensei.run_training_cycle(
        sessions=sessions,
        model_id=model_id,
        export_formats=[
            ExportFormat.JSONL,
            ExportFormat.ALPACA,
            ExportFormat.SHAREGPT,
            ExportFormat.DPO,
        ],
        auto_promote=True,
    )

    # Print grading results
    print("Grading Results:")
    print("-" * 40)
    for i, assessment in enumerate(result.assessments):
        challenge = sessions[i].challenge
        print(
            f"  {challenge.id}: Grade {assessment.grade.value} (Score: {assessment.score})"
        )
        if assessment.all_issues:
            for issue in assessment.all_issues[:2]:
                print(f"    - {issue}")

    print()

    # Print extraction summary
    print("Training Examples Extracted:")
    print("-" * 40)
    by_type: dict[str, int] = {}
    for ex in result.examples:
        by_type[ex.example_type] = by_type.get(ex.example_type, 0) + 1
    for ex_type, count in sorted(by_type.items()):
        print(f"  {ex_type}: {count}")
    print(f"  TOTAL: {len(result.examples)}")
    print()

    # Print export results
    print("Training Data Exported:")
    print("-" * 40)
    for fmt, path in result.exports.items():
        size = path.stat().st_size
        print(f"  {fmt.value}: {path.name} ({size} bytes)")
    print()

    # Print progress
    print("Model Progress:")
    print("-" * 40)
    print(result.progress.display_status())
    print()

    if result.promotion:
        print(f"*** PROMOTED TO: {result.promotion.display} ***")
        print()

    # ========================================================================
    # Summary
    # ========================================================================

    duration = (datetime.now() - start_time).total_seconds()

    print("=" * 70)
    print("END-TO-END SUMMARY")
    print("=" * 70)
    print(f"Duration: {duration:.2f}s")
    print(f"Challenges: {passed}/{len(sessions)} passed")
    print(f"Training Examples: {len(result.examples)}")
    print(f"Export Files: {len(result.exports)}")
    print(f"Final Belt: {result.progress.current_belt.display}")
    print(f"Pass Rate: {result.progress.pass_rate:.1f}%")
    print(f"Average Score: {result.progress.average_score:.1f}")
    print("=" * 70)

    # Show sample training data
    if result.examples:
        print("\nSample Training Example (Alpaca format):")
        print("-" * 40)
        sample = result.examples[0]
        alpaca = sample.to_alpaca()
        print(f"Instruction: {alpaca['instruction'][:100]}...")
        print(f"Input: {alpaca['input'][:100] if alpaca['input'] else '(none)'}...")
        print(f"Output: {alpaca['output'][:100]}...")

    set_engine_state("idle")
    return 0


# ============================================================================
# Entry Point
# ============================================================================


def main():
    parser = argparse.ArgumentParser(description="End-to-End Test")
    parser.add_argument(
        "--mode",
        choices=["mock", "live", "mlx"],
        default="mock",
        help="LLM mode: mock (expected answers), live (Ollama), or mlx (Native Mac)",
    )
    parser.add_argument(
        "--device",
        default="emulator-5554",
        help="Device ID for ADB",
    )
    parser.add_argument(
        "--belt",
        choices=[
            "white",
            "yellow",
            "orange",
            "green",
            "blue",
            "purple",
            "brown",
            "black",
        ],
        default="white",
        help="Belt level to test",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Ollama model name (default: WhiteRabbitNeo)",
    )

    args = parser.parse_args()
    exit_code = run_end_to_end(
        mode=args.mode, device_id=args.device, belt=args.belt, model=args.model
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
