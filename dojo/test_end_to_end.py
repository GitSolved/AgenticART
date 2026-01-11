#!/usr/bin/env python3
"""
End-to-End Test - Run Phase 2 (Curriculum) and Phase 3 (Sensei) together.

Usage:
    python -m dojo.test_end_to_end --mode mock    # Test with mock LLM
    python -m dojo.test_end_to_end --mode live    # Test with Ollama
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys

# Suppress tokenizer parallelism warnings
os.environ["TOKENIZERS_PARALLELISM"] = "false"

from datetime import datetime
from pathlib import Path
from typing import Any, Optional

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from agent.llm_client import OllamaClient  # noqa: E402
from dojo import (  # noqa: E402
    Belt,
    Challenger,
    ChallengeSession,
    ContextInjector,
    ErrorExtractor,
    Executor,
    Sensei,
    UnifiedCurriculum,
)
from dojo.sensei import ExportFormat  # noqa: E402

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
            os.path.expandvars(r"%USERPROFILE%\AppData\Local\Android\Sdk\platform-tools\adb.exe"),
        ]
        for path in common_paths:
            if os.path.exists(path):
                return path

    return "adb"


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
                import json
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
        import json
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
# LLM Clients (from test_phase2.py)
# ============================================================================

class MockLLMClient:
    """Mock LLM that returns expected answers for testing."""

    # V2 pillar-based challenges (reasoning before execution)
    ANSWERS = {
        # White belt - methodology pillar
        "method_observe_white_001": "shell getprop ro.build.version.release",
        "static_basic_white_001": "shell pm list packages",
        "neg_secure_white_001": "shell getprop ro.product.model",
        "neg_secure_white_002": "shell ps",
        "taxonomy_basic_white_001": "shell cat /data/system/packages.xml",
        # Yellow belt - hypothesis formation
        "method_hypothesis_yellow_001": "shell dumpsys package com.android.settings | grep permission",
        "static_dataflow_yellow_001": "shell am start -n com.android.settings/.Settings",
        "neg_compare_yellow_001": "shell ip addr",
        "taxonomy_owasp_yellow_001": "shell logcat -d ActivityManager:E *:S",
        "transfer_api_yellow_001": "shell dumpsys activity services",
        # Orange belt - verification design
        "method_test_orange_001": "shell run-as com.android.settings ls /data/data/com.android.settings/",
        "static_crossfunc_orange_001": "shell sqlite3 /data/data/com.android.providers.contacts/databases/contacts2.db '.tables'",
        "neg_subtle_orange_001": "shell netstat -an",
        "taxonomy_ambiguous_orange_001": "shell content query --uri content://settings/system",
        "transfer_domain_orange_001": "shell cat /proc/$(pidof system_server)/maps",
    }

    RETRY_ANSWERS = {
        "taxonomy_basic_white_001": "shell su -c 'cat /data/system/packages.xml'",
        "method_test_orange_001": "shell ls /data/data/com.android.settings/",
        "static_crossfunc_orange_001": "shell cat /data/data/com.android.providers.contacts/databases/contacts2.db",
    }

    CHALLENGE_IDENTIFIERS = [
        # White belt - methodology pillar
        ("taxonomy_basic_white_001", ["packages.xml", "/data/system", "protected file"]),
        ("neg_secure_white_002", ["running processes", "process enumeration", "process id"]),
        ("neg_secure_white_001", ["device model", "model name", "marketing name"]),
        ("static_basic_white_001", ["installed packages", "package manager", "pm list"]),
        ("method_observe_white_001", ["android version", "version number", "version of"]),
        # Yellow belt - hypothesis formation
        ("method_hypothesis_yellow_001", ["app permission", "permissions requested", "com.android.settings"]),
        ("static_dataflow_yellow_001", ["launch activity", "start activity", "settings app"]),
        ("neg_compare_yellow_001", ["network interface", "network configuration", "ip address"]),
        ("taxonomy_owasp_yellow_001", ["logcat", "error level", "activitymanager"]),
        ("transfer_api_yellow_001", ["running services", "active service", "dumpsys activity"]),
        # Orange belt - verification design
        ("method_test_orange_001", ["app data directory", "data/data", "run-as"]),
        ("static_crossfunc_orange_001", ["sqlite", "database", "contacts2.db"]),
        ("neg_subtle_orange_001", ["network connections", "netstat", "listening ports"]),
        ("taxonomy_ambiguous_orange_001", ["content provider", "content query", "settings/system"]),
        ("transfer_domain_orange_001", ["memory map", "proc/", "/maps"]),
    ]

    def __init__(self):
        self.call_count = 0
        self.last_challenge_id = None

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        self.call_count += 1
        prompt_lower = prompt.lower()

        if "previous attempt failed" in prompt_lower or "your previous command failed" in prompt_lower:
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

    def __init__(self, model_path: str, adapter_path: Optional[str] = None):
        from pathlib import Path

        from mlx_lm import load

        # Expand variables and resolve path for local check
        expanded_path = Path(os.path.expandvars(os.path.expanduser(model_path)))

        if expanded_path.exists():
            load_path = str(expanded_path.resolve())
            print(f"🚀 Loading Native MLX Brain (Local): {load_path}...")
        else:
            load_path = model_path
            print(f"🚀 Loading Native MLX Brain (HF Hub): {load_path}...")

        if adapter_path:
            print(f"   + Adapter: {adapter_path}")

        # Capture all returned values to be version-agnostic
        if adapter_path:
            results = load(load_path, adapter_path=adapter_path)
        else:
            results = load(load_path)

        self.model = results[0]
        self.tokenizer = results[1]

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        import re

        from mlx_lm import stream_generate

        # Parse the prompt to extract Instruction and Input
        input_match = re.search(r"## Device Context", prompt)
        if input_match:
            input_start = input_match.start()
            raw_input = prompt[input_start:]
            input_context = raw_input.replace("## Device Context", "Device Context:")
            pre_input = prompt[:input_start].strip()
            diff_match = re.search(r"Difficulty: \d+/\d+", pre_input)
            instruction = pre_input[diff_match.end():].strip() if diff_match else pre_input.strip()
        else:
            instruction = prompt.strip()
            input_context = ""

        # Construct messages for chat template
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})

        full_content = instruction
        if input_context:
            full_content += f"\n\nInput:\n{input_context}"

        messages.append({"role": "user", "content": full_content})

        # Try using chat template
        try:
            if hasattr(self.tokenizer, "apply_chat_template"):
                formatted_prompt = self.tokenizer.apply_chat_template(
                    messages,
                    tokenize=False,
                    add_generation_prompt=True
                )
            else:
                raise AttributeError("No chat template")
        except Exception:
            # Fallback to manual formatting
            if input_context:
                formatted_prompt = f"### Instruction:\n{instruction}\n\n### Input:\n{input_context}\n\n### Response: "
            else:
                formatted_prompt = f"### Instruction:\n{instruction}\n\n### Response: "

        # Manual streaming to support stop tokens
        stop_sequences = ["<|endoftext|>", "###", "Human:", "Assistant:", "\n\n", "<|im_end|>"]
        response_text = ""

        for response in stream_generate(self.model, self.tokenizer, prompt=formatted_prompt, max_tokens=256):
            response_text += response.text
            if any(stop in response_text for stop in stop_sequences):
                for stop in stop_sequences:
                    if stop in response_text:
                        response_text = response_text[:response_text.find(stop)]
                break

        # Post-processing to handle hallucinations
        lines = response_text.strip().split('\n')

        # Priority 1: Find the line that actually contains the command
        for line in lines:
            clean_line = line.strip()
            # Handle markdown code blocks
            clean_line = clean_line.replace('`', '').strip()
            if clean_line.startswith('shell '):
                return clean_line
            # Also accept 'adb shell' and strip 'adb '
            if clean_line.startswith('adb shell '):
                return clean_line[4:] # Strip 'adb ' to keep 'shell ...'

        # Priority 2: Return the first non-empty line if no 'shell' prefix found
        for line in lines:
            clean_line = line.strip().replace('`', '')
            if clean_line:
                # If it looks like a command but missing 'shell', maybe prepend it?
                # But for now, just return it.
                return clean_line

        print(f"[DEBUG] No command found in response:\n{response_text}")
        return ""


# ============================================================================
# End-to-End Runner
# ============================================================================

def run_end_to_end(
    mode: str = "mlx",
    device_id: str = "emulator-5554",
    belt: str = "white",
    model: Optional[str] = None,
    adapter: Optional[str] = None,
    limit: Optional[int] = None,
) -> int:
    """Run the complete Phase 2 + Phase 3 pipeline."""
    import yaml

    # Load defaults from settings.yaml
    settings = {}
    settings_path = Path(project_root) / "config" / "settings.yaml"
    if settings_path.exists():
        try:
            with open(settings_path, "r") as f:
                settings = yaml.safe_load(f)
        except Exception as e:
            print(f"Warning: Could not load settings.yaml: {e}")

        # Resolve mode and model from settings if not provided
        llm_settings = settings.get("agent", {}).get("llm", {})
        if mode is None:
            mode = llm_settings.get("provider", "mlx")

        if model is None:
            if mode == "mlx":
                model = llm_settings.get("mlx", {}).get("model")
            elif mode == "live" or mode == "ollama":
                model = llm_settings.get("ollama", {}).get("model")
    if not adapter and mode == "mlx":
        adapter = llm_settings.get("mlx", {}).get("adapter")

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
            llm = MLXLLMClient(model_path=model_path, adapter_path=adapter)
            print(f"LLM: Native MLX ({model_path})")
        except Exception as e:
            print(f"ERROR: {e}")
            return 1
    elif mode == "live":
        try:
            # Use OllamaClient from agent package for live mode to match imports
            model_name = (
                model
                or "hf.co/bartowski/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B-GGUF:Q4_K_M"
            )
            llm = OllamaClient(model=model_name)
            print(f"LLM: Ollama ({llm.model})")
        except Exception as e:
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
        return 1

    device_info = executor.get_device_info()
    print(f"Connected: {device_id} (Android {device_info.get('android_version', '?')})")
    print()

    # loader = ChallengeLoader() -> UnifiedCurriculum handles this now
    curriculum = UnifiedCurriculum.load()
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

    # Run challenges for the specified belt
    print("-" * 70)
    print(f"RUNNING {belt_enum.value.upper()} BELT CHALLENGES")
    print("-" * 70 + "\n")

    # Get challenges for this belt
    challenge_ids = []
    for stage in curriculum.stages_in_order():
        if stage.belt == belt_enum:
            challenge_ids.extend(stage.challenge_ids)

    challenges = []
    for cid in challenge_ids:
        try:
            challenges.append(curriculum.load_challenge(cid))
        except Exception:
            continue

    if limit:
        challenges = challenges[:limit]

    print(f"Loaded {len(challenges)} {belt_enum.value} belt challenges\n")

    sessions: list[ChallengeSession] = []
    for challenge in challenges:
        print(f"Challenge: {challenge.id} - {challenge.name}")
        # Cast to Any/Challenge to bypass mypy check for now as Challenger expects V1 Challenge
        # Ideally Challenger should be updated to support ChallengeV2
        from typing import Any, cast
        session = challenger.run_challenge(cast(Any, challenge))
        sessions.append(session)

        status = "PASS" if session.final_success else "FAIL"
        print(f"Result: {status} ({session.total_attempts} attempts)")
        if not session.final_success:
            print(f"Error: {session.attempts[-1].error_context.error_type if session.attempts[-1].error_context else 'Unknown'}")
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

    model_id = f"test-{mode}-{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    # Run training cycle
    print(f"Model ID: {model_id}")
    print("Running training cycle...")
    print()

    result = sensei.run_training_cycle(
        sessions=sessions,
        model_id=model_id,
        export_formats=[ExportFormat.JSONL, ExportFormat.ALPACA, ExportFormat.SHAREGPT, ExportFormat.DPO],
        auto_promote=True,
    )

    # Print grading results
    print("Grading Results:")
    print("-" * 40)
    for i, assessment in enumerate(result.assessments):
        # Cast to Any to access id property which exists on both V1 and V2
        challenge_obj: Any = sessions[i].challenge
        print(f"  {challenge_obj.id}: Grade {assessment.grade.value} (Score: {assessment.score})")
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

    return 0


# ============================================================================
# Entry Point
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="End-to-End Test")
    parser.add_argument(
        "--mode",
        choices=["mock", "live", "mlx"],
        default=None,
        help="LLM mode: mock, live (Ollama), or mlx (Native Mac). Defaults to settings.yaml",
    )
    parser.add_argument(
        "--device",
        default="emulator-5554",
        help="Device ID for ADB",
    )
    parser.add_argument(
        "--belt",
        choices=["white", "yellow", "orange", "green", "blue", "purple", "brown", "black"],
        default="white",
        help="Belt level to test",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Ollama model name (default: WhiteRabbitNeo)",
    )
    parser.add_argument(
        "--adapter",
        default=None,
        help="Path to LoRA adapters (MLX mode only)",
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit number of challenges to run",
    )

    args = parser.parse_args()
    exit_code = run_end_to_end(
        mode=args.mode,
        device_id=args.device,
        belt=args.belt,
        model=args.model,
        adapter=args.adapter,
        limit=args.limit,
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
