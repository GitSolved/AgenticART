#!/usr/bin/env python3
"""
AgenticART CLI - Interactive Dojo Configuration

Usage:
    python -m dojo.cli
    python dojo/cli.py
"""

import os
import subprocess
import sys
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DojoConfig:
    """Configuration for a Dojo training session."""
    # Environment
    rooted: bool = False

    # Target
    android_version: str = "14"
    android_api: int = 34
    persona: str = "android_14_user.yaml"
    device: str = "emulator-5554"

    # Challenge
    belt: str = "white"
    challenge_count: int = 17

    # Model (for distillation: teacher generates, student learns)
    mode: str = "ollama"  # ollama, mlx, openai, anthropic
    teacher_model: str = "llama3.1:70b"  # Large model for generation
    student_model: str = "llama3.1:8b"   # Small model for fine-tuning
    model: str = "llama3.1:8b"  # Active model (student or teacher)
    distillation_mode: bool = False  # Enable teacher->student workflow

    # Execution
    challenger: str = "react"  # basic, react, hybrid
    executor: str = "live"  # live, simulation, dry-run

    # Output
    output_dir: str = "dojo_output"
    verbose: bool = False


# Belt statistics
BELT_STATS = {
    'white':  {'challenges': 17, 'focus': 'Device recon, basic ADB', 'exec_mode': 'full_execution', 'skill': 'Beginner'},
    'yellow': {'challenges': 23, 'focus': 'Info disclosure, DoS', 'exec_mode': 'full_execution', 'skill': 'Novice'},
    'orange': {'challenges': 43, 'focus': 'Permission bypass, logic bugs', 'exec_mode': 'full_execution', 'skill': 'Intermediate'},
    'green':  {'challenges': 43, 'focus': 'IPC, content providers, intents', 'exec_mode': 'full_execution', 'skill': 'Intermediate+'},
    'blue':   {'challenges': 58, 'focus': 'Buffer overflows, EoP', 'exec_mode': 'detection_analysis', 'skill': 'Advanced'},
    'brown':  {'challenges': 47, 'focus': 'UAF, race conditions', 'exec_mode': 'detection_analysis', 'skill': 'Expert'},
    'purple': {'challenges': 28, 'focus': 'Qualcomm critical, RCE', 'exec_mode': 'detection_only', 'skill': 'Elite'},
    'black':  {'challenges': 24, 'focus': 'Kernel exploits, zero-click', 'exec_mode': 'detection_only', 'skill': 'Master'},
}


def clear_screen():
    """Clear terminal screen."""
    print("\033[2J\033[H", end="")


def print_banner():
    """Print AgenticART banner."""
    banner = """
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║     █████╗  ██████╗ ███████╗███╗   ██╗████████╗██╗ ██████╗       ║
║    ██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝██║██╔════╝       ║
║    ███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║   ██║██║            ║
║    ██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║   ██║██║            ║
║    ██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║   ██║╚██████╗       ║
║    ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝ ╚═════╝       ║
║                                                                   ║
║              Android Red Team Training Dojo                       ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
    """
    print(banner)


def print_menu(title: str, options: list[dict], show_back: bool = True) -> int:
    """Print a menu and get user selection."""
    print(f"\n{'─' * 60}")
    print(f"  {title}")
    print(f"{'─' * 60}\n")

    for i, opt in enumerate(options, 1):
        status = opt.get('status', '')
        status_str = f" [{status}]" if status else ""
        print(f"  [{i}] {opt['name']}{status_str}")
        if opt.get('description'):
            print(f"      └─ {opt['description']}")

    if show_back:
        print(f"\n  [0] {'Exit' if not show_back else 'Back'}")
    print(f"{'─' * 60}")

    while True:
        try:
            choice = input("\n  Select option: ").strip()
            if choice == '0':
                return 0
            num = int(choice)
            if 1 <= num <= len(options):
                return num
            print("  Invalid selection. Try again.")
        except ValueError:
            print("  Please enter a number.")


def get_input(prompt: str, default: str = "") -> str:
    """Get text input with optional default."""
    default_str = f" [{default}]" if default else ""
    result = input(f"  {prompt}{default_str}: ").strip()
    return result if result else default


def detect_devices() -> list[str]:
    """Detect connected ADB devices."""
    devices = []
    try:
        result = subprocess.run(['adb', 'devices'], capture_output=True, text=True)
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')[1:]
            for line in lines:
                if '\tdevice' in line:
                    device_id = line.split('\t')[0]
                    devices.append(device_id)
    except FileNotFoundError:
        pass
    return devices


def detect_ollama_models() -> list[str]:
    """Detect installed Ollama models."""
    models = []
    try:
        result = subprocess.run(['ollama', 'list'], capture_output=True, text=True)
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')[1:]
            for line in lines:
                if line.strip():
                    model_name = line.split()[0]
                    models.append(model_name)
    except FileNotFoundError:
        pass
    return models


def detect_mlx_models() -> list[str]:
    """Detect local MLX models."""
    models = []
    model_dirs = [Path('models'), Path.home() / '.cache' / 'huggingface']

    for model_dir in model_dirs:
        if model_dir.exists():
            for item in model_dir.iterdir():
                if item.is_dir() and (item / 'config.json').exists():
                    models.append(str(item))
    return models


# ═══════════════════════════════════════════════════════════════════
# MENU FUNCTIONS
# ═══════════════════════════════════════════════════════════════════

def select_environment(config: DojoConfig) -> None:
    """Select rooted or unrooted environment."""
    options = [
        {
            'name': 'Non-Rooted (Recommended)',
            'description': 'Realistic - matches 95% of real devices',
            'value': False,
            'status': '✓ Realistic'
        },
        {
            'name': 'Rooted',
            'description': 'Full access - forensics/post-exploitation training',
            'value': True,
            'status': '⚠ Setup required'
        }
    ]

    choice = print_menu("STEP 1/8: SELECT ENVIRONMENT", options)
    if choice == 0:
        sys.exit(0)
    config.rooted = options[choice - 1]['value']


def select_android_version(config: DojoConfig) -> None:
    """Select Android version to target."""
    options = [
        {
            'name': 'Android 16 (API 36)',
            'description': 'Baklava - desktop windowing, satellite SOS',
            'value': '16', 'api': 36,
            'persona': 'android_16_user.yaml',
            'status': 'Preview'
        },
        {
            'name': 'Android 15 (API 35)',
            'description': 'Private space, partial screen sharing',
            'value': '15', 'api': 35,
            'persona': 'android_15_user.yaml',
            'status': 'Current'
        },
        {
            'name': 'Android 14 (API 34)',
            'description': 'Predictive back, photo picker, passkeys',
            'value': '14', 'api': 34,
            'persona': 'android_14_user.yaml',
            'status': '✓ Recommended'
        },
        {
            'name': 'Android 11 (API 30)',
            'description': 'Scoped storage, one-time permissions',
            'value': '11', 'api': 30,
            'persona': 'android_11_user.yaml',
            'status': 'Legacy'
        }
    ]

    choice = print_menu("STEP 2/8: SELECT ANDROID VERSION", options)
    if choice == 0:
        sys.exit(0)

    selected = options[choice - 1]
    config.android_version = selected['value']
    config.android_api = selected['api']
    config.persona = selected['persona']


def select_device(config: DojoConfig) -> None:
    """Select target device."""
    devices = detect_devices()

    options = []

    # Add detected devices
    for device in devices:
        options.append({
            'name': device,
            'description': 'Connected device',
            'value': device,
            'status': '✓ Online'
        })

    # Add common defaults
    options.extend([
        {
            'name': 'emulator-5554',
            'description': 'Default Android Emulator',
            'value': 'emulator-5554',
            'status': 'Default' if 'emulator-5554' not in devices else '✓ Online'
        },
        {
            'name': '127.0.0.1:5555',
            'description': 'ADB over TCP (WSL/Remote)',
            'value': '127.0.0.1:5555',
            'status': 'TCP'
        },
        {
            'name': 'Custom...',
            'description': 'Enter custom device address',
            'value': 'custom',
            'status': ''
        }
    ])

    choice = print_menu("STEP 3/8: SELECT TARGET DEVICE", options)
    if choice == 0:
        sys.exit(0)

    selected = options[choice - 1]
    if selected['value'] == 'custom':
        config.device = get_input("Enter device (IP:port or serial)", "127.0.0.1:5555")
    else:
        config.device = selected['value']


def select_belt(config: DojoConfig) -> None:
    """Select challenge belt level."""
    options = []
    total_challenges = sum(s['challenges'] for s in BELT_STATS.values())

    # Print curriculum overview header
    print(f"\n{'─' * 65}")
    print("  CURRICULUM OVERVIEW")
    print(f"{'─' * 65}")
    print(f"  Total Challenges: {total_challenges} | Based on real CVEs from NVD")
    print(f"{'─' * 65}")

    for belt, stats in BELT_STATS.items():
        exec_icon = '✓' if stats['exec_mode'] == 'full_execution' else '◐' if 'analysis' in stats['exec_mode'] else '○'
        options.append({
            'name': f"{belt.capitalize()} Belt ({stats['skill']})",
            'description': f"{stats['focus']} | {exec_icon} {stats['exec_mode'].replace('_', ' ').title()}",
            'value': belt,
            'challenges': stats['challenges'],
            'status': f"{stats['challenges']} challenges"
        })

    # Add "all" option
    options.append({
        'name': 'All Belts (Full Curriculum)',
        'description': 'Progressive training from White to Black',
        'value': 'all',
        'challenges': total_challenges,
        'status': f"{total_challenges} total"
    })

    print(f"\n  Legend: ✓ Full Execution | ◐ Detection+Analysis | ○ Detection Only\n")

    choice = print_menu("STEP 4/8: SELECT CHALLENGE LEVEL", options)
    if choice == 0:
        sys.exit(0)

    selected = options[choice - 1]
    config.belt = selected['value']
    config.challenge_count = selected['challenges']


def select_workflow(config: DojoConfig) -> None:
    """Select training workflow (single model or distillation)."""
    options = [
        {
            'name': 'Single Model',
            'description': 'Run challenges with one model (inference/evaluation)',
            'value': False,
            'status': '✓ Simple'
        },
        {
            'name': 'Teacher-Student Distillation',
            'description': 'Large model generates traces, small model learns',
            'value': True,
            'status': 'Training'
        }
    ]

    choice = print_menu("STEP 5/8: SELECT WORKFLOW", options)
    if choice == 0:
        sys.exit(0)

    config.distillation_mode = options[choice - 1]['value']


def select_inference_mode(config: DojoConfig) -> None:
    """Select inference backend."""
    options = [
        {
            'name': 'Ollama (Local)',
            'description': 'Local inference via Ollama',
            'value': 'ollama',
            'status': '✓ Recommended'
        },
        {
            'name': 'MLX (Apple Silicon)',
            'description': 'Native M-series acceleration',
            'value': 'mlx',
            'status': 'macOS only'
        },
        {
            'name': 'OpenAI API',
            'description': 'Cloud inference (requires API key)',
            'value': 'openai',
            'status': '$ Cost'
        },
        {
            'name': 'Anthropic API',
            'description': 'Claude models (requires API key)',
            'value': 'anthropic',
            'status': '$ Cost'
        }
    ]

    step = "STEP 6/8" if config.distillation_mode else "STEP 6/8"
    choice = print_menu(f"{step}: SELECT INFERENCE BACKEND", options)
    if choice == 0:
        sys.exit(0)

    config.mode = options[choice - 1]['value']


def get_model_options(mode: str, role: str = "model") -> list[dict]:
    """Get model options based on inference mode."""
    options = []

    if mode == 'ollama':
        installed = detect_ollama_models()
        if role == "teacher":
            suggested = [
                ('llama3.1:70b', 'Large - Best quality, requires 48GB+ RAM'),
                ('qwen2.5:72b', 'Large - Strong reasoning'),
                ('qwen2.5:32b', 'Good balance of quality/speed'),
                ('mixtral:8x7b', 'MoE - Fast with good quality'),
            ]
        else:  # student or single model
            suggested = [
                ('llama3.1:8b', 'Small - Fast, good for fine-tuning'),
                ('qwen2.5:7b', 'Small - Strong reasoning'),
                ('llama3.1:70b', 'Large - Best quality'),
                ('qwen2.5:32b', 'Medium - Good balance'),
                ('codellama:13b', 'Code-focused'),
                ('deepseek-coder:6.7b', 'Code specialist'),
            ]

        for model, desc in suggested:
            status = '✓ Installed' if model in installed else '↓ Pull needed'
            options.append({
                'name': model,
                'description': desc,
                'value': model,
                'status': status
            })

    elif mode == 'mlx':
        local_models = detect_mlx_models()
        if role == "teacher":
            suggested = [
                ('models/Qwen2.5-72B-Instruct-4bit', '72B 4-bit - Best quality'),
                ('models/Llama-3.1-70B-Instruct-4bit', '70B 4-bit - Strong'),
                ('mlx-community/Qwen2.5-Coder-32B-Instruct-4bit', 'Code specialist'),
            ]
        else:
            suggested = [
                ('models/Qwen2.5-7B-Instruct-4bit', '7B 4-bit - Fast for fine-tuning'),
                ('models/Llama-3.1-8B-Instruct-4bit', '8B 4-bit - Fast'),
                ('models/Qwen2.5-32B-Instruct-4bit', '32B 4-bit - Good balance'),
                ('models/Qwen2.5-72B-Instruct-4bit', '72B 4-bit - Best quality'),
            ]

        for model, desc in suggested:
            status = '✓ Local' if model in local_models else 'Download needed'
            options.append({
                'name': model,
                'description': desc,
                'value': model,
                'status': status
            })

    elif mode == 'openai':
        if role == "teacher":
            options = [
                {'name': 'gpt-4-turbo', 'description': 'Latest GPT-4 - Best quality', 'value': 'gpt-4-turbo', 'status': '$$$'},
                {'name': 'gpt-4o', 'description': 'Multimodal GPT-4', 'value': 'gpt-4o', 'status': '$$$'},
            ]
        else:
            options = [
                {'name': 'gpt-3.5-turbo', 'description': 'Fast and cheap - good student', 'value': 'gpt-3.5-turbo', 'status': '$'},
                {'name': 'gpt-4-turbo', 'description': 'Latest GPT-4', 'value': 'gpt-4-turbo', 'status': '$$'},
                {'name': 'gpt-4o-mini', 'description': 'Efficient GPT-4', 'value': 'gpt-4o-mini', 'status': '$$'},
            ]

    elif mode == 'anthropic':
        if role == "teacher":
            options = [
                {'name': 'claude-3-opus', 'description': 'Most capable - ideal teacher', 'value': 'claude-3-opus-20240229', 'status': '$$$'},
                {'name': 'claude-3.5-sonnet', 'description': 'Fast and capable', 'value': 'claude-3-5-sonnet-20241022', 'status': '$$'},
            ]
        else:
            options = [
                {'name': 'claude-3-haiku', 'description': 'Fast - good student', 'value': 'claude-3-haiku-20240307', 'status': '$'},
                {'name': 'claude-3-sonnet', 'description': 'Balanced', 'value': 'claude-3-sonnet-20240229', 'status': '$$'},
                {'name': 'claude-3.5-sonnet', 'description': 'Latest Sonnet', 'value': 'claude-3-5-sonnet-20241022', 'status': '$$'},
            ]

    options.append({
        'name': 'Custom...',
        'description': 'Enter custom model name/path',
        'value': 'custom',
        'status': ''
    })

    return options


def select_model(config: DojoConfig) -> None:
    """Select LLM model based on inference mode."""
    if config.distillation_mode:
        # Select teacher model
        print(f"\n{'═' * 65}")
        print("  TEACHER MODEL (generates gold traces)")
        print(f"{'═' * 65}")

        teacher_options = get_model_options(config.mode, "teacher")
        choice = print_menu("STEP 7a/8: SELECT TEACHER MODEL", teacher_options)
        if choice == 0:
            sys.exit(0)

        selected = teacher_options[choice - 1]
        if selected['value'] == 'custom':
            config.teacher_model = get_input("Enter teacher model name/path")
        else:
            config.teacher_model = selected['value']

        # Select student model
        print(f"\n{'═' * 65}")
        print("  STUDENT MODEL (learns from teacher traces)")
        print(f"{'═' * 65}")

        student_options = get_model_options(config.mode, "student")
        choice = print_menu("STEP 7b/8: SELECT STUDENT MODEL", student_options)
        if choice == 0:
            sys.exit(0)

        selected = student_options[choice - 1]
        if selected['value'] == 'custom':
            config.student_model = get_input("Enter student model name/path")
        else:
            config.student_model = selected['value']

        # Set active model to teacher (for initial generation)
        config.model = config.teacher_model

    else:
        # Single model selection
        options = get_model_options(config.mode, "model")
        choice = print_menu("STEP 7/8: SELECT MODEL", options)
        if choice == 0:
            sys.exit(0)

        selected = options[choice - 1]
        if selected['value'] == 'custom':
            config.model = get_input("Enter model name or path")
        else:
            config.model = selected['value']


def select_execution_options(config: DojoConfig) -> None:
    """Select challenger and executor type."""

    # Challenger selection
    challenger_options = [
        {
            'name': 'ReAct (Reason + Act)',
            'description': 'Multi-step reasoning, adapts to failures',
            'value': 'react',
            'status': '✓ Recommended'
        },
        {
            'name': 'Basic',
            'description': 'Single-turn, fast but less reliable',
            'value': 'basic',
            'status': 'Simple'
        },
        {
            'name': 'Hybrid',
            'description': 'ReAct for complex, Basic for simple',
            'value': 'hybrid',
            'status': 'Adaptive'
        }
    ]

    print(f"\n{'─' * 60}")
    print("  STEP 8/8: EXECUTION OPTIONS")
    print(f"{'─' * 60}")

    choice = print_menu("  Challenger Strategy", challenger_options, show_back=False)
    if choice == 0:
        sys.exit(0)
    config.challenger = challenger_options[choice - 1]['value']

    # Executor selection
    executor_options = [
        {
            'name': 'Live Execution',
            'description': 'Execute on real device/emulator',
            'value': 'live',
            'status': '✓ Real'
        },
        {
            'name': 'Simulation',
            'description': 'Mock responses for testing',
            'value': 'simulation',
            'status': 'Testing'
        },
        {
            'name': 'Dry Run',
            'description': 'Show commands without executing',
            'value': 'dry-run',
            'status': 'Preview'
        }
    ]

    choice = print_menu("  Executor Mode", executor_options, show_back=False)
    if choice == 0:
        sys.exit(0)
    config.executor = executor_options[choice - 1]['value']


def build_command(config: DojoConfig) -> list[str]:
    """Build the full command from configuration."""
    cmd = [
        'python3', '-m', 'dojo.test_end_to_end',
        '--mode', config.mode,
        '--model', config.model,
        '--belt', config.belt,
        '--challenger', config.challenger,
        '--executor', config.executor,
        '--device', config.device,
        '--persona', config.persona,
        '--output', config.output_dir,
    ]

    if config.rooted:
        cmd.append('--rooted')

    if config.verbose:
        cmd.append('--verbose')

    if config.distillation_mode:
        cmd.extend(['--teacher', config.teacher_model])
        cmd.extend(['--student', config.student_model])
        cmd.append('--distillation')

    return cmd


def show_summary(config: DojoConfig) -> bool:
    """Show configuration summary and confirm."""
    clear_screen()
    print_banner()

    cmd = build_command(config)

    # Build model section based on distillation mode
    if config.distillation_mode:
        model_section = f"""  ┌─ Model (Distillation) ──────────────────────────────────────┐
  │  Backend:         {config.mode.upper():40} │
  │  Teacher Model:   {config.teacher_model[:40]:40} │
  │  Student Model:   {config.student_model[:40]:40} │
  │  Workflow:        {'Teacher generates → Student learns':40} │
  └────────────────────────────────────────────────────────────┘"""
    else:
        model_section = f"""  ┌─ Model ────────────────────────────────────────────────────┐
  │  Backend:         {config.mode.upper():40} │
  │  Model:           {config.model[:40]:40} │
  │  Workflow:        {'Single model inference':40} │
  └────────────────────────────────────────────────────────────┘"""

    print(f"""
{'═' * 65}
  CONFIGURATION SUMMARY
{'═' * 65}

  ┌─ Environment ──────────────────────────────────────────────┐
  │  Root Access:     {'Yes (forensics mode)' if config.rooted else 'No (realistic training)':40} │
  │  Android:         {f'Android {config.android_version} (API {config.android_api})':40} │
  │  Device:          {config.device:40} │
  │  Persona:         {config.persona:40} │
  └────────────────────────────────────────────────────────────┘

  ┌─ Challenge ────────────────────────────────────────────────┐
  │  Belt Level:      {f'{config.belt.capitalize()} Belt ({config.challenge_count} challenges)':40} │
  └────────────────────────────────────────────────────────────┘

{model_section}

  ┌─ Execution ────────────────────────────────────────────────┐
  │  Challenger:      {config.challenger.capitalize():40} │
  │  Executor:        {config.executor.capitalize():40} │
  │  Output:          {config.output_dir:40} │
  └────────────────────────────────────────────────────────────┘

{'═' * 65}
  COMMAND
{'═' * 65}

  {' '.join(cmd)}

{'═' * 65}
""")

    if config.rooted:
        print("  ⚠️  WARNING: Rooted mode requires a rooted emulator/device")
        print("      See: docs/rooted-setup.md\n")

    print("  [1] Run this configuration")
    print("  [2] Copy command to clipboard")
    print("  [3] Save command to file")
    print("  [4] Start over")
    print("  [0] Exit")
    print(f"{'─' * 65}")

    choice = input("\n  Select option: ").strip()

    if choice == '1':
        return True
    elif choice == '2':
        try:
            # Try to copy to clipboard
            subprocess.run(['pbcopy'], input=' '.join(cmd).encode(), check=True)
            print("\n  ✓ Command copied to clipboard!")
        except Exception:
            try:
                subprocess.run(['xclip', '-selection', 'clipboard'], input=' '.join(cmd).encode(), check=True)
                print("\n  ✓ Command copied to clipboard!")
            except Exception:
                print(f"\n  Command: {' '.join(cmd)}")
        return False
    elif choice == '3':
        filename = get_input("Filename", "dojo_command.sh")
        with open(filename, 'w') as f:
            f.write("#!/bin/bash\n")
            f.write(f"# AgenticART Dojo Command\n")
            f.write(f"# Generated: {config.android_version} / {config.belt} belt\n\n")
            f.write(' '.join(cmd) + '\n')
        print(f"\n  ✓ Saved to {filename}")
        return False
    elif choice == '4':
        return None  # Start over
    else:
        return False


def run_command(config: DojoConfig):
    """Execute the configuration."""
    cmd = build_command(config)

    print(f"\n{'─' * 65}")
    print(f"  Executing: {' '.join(cmd[:6])}...")
    print(f"{'─' * 65}\n")

    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\n\n  Training interrupted by user.")
    except Exception as e:
        print(f"\n  Error: {e}")


def main():
    """Main CLI entry point."""
    while True:
        config = DojoConfig()

        clear_screen()
        print_banner()
        select_environment(config)

        clear_screen()
        print_banner()
        select_android_version(config)

        clear_screen()
        print_banner()
        select_device(config)

        clear_screen()
        print_banner()
        select_belt(config)

        clear_screen()
        print_banner()
        select_workflow(config)

        clear_screen()
        print_banner()
        select_inference_mode(config)

        clear_screen()
        print_banner()
        select_model(config)

        clear_screen()
        print_banner()
        select_execution_options(config)

        result = show_summary(config)

        if result is True:
            run_command(config)
            break
        elif result is False:
            input("\n  Press Enter to continue...")
            continue
        elif result is None:
            continue  # Start over
        else:
            break


if __name__ == '__main__':
    main()
