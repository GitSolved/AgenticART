#!/usr/bin/env python3
"""
AgenticART Environment Setup Script

Comprehensive setup for Android security training environments.
Handles device detection, app installation, persona provisioning,
and CTF flag planting.

Usage:
    # Full setup with default settings
    python scripts/setup_environment.py

    # Setup with specific persona
    python scripts/setup_environment.py --persona rooted_android_14

    # Dry run (show what would happen)
    python scripts/setup_environment.py --dry-run

    # Only install vulnerable apps
    python scripts/setup_environment.py --targets-only

    # Check device status
    python scripts/setup_environment.py --status

    # Show training summary
    python scripts/setup_environment.py --summary
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from dojo.device import DeviceManager  # noqa: E402


def print_header(title: str) -> None:
    """Print a formatted header."""
    print()
    print("=" * 60)
    print(f" {title}")
    print("=" * 60)


def cmd_setup(args: argparse.Namespace) -> int:
    """Run full environment setup."""
    manager = DeviceManager(device_id=args.device)

    results = manager.setup_environment(
        persona=args.persona,
        install_targets=not args.skip_targets,
        plant_flags=not args.skip_flags,
        dry_run=args.dry_run,
    )

    if args.json:
        print(json.dumps(results, indent=2))

    return 0 if results["success"] else 1


def cmd_status(args: argparse.Namespace) -> int:
    """Show device status."""
    manager = DeviceManager(device_id=args.device)

    print_header("Device Status")

    info = manager.detect_device()

    if not info.connected:
        print(f"\n❌ Device not connected: {info.device_id}")
        print("\nTroubleshooting:")
        print("  1. Ensure emulator is running")
        print("  2. Check 'adb devices' shows the device")
        print("  3. Try 'adb kill-server && adb start-server'")
        return 1

    print(f"\n✓ Device: {info.device_id}")
    print(f"  Model: {info.model}")
    print(f"  Manufacturer: {info.manufacturer}")
    print(f"  Android: {info.android_version} (API {info.api_level})")
    print(f"  Emulator: {'Yes' if info.is_emulator else 'No'}")
    print(f"  Rooted: {'Yes' if info.is_rooted else 'No'}", end="")
    if info.root_method:
        print(f" ({info.root_method})")
    else:
        print()

    # Show root access test
    print("\nRoot Access Test:")
    if info.is_rooted:
        if manager.check_root_access():
            print("  ✓ Root commands execute successfully")
        else:
            print("  ⚠ Root detected but commands may require permission")
    else:
        print("  - Device is not rooted")
        print("  - Only unrooted challenges will be available")

    # Validate environment
    validation = manager.validate_environment()
    print("\nEnvironment Validation:")
    if validation["ready"]:
        print("  ✓ Ready for training")
    else:
        for issue in validation["issues"]:
            print(f"  ⚠ {issue}")

    if args.json:
        print("\n" + json.dumps(info.to_dict(), indent=2))

    return 0


def cmd_summary(args: argparse.Namespace) -> int:
    """Show training summary."""
    manager = DeviceManager(device_id=args.device)

    print_header("Training Summary")

    # Detect device first
    info = manager.detect_device()
    if not info.connected:
        print(f"\n❌ Device not connected: {info.device_id}")
        return 1

    summary = manager.get_training_summary()

    print(f"\nDevice: {info.model} (API {info.api_level})")
    print(f"Root Status: {'Rooted' if info.is_rooted else 'Unrooted'}")

    print("\nChallenges by Belt:")
    print("-" * 40)
    total_all = 0
    total_compatible = 0
    for belt, counts in summary["challenges"].items():
        total_all += counts["total"]
        total_compatible += counts["compatible"]
        print(f"  {belt.title():12} {counts['compatible']:3} / {counts['total']:3} compatible")
    print("-" * 40)
    print(f"  {'Total':12} {total_compatible:3} / {total_all:3} compatible")

    vuln_stats = summary["vulnerabilities"]
    print("\nVulnerable Targets:")
    print(f"  Apps: {vuln_stats['total_apps']}")
    print(f"  Total Vulnerabilities: {vuln_stats['total_vulnerabilities']}")
    print(f"  Root Required: {vuln_stats['root_required']}")
    print(f"  Accessible (unrooted): {vuln_stats['unrooted_accessible']}")

    if not info.is_rooted:
        print("\n💡 Tip: Use a rooted device/emulator to access all challenges")
        print("   See: dojo/personas/rooted_android_14.yaml")

    if args.json:
        print("\n" + json.dumps(summary, indent=2))

    return 0


def cmd_targets(args: argparse.Namespace) -> int:
    """Install vulnerable target apps only."""
    manager = DeviceManager(device_id=args.device)

    print_header("Installing Vulnerable Targets")

    # Check device
    info = manager.detect_device()
    if not info.connected:
        print(f"\n❌ Device not connected: {info.device_id}")
        return 1

    print(f"\nDevice: {info.model} (API {info.api_level})")

    # Install targets
    results = manager.setup_vulnerable_targets(
        apps=args.apps.split(",") if args.apps else None,
        dry_run=args.dry_run,
    )

    print("\nResults:")
    for result in results:
        status = "✓" if result.success else "❌"
        print(f"  {status} {result.step}: {result.message}")

    success_count = sum(1 for r in results if r.success)
    print(f"\n{success_count}/{len(results)} targets installed")

    return 0 if success_count == len(results) else 1


def cmd_flags(args: argparse.Namespace) -> int:
    """Plant CTF flags only."""
    manager = DeviceManager(device_id=args.device)

    print_header("Planting CTF Flags")

    # Check device
    info = manager.detect_device()
    if not info.connected:
        print(f"\n❌ Device not connected: {info.device_id}")
        return 1

    print(f"\nDevice: {info.model}")
    print(f"Root: {'Yes' if info.is_rooted else 'No'}")

    if not info.is_rooted:
        print("\n⚠ Device is not rooted - only unrooted flags will be planted")

    # Plant flags
    results = manager.plant_flags(
        apps=args.apps.split(",") if args.apps else None,
        dry_run=args.dry_run,
    )

    print("\nResults:")
    for result in results:
        status = "✓" if result.success else "⏭"
        print(f"  {status} {result.step}: {result.message}")

    success_count = sum(1 for r in results if r.success)
    print(f"\n{success_count}/{len(results)} flags processed")

    return 0


def cmd_provision(args: argparse.Namespace) -> int:
    """Provision persona data only."""
    manager = DeviceManager(device_id=args.device)

    if not args.persona:
        print("Error: --persona is required for provision command")
        return 1

    print_header(f"Provisioning Persona: {args.persona}")

    # Check device
    info = manager.detect_device()
    if not info.connected:
        print(f"\n❌ Device not connected: {info.device_id}")
        return 1

    # Resolve persona path
    persona_path = manager._resolve_persona_path(args.persona)
    if not persona_path or not persona_path.exists():
        print(f"\n❌ Persona not found: {args.persona}")
        print("\nAvailable personas:")
        personas_dir = Path(__file__).parent.parent / "dojo" / "personas"
        for p in personas_dir.glob("*.yaml"):
            if p.name != "base_persona.yaml":
                print(f"  - {p.stem}")
        return 1

    # Provision
    results = manager.provision_persona(persona_path, dry_run=args.dry_run)

    print("\nResults:")
    for result in results:
        status = "✓" if result.success else "❌"
        print(f"  {status} {result.step}: {result.message}")
        for detail in result.details[:3]:  # Show first 3 details
            print(f"      {detail}")

    return 0


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="AgenticART Environment Setup",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full setup
  python scripts/setup_environment.py

  # Check device status
  python scripts/setup_environment.py --status

  # Show what's available for training
  python scripts/setup_environment.py --summary

  # Setup with rooted persona
  python scripts/setup_environment.py --persona rooted_android_14

  # Dry run (no changes)
  python scripts/setup_environment.py --dry-run

  # Install specific vulnerable apps
  python scripts/setup_environment.py --targets-only --apps insecure_bank,diva
        """,
    )

    # Global options
    parser.add_argument(
        "--device",
        "-d",
        help="Device ID (default: auto-detect or EMULATOR_DEVICE env)",
    )
    parser.add_argument(
        "--dry-run",
        "-n",
        action="store_true",
        help="Show what would be done without making changes",
    )
    parser.add_argument(
        "--json",
        "-j",
        action="store_true",
        help="Output results as JSON",
    )

    # Mode selection
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--status",
        "-s",
        action="store_true",
        help="Show device status only",
    )
    mode_group.add_argument(
        "--summary",
        action="store_true",
        help="Show training summary",
    )
    mode_group.add_argument(
        "--targets-only",
        action="store_true",
        help="Only install vulnerable target apps",
    )
    mode_group.add_argument(
        "--flags-only",
        action="store_true",
        help="Only plant CTF flags",
    )
    mode_group.add_argument(
        "--provision-only",
        action="store_true",
        help="Only provision persona data",
    )

    # Setup options
    parser.add_argument(
        "--persona",
        "-p",
        help="Persona name or path (e.g., rooted_android_14)",
    )
    parser.add_argument(
        "--apps",
        help="Comma-separated list of app IDs (e.g., insecure_bank,diva)",
    )
    parser.add_argument(
        "--skip-targets",
        action="store_true",
        help="Skip installing vulnerable apps",
    )
    parser.add_argument(
        "--skip-flags",
        action="store_true",
        help="Skip planting CTF flags",
    )

    args = parser.parse_args()

    # Route to appropriate command
    if args.status:
        return cmd_status(args)
    elif args.summary:
        return cmd_summary(args)
    elif args.targets_only:
        return cmd_targets(args)
    elif args.flags_only:
        return cmd_flags(args)
    elif args.provision_only:
        return cmd_provision(args)
    else:
        return cmd_setup(args)


if __name__ == "__main__":
    sys.exit(main())
