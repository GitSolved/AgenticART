#!/usr/bin/env python3
"""
Device Provisioning Script for AgenticART Personas.

This is a convenience wrapper around the DeviceManager.
For full functionality, use scripts/setup_environment.py instead.

Usage:
    python dojo/personas/setup/provision_device.py android_14_user
    python dojo/personas/setup/provision_device.py rooted_android_14 --dry-run
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from dojo.device import DeviceManager  # noqa: E402


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Provision Android device with persona (legacy script)",
        epilog="For full setup, use: python scripts/setup_environment.py",
    )
    parser.add_argument(
        "persona",
        help="Persona name (e.g., android_14_user) or path to YAML file",
    )
    parser.add_argument(
        "--device", "-d",
        help="Device ID (default: from EMULATOR_DEVICE env or auto-detect)",
    )
    parser.add_argument(
        "--dry-run", "-n",
        action="store_true",
        help="Show what would be done without making changes",
    )

    args = parser.parse_args()

    # Create device manager
    manager = DeviceManager(device_id=args.device)

    # Check device connection
    info = manager.detect_device()
    if not info.connected:
        print(f"❌ Device not connected: {manager.device_id}")
        print("\nTip: Ensure your emulator is running and try again.")
        return 1

    print(f"🔧 Provisioning device {manager.device_id}")
    print(f"   Model: {info.model}")
    print(f"   Android: {info.android_version} (API {info.api_level})")
    print(f"   Rooted: {info.is_rooted}")
    print(f"   Persona: {args.persona}")
    print(f"   Dry run: {args.dry_run}")
    print()

    # Resolve persona path
    persona_path = manager._resolve_persona_path(args.persona)
    if not persona_path or not persona_path.exists():
        # Try legacy path resolution
        if args.persona.endswith(".yaml"):
            persona_path = Path(args.persona)
        else:
            persona_path = Path(__file__).parent.parent / f"{args.persona}.yaml"

    if not persona_path.exists():
        print(f"❌ Persona not found: {args.persona}")
        print("\nAvailable personas:")
        personas_dir = Path(__file__).parent.parent
        for p in personas_dir.glob("*.yaml"):
            if p.name != "base_persona.yaml":
                print(f"   - {p.stem}")
        return 1

    # Provision
    results = manager.provision_persona(persona_path, dry_run=args.dry_run)

    # Print results
    print("=" * 60)
    all_success = all(r.success for r in results)

    if all_success:
        print("✅ Provisioning complete!")
    else:
        print("⚠️  Provisioning completed with issues")

    for result in results:
        status = "✓" if result.success else "✗"
        print(f"   {status} {result.step}: {result.message}")

    print("=" * 60)

    # Suggest full setup script
    print("\n💡 For complete setup including vulnerable apps and flags:")
    print(f"   python scripts/setup_environment.py --persona {args.persona}")

    return 0 if all_success else 1


if __name__ == "__main__":
    sys.exit(main())
