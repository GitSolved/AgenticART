from __future__ import annotations

import os
import sys
from pathlib import Path

# Add project root to path BEFORE local imports
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from dotenv import load_dotenv

# Local imports
from dojo.tools.nvd_challenge_generator import NVDChallengeGenerator

load_dotenv()


def main():
    api_key = os.getenv("NVD_API_KEY")
    if not api_key:
        print("Error: NVD_API_KEY not found in environment.")
        return

    generator = NVDChallengeGenerator(api_key=api_key)

    print("📡 Fetching 50 recent Android vulnerabilities from NVD...")
    cves = generator.fetch_recent_android_cves(android_version="14", limit=50)

    print(f"✅ Found {len(cves)} candidates. Generating templates and exporting...")

    stats = {}

    for cve in cves:
        template = generator.create_challenge_template(cve)
        belt = template["belt"]
        generator.export_to_curriculum(template)

        stats[belt] = stats.get(belt, 0) + 1

    print("\n🏁 NVD Challenge Generation Complete!")
    print("----------------------------------------")
    for belt, count in stats.items():
        print(f"  {belt.upper()}: {count} new challenges added")
    print("----------------------------------------")
    print(
        "You can now run 'python dojo/test_end_to_end.py' to begin model training on this new data."
    )


if __name__ == "__main__":
    main()
