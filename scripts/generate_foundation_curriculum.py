from __future__ import annotations

import os
import sys
from pathlib import Path

from dotenv import load_dotenv

# Local imports
from dojo.tools.nvd_challenge_generator import NVDChallengeGenerator

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

load_dotenv()


def main():
    api_key = os.getenv("NVD_API_KEY")
    generator = NVDChallengeGenerator(api_key=api_key)

    # Foundational Knowledge Queries
    foundations = [
        "Android Intent Redirection",
        "Android Content Provider leak",
        "Android Kernel Use-after-free",
        "Android Binder LPE",
        "Android SystemUI vulnerability",
    ]

    print("🧠 Building Knowledge Foundation from NVD...")

    for query in foundations:
        print(f"\nTargeting Foundation: {query}")
        params = {"keywordSearch": query, "resultsPerPage": "5"}

        try:
            response = generator.session.get(generator.BASE_URL, params=params, timeout=30)
            if response.status_code == 200:
                data = response.json()
                for v in data.get("vulnerabilities", []):
                    cve = generator._parse_cve(v)
                    if cve:
                        template = generator.create_challenge_template(cve)
                        generator.export_to_curriculum(template)
                        print(f"  - Added {cve.cve_id} to {template['belt'].upper()} Belt")
        except Exception as e:
            print(f"  - Error fetching {query}: {e}")

    print("\n🏁 Foundation Pack complete. Your Dojo now has a structural knowledge base.")


if __name__ == "__main__":
    main()
