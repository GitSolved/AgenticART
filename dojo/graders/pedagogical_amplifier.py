#!/usr/bin/env python3
"""
Pedagogical Amplifier: Quality-Preserving Training Data Expansion

Unlike simple variation (rephrasing), pedagogical amplification creates
meaningful variations that each teach something different:

1. Reasoning Method Variations: Same challenge, different reasoning approaches
2. Belt Level Adaptations: Same principle at different complexity levels
3. Transfer Context Variations: Same principle in different application domains
4. Error Mode Variations: Different failure modes as rejected responses
5. Investigation Path Variations: Different valid approaches to same problem

Key principle: Each variation must teach something the original didn't.
Simple rephrasing is NOT pedagogically valuable.
"""

import copy
import json
from datetime import datetime
from pathlib import Path
from typing import Iterator


class PedagogicalAmplifier:
    """Amplifies training data while preserving educational value."""

    def __init__(self):
        self.reasoning_methods = [
            "deductive", "inductive", "systems_analysis", "evidence_evaluation"
        ]
        self.belt_levels = [
            "white", "yellow", "orange", "green", "blue", "purple", "brown", "black"
        ]
        self.bad_habits = [
            "pattern_matching_without_verification",
            "assuming_tools_are_correct",
            "stopping_at_first_finding",
            "overconfidence_without_evidence",
            "accepting_authority_uncritically"
        ]
        self.false_beliefs = [
            "obfuscation_is_security",
            "root_detection_stops_attacks",
            "ssl_pinning_is_unbreakable",
            "native_code_is_more_secure",
            "cve_descriptions_are_complete"
        ]

    def amplify_with_different_rejection_modes(
        self, pair: dict, all_habits: bool = True
    ) -> Iterator[dict]:
        """Generate variations with different rejection failure modes."""

        # Original pair
        yield pair

        base_prompt = pair["prompt"]
        base_chosen = pair["chosen"]

        # Generate rejected responses for each bad habit
        for habit in self.bad_habits[:3] if not all_habits else self.bad_habits:
            rejected = self._generate_bad_habit_rejection(habit, pair)
            new_pair = {
                "prompt": base_prompt,
                "chosen": base_chosen,
                "rejected": rejected,
                "metadata": {
                    **pair.get("metadata", {}),
                    "rejection_mode": habit,
                    "amplification_type": "error_mode_variation"
                }
            }
            yield new_pair

    def amplify_with_transfer_contexts(self, pair: dict) -> Iterator[dict]:
        """Generate variations showing same principle in different contexts."""

        yield pair

        transfer_contexts = [
            {
                "domain": "Web Application",
                "context": "A web application with similar security assumptions",
                "principle_application": "Same principle applies to web client-side code"
            },
            {
                "domain": "IoT Device",
                "context": "An IoT device running embedded software",
                "principle_application": "Same principle applies to firmware analysis"
            },
            {
                "domain": "Desktop Application",
                "context": "A desktop application with license protection",
                "principle_application": "Same principle applies to local binary analysis"
            }
        ]

        for ctx in transfer_contexts:
            transfer_addition = f"""

---

## Transfer Application: {ctx['domain']}

**Context**: {ctx['context']}

**How the Principle Applies**: {ctx['principle_application']}

This demonstrates that the principle discovered isn't specific to mobile apps—
it applies anywhere similar conditions exist. Recognizing this pattern across
domains is what separates true understanding from memorized technique.
"""
            new_pair = copy.deepcopy(pair)
            new_pair["chosen"] = pair["chosen"] + transfer_addition
            new_pair["metadata"] = {
                **pair.get("metadata", {}),
                "transfer_domain": ctx["domain"],
                "amplification_type": "transfer_context_variation"
            }
            yield new_pair

    def amplify_with_reasoning_approaches(self, pair: dict) -> Iterator[dict]:
        """Generate variations using different reasoning methods for same problem."""

        yield pair

        primary = pair.get("metadata", {}).get("primary_reasoning", "")

        # Add alternative reasoning approaches
        for method in self.reasoning_methods:
            if method != primary:
                alternative_section = f"""

---

## Alternative Approach: {method.replace('_', ' ').title()} Reasoning

The same conclusion can be reached through {method.replace('_', ' ')}:

"""
                if method == "deductive":
                    alternative_section += """
**Premise 1**: [General principle]
**Premise 2**: [Specific observation]
**Conclusion**: [What follows necessarily]
"""
                elif method == "inductive":
                    alternative_section += """
**Observation 1**: [First instance]
**Observation 2**: [Second instance]
**Pattern**: [What connects them]
**Hypothesis**: [General principle]
"""
                elif method == "systems_analysis":
                    alternative_section += """
**Components**: [System parts]
**Interactions**: [How they relate]
**Emergent Property**: [What arises from interaction]
"""
                elif method == "evidence_evaluation":
                    alternative_section += """
**Claim**: [Assertion]
**Evidence**: [Support]
**Quality**: [Assessment]
**Conclusion**: [Verdict]
"""

                alternative_section += """
The convergence of multiple reasoning approaches strengthens confidence
in the conclusion and demonstrates the robustness of the principle.
"""

                new_pair = copy.deepcopy(pair)
                new_pair["chosen"] = pair["chosen"] + alternative_section
                new_pair["metadata"] = {
                    **pair.get("metadata", {}),
                    "alternative_reasoning": method,
                    "amplification_type": "reasoning_approach_variation"
                }
                yield new_pair

    def _generate_bad_habit_rejection(self, habit: str, pair: dict) -> str:
        """Generate a rejected response demonstrating a specific bad habit."""

        habit_responses = {
            "pattern_matching_without_verification": """## Analysis

I've seen this pattern before. This looks like a standard vulnerability type.

Running the standard bypass script...

Result: Bypassed.

The technique worked as expected.
""",
            "assuming_tools_are_correct": """## Analysis

I ran automated tools on this target:
- Scanner found no vulnerabilities
- Linter passed all checks
- Static analyzer reported clean

Based on tool results: The application is secure.

No further investigation needed.
""",
            "stopping_at_first_finding": """## Analysis

Found vulnerability: Hardcoded credentials in strings.xml

Severity: High

Report complete.
""",
            "overconfidence_without_evidence": """## Analysis

This is definitely a critical vulnerability. I'm 100% certain it can be exploited.

The impact is severe and the app is completely compromised.

Remediation is urgent.
""",
            "accepting_authority_uncritically": """## Analysis

According to the official documentation, this implementation follows best practices.

The vendor claims the security is robust.

Industry experts recommend this approach.

Therefore, no significant vulnerabilities are expected.
"""
        }

        return habit_responses.get(habit, """## Analysis

I analyzed the app. Found some issues. Fixed.

Done.
""")

    def amplify_dataset(
        self,
        input_path: Path,
        output_path: Path,
        include_error_modes: bool = True,
        include_transfer: bool = True,
        include_reasoning: bool = True
    ) -> dict:
        """Amplify a dataset while preserving pedagogical quality."""

        # Load original data
        original_pairs = []
        with open(input_path, "r") as f:
            for line in f:
                if line.strip():
                    original_pairs.append(json.loads(line))

        print(f"Loaded {len(original_pairs)} original pairs from {input_path}")

        # Amplify
        amplified_pairs = []
        for pair in original_pairs:
            # Error mode variations
            if include_error_modes:
                for amp_pair in self.amplify_with_different_rejection_modes(pair, all_habits=False):
                    amplified_pairs.append(amp_pair)

            # Transfer context variations
            if include_transfer:
                for amp_pair in self.amplify_with_transfer_contexts(pair):
                    amplified_pairs.append(amp_pair)

            # Reasoning approach variations
            if include_reasoning:
                for amp_pair in self.amplify_with_reasoning_approaches(pair):
                    amplified_pairs.append(amp_pair)

        # Deduplicate (exact matches only)
        seen_prompts = set()
        unique_pairs = []
        for pair in amplified_pairs:
            key = (pair["prompt"][:200], pair["chosen"][:200], pair["rejected"][:200])
            if key not in seen_prompts:
                seen_prompts.add(key)
                unique_pairs.append(pair)

        # Save
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            for pair in unique_pairs:
                f.write(json.dumps(pair) + "\n")

        stats = {
            "original_pairs": len(original_pairs),
            "amplified_pairs": len(unique_pairs),
            "amplification_factor": len(unique_pairs) / max(len(original_pairs), 1),
            "error_modes": include_error_modes,
            "transfer_contexts": include_transfer,
            "reasoning_variations": include_reasoning
        }

        print(f"Amplified to {len(unique_pairs)} pairs ({stats['amplification_factor']:.1f}x)")
        print(f"Saved to {output_path}")

        return stats


def combine_pedagogical_training_data(output_dir: Path) -> dict:
    """Combine all high-quality pedagogical training data into unified dataset."""

    pedagogical_files = [
        "unified_complete_*.jsonl",
        "inquiry_based.jsonl",
        "integrated_reasoning.jsonl",
        "meaningful_challenges.jsonl",
        "dual_mandate_training.jsonl",
        "deconditioning_*.jsonl",
        "false_beliefs_*.jsonl"
    ]

    all_pairs = []
    sources = {}

    for pattern in pedagogical_files:
        matches = list(output_dir.glob(pattern))
        for match in matches:
            with open(match, "r") as f:
                count = 0
                for line in f:
                    if line.strip():
                        pair = json.loads(line)
                        pair["metadata"] = pair.get("metadata", {})
                        pair["metadata"]["source_file"] = match.name
                        all_pairs.append(pair)
                        count += 1
                sources[match.name] = count
                print(f"  Loaded {count} pairs from {match.name}")

    # Save combined
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    combined_path = output_dir / f"pedagogical_combined_{timestamp}.jsonl"

    with open(combined_path, "w") as f:
        for pair in all_pairs:
            f.write(json.dumps(pair) + "\n")

    print("\n=== Combined Pedagogical Training Data ===")
    print(f"Total pairs: {len(all_pairs)}")
    print(f"Sources: {len(sources)} files")
    print(f"Output: {combined_path}")

    return {
        "total_pairs": len(all_pairs),
        "sources": sources,
        "output_path": str(combined_path)
    }


def main():
    """Demonstrate pedagogical amplification."""
    output_dir = Path("dojo/training_data")

    print("=" * 70)
    print("PEDAGOGICAL AMPLIFIER")
    print("Quality-Preserving Training Data Expansion")
    print("=" * 70)

    # First, combine existing pedagogical data
    print("\n1. Combining existing pedagogical training data...")
    combine_pedagogical_training_data(output_dir)

    # Then amplify the unified curriculum data
    print("\n2. Amplifying unified curriculum data...")
    amplifier = PedagogicalAmplifier()

    # Find the unified curriculum file
    unified_files = list(output_dir.glob("unified_curriculum_*.jsonl"))
    if unified_files:
        latest_unified = max(unified_files, key=lambda p: p.stat().st_mtime)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        amplified_path = output_dir / f"unified_amplified_{timestamp}.jsonl"

        amp_stats = amplifier.amplify_dataset(
            latest_unified,
            amplified_path,
            include_error_modes=True,
            include_transfer=True,
            include_reasoning=True
        )

        print(f"\nAmplification stats: {amp_stats}")

    print("\n" + "=" * 70)
    print("DONE")
    print("=" * 70)


if __name__ == "__main__":
    main()
