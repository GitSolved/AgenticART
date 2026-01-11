"""
Statistical Analysis for Baseline Comparison Experiment

Computes significance tests and effect sizes to determine
if AgenticART's complexity is justified.
"""

import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np
from scipy import stats


@dataclass
class ComparisonResult:
    """Result of comparing two experimental arms."""

    arm_a: str
    arm_b: str

    # Sample sizes
    n_a: int
    n_b: int

    # Pass rates
    rate_a: float
    rate_b: float

    # Statistical test
    test_name: str
    statistic: float
    p_value: float

    # Effect size
    effect_size: float
    effect_size_name: str

    # Interpretation
    significant: bool  # p < 0.05
    practical_significance: str  # "negligible", "small", "medium", "large"


class StatisticalAnalyzer:
    """
    Analyze experiment results for statistical significance.

    ★ Insight ─────────────────────────────────────
    We use multiple comparison correction (Bonferroni) because
    we're comparing 5 arms, which means 10 pairwise comparisons.
    Without correction, we'd expect ~0.5 false positives by chance
    at α=0.05.
    ─────────────────────────────────────────────────
    """

    def __init__(self, results_path: Path):
        with open(results_path) as f:
            self.data = json.load(f)

        self.challenge_results = self.data["challenge_results"]
        self.arms = list(set(r["arm"] for r in self.challenge_results))

    def _get_arm_outcomes(self, arm: str, metric: str = "verification_passed") -> list[bool]:
        """Get binary outcomes for an arm."""
        return [
            r[metric]
            for r in self.challenge_results
            if r["arm"] == arm
        ]

    def compare_arms(
        self,
        arm_a: str,
        arm_b: str,
        metric: str = "verification_passed",
        alpha: float = 0.05,
    ) -> ComparisonResult:
        """
        Compare two arms using appropriate statistical test.

        For binary outcomes, we use:
        - Chi-squared test for independence
        - Effect size: Cohen's h (difference in arcsine-transformed proportions)
        """
        outcomes_a = self._get_arm_outcomes(arm_a, metric)
        outcomes_b = self._get_arm_outcomes(arm_b, metric)

        n_a, n_b = len(outcomes_a), len(outcomes_b)
        rate_a = sum(outcomes_a) / n_a if n_a else 0
        rate_b = sum(outcomes_b) / n_b if n_b else 0

        # Contingency table for chi-squared
        # [[successes_a, failures_a], [successes_b, failures_b]]
        table = np.array([
            [sum(outcomes_a), n_a - sum(outcomes_a)],
            [sum(outcomes_b), n_b - sum(outcomes_b)],
        ])

        # Chi-squared test
        chi2, p_value, dof, expected = stats.chi2_contingency(table)

        # Cohen's h effect size
        # h = 2 * (arcsin(sqrt(p1)) - arcsin(sqrt(p2)))
        h = 2 * (np.arcsin(np.sqrt(rate_a)) - np.arcsin(np.sqrt(rate_b)))
        abs_h = abs(h)

        # Interpret effect size (Cohen's conventions)
        if abs_h < 0.2:
            practical = "negligible"
        elif abs_h < 0.5:
            practical = "small"
        elif abs_h < 0.8:
            practical = "medium"
        else:
            practical = "large"

        return ComparisonResult(
            arm_a=arm_a,
            arm_b=arm_b,
            n_a=n_a,
            n_b=n_b,
            rate_a=rate_a,
            rate_b=rate_b,
            test_name="chi-squared",
            statistic=chi2,
            p_value=p_value,
            effect_size=h,
            effect_size_name="Cohen's h",
            significant=p_value < alpha,
            practical_significance=practical,
        )

    def run_all_comparisons(
        self,
        metric: str = "verification_passed",
        alpha: float = 0.05,
    ) -> list[ComparisonResult]:
        """
        Run all pairwise comparisons with Bonferroni correction.

        ★ Insight ─────────────────────────────────────
        Bonferroni correction: If we make k comparisons, we use
        α/k as our significance threshold. This is conservative
        but prevents false discoveries in multiple testing.
        ─────────────────────────────────────────────────
        """
        n_comparisons = len(self.arms) * (len(self.arms) - 1) // 2
        corrected_alpha = alpha / n_comparisons

        results = []
        for i, arm_a in enumerate(self.arms):
            for arm_b in self.arms[i + 1:]:
                result = self.compare_arms(arm_a, arm_b, metric, corrected_alpha)
                results.append(result)

        return results

    def analyze_by_tier(self, metric: str = "verification_passed") -> dict:
        """
        Analyze performance breakdown by difficulty tier.

        This reveals WHERE the differences emerge - at easy challenges
        or hard ones?
        """
        tiers = list(set(r["tier"] for r in self.challenge_results))

        analysis = {}
        for tier in tiers:
            tier_results = [r for r in self.challenge_results if r["tier"] == tier]

            arm_rates = {}
            for arm in self.arms:
                arm_tier = [r for r in tier_results if r["arm"] == arm]
                if arm_tier:
                    arm_rates[arm] = sum(r[metric] for r in arm_tier) / len(arm_tier)
                else:
                    arm_rates[arm] = None

            analysis[tier] = arm_rates

        return analysis

    def analyze_by_pillar(self, metric: str = "verification_passed") -> dict:
        """
        Analyze performance breakdown by security pillar.

        This reveals if Expert Mixture provides advantage in
        specific domains.
        """
        pillars = list(set(r["pillar"] for r in self.challenge_results))

        analysis = {}
        for pillar in pillars:
            pillar_results = [r for r in self.challenge_results if r["pillar"] == pillar]

            arm_rates = {}
            for arm in self.arms:
                arm_pillar = [r for r in pillar_results if r["arm"] == arm]
                if arm_pillar:
                    arm_rates[arm] = sum(r[metric] for r in arm_pillar) / len(arm_pillar)
                else:
                    arm_rates[arm] = None

            analysis[pillar] = arm_rates

        return analysis

    def compute_ablation_effects(self) -> dict:
        """
        Compute the incremental effect of each complexity addition.

        ★ Insight ─────────────────────────────────────
        This is the KEY analysis for the project decision.
        We isolate the effect of:
        1. Fine-tuning at all (B → C)
        2. Expert Mixture (C → D)
        3. Best-of-N + CoT (D → E)
        ─────────────────────────────────────────────────
        """
        effects = {}

        # Effect of fine-tuning (prompted → single LoRA)
        if "QWEN_PROMPTED" in self.arms and "QWEN_SINGLE_LORA" in self.arms:
            comparison = self.compare_arms("QWEN_PROMPTED", "QWEN_SINGLE_LORA")
            effects["fine_tuning"] = {
                "delta": comparison.rate_b - comparison.rate_a,
                "effect_size": comparison.effect_size,
                "significant": comparison.significant,
                "interpretation": f"Fine-tuning adds {(comparison.rate_b - comparison.rate_a)*100:.1f}pp"
            }

        # Effect of Expert Mixture (single LoRA → mixture)
        if "QWEN_SINGLE_LORA" in self.arms and "QWEN_EXPERT_MIXTURE" in self.arms:
            comparison = self.compare_arms("QWEN_SINGLE_LORA", "QWEN_EXPERT_MIXTURE")
            effects["expert_mixture"] = {
                "delta": comparison.rate_b - comparison.rate_a,
                "effect_size": comparison.effect_size,
                "significant": comparison.significant,
                "interpretation": f"Expert Mixture adds {(comparison.rate_b - comparison.rate_a)*100:.1f}pp"
            }

        # Effect of Best-of-N + CoT (mixture → full)
        if "QWEN_EXPERT_MIXTURE" in self.arms and "AGENTIC_ART_FULL" in self.arms:
            comparison = self.compare_arms("QWEN_EXPERT_MIXTURE", "AGENTIC_ART_FULL")
            effects["best_of_n_cot"] = {
                "delta": comparison.rate_b - comparison.rate_a,
                "effect_size": comparison.effect_size,
                "significant": comparison.significant,
                "interpretation": f"Best-of-N + CoT adds {(comparison.rate_b - comparison.rate_a)*100:.1f}pp"
            }

        # Full pipeline vs Claude baseline
        if "CLAUDE_PROMPTED" in self.arms and "AGENTIC_ART_FULL" in self.arms:
            comparison = self.compare_arms("CLAUDE_PROMPTED", "AGENTIC_ART_FULL")
            effects["vs_frontier"] = {
                "delta": comparison.rate_b - comparison.rate_a,
                "effect_size": comparison.effect_size,
                "significant": comparison.significant,
                "interpretation": f"Full pipeline vs Claude: {(comparison.rate_b - comparison.rate_a)*100:+.1f}pp"
            }

        return effects

    def generate_report(self) -> str:
        """Generate a human-readable analysis report."""
        lines = [
            "=" * 70,
            "BASELINE COMPARISON EXPERIMENT - STATISTICAL ANALYSIS",
            "=" * 70,
            "",
        ]

        # Overall pass rates
        lines.append("OVERALL PASS RATES")
        lines.append("-" * 40)
        for arm in self.arms:
            outcomes = self._get_arm_outcomes(arm)
            rate = sum(outcomes) / len(outcomes) if outcomes else 0
            lines.append(f"  {arm:30} {rate:6.1%}  (n={len(outcomes)})")
        lines.append("")

        # Ablation effects
        effects = self.compute_ablation_effects()
        lines.append("ABLATION ANALYSIS")
        lines.append("-" * 40)
        for component, data in effects.items():
            sig_marker = "***" if data["significant"] else ""
            lines.append(f"  {component:20} {data['delta']:+6.1%}  (h={data['effect_size']:.2f}) {sig_marker}")
            lines.append(f"    → {data['interpretation']}")
        lines.append("")

        # By-tier analysis
        tier_analysis = self.analyze_by_tier()
        lines.append("PERFORMANCE BY DIFFICULTY TIER")
        lines.append("-" * 40)

        # Header
        header = "  Tier".ljust(12)
        for arm in self.arms:
            header += arm[:15].center(15)
        lines.append(header)

        for tier, rates in tier_analysis.items():
            row = f"  {tier}".ljust(12)
            for arm in self.arms:
                rate = rates.get(arm)
                if rate is not None:
                    row += f"{rate:6.1%}".center(15)
                else:
                    row += "N/A".center(15)
            lines.append(row)
        lines.append("")

        # Key findings
        lines.append("KEY FINDINGS")
        lines.append("-" * 40)

        # Check if pipeline beats Claude
        if "vs_frontier" in effects:
            if effects["vs_frontier"]["delta"] > 0 and effects["vs_frontier"]["significant"]:
                lines.append("  ✓ Full pipeline OUTPERFORMS Claude (statistically significant)")
            elif effects["vs_frontier"]["delta"] > 0:
                lines.append("  ~ Full pipeline outperforms Claude (not statistically significant)")
            else:
                lines.append("  ✗ Claude baseline outperforms full pipeline")

        # Check if complexity is justified
        if "expert_mixture" in effects and "best_of_n_cot" in effects:
            mixture_gain = effects["expert_mixture"]["delta"]
            search_gain = effects["best_of_n_cot"]["delta"]

            if mixture_gain > 0.05 and effects["expert_mixture"]["significant"]:
                lines.append("  ✓ Expert Mixture provides meaningful improvement")
            else:
                lines.append("  ✗ Expert Mixture does NOT provide meaningful improvement")
                lines.append("    → Consider simplifying to single adapter")

            if search_gain > 0.05 and effects["best_of_n_cot"]["significant"]:
                lines.append("  ✓ Best-of-N + CoT provides meaningful improvement")
            else:
                lines.append("  ✗ Best-of-N + CoT does NOT provide meaningful improvement")
                lines.append("    → Consider removing search complexity")

        lines.append("")
        lines.append("=" * 70)

        return "\n".join(lines)


def main():
    """Run statistical analysis on experiment results."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python statistical_analysis.py <results_file.json>")
        sys.exit(1)

    results_path = Path(sys.argv[1])
    analyzer = StatisticalAnalyzer(results_path)

    report = analyzer.generate_report()
    print(report)

    # Save report
    report_path = results_path.with_suffix(".analysis.txt")
    with open(report_path, "w") as f:
        f.write(report)
    print(f"\nReport saved to: {report_path}")


if __name__ == "__main__":
    main()
