"""Master Refinery - Manages a persistent, ever-growing master dataset."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from dojo.models import Grade, TrainingExample


class MasterRefinery:
    """Manages the Gold Standard dataset by merging and ranking new data."""

    def __init__(self, master_dir: Path = Path("master_dataset")):
        self.master_dir = master_dir
        self.master_dir.mkdir(parents=True, exist_ok=True)
        self.alpaca_path = self.master_dir / "master_alpaca.json"
        self.dpo_path = self.master_dir / "master_dpo.jsonl"
        self.discovery_path = self.master_dir / "master_discovery.jsonl"

    def load_master_alpaca(self) -> List[Dict[str, Any]]:
        """Load current master SFT data."""
        if not self.alpaca_path.exists():
            return []
        try:
            with open(self.alpaca_path, "r") as f:
                return json.load(f)
        except Exception:
            return []

    def sync_alpaca(self, new_examples: List[TrainingExample]):
        """Merge new successes into the master set, prioritizing quality."""
        master = self.load_master_alpaca()
        lookup = {f"{ex['instruction']}|{ex.get('input', '')}": ex for ex in master}

        added_count = 0
        updated_count = 0

        for ex in new_examples:
            if ex.example_type not in ("positive", "kata"):
                continue

            key = f"{ex.instruction}|{ex.input_text}"
            new_data = ex.to_alpaca()
            new_data["_grade"] = ex.grade.value if ex.grade else "A"
            new_data["_type"] = ex.example_type

            if key in lookup:
                existing = lookup[key]
                is_improvement = False
                if ex.example_type == "kata" and existing.get("_type") != "kata":
                    is_improvement = True
                elif ex.grade == Grade.A and existing.get("_grade") != "A":
                    is_improvement = True

                if is_improvement:
                    lookup[key] = new_data
                    updated_count += 1
            else:
                lookup[key] = new_data
                added_count += 1

        final_list = []
        for val in lookup.values():
            final_list.append({k: v for k, v in val.items() if not k.startswith("_")})

        with open(self.alpaca_path, "w") as f:
            json.dump(final_list, f, indent=2)

        return added_count, updated_count

    def load_master_dpo(self) -> List[Dict[str, Any]]:
        """Load current master DPO pairs."""
        if not self.dpo_path.exists():
            return []
        pairs = []
        try:
            with open(self.dpo_path, "r") as f:
                for line in f:
                    if line.strip():
                        pairs.append(json.loads(line))
        except Exception:
            pass
        return pairs

    def sync_dpo(self, new_pairs: List[Any]):
        """Merge new DPO pairs, avoiding exact duplicates."""
        master = self.load_master_dpo()
        existing_keys = {f"{p['prompt']}|{p['chosen']}|{p['rejected']}" for p in master}

        added_count = 0
        for p_obj in new_pairs:
            p = p_obj.to_dict() if hasattr(p_obj, "to_dict") else p_obj
            key = f"{p['prompt']}|{p['chosen']}|{p['rejected']}"
            if key not in existing_keys:
                master.append(p)
                added_count += 1
                existing_keys.add(key)

        with open(self.dpo_path, "w") as f:
            for p in master:
                f.write(json.dumps(p) + "\n")
        return added_count

    def sync_discovery(self, new_examples: List[TrainingExample]):
        """Store all exploration attempts in the discovery warehouse."""
        if not self.discovery_path.exists():
            open(self.discovery_path, "w").close()

        added_count = 0
        with open(self.discovery_path, "a", encoding="utf-8") as f:
            for ex in new_examples:
                f.write(json.dumps(ex.to_dict(), ensure_ascii=False) + "\n")
                added_count += 1
        return added_count
