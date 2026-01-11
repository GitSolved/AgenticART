"""
Dojo Orchestrator

The 'Grand Loop' that manages the end-to-end execution of a Dojo challenge:
1. Load Challenge
2. Reset Device
3. Deploy Target (APK)
4. Run Student (Challenger)
5. Evaluate Performance (Sensei)
6. Reset & Cleanup
"""

import logging
from pathlib import Path

from dojo.curriculum.challenger import Challenger
from dojo.curriculum.loader import UnifiedCurriculum
from dojo.infrastructure.device_manager import DeviceManager
from dojo.models import Belt
from dojo.sensei.sensei import Sensei

logger = logging.getLogger(__name__)

class DojoOrchestrator:
    """Orchestrates live-fire challenges on physical/virtual devices."""

    def __init__(
        self,
        challenger: Challenger,
        sensei: Sensei,
        device_manager: DeviceManager,
        targets_dir: Path
    ):
        self.challenger = challenger
        self.sensei = sensei
        self.device_manager = device_manager
        self.targets_dir = Path(targets_dir)

    def run_live_challenge(self, challenge_id: str, apk_name: str, model_id: str):
        """Runs a single challenge against a live device."""
        print(f"--- Running Live Challenge: {challenge_id} ---")

        # 1. Prepare Device
        if not self.device_manager.ensure_ready():
            return None

        self.device_manager.reset_environment()

        # 2. Deploy Target
        apk_path = self.targets_dir / apk_name
        if not self.device_manager.deploy_target(apk_path):
            return None

        # 3. Run Student Attempt
        # We fetch the challenge definition from the loader
        curriculum = UnifiedCurriculum.load()
        challenge = curriculum.load_challenge(challenge_id)

        print(f"Running model {model_id}...")
        # Note: Challenger expects V1 Challenge, but we are passing V2 Challenge.
        # This requires Challenger to be updated or type-ignored for now.
        session = self.challenger.run_challenge(challenge) # type: ignore

        # 4. Grade Attempt
        print("Evaluating performance via Sensei...")
        assessment, _ = self.sensei.evaluate_session(session, model_id)

        # 5. Cleanup
        # Extract package name from vars if possible, or use a mapping
        # For now, let's assume the APK name corresponds to the package roughly
        # In a real setup, we'd have this in the challenge metadata

        return assessment

    def run_belt_exam(self, belt: Belt, model_id: str):
        """Runs all challenges for a belt as a single exam session."""
        curriculum = UnifiedCurriculum.load()

        # Get challenges for this belt
        challenge_ids = []
        for stage in curriculum.stages_in_order():
            if stage.belt == belt:
                challenge_ids.extend(stage.challenge_ids)

        challenges = []
        for cid in challenge_ids:
            try:
                challenges.append(curriculum.load_challenge(cid))
            except Exception:
                continue

        results = []
        for challenge in challenges:
            # Map challenge ID to APK (this should be in the challenge metadata ideally)
            # Placeholder mapping for V2 pillar-based challenges
            apk_map = {
                "method_observe_white_001": "exam_target_alpha.apk",
                "static_basic_white_001": "exam_target_beta.apk",
                "neg_secure_white_001": "exam_target_gamma.apk",
                "neg_secure_white_002": "exam_target_delta.apk",
                "taxonomy_basic_white_001": "exam_target_epsilon.apk",
            }
            apk_name = apk_map.get(challenge.id, "target.apk")

            res = self.run_live_challenge(challenge.id, apk_name, model_id)
            if res:
                results.append(res)

        return results
