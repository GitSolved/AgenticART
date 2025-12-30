"""
Hybrid Challenger - implements tiered escalation logic.

Workflow:
1. Turn 1 (Basic): Try the obvious one-liner.
2. If Turn 1 fails: Use ErrorExtractor logic to decide if ReAct is needed.
3. If reasoning is needed: Handover to ReActChallenger for subsequent turns.
"""

from __future__ import annotations

from datetime import datetime
from typing import Callable, Optional

from dojo.curriculum.challenger import Challenger, ChallengeSession
from dojo.models import Challenge
from dojo.react_challenger import ReActChallenger


class HybridChallenger:
    def __init__(
        self,
        basic_challenger: Challenger,
        react_challenger: ReActChallenger,
        on_transition: Optional[Callable[[str], None]] = None,
    ):
        self.basic = basic_challenger
        self.react = react_challenger
        self.on_transition = on_transition

    def run_challenge(self, challenge: Challenge, model_id: str = "") -> ChallengeSession:
        """Run a challenge using tiered escalation logic."""
        print("  [HYBRID] Starting Turn 1 with BASIC challenger...")

        # 1. Run exactly 1 basic attempt
        original_max_retries = self.basic.max_retries
        self.basic.max_retries = 1
        session = self.basic.run_challenge(challenge)
        self.basic.max_retries = original_max_retries

        # If success, we are done
        if session.final_success:
            return session

        # 2. Analyze failure
        last_attempt = session.attempts[-1]
        error_ctx = last_attempt.error_context

        if not error_ctx:
            # Fallback extraction if it failed
            error_ctx = self.basic.error_extractor.extract(
                last_attempt.execution_result, last_attempt.model_output
            )

        # 3. Decision: Escalate?
        should_escalate = self.basic.error_extractor.should_escalate_to_react(error_ctx)

        if should_escalate:
            if self.on_transition:
                self.on_transition(f"Escalating to ReAct due to: {error_ctx.error_type}")
            print(
                f"  [HYBRID] Escalation triggered: {error_ctx.error_type}. Starting ReAct loop..."
            )

            # Start ReAct challenger
            # Note: We keep the history of the first failed attempt in the session record
            react_session = self.react.run_challenge(challenge, model_id=model_id)

            # Merge the sessions
            # Prepend the basic attempt to the react attempts
            all_attempts = session.attempts + react_session.attempts

            # Re-index attempt numbers
            for i, att in enumerate(all_attempts):
                att.attempt_number = i + 1

            return ChallengeSession(
                challenge=challenge,
                attempts=all_attempts,
                started_at=session.started_at,
                completed_at=datetime.now(),
            )
        else:
            print("  [HYBRID] No escalation needed. Retrying with Basic...")
            # If not escalating, finish the remaining basic attempts
            # We already used 1, so we do max_retries - 1 more
            remaining = original_max_retries - 1
            if remaining > 0:
                self.basic.max_retries = remaining
                second_session = self.basic.run_challenge(challenge)
                self.basic.max_retries = original_max_retries

                # Merge sessions
                all_attempts = session.attempts + second_session.attempts
                for i, att in enumerate(all_attempts):
                    att.attempt_number = i + 1

                return ChallengeSession(
                    challenge=challenge,
                    attempts=all_attempts,
                    started_at=session.started_at,
                    completed_at=datetime.now(),
                )

        return session
