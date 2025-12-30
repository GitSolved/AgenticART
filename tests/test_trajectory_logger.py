"""Tests for trajectory_logger.py quality filtering logic."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from dojo.trajectory_logger import TrajectoryLogger
from dojo.trajectory_schema import (
    Trajectory,
)


class TestIsHighQuality:
    """Tests for the is_high_quality method."""

    def test_success_always_passes(self, successful_trajectory: Trajectory):
        """Successful trajectories are always high quality."""
        logger = TrajectoryLogger(output_dir=tempfile.mkdtemp())
        assert logger.is_high_quality(successful_trajectory) is True

    def test_filters_short_trajectories(self, failed_trajectory_short: Trajectory):
        """Trajectories with < 2 steps are filtered out."""
        logger = TrajectoryLogger(output_dir=tempfile.mkdtemp())
        assert logger.is_high_quality(failed_trajectory_short) is False

    def test_filters_retry_loops(self, failed_trajectory_retry_loop: Trajectory):
        """Trajectories with consecutive identical commands are filtered."""
        logger = TrajectoryLogger(output_dir=tempfile.mkdtemp())
        assert (
            logger.is_high_quality(
                failed_trajectory_retry_loop,
                max_consecutive_failures=2,
            )
            is False
        )

    def test_allows_strategy_pivots(self, failed_trajectory_with_pivot: Trajectory):
        """Failed trajectories with strategy pivots are high quality."""
        logger = TrajectoryLogger(output_dir=tempfile.mkdtemp())
        assert logger.is_high_quality(failed_trajectory_with_pivot) is True

    def test_filters_low_diversity(self, failed_trajectory_low_diversity: Trajectory):
        """Trajectories with low action diversity are filtered."""
        logger = TrajectoryLogger(output_dir=tempfile.mkdtemp())
        # 2 unique commands out of 5 = 40% diversity, below 70% threshold
        assert (
            logger.is_high_quality(
                failed_trajectory_low_diversity,
                min_action_diversity=0.7,
            )
            is False
        )


class TestGetHighQualityTrajectories:
    """Tests for filtering trajectory collections."""

    def test_filters_collection(
        self,
        successful_trajectory: Trajectory,
        failed_trajectory_short: Trajectory,
        failed_trajectory_with_pivot: Trajectory,
    ):
        """get_high_quality_trajectories correctly filters a collection."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = TrajectoryLogger(output_dir=tmpdir, auto_save=False)
            # Manually add trajectories
            logger._trajectories = [
                successful_trajectory,
                failed_trajectory_short,
                failed_trajectory_with_pivot,
            ]

            high_quality = logger.get_high_quality_trajectories()

            assert len(high_quality) == 2
            assert successful_trajectory in high_quality
            assert failed_trajectory_with_pivot in high_quality
            assert failed_trajectory_short not in high_quality


class TestExportHighQualityTrainingData:
    """Tests for exporting filtered training data."""

    def test_exports_only_high_quality(
        self,
        successful_trajectory: Trajectory,
        failed_trajectory_short: Trajectory,
    ):
        """export_high_quality_training_data only includes high-quality trajectories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = TrajectoryLogger(output_dir=tmpdir, auto_save=False)
            logger._trajectories = [
                successful_trajectory,
                failed_trajectory_short,
            ]

            filepath = logger.export_high_quality_training_data()

            assert filepath.exists()
            with open(filepath) as f:
                lines = f.readlines()

            # Only successful trajectory should be exported
            assert len(lines) == 1
            data = json.loads(lines[0])
            assert data["challenge_id"] == "white_001"


class TestGetQualityStatistics:
    """Tests for quality statistics."""

    def test_empty_trajectories(self):
        """Empty trajectory list returns count 0."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = TrajectoryLogger(output_dir=tmpdir)
            stats = logger.get_quality_statistics()
            assert stats["count"] == 0

    def test_calculates_quality_rate(
        self,
        successful_trajectory: Trajectory,
        failed_trajectory_short: Trajectory,
        failed_trajectory_with_pivot: Trajectory,
    ):
        """Quality statistics correctly calculate quality rate."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = TrajectoryLogger(output_dir=tmpdir, auto_save=False)
            logger._trajectories = [
                successful_trajectory,
                failed_trajectory_short,
                failed_trajectory_with_pivot,
            ]

            stats = logger.get_quality_statistics()

            assert stats["total"] == 3
            assert stats["high_quality"] == 2
            assert stats["low_quality"] == 1
            assert stats["quality_rate"] == pytest.approx(2 / 3)


class TestTrajectoryLogging:
    """Tests for the trajectory logging context manager."""

    def test_start_trajectory_context_manager(self):
        """Trajectory context manager properly creates and saves trajectories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = TrajectoryLogger(output_dir=tmpdir, auto_save=True)

            with logger.start_trajectory(
                challenge_id="test_001",
                challenge_name="Test Challenge",
                belt="white",
                objective="Test objective",
                device_context={"test": True},
                hints=["hint1"],
                model_id="test-model",
            ) as traj:
                traj.log_initial_thought("Initial analysis")

            # Check trajectory was saved
            saved_files = list(Path(tmpdir).glob("traj_*.json"))
            assert len(saved_files) == 1

            with open(saved_files[0]) as f:
                data = json.load(f)

            assert data["challenge_id"] == "test_001"
            assert data["initial_thought"]["content"] == "Initial analysis"

    def test_step_context_manager(self):
        """Step context manager properly builds steps."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = TrajectoryLogger(output_dir=tmpdir, auto_save=False)

            with logger.start_trajectory(
                challenge_id="test_002",
                challenge_name="Test",
                belt="white",
                objective="Test",
            ) as traj:
                with traj.step() as step:
                    step.think("Testing thought")
                    step.act("adb_shell", "shell test command")
                    step.observe(stdout="output", exit_code=0)
                    step.reflect("It worked")

            # Check step was recorded
            trajectory = logger._trajectories[0]
            assert len(trajectory.steps) == 1
            assert trajectory.steps[0].thought.content == "Testing thought"
            assert trajectory.steps[0].action.command == "shell test command"
            assert trajectory.steps[0].observation.stdout == "output"
            assert trajectory.steps[0].reflection.what_happened == "It worked"


class TestGetStatistics:
    """Tests for general statistics."""

    def test_success_rate_calculation(
        self,
        successful_trajectory: Trajectory,
        failed_trajectory_short: Trajectory,
    ):
        """Statistics correctly calculate success rate."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = TrajectoryLogger(output_dir=tmpdir, auto_save=False)
            logger._trajectories = [
                successful_trajectory,
                failed_trajectory_short,
            ]

            stats = logger.get_statistics()

            assert stats["count"] == 2
            assert stats["success_rate"] == 0.5
            assert stats["total_steps"] == 2  # 1 step each
