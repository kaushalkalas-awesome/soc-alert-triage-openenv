# Copyright (c) 2026. All rights reserved.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""SOC Alert Triage Environment - Server-Side Game Logic.

This is the environment implementation that runs on the server.
It contains the game logic, state management, and reward calculation.
"""

from __future__ import annotations

import random
import uuid
from dataclasses import asdict
from typing import Any, Dict, List, Optional

try:
    from openenv.core.env_server import Environment
except ImportError:
    # Fallback if openenv not available
    class Environment:
        pass

from .graders import grade_easy, grade_hard, grade_medium
from .models import SocAlertAction, SocAlertObservation, SocAlertState
from .utils import AlertCase, build_case_bank, task_to_levels


class SocAlertTriageEnvironment(Environment):
    """
    SOC Alert Triage Environment - Server Implementation.

    Simulates a real SOC analyst workflow for alert triage with:
    - Alert classification (TP/FP/Benign/NeedsMoreData)
    - Severity assignment
    - Response action selection

    Inherits from openenv.core.env_server.Environment for framework integration.
    """

    SUPPORTS_CONCURRENT_SESSIONS = True

    def __init__(self) -> None:
        """Initialize the environment."""
        self.task_name: str = "task_easy_verdict"
        self.rng: random.Random = random.Random(42)
        self.case_bank: List[AlertCase] = build_case_bank()
        self.current_case: Optional[AlertCase] = None
        self.steps: int = 0
        self.max_steps: int = 1
        self.episode_id: Optional[str] = None
        self.allowed_levels: List[str] = []

    def _set_task(self, task_name: str = "task_easy_verdict") -> None:
        """Set the task and update allowed difficulty levels."""
        self.task_name = task_name
        self.allowed_levels = task_to_levels(task_name)

    def _sample_case(self) -> AlertCase:
        """Sample a random alert case from the dataset."""
        pool = [c for c in self.case_bank if c.task_level in self.allowed_levels]
        if not pool:
            raise RuntimeError("No dataset cases available for selected task")
        return self.rng.choice(pool)

    def _observe(self, case: AlertCase) -> Dict[str, Any]:
        """Convert an alert case to observation dict."""
        return {
            "alert_id": case.alert_id,
            "task_name": self.task_name,
            "state": {
                "ip": case.ip,
                "user": case.user,
                "activity": case.activity,
                "event_time": case.event_time,
                "threat_intel": case.threat_intel,
                "behavior_pattern": case.behavior_pattern,
            },
            "expected_action_schema": {
                "verdict": "TP|FP|Benign|NeedsMoreData",
                "severity": "critical|high|medium|low",
                "response_action": "block|isolate|escalate|ignore",
            },
        }

    def reset(
        self, seed: Optional[int] = None, episode_id: Optional[str] = None, **kwargs
    ) -> SocAlertObservation:
        """
        Reset environment and return initial observation.

        Args:
            seed: Random seed for reproducibility
            episode_id: Optional episode identifier
            **kwargs: May include task_name for setting the task

        Returns:
            SocAlertObservation: Initial observation for the episode
        """
        if seed is not None:
            self.rng = random.Random(seed)

        # Set task from kwargs if provided
        task_name = kwargs.get("task_name", "task_easy_verdict")
        self._set_task(task_name)

        self.episode_id = episode_id or str(uuid.uuid4())
        self.steps = 0
        self.current_case = self._sample_case()

        obs_dict = self._observe(self.current_case)
        return SocAlertObservation(
            alert_id=obs_dict["alert_id"],
            task_name=obs_dict["task_name"],
            state=obs_dict["state"],
            expected_action_schema=obs_dict["expected_action_schema"],
        )

    def step(
        self, action: SocAlertAction | Dict[str, str], **kwargs
    ) -> SocAlertObservation:
        """
        Execute one environment step.

        Args:
            action: Agent's action (dict or SocAlertAction)
            **kwargs: Additional parameters

        Returns:
            SocAlertObservation: Observation after step, with reward and done signal
        """
        if self.current_case is None:
            raise RuntimeError("Call reset() before step().")

        # Handle both Pydantic model and dict inputs
        if isinstance(action, SocAlertAction):
            action_dict = action.model_dump()
        else:
            action_dict = action

        self.steps += 1
        truth = asdict(self.current_case)

        # Grade the action based on task
        if self.task_name == "task_easy_verdict":
            reward = grade_easy(action_dict, truth)
        elif self.task_name == "task_medium_verdict_severity":
            reward = grade_medium(action_dict, truth)
        elif self.task_name == "task_hard_full_triage":
            reward = grade_hard(action_dict, truth)
        else:
            raise ValueError(f"Unsupported task: {self.task_name}")

        terminated = self.steps >= self.max_steps

        obs_dict = self._observe(self.current_case)
        obs = SocAlertObservation(
            alert_id=obs_dict["alert_id"],
            task_name=obs_dict["task_name"],
            state=obs_dict["state"],
            expected_action_schema=obs_dict["expected_action_schema"],
            reward=float(reward),
            done=terminated,
        )

        return obs

    @property
    def state(self) -> SocAlertState:
        """Return current episode state."""
        return SocAlertState(
            task_name=self.task_name,
            steps=self.steps,
            max_steps=self.max_steps,
            current_case=asdict(self.current_case) if self.current_case else None,
        )
