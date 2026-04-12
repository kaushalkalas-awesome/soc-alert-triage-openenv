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

try:
    from .graders import grade_easy, grade_hard, grade_medium
    from .utils import AlertCase, TASK_MAX_STEPS, generate_case, task_to_levels
except ImportError:
    from graders import grade_easy, grade_hard, grade_medium
    from utils import AlertCase, TASK_MAX_STEPS, generate_case, task_to_levels

try:
    from ..models import SocAlertAction, SocAlertObservation, SocAlertState
except ImportError as e:
    if "relative import" not in str(e) and "no known parent package" not in str(e):
        raise
    from models import SocAlertAction, SocAlertObservation, SocAlertState


class SocAlertTriageEnvironment(Environment):
    """
    SOC Alert Triage Environment - Server Implementation.

    Simulates a real SOC analyst workflow for alert triage with:
    - Alert classification (TP/FP/Benign/NeedsMoreData)
    - Severity assignment
    - Response action selection

    Supports multi-step episodes where the agent can refine its
    triage decision across steps with progressive feedback.

    Inherits from openenv.core.env_server.Environment for framework integration.
    """

    SUPPORTS_CONCURRENT_SESSIONS = True

    def __init__(self) -> None:
        """Initialize the environment."""
        super().__init__()
        self.task_name: str = "task_easy_verdict"
        self.rng: random.Random = random.Random(42)
        self.current_case: Optional[AlertCase] = None
        self.steps: int = 0
        self.max_steps: int = 1
        self.episode_id: Optional[str] = None
        self.allowed_levels: List[str] = []
        self.last_reward: float = 0.0
        self.last_feedback: str = ""
        self.best_reward: float = 0.0
        self.tool_logs: List[str] = []

    def _set_task(self, task_name: str = "task_easy_verdict") -> None:
        """Set the task and update allowed difficulty levels and max steps."""
        self.task_name = task_name
        self.allowed_levels = task_to_levels(task_name)
        self.max_steps = TASK_MAX_STEPS.get(task_name, 1)

    def _sample_case(self) -> AlertCase:
        """Generate a random alert case procedurally."""
        return generate_case(self.rng, self.allowed_levels)

    def _observe(self, case: AlertCase, include_feedback: bool = False) -> Dict[str, Any]:
        """Convert an alert case to observation dict.

        For multi-step episodes, intermediate steps include feedback
        from the previous attempt so the agent can self-correct.
        """
        obs: Dict[str, Any] = {
            "alert_id": case.alert_id,
            "task_name": self.task_name,
            "state": {
                "ip": case.ip,
                "user": case.user,
                "activity": case.activity,
                "event_time": case.event_time,
                "threat_intel": case.threat_intel,
                "behavior_pattern": case.behavior_pattern,
                "tool_history": self.tool_logs,
            },
            "expected_action_schema": {
                "verdict": "TP|FP|Benign|NeedsMoreData",
                "severity": "critical|high|medium|low",
                "response_action": "block|isolate|escalate|ignore",
                "tool_name": "query_threat_intel|check_user_history|analyze_payload",
            },
        }
        if include_feedback and self.last_feedback:
            obs["feedback"] = self.last_feedback
            obs["previous_reward"] = self.last_reward
            obs["step_number"] = self.steps
            obs["steps_remaining"] = self.max_steps - self.steps
        return obs

    def _execute_tool(self, tool_name: str, tool_query: str) -> str:
        """Mock tool execution for information gathering."""
        truth = asdict(self.current_case) if self.current_case else {}
        
        if tool_name == "query_threat_intel":
            return f"Intel for {tool_query}: {truth.get('threat_intel', 'Unknown')}"
        elif tool_name == "check_user_history":
            return f"History for {tool_query}: User profile matches observed activity: {truth.get('expected_verdict', 'Unknown') == 'Benign'}"
        elif tool_name == "analyze_payload":
            return f"Analysis on {tool_query}: Payload characteristic suggests: {truth.get('expected_severity', 'Unknown')} severity threat."
            
        return f"Tool {tool_name} is not recognized or failed to execute."

    def _generate_feedback(self, action_dict: Dict[str, str], reward: float) -> str:
        """Generate human-readable feedback for multi-step self-correction."""
        if reward >= 1.0:
            return "Perfect score — your triage is correct."

        hints = []
        truth = asdict(self.current_case) if self.current_case else {}

        # Verdict feedback
        if action_dict.get("verdict", "").lower() != truth.get("expected_verdict", "").lower():
            hints.append(
                f"Your verdict '{action_dict.get('verdict', '')}' may not be correct. "
                "Re-examine the threat intelligence and behavior pattern."
            )

        # Severity feedback (for medium/hard tasks)
        if self.task_name != "task_easy_verdict":
            if action_dict.get("severity", "").lower() != truth.get("expected_severity", "").lower():
                hints.append(
                    f"Severity '{action_dict.get('severity', '')}' seems off. "
                    "Consider the threat intel confidence level and impact scope."
                )

        # Response action feedback (for hard tasks)
        if self.task_name == "task_hard_full_triage":
            if action_dict.get("response_action", "").lower() != truth.get("expected_action", "").lower():
                hints.append(
                    f"Response action '{action_dict.get('response_action', '')}' could be improved. "
                    "Match the action to the severity and urgency of the threat."
                )

        if not hints:
            return f"Close but not perfect (reward: {reward:.2f}). Review your assessment."
        return " | ".join(hints)

    def reset(
        self, seed: Optional[int] = None, episode_id: Optional[str] = None, **kwargs
    ) -> SocAlertObservation:
        """
        Reset environment and return initial observation.
        """
        if seed is not None:
            self.rng = random.Random(seed)

        task_name = kwargs.get("task_name", "task_easy_verdict")
        self._set_task(task_name)

        self.episode_id = episode_id or str(uuid.uuid4())
        self.steps = 0
        self.last_reward = 0.0
        self.last_feedback = ""
        self.best_reward = 0.0
        self.tool_logs = []
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
        """
        if self.current_case is None:
            raise RuntimeError("Call reset() before step().")

        if isinstance(action, SocAlertAction):
            action_dict = action.model_dump(exclude_unset=True)
        else:
            action_dict = action

        self.steps += 1
        
        # Tool execution branch
        tool_name = action_dict.get("tool_name")
        if tool_name:
            tool_query = action_dict.get("tool_query", "")
            result = self._execute_tool(tool_name, tool_query)
            self.tool_logs.append(f"Used {tool_name}({tool_query}) -> {result}")
            
            terminated = self.steps >= self.max_steps
            obs_dict = self._observe(
                self.current_case,
                include_feedback=False,
            )
            return SocAlertObservation(
                alert_id=obs_dict["alert_id"],
                task_name=obs_dict["task_name"],
                state=obs_dict["state"],
                expected_action_schema=obs_dict["expected_action_schema"],
                reward=float(self.best_reward),
                done=terminated,
            )

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

        self.best_reward = max(self.best_reward, reward)
        self.last_reward = reward

        terminated = self.steps >= self.max_steps
        is_perfect = reward >= 0.99  # Allow float precision tolerance

        # Generate feedback for non-final, non-perfect steps
        if not terminated and not is_perfect:
            self.last_feedback = self._generate_feedback(action_dict, reward)
        else:
            self.last_feedback = ""

        final_reward = self.best_reward if terminated else reward

        obs_dict = self._observe(
            self.current_case,
            include_feedback=(not terminated and not is_perfect),
        )
        return SocAlertObservation(
            alert_id=obs_dict["alert_id"],
            task_name=obs_dict["task_name"],
            state=obs_dict["state"],
            expected_action_schema=obs_dict["expected_action_schema"],
            reward=float(final_reward),
            done=terminated or is_perfect,
        )

    @property
    def state(self) -> SocAlertState:
        """Return current episode state."""
        return SocAlertState(
            task_name=self.task_name,
            steps=self.steps,
            max_steps=self.max_steps,
            current_case=asdict(self.current_case) if self.current_case else None,
        )
