# Copyright (c) 2026. All rights reserved.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""SOC Alert Triage Environment - Server-Side Game Logic.

This is the environment implementation that runs on the server.
It contains the game logic, state management, and reward calculation.

NEW CREATIVE FEATURES:
- Escalation Budget: Human-in-the-loop mechanic with limited escalations
- Confidence Calibration: Agents must be calibrated in their confidence scores
- Attack Campaigns: Progressive multi-alert attack scenarios
- Explainability: Reasoning output for decision transparency
"""

from __future__ import annotations

import math
import random
import uuid
from dataclasses import asdict
from typing import Any, Dict, List, Optional, Tuple

try:
    from openenv.core.env_server import Environment
except ImportError:
    # Fallback if openenv not available
    class Environment:
        pass

try:
    from .campaigns import CampaignManager, get_campaign_for_task
    from .graders import grade_easy, grade_hard, grade_medium, calculate_calibration_score
    from .utils import AlertCase, TASK_MAX_STEPS, generate_case, task_to_levels
except ImportError:
    from campaigns import CampaignManager, get_campaign_for_task
    from graders import grade_easy, grade_hard, grade_medium, calculate_calibration_score
    from utils import AlertCase, TASK_MAX_STEPS, generate_case, task_to_levels

try:
    from ..models import SocAlertAction, SocAlertObservation, SocAlertState
except ImportError as e:
    if "relative import" not in str(e) and "no known parent package" not in str(e):
        raise
    from models import SocAlertAction, SocAlertObservation, SocAlertState


class SocAlertTriageEnvironment(Environment):
    """
    SOC Alert Triage Environment - Server Implementation with Creative Mechanics.

    Simulates a real SOC analyst workflow with novel features:
    - Escalation Budget: Limited human analyst access (human-in-the-loop)
    - Confidence Calibration: Agents must be well-calibrated
    - Attack Campaigns: Progressive multi-alert scenarios
    - Explainability: Required reasoning output

    Inherits from openenv.core.env_server.Environment for framework integration.
    """

    SUPPORTS_CONCURRENT_SESSIONS = True

    # NEW: Escalation budget per task difficulty
    ESCALATION_BUDGET = {
        "task_easy_verdict": 0,  # No escalation needed for easy
        "task_medium_verdict_severity": 1,  # 1 escalation allowed
        "task_hard_full_triage": 2,  # 2 escalations allowed
    }

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
        
        # NEW: Escalation tracking
        self.escalation_budget: int = 0
        self.escalation_used: int = 0
        
        # NEW: Confidence calibration tracking
        self.confidence_history: List[float] = []
        self.accuracy_history: List[bool] = []
        
        # NEW: Campaign tracking
        self.campaign_manager: Optional[CampaignManager] = None
        self.alert_number: int = 0
        self.total_alerts_in_campaign: int = 1

    def _set_task(self, task_name: str = "task_easy_verdict") -> None:
        """Set the task and update allowed difficulty levels and max steps."""
        self.task_name = task_name
        self.allowed_levels = task_to_levels(task_name)
        self.max_steps = TASK_MAX_STEPS.get(task_name, 1)
        self.escalation_budget = self.ESCALATION_BUDGET.get(task_name, 0)

    def _sample_case(self) -> AlertCase:
        """Generate a random alert case procedurally."""
        # For campaign mode, get next alert from campaign
        if self.campaign_manager and self.campaign_manager.has_more_alerts():
            return self.campaign_manager.get_next_alert()
        
        # Enable correlation mode for hard tasks (30% chance)
        use_correlation = self.task_name == "task_hard_full_triage"
        return generate_case(self.rng, self.allowed_levels, use_correlation=use_correlation)

    def _observe(self, case: AlertCase, include_feedback: bool = False) -> Dict[str, Any]:
        """Convert an alert case to observation dict."""
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
                "reasoning": "str - explanation for the decision",
                "confidence": "float - 0.0 to 1.0 confidence score",
                "escalate_to_human": "bool - request human analyst",
            },
        }
        
        # NEW: Episode progress info
        obs["episode_info"] = {
            "alert_number": self.alert_number,
            "total_alerts": self.total_alerts_in_campaign,
            "escalation_budget_remaining": self.escalation_budget - self.escalation_used,
            "escalation_budget_total": self.escalation_budget,
        }
        
        # Include correlated alerts for hard task scenarios
        if case.related_alerts:
            obs["state"]["related_alerts"] = case.related_alerts
            obs["state"]["correlation_context"] = (
                "This alert is part of a correlated attack pattern. "
                "Consider all related alerts when making your triage decision."
            )
        
        # Include time pressure indicator for alert fatigue simulation
        if case.time_pressure:
            obs["state"]["time_pressure_seconds"] = case.time_pressure
            obs["state"]["alert_fatigue_warning"] = (
                f"HIGH PRIORITY: Time-sensitive alert. "
                f"Recommend decision within {case.time_pressure} seconds."
            )
        
        # NEW: Campaign context
        if self.campaign_manager and self.campaign_manager.is_active:
            obs["state"]["campaign_context"] = self.campaign_manager.get_context()
        
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

    def _calculate_confidence_penalty(self, confidence: float, is_correct: bool) -> float:
        """Calculate penalty for poor confidence calibration.
        
        Agents should be:
        - High confidence (>0.8) when correct
        - Low confidence (<0.5) when incorrect
        """
        if confidence is None:
            return 0.0  # No confidence provided, no penalty
            
        if is_correct and confidence < 0.5:
            # Underconfident when correct
            return -0.1 * (0.5 - confidence)
        elif not is_correct and confidence > 0.7:
            # Overconfident when wrong
            return -0.15 * (confidence - 0.7)
        elif is_correct and confidence > 0.8:
            # Well calibrated and confident
            return 0.05
        
        return 0.0

    def _handle_escalation(self) -> Tuple[float, bool]:
        """Handle escalation to human analyst.
        
        Returns:
            (reward, done): Reward for escalation and whether episode ends
        """
        if self.escalation_used >= self.escalation_budget:
            # No budget left - major penalty
            return -0.5, True
        
        self.escalation_used += 1
        
        # Escalation provides ground truth but with lower reward
        # This models real SOC where escalation gets answer but costs human time
        truth = asdict(self.current_case) if self.current_case else {}
        expected_verdict = truth.get("expected_verdict", "")
        
        # Reward based on appropriateness of escalation
        if expected_verdict in ["NeedsMoreData", "TP"]:
            # Good escalation - ambiguous or true threat
            return 0.4, True
        else:
            # Unnecessary escalation - could have handled autonomously
            return 0.2, True

    def _generate_feedback(self, action_dict: Dict[str, str], reward: float, 
                          confidence: Optional[float] = None, 
                          calibration_penalty: float = 0.0) -> str:
        """Generate human-readable feedback for multi-step self-correction."""
        if reward >= 0.99:
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
        
        # NEW: Confidence calibration feedback
        if calibration_penalty < -0.05:
            if confidence and confidence > 0.7:
                hints.append("You were overconfident in an incorrect decision.")
            elif confidence and confidence < 0.5:
                hints.append("You were underconfident in a correct decision.")

        if not hints:
            return f"Close but not perfect (reward: {reward:.2f}). Review your assessment."
        return " | ".join(hints)

    def reset(
        self, seed: Optional[int] = None, episode_id: Optional[str] = None, **kwargs
    ) -> SocAlertObservation:
        """
        Reset environment and return initial observation.
        
        NEW: Supports campaign mode for progressive attack scenarios.
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
        
        # NEW: Reset escalation tracking
        self.escalation_used = 0
        
        # NEW: Reset confidence tracking
        self.confidence_history = []
        self.accuracy_history = []
        
        # NEW: Initialize campaign for hard tasks (50% chance)
        self.campaign_manager = None
        self.alert_number = 1
        self.total_alerts_in_campaign = 1
        
        if task_name == "task_hard_full_triage" and self.rng.random() < 0.5:
            self.campaign_manager = get_campaign_for_task(self.rng)
            self.total_alerts_in_campaign = self.campaign_manager.total_alerts
        
        self.current_case = self._sample_case()

        obs_dict = self._observe(self.current_case)
        return SocAlertObservation(
            alert_id=obs_dict["alert_id"],
            task_name=obs_dict["task_name"],
            state=obs_dict["state"],
            expected_action_schema=obs_dict["expected_action_schema"],
            episode_info=obs_dict.get("episode_info"),
        )

    def step(
        self, action: SocAlertAction | Dict[str, str], **kwargs
    ) -> SocAlertObservation:
        """
        Execute one environment step.
        
        NEW: Handles escalation, confidence calibration, and explainability.
        """
        if self.current_case is None:
            raise RuntimeError("Call reset() before step().")

        if isinstance(action, SocAlertAction):
            action_dict = action.model_dump(exclude_unset=True)
        else:
            action_dict = action

        self.steps += 1
        
        # NEW: Handle escalation action
        if action_dict.get("escalate_to_human"):
            reward, done = self._handle_escalation()
            self.best_reward = max(self.best_reward, reward)
            self.last_reward = reward
            
            obs_dict = self._observe(self.current_case)
            return SocAlertObservation(
                alert_id=obs_dict["alert_id"],
                task_name=obs_dict["task_name"],
                state=obs_dict["state"],
                expected_action_schema=obs_dict["expected_action_schema"],
                reward=float(reward),
                done=done,
                episode_info=obs_dict.get("episode_info"),
            )
        
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
                episode_info=obs_dict.get("episode_info"),
            )

        truth = asdict(self.current_case)

        # Grade the action based on task
        if self.task_name == "task_easy_verdict":
            base_reward = grade_easy(action_dict, truth)
        elif self.task_name == "task_medium_verdict_severity":
            base_reward = grade_medium(action_dict, truth)
        elif self.task_name == "task_hard_full_triage":
            base_reward = grade_hard(action_dict, truth)
        else:
            raise ValueError(f"Unsupported task: {self.task_name}")

        # NEW: Calculate correctness for confidence calibration
        is_correct = base_reward >= 0.8
        
        # NEW: Track confidence and accuracy
        confidence = action_dict.get("confidence")
        if confidence is not None:
            self.confidence_history.append(confidence)
            self.accuracy_history.append(is_correct)
        
        # NEW: Calculate confidence calibration penalty/bonus
        calibration_adjustment = self._calculate_confidence_penalty(confidence, is_correct)
        
        # NEW: Explainability bonus (if reasoning provided)
        explainability_bonus = 0.0
        if action_dict.get("reasoning") and len(action_dict.get("reasoning", "")) > 20:
            explainability_bonus = 0.02  # Small bonus for providing reasoning
        
        # Calculate final reward
        reward = base_reward + calibration_adjustment + explainability_bonus
        reward = max(0.01, min(0.99, reward))  # Clamp to valid range

        self.best_reward = max(self.best_reward, reward)
        self.last_reward = reward

        terminated = self.steps >= self.max_steps
        is_perfect = base_reward >= 0.99  # Base reward must be perfect

        # Generate feedback for non-final, non-perfect steps
        if not terminated and not is_perfect:
            self.last_feedback = self._generate_feedback(
                action_dict, base_reward, confidence, calibration_adjustment
            )
        else:
            self.last_feedback = ""

        final_reward = self.best_reward if terminated else reward

        obs_dict = self._observe(
            self.current_case,
            include_feedback=(not terminated and not is_perfect),
        )
        
        # Check if campaign continues
        episode_done = terminated or is_perfect
        
        return SocAlertObservation(
            alert_id=obs_dict["alert_id"],
            task_name=obs_dict["task_name"],
            state=obs_dict["state"],
            expected_action_schema=obs_dict["expected_action_schema"],
            reward=float(final_reward),
            done=episode_done,
            episode_info=obs_dict.get("episode_info"),
        )

    @property
    def state(self) -> SocAlertState:
        """Return current episode state."""
        return SocAlertState(
            task_name=self.task_name,
            steps=self.steps,
            max_steps=self.max_steps,
            current_case=asdict(self.current_case) if self.current_case else None,
            escalation_budget=self.escalation_budget,
            escalation_used=self.escalation_used,
            confidence_history=self.confidence_history,
            accuracy_history=self.accuracy_history,
        )
