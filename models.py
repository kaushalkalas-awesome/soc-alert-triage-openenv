# Copyright (c) 2026. All rights reserved.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Type-safe models for SOC Alert Triage environment."""

from __future__ import annotations

from typing import Any, Optional

from openenv.core.env_server.types import Action, Observation, State
from pydantic import Field


class SocAlertAction(Action):
    """Agent's action in response to a SOC alert or a tool call.
    
    NEW: Supports reasoning output for explainability and confidence scoring.
    """

    verdict: Optional[str] = Field(default=None, description="TP, FP, Benign, or NeedsMoreData")
    severity: Optional[str] = Field(default=None, description="critical, high, medium, or low")
    response_action: Optional[str] = Field(default=None, description="block, isolate, escalate, or ignore")
    
    # Tool calling
    tool_name: Optional[str] = Field(default=None, description="Tool to execute (e.g., query_threat_intel, check_user_history, analyze_payload)")
    tool_query: Optional[str] = Field(default=None, description="Argument for the tool")
    
    # NEW: Explainability and confidence features
    reasoning: Optional[str] = Field(default=None, description="Agent's reasoning for the decision (explainability)")
    confidence: Optional[float] = Field(default=None, description="Confidence score 0.0-1.0 (calibration)")
    escalate_to_human: Optional[bool] = Field(default=None, description="Request human analyst escalation")


class SocAlertObservation(Observation):
    """Observation: the alert data agent sees."""

    alert_id: str
    task_name: str
    state: dict[str, Any] = Field(
        ...,
        description="Alert context with ip, user, activity, event_time, threat_intel, behavior_pattern",
    )
    expected_action_schema: dict[str, str] = Field(
        ..., description="Valid value ranges for actions"
    )
    reward: Optional[float] = Field(default=None, description="Reward signal")
    done: bool = Field(default=False, description="Episode termination signal")
    
    # NEW: Episode-level metadata
    episode_info: Optional[dict[str, Any]] = Field(default=None, description="Episode progress: alert_number, total_alerts, escalation_budget_remaining")


class SocAlertState(State):
    """Episode state metadata."""

    task_name: str
    steps: int = 0
    max_steps: int = 1
    current_case: Optional[dict[str, Any]] = None
    
    # NEW: Escalation budget tracking
    escalation_budget: int = Field(default=0, description="Remaining escalations to human analysts")
    escalation_used: int = Field(default=0, description="Number of escalations used this episode")
    
    # NEW: Confidence calibration tracking
    confidence_history: list[float] = Field(default_factory=list, description="History of confidence scores")
    accuracy_history: list[bool] = Field(default_factory=list, description="History of correctness")
    
    # NEW: Campaign tracking
    campaign_progress: dict[str, Any] = Field(default_factory=dict, description="Progress through attack campaign")
