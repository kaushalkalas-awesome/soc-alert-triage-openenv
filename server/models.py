"""Type-safe models for SOC Alert Triage environment using Pydantic."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class SocAlertAction(BaseModel):
    """Agent's action in response to a SOC alert."""

    verdict: str = Field(..., description="TP, FP, Benign, or NeedsMoreData")
    severity: str = Field(..., description="critical, high, medium, or low")
    response_action: str = Field(..., description="block, isolate, escalate, or ignore")


class SocAlertObservation(BaseModel):
    """Observation: the alert data agent sees."""

    alert_id: str
    task_name: str
    state: dict = Field(
        ...,
        description="Alert context with ip, user, activity, event_time, threat_intel, behavior_pattern",
    )
    expected_action_schema: dict = Field(..., description="Valid value ranges for actions")
    reward: Optional[float] = Field(default=None, description="Reward signal")
    done: bool = Field(default=False, description="Episode termination signal")


class SocAlertState(BaseModel):
    """Episode state metadata."""

    task_name: str
    steps: int = 0
    max_steps: int = 1
    current_case: Optional[dict] = None
