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
    """Agent's action in response to a SOC alert."""

    verdict: str = Field(..., description="TP, FP, Benign, or NeedsMoreData")
    severity: str = Field(..., description="critical, high, medium, or low")
    response_action: str = Field(..., description="block, isolate, escalate, or ignore")


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


class SocAlertState(State):
    """Episode state metadata."""

    task_name: str
    steps: int = 0
    max_steps: int = 1
    current_case: Optional[dict[str, Any]] = None
