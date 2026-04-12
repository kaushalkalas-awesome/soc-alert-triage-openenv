"""SOC Alert Triage Environment Client.

This is what users import and use to interact with the environment.
It can work with both local and remote (HF Spaces) deployments.
"""

from __future__ import annotations

from typing import Optional

try:
    from openenv.core.client_types import StepResult
    from openenv.core.env_client import EnvClient
except ImportError:
    # Fallback for basic usage without openenv client
    class StepResult:
        def __init__(self, observation, reward, done):
            self.observation = observation
            self.reward = reward
            self.done = done

    class EnvClient:
        pass


from .models import SocAlertAction, SocAlertObservation, SocAlertState


class SocAlertTriageEnv(EnvClient):
    """
    SOC Alert Triage Environment Client.

    Usage (local):
        env = SocAlertTriageEnv(base_url="http://localhost:8000")
        obs = env.reset()
        action = SocAlertAction(verdict="TP", severity="high", response_action="isolate")
        obs = env.step(action)

    Usage (HF Spaces):
        env = SocAlertTriageEnv(base_url="https://<your-space>.hf.space")
        obs = env.reset()
        ...
    """

    def _step_payload(self, action: SocAlertAction) -> dict:
        """Convert action to payload for wire format."""
        return action.model_dump() if isinstance(action, SocAlertAction) else action

    def _parse_result(self, payload: dict) -> StepResult:
        """Parse server response into StepResult."""
        obs_data = payload.get("observation", {})
        obs = SocAlertObservation(
            alert_id=obs_data.get("alert_id", ""),
            task_name=obs_data.get("task_name", ""),
            state=obs_data.get("state", {}),
            expected_action_schema=obs_data.get("expected_action_schema", {}),
            reward=payload.get("reward"),
            done=payload.get("done", False),
        )
        return StepResult(
            observation=obs,
            reward=payload.get("reward"),
            done=payload.get("done", False),
        )

    def _parse_state(self, payload: dict) -> SocAlertState:
        """Parse server state into SocAlertState."""
        return SocAlertState(
            task_name=payload.get("task_name", ""),
            steps=payload.get("steps", 0),
            max_steps=payload.get("max_steps", 1),
            current_case=payload.get("current_case"),
        )
