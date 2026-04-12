"""FastAPI Application for SOC Alert Triage Environment.

This file creates the FastAPI app for serving the environment.
It handles HTTP/WebSocket communication with the environment.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from .environment import SocAlertTriageEnvironment
from .models import SocAlertAction, SocAlertObservation, SocAlertState

# Create FastAPI app
app = FastAPI(
    title="SOC Alert Triage Environment",
    description="OpenEnv-compatible SOC alert triage environment",
    version="0.1.0",
)

# Global environment instance (for single-session local testing)
# In production, use create_fastapi_app or implement proper session management
env = SocAlertTriageEnvironment()

@app.get("/")
def root():
    return {"message": "SOC Alert Triage OpenEnv is running"}

@app.get("/health")
def health() -> dict:
    """Health check endpoint."""
    return {"status": "ok"}


@app.post("/reset")
def reset_env(task_name: str = "task_easy_verdict") -> dict:
    """Reset the environment."""
    obs = env.reset(task_name=task_name)
    return {
        "observation": {
            "alert_id": obs.alert_id,
            "task_name": obs.task_name,
            "state": obs.state,
            "expected_action_schema": obs.expected_action_schema,
        },
        "reward": obs.reward,
        "done": obs.done,
    }


@app.post("/step")
def step_env(action: SocAlertAction) -> dict:
    """Execute one step in the environment."""
    obs = env.step(action)
    return {
        "observation": {
            "alert_id": obs.alert_id,
            "task_name": obs.task_name,
            "state": obs.state,
            "expected_action_schema": obs.expected_action_schema,
        },
        "reward": obs.reward,
        "done": obs.done,
    }


@app.get("/state")
def get_state() -> dict:
    """Get current environment state."""
    state_obj = env.state
    return {
        "task_name": state_obj.task_name,
        "steps": state_obj.steps,
        "max_steps": state_obj.max_steps,
        "current_case": state_obj.current_case,
    }


def main():
    """Run the FastAPI server."""
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7860)


if __name__ == "__main__":
    main()
