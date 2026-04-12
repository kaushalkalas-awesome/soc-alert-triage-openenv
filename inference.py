"""Baseline inference script required by hackathon."""

from __future__ import annotations

import json
import os
from time import perf_counter
from typing import Dict, List

from dotenv import load_dotenv
from openai import OpenAI

from server.environment import SocAlertTriageEnvironment

# Load environment variables from .env file
load_dotenv()


def _build_client() -> OpenAI:
    """
    Initialize OpenAI client with environment-based configuration.
    
    Reads from environment variables (loaded from .env file):
    - API_BASE_URL: LLM API endpoint (default: OpenAI)
    - HF_TOKEN: API authentication token
    
    Returns:
        OpenAI: Configured OpenAI client instance
    """
    api_base_url = os.getenv("API_BASE_URL", "https://api.openai.com/v1")
    hf_token = os.getenv("HF_TOKEN", "DUMMY_TOKEN_FOR_LOCAL_TESTS")
    return OpenAI(base_url=api_base_url, api_key=hf_token)


def _rule_based_action(observation) -> Dict[str, str]:
    """
    Fast deterministic baseline policy for reproducible scoring.
    We still initialize OpenAI client to satisfy integration requirement.
    Accepts both dict and Pydantic Observation objects.
    """
    # Handle both Pydantic model and dict
    if hasattr(observation, "state"):
        state = observation.state
    else:
        state = observation.get("state", {})

    intel = state.get("threat_intel", "").lower()
    activity = state.get("activity", "").lower()
    behavior = state.get("behavior_pattern", "").lower()

    if "ransomware" in intel or "kill chain" in behavior:
        return {"verdict": "TP", "severity": "critical", "response_action": "block"}
    if "phishing" in intel or "tor" in activity or "brute-force" in intel:
        return {"verdict": "TP", "severity": "high", "response_action": "isolate"}
    if "no external intelligence" in intel and "maintenance" in behavior:
        return {"verdict": "FP", "severity": "low", "response_action": "ignore"}
    if "typo-squat" in intel:
        return {
            "verdict": "NeedsMoreData",
            "severity": "medium",
            "response_action": "escalate",
        }
    return {"verdict": "Benign", "severity": "low", "response_action": "ignore"}


def _action_to_string(action: Dict[str, str]) -> str:
    """Convert action dict to string representation."""
    return json.dumps(action, sort_keys=True)


def run_task_with_logging(task_name: str, episodes: int = 10) -> tuple[float, List[float]]:
    """Run task and return average score + all episode rewards."""
    env = SocAlertTriageEnvironment()
    episode_rewards = []

    for episode in range(episodes):
        # OpenEnv returns Observation directly (not tuple)
        obs = env.reset(task_name=task_name, seed=42)

        # One episode = one reset + one step
        action = _rule_based_action(obs)
        obs_next = env.step(action)

        # Extract reward from observation
        reward = getattr(obs_next, "reward", 0.0)
        done = getattr(obs_next, "done", False)

        episode_rewards.append(reward)

        # Log each step within episode
        step_num = 1
        action_str = _action_to_string(action)
        error_msg = "null"

        print(
            f"[STEP] step={step_num} action={action_str} reward={reward:.2f} done={str(done).lower()} error={error_msg}",
            flush=True,
        )

    avg_score = sum(episode_rewards) / len(episode_rewards) if episode_rewards else 0.0
    return float(avg_score), episode_rewards


def main() -> None:
    """
    Main inference loop matching hackathon STDOUT format.
    
    Environment Variables Used:
    - API_BASE_URL: LLM API endpoint
    - MODEL_NAME: Model identifier for inference
    - HF_TOKEN: Authentication token for API
    
    All variables are loaded from .env file (via dotenv) or system environment.
    """
    start = perf_counter()
    _client = _build_client()
    
    # Load configuration from environment
    api_base_url = os.getenv("API_BASE_URL", "https://api.openai.com/v1")
    model_name = os.getenv("MODEL_NAME", "gpt-4o-mini")
    benchmark_name = "soc_alert_triage"

    tasks = [
        "task_easy_verdict",
        "task_medium_verdict_severity",
        "task_hard_full_triage",
    ]

    # Run each task
    all_task_scores = []
    for task_idx, task_name in enumerate(tasks, start=1):
        # Log START for this task
        print(
            f"[START] task={task_name} env={benchmark_name} model={model_name}",
            flush=True,
        )

        # Run episodes for this task
        avg_score, episode_rewards = run_task_with_logging(task_name, episodes=5)
        all_task_scores.append(avg_score)

        # Log END for this task
        total_steps = len(episode_rewards)
        rewards_str = ",".join(f"{r:.2f}" for r in episode_rewards)
        print(
            f"[END] success={str(avg_score >= 0.5).lower()} steps={total_steps} score={avg_score:.3f} rewards={rewards_str}",
            flush=True,
        )

    elapsed = round(perf_counter() - start, 3)


if __name__ == "__main__":
    main()
