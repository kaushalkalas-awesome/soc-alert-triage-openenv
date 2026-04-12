# Copyright (c) 2026. All rights reserved.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
SOC Alert Triage Environment HTTP client.

This client uses the OpenEnv HTTP endpoints exposed by the SOC triage server:
/reset, /step, and /state. It also includes a scenario runner for benchmarks.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import random
import string
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generic, List, Optional, TypeVar

import httpx

try:
    from .models import SocAlertAction, SocAlertObservation
except ImportError:
    from models import SocAlertAction, SocAlertObservation

ObsT = TypeVar("ObsT")


@dataclass
class StepResult(Generic[ObsT]):
    observation: ObsT
    reward: Optional[float] = None
    done: bool = False


logger = logging.getLogger(__name__)
DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parent / "response_output"


def _generate_session_id() -> str:
    timestamp = int(time.time() * 1000)
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=9))
    return f"session_{timestamp}_{suffix}"


class SocAlertTriageEnv:
    """HTTP client for the SOC Alert Triage environment."""

    def __init__(
        self,
        base_url: str = "http://localhost:7860",
        timeout_s: float = 60.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s
        self._client: Optional[httpx.Client] = None

    def __enter__(self) -> "SocAlertTriageEnv":
        self._ensure_client()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def _ensure_client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self.timeout_s)
        return self._client

    def _headers(self) -> Dict[str, str]:
        return {"Content-Type": "application/json"}

    def _parse_step_result(
        self, payload: Dict[str, Any]
    ) -> StepResult[SocAlertObservation]:
        obs_data = payload.get("observation", {})
        observation = SocAlertObservation(
            alert_id=obs_data.get("alert_id", ""),
            task_name=obs_data.get("task_name", ""),
            state=obs_data.get("state", {}),
            expected_action_schema=obs_data.get("expected_action_schema", {}),
            reward=payload.get("reward"),
            done=payload.get("done", False),
        )
        return StepResult(
            observation=observation,
            reward=payload.get("reward"),
            done=payload.get("done", False),
        )

    def reset(
        self,
        task_name: str = "task_easy_verdict",
        seed: Optional[int] = None,
    ) -> StepResult[SocAlertObservation]:
        """Reset the environment and return initial observation."""
        payload: Dict[str, Any] = {"task_name": task_name}
        if seed is not None:
            payload["seed"] = seed

        client = self._ensure_client()
        response = client.post(
            f"{self.base_url}/reset",
            json=payload,
            headers=self._headers(),
        )
        response.raise_for_status()
        return self._parse_step_result(response.json())

    def step(
        self,
        action: SocAlertAction | Dict[str, Any],
    ) -> StepResult[SocAlertObservation]:
        """Execute one environment step with the given action."""
        if isinstance(action, SocAlertAction):
            action_payload = action.model_dump(exclude_none=True)
        elif isinstance(action, dict):
            action_payload = action
        else:
            raise TypeError("action must be SocAlertAction or dict")

        client = self._ensure_client()
        response = client.post(
            f"{self.base_url}/step",
            json=action_payload,
            headers=self._headers(),
        )
        response.raise_for_status()
        return self._parse_step_result(response.json())

    def state(self) -> Dict[str, Any]:
        """Get current environment state."""
        client = self._ensure_client()
        response = client.get(
            f"{self.base_url}/state",
            headers=self._headers(),
        )
        response.raise_for_status()
        return response.json()

    def health(self) -> Dict[str, Any]:
        """Check server health."""
        client = self._ensure_client()
        response = client.get(f"{self.base_url}/health")
        response.raise_for_status()
        return response.json()


@dataclass
class ScenarioConfig:
    """Configuration for a benchmark scenario."""

    gym_enviornment_url: str
    system_prompt: str
    user_prompt: str
    llm_model: str
    llm_provider: str
    llm_api_key: str
    seed_database_file: str = ""
    execution_mode: str = "openenv"
    expected_tools: List[str] = field(default_factory=list)
    restricted_tools: List[str] = field(default_factory=list)
    verifiers: List[Dict[str, Any]] = field(default_factory=list)
    tasks: List[Dict[str, Any]] = field(default_factory=list)
    number_of_runs: int = 1
    reset_database_between_runs: bool = True
    temperature: float = 0.0
    max_tokens: int = 4096
    max_iterations: int = 20
    output_dir: Path = DEFAULT_OUTPUT_DIR


class VerifierEngine:
    """Verifies agent responses against expected values."""

    def __init__(self, client: SocAlertTriageEnv):
        self.client = client

    async def execute_verifier(
        self,
        verifier: Dict[str, Any],
        agent_action: Dict[str, Any],
        ground_truth: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Execute a single verifier against agent output."""
        verifier_type = verifier.get("verifier_type")

        if verifier_type == "response_check":
            return self._execute_response_check(
                verifier.get("validation_config", {}),
                agent_action,
                ground_truth,
            )

        return {"passed": False, "error": f"Unsupported verifier type: {verifier_type}"}

    def _execute_response_check(
        self,
        validation_config: Dict[str, Any],
        agent_action: Dict[str, Any],
        ground_truth: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Check if a specific field in the agent action matches ground truth."""
        field_name = validation_config.get("field", "")
        comparison_type = validation_config.get("comparison_type", "equals")

        truth_key_map = {
            "verdict": "expected_verdict",
            "severity": "expected_severity",
            "response_action": "expected_action",
        }

        truth_key = truth_key_map.get(field_name, field_name)
        actual_value = agent_action.get(field_name, "")
        expected_value = ground_truth.get(truth_key, "")

        if comparison_type == "equals":
            passed = str(actual_value).strip() == str(expected_value).strip()
        elif comparison_type == "contains":
            passed = str(expected_value).strip() in str(actual_value).strip()
        else:
            return {"passed": False, "error": f"Unknown comparison type: {comparison_type}"}

        return {
            "passed": passed,
            "field": field_name,
            "expected": expected_value,
            "actual": actual_value,
            "comparison_type": comparison_type,
        }


class ScenarioRunner:
    """Runs benchmark scenarios against the SOC triage environment."""

    def __init__(self, config: ScenarioConfig):
        self.config = config
        self.client = SocAlertTriageEnv(
            base_url=config.gym_enviornment_url,
        )
        self.verifier_engine = VerifierEngine(self.client)

    async def execute_benchmark(self) -> Dict[str, Any]:
        """Execute the full benchmark across all tasks."""
        runs: List[Dict[str, Any]] = []

        for task_config in self.config.tasks:
            task_name = task_config.get("task_name", "task_easy_verdict")
            episodes = task_config.get("episodes", 5)

            task_result = await self.execute_task(task_name, episodes)
            runs.append(task_result)

        statistics = self._calculate_statistics(runs)
        return {
            "benchmark_config": {
                "execution_mode": self.config.execution_mode,
                "model": f"{self.config.llm_provider}/{self.config.llm_model}",
                "number_of_runs": self.config.number_of_runs,
                "tasks": [t.get("task_name") for t in self.config.tasks],
            },
            "runs": runs,
            "statistics": statistics,
        }

    async def execute_task(
        self, task_name: str, episodes: int = 5
    ) -> Dict[str, Any]:
        """Execute a single task over multiple episodes."""
        start_time = datetime.now(timezone.utc)
        episode_results: List[Dict[str, Any]] = []

        for episode in range(episodes):
            result = await self._execute_episode(task_name, episode, seed=42 + episode)
            episode_results.append(result)

        execution_time_ms = int(
            (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
        )

        rewards = [r.get("reward", 0.0) for r in episode_results]
        avg_reward = sum(rewards) / len(rewards) if rewards else 0.0

        return {
            "task_name": task_name,
            "started_at": start_time.isoformat(),
            "execution_time_ms": execution_time_ms,
            "episodes": episode_results,
            "average_reward": avg_reward,
            "total_episodes": len(episode_results),
        }

    async def _execute_episode(
        self, task_name: str, episode_num: int, seed: int = 42
    ) -> Dict[str, Any]:
        """Execute a single episode (reset + step)."""
        # Reset environment
        reset_result = self.client.reset(task_name=task_name, seed=seed)
        obs = reset_result.observation

        # Generate action (rule-based for now)
        action = self._rule_based_policy(obs)

        # Step
        step_result = self.client.step(action)

        reward = step_result.reward or 0.0
        done = step_result.done

        return {
            "episode": episode_num,
            "alert_id": obs.alert_id,
            "action": action,
            "reward": reward,
            "done": done,
        }

    def _rule_based_policy(self, observation: SocAlertObservation) -> Dict[str, str]:
        """Deterministic baseline policy for scoring."""
        state = observation.state
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

    def _calculate_statistics(self, runs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate aggregate statistics across all task runs."""
        total_episodes = sum(r.get("total_episodes", 0) for r in runs)
        all_rewards = []
        for run in runs:
            for ep in run.get("episodes", []):
                all_rewards.append(ep.get("reward", 0.0))

        mean_reward = sum(all_rewards) / len(all_rewards) if all_rewards else 0.0
        task_averages = {
            r["task_name"]: r.get("average_reward", 0.0) for r in runs
        }

        return {
            "total_tasks": len(runs),
            "total_episodes": total_episodes,
            "mean_reward": mean_reward,
            "task_averages": task_averages,
        }


def _resolve_api_key(provider: str, config_key: Optional[str]) -> str:
    """Resolve LLM API key from config or environment."""
    if config_key:
        return config_key

    provider = provider.lower()
    env_map = {
        "openai": "OPENAI_API_KEY",
        "anthropic": "ANTHROPIC_API_KEY",
        "google": "GOOGLE_API_KEY",
    }
    key = os.getenv(env_map.get(provider, "LLM_API_KEY")) or os.getenv("LLM_API_KEY")
    if not key:
        raise ValueError("LLM API key is required for scenario runs")
    return key


def _load_scenario_config(
    config_path: str,
    base_url_override: Optional[str] = None,
    output_dir: Optional[str] = None,
) -> ScenarioConfig:
    """Load scenario config from JSON file."""
    path = Path(config_path).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"Scenario config not found: {path}")

    with path.open("r", encoding="utf-8") as file:
        config_data = json.load(file)

    # Filter out comment fields
    config_data = {k: v for k, v in config_data.items() if not str(k).startswith("_")}

    base_url = (
        base_url_override
        or config_data.get("gym_enviornment_url")
        or config_data.get("gym_environment_url")
        or config_data.get("base_url")
    )
    if not base_url:
        raise ValueError("Missing gym_enviornment_url in scenario config")

    llm_provider = config_data.get("llm_provider", "openai")
    llm_model = config_data.get("llm_model", "gpt-4o-mini")
    llm_api_key = _resolve_api_key(llm_provider, config_data.get("llm_api_key"))

    output_path = (
        Path(output_dir).expanduser().resolve() if output_dir else DEFAULT_OUTPUT_DIR
    )

    return ScenarioConfig(
        gym_enviornment_url=base_url,
        seed_database_file=config_data.get("seed_database_file", ""),
        system_prompt=config_data.get("system_prompt", ""),
        user_prompt=config_data.get("user_prompt", ""),
        llm_model=llm_model,
        llm_provider=llm_provider,
        llm_api_key=llm_api_key,
        execution_mode=config_data.get("execution_mode", "openenv"),
        expected_tools=config_data.get("expected_tools", []) or [],
        restricted_tools=config_data.get("restricted_tools", []) or [],
        verifiers=config_data.get("verifiers", []) or [],
        tasks=config_data.get("tasks", []) or [],
        number_of_runs=config_data.get("number_of_runs", 1),
        reset_database_between_runs=config_data.get("reset_database_between_runs", True),
        temperature=config_data.get("temperature", 0.0),
        max_tokens=config_data.get("max_tokens", 4096),
        max_iterations=config_data.get("max_iterations", 20),
        output_dir=output_path,
    )


def _write_scenario_output(result: Dict[str, Any], output_dir: Path) -> Path:
    """Write benchmark results to JSON file."""
    output_dir.mkdir(parents=True, exist_ok=True)
    filename = (
        f"benchmark_results_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
    )
    output_path = output_dir / filename
    with output_path.open("w", encoding="utf-8") as file:
        json.dump(result, file, indent=2, default=str)
    return output_path


def main() -> None:
    """CLI entry point for SOC Alert Triage environment client."""
    parser = argparse.ArgumentParser(description="SOC Alert Triage environment HTTP client")
    parser.add_argument("--base-url", default="http://localhost:7860")
    parser.add_argument("--scenario", default=None, help="Path to scenario_config.json")
    parser.add_argument("--output-dir", default=None)
    parser.add_argument(
        "--task",
        default=None,
        choices=[
            "task_easy_verdict",
            "task_medium_verdict_severity",
            "task_hard_full_triage",
        ],
    )
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    if args.scenario:
        logging.basicConfig(
            level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
        )
        config = _load_scenario_config(
            config_path=args.scenario,
            base_url_override=args.base_url if args.base_url != "http://localhost:7860" else None,
            output_dir=args.output_dir,
        )

        async def _run() -> None:
            runner = ScenarioRunner(config)
            result = await runner.execute_benchmark()
            output_path = _write_scenario_output(result, config.output_dir)
            logger.info("Scenario results saved to %s", output_path)
            print(f"\nResults saved to: {output_path}")

        asyncio.run(_run())
        return

    # Interactive mode: single reset/step
    with SocAlertTriageEnv(base_url=args.base_url) as client:
        task_name = args.task or "task_easy_verdict"

        # Health check
        try:
            health = client.health()
            print(f"Server health: {health}")
        except Exception as e:
            print(f"Server health check failed: {e}")
            return

        # Reset
        reset_result = client.reset(task_name=task_name, seed=args.seed)
        obs = reset_result.observation
        print(f"\nTask: {task_name}")
        print(f"Alert ID: {obs.alert_id}")
        print(f"State: {json.dumps(obs.state, indent=2)}")

        # Get state
        state = client.state()
        print(f"\nEnvironment state: {json.dumps(state, indent=2)}")


if __name__ == "__main__":
    main()
