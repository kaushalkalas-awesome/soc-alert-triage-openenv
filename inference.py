# Copyright (c) 2026. All rights reserved.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Inference Script - SOC Alert Triage Environment
===================================
MANDATORY
- Before submitting, ensure the following variables are defined in your environment configuration:
    API_BASE_URL   The API endpoint for the LLM.
    MODEL_NAME     The model identifier to use for inference.
    HF_TOKEN       Your Hugging Face / API key.

- Defaults are set only for API_BASE_URL and MODEL_NAME:
    API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
    MODEL_NAME = os.getenv("MODEL_NAME", "gpt-4o-mini")

- The inference script must be named `inference.py` and placed in the root directory of the project
- Participants must use OpenAI Client for all LLM calls using above variables

STDOUT FORMAT
    [START] task=<task_name> env=<benchmark> model=<model_name>
    [STEP]  step=<n> action=<action_str> reward=<0.00> done=<true|false> error=<msg|null>
    [END]   success=<true|false> steps=<n> score=<score> rewards=<r1,r2,...,rn>
"""

from __future__ import annotations

import json
import os
import textwrap
from time import perf_counter
from typing import Dict, List, Optional

from dotenv import load_dotenv
from openai import OpenAI

from server.environment import SocAlertTriageEnvironment

# Load environment variables from .env file
load_dotenv()

# ── Environment variables (matching hackathon sample) ────────────────────────
API_KEY = os.getenv("API_KEY")
API_BASE_URL = os.getenv("API_BASE_URL")
MODEL_NAME = os.getenv("MODEL_NAME")
BENCHMARK = "soc_alert_triage"
TEMPERATURE = 0.0
MAX_TOKENS = 200

# ── System prompt for the SOC analyst agent ──────────────────────────────────
SYSTEM_PROMPT = textwrap.dedent("""\
    You are a SOC (Security Operations Center) analyst AI. You receive security
    alerts and must triage them. For every alert, respond with ONLY a valid JSON
    object containing exactly three fields:

    {
      "verdict": "<TP|FP|Benign|NeedsMoreData>",
      "severity": "<critical|high|medium|low>",
      "response_action": "<block|isolate|escalate|ignore>"
    }

    Rules:
    - verdict must be one of: TP, FP, Benign, NeedsMoreData
    - severity must be one of: critical, high, medium, low
    - response_action must be one of: block, isolate, escalate, ignore
    - Output ONLY the JSON object, no explanation, no markdown fences.
""")


# ── Logging helpers (matching hackathon STDOUT format) ───────────────────────
def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)


def log_step(step: int, action: str, reward: float, done: bool, error: Optional[str]) -> None:
    error_val = error if error else "null"
    done_val = str(done).lower()
    print(
        f"[STEP] step={step} action={action} reward={reward:.2f} done={done_val} error={error_val}",
        flush=True,
    )


def log_end(success: bool, steps: int, score: float, rewards: List[float]) -> None:
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(
        f"[END] success={str(success).lower()} steps={steps} score={score:.3f} rewards={rewards_str}",
        flush=True,
    )


# ── LLM interaction ─────────────────────────────────────────────────────────
def build_user_prompt(observation) -> str:
    """Build the user prompt from the alert observation."""
    if hasattr(observation, "state"):
        state = observation.state
    else:
        state = observation.get("state", {})

    return textwrap.dedent(f"""\
        Triage the following security alert:

        IP: {state.get('ip', 'N/A')}
        User: {state.get('user', 'N/A')}
        Activity: {state.get('activity', 'N/A')}
        Event Time: {state.get('event_time', 'N/A')}
        Threat Intelligence: {state.get('threat_intel', 'N/A')}
        Behavior Pattern: {state.get('behavior_pattern', 'N/A')}

        Respond with ONLY a JSON object with verdict, severity, and response_action.
    """)


def get_model_action(client: OpenAI, observation) -> Dict[str, str]:
    """
    Call the LLM through the hackathon proxy to get a triage decision.

    Falls back to a safe default if the LLM response cannot be parsed.
    """
    user_prompt = build_user_prompt(observation)

    try:
        completion = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=TEMPERATURE,
            max_tokens=MAX_TOKENS,
            stream=False,
        )

        content = (completion.choices[0].message.content or "").strip()

        # Strip markdown fences if the model wraps in ```json ... ```
        if content.startswith("```"):
            content = content.split("\n", 1)[-1]
        if content.endswith("```"):
            content = content.rsplit("```", 1)[0]
        content = content.strip()

        action = json.loads(content)

        # Validate required fields exist
        required = {"verdict", "severity", "response_action"}
        if not required.issubset(action.keys()):
            raise ValueError(f"Missing fields: {required - action.keys()}")

        return {
            "verdict": str(action["verdict"]).strip(),
            "severity": str(action["severity"]).strip(),
            "response_action": str(action["response_action"]).strip(),
        }

    except Exception as exc:
        print(f"[DEBUG] Model request/parse failed: {exc}", flush=True)
        return {"verdict": "TP", "severity": "medium", "response_action": "escalate"}


def _action_to_string(action: Dict[str, str]) -> str:
    """Convert action dict to string representation."""
    return json.dumps(action, sort_keys=True)


# ── Main inference loop ─────────────────────────────────────────────────────
def main() -> None:
    """
    Main inference loop matching hackathon STDOUT format.

    Environment Variables Used:
    - API_BASE_URL: LLM API endpoint
    - MODEL_NAME: Model identifier for inference
    - HF_TOKEN / API_KEY: Authentication token for API
    """
    start = perf_counter()

    # Build OpenAI client using hackathon-injected env vars
    client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)

    tasks = [
        "task_easy_verdict",
        "task_medium_verdict_severity",
        "task_hard_full_triage",
    ]

    all_task_scores = []
    for task_name in tasks:
        log_start(task=task_name, env=BENCHMARK, model=MODEL_NAME)

        env = SocAlertTriageEnvironment()
        rewards: List[float] = []
        steps_taken = 0

        try:
            for episode in range(5):
                obs = env.reset(task_name=task_name, seed=42 + episode)

                # Call the LLM through the hackathon proxy
                action = get_model_action(client, obs)
                obs_next = env.step(action)

                reward = getattr(obs_next, "reward", 0.0)
                done = getattr(obs_next, "done", False)
                error = None

                rewards.append(reward)
                steps_taken += 1

                log_step(
                    step=steps_taken,
                    action=_action_to_string(action),
                    reward=reward,
                    done=done,
                    error=error,
                )

            avg_score = sum(rewards) / len(rewards) if rewards else 0.0
            avg_score = min(max(avg_score, 0.0), 1.0)
            success = avg_score >= 0.5
            all_task_scores.append(avg_score)

        finally:
            log_end(
                success=success if 'success' in dir() or 'success' in locals() else False,
                steps=steps_taken,
                score=avg_score if 'avg_score' in locals() else 0.0,
                rewards=rewards,
            )

    elapsed = round(perf_counter() - start, 3)


if __name__ == "__main__":
    main()
