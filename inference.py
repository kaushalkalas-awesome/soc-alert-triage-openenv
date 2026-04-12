# Copyright (c) 2026. All rights reserved.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Inference Script - SOC Alert Triage Environment (ENHANCED WITH CREATIVE FEATURES)
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
from typing import Any, Dict, List, Optional

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
MAX_TOKENS = 400  # Increased to accommodate reasoning
MAX_RETRIES = 2  # Retry on invalid JSON before falling back

# ── System prompt with creative features (Confidence, Reasoning, Escalation) ────
SYSTEM_PROMPT = textwrap.dedent("""\
    You are an expert SOC (Security Operations Center) analyst. You receive
    security alerts and must triage them based on the evidence provided.

    You have THREE options for your response:
    
    OPTION 1: GATHER INFORMATION (Tool Call)
    If you need more information before deciding, you can call a tool. Return ONLY a JSON object with:
    {"tool_name": "<query_threat_intel|check_user_history|analyze_payload>", "tool_query": "<argument>"}
    
    OPTION 2: FINAL DECISION (Autonomous Triage)
    If you have enough information, make your final triage decision. Return ONLY a JSON object with:
    {
      "verdict": "...",
      "severity": "...",
      "response_action": "...",
      "confidence": 0.0-1.0,
      "reasoning": "brief explanation of your decision"
    }

    OPTION 3: ESCALATE TO HUMAN (Limited Budget)
    If you are uncertain and have escalation budget remaining, escalate to human analysts:
    {"escalate_to_human": true}
    
    IMPORTANT CREATIVE FEATURES:
    
    1. CONFIDENCE CALIBRATION (REQUIRED):
       - Include "confidence": 0.0-1.0 in your decision
       - You are PENALIZED for overconfidence when wrong (-0.15)
       - You are PENALIZED for underconfidence when right (-0.10)
       - Be well-calibrated: high confidence only when certain
       - Example: If evidence is clear (malware hash match), confidence = 0.9+
       - Example: If evidence is ambiguous, confidence = 0.5-0.7
    
    2. EXPLAINABILITY BONUS:
       - Include "reasoning": "explanation of your decision" (20+ characters)
       - Earn +0.02 bonus for providing reasoning
       - Good reasoning references specific alert indicators
       - Example: "Confidence 0.92 because: known malware hash matches, unusual process behavior detected"
    
    3. ESCALATION BUDGET:
       - Easy task: 0 escalations
       - Medium task: 1 escalation allowed
       - Hard task: 2 escalations allowed  
       - Escalation gives correct answer but lower reward (0.2-0.4 vs 0.8-1.0)
       - Use escalation when confidence is low (<0.6) but budget remains
       - Running out of budget causes -0.5 penalty
    
    4. ATTACK CAMPAIGNS (Hard Task):
       - Some scenarios are multi-alert campaigns (ransomware, APT, insider threat)
       - Early detection in campaign progression earns higher rewards
       - Look for correlation hints between alerts
       - Campaign alerts are marked with [CORRELATED: CampaignName]

    Final Decision Field values:
    - verdict: TP (True Positive), FP (False Positive), Benign, NeedsMoreData
    - severity: critical, high, medium, low
    - response_action: block, isolate, escalate, ignore
    - confidence: 0.0-1.0 (REQUIRED - affects reward calibration)
    - reasoning: str (RECOMMENDED - 20+ chars for +0.02 bonus)
    - escalate_to_human: bool (use when uncertain)

    Decision guidelines:
    - TP + critical + block: Active ransomware, kill chain, BEC wire fraud
    - TP + high + isolate: Brute-force, phishing, credential theft, data exfil
    - TP + medium + escalate: Ambiguous threats needing analyst review
    - FP + low + ignore: Known maintenance schedules, authorized automation
    - Benign + low + ignore: Normal business operations, CI/CD pipelines
    - NeedsMoreData + medium + escalate: Suspicious but insufficient evidence

    Note: You must NOT include explanation text, or markdown fences. Output plain JSON.
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
def build_user_prompt(observation, feedback: str = "", episode_info: Optional[Dict] = None) -> str:
    """Build the user prompt from the alert observation.

    If feedback is provided (multi-step), include it so the LLM can
    self-correct its previous answer.
    
    NEW: Includes episode_info for escalation budget and campaign tracking.
    """
    if hasattr(observation, "state"):
        state = observation.state
    else:
        state = observation.get("state", {})

    prompt = textwrap.dedent(f"""\
        Triage the following security alert:

        IP: {state.get('ip', 'N/A')}
        User: {state.get('user', 'N/A')}
        Activity: {state.get('activity', 'N/A')}
        Event Time: {state.get('event_time', 'N/A')}
        Threat Intelligence: {state.get('threat_intel', 'N/A')}
        Behavior Pattern: {state.get('behavior_pattern', 'N/A')}
    """)

    # NEW: Include episode info (escalation budget, campaign progress)
    if episode_info:
        prompt += f"\nEpisode Progress: Alert {episode_info.get('alert_number', 1)} of {episode_info.get('total_alerts', 1)}\n"
        budget_remaining = episode_info.get('escalation_budget_remaining', 0)
        budget_total = episode_info.get('escalation_budget_total', 0)
        if budget_total > 0:
            prompt += f"Escalation Budget: {budget_remaining} of {budget_total} remaining\n"
    
    # Include campaign context if present
    campaign_context = state.get("campaign_context")
    if campaign_context:
        prompt += f"\nCampaign Context: {campaign_context}\n"
    
    # Include time pressure warning if present
    time_pressure = state.get("time_pressure_seconds")
    if time_pressure:
        prompt += f"\nTIME PRESSURE: Decision needed within {time_pressure} seconds\n"

    tool_history = state.get("tool_history", [])
    if tool_history:
        prompt += "\nTool History:\n" + "\n".join(tool_history) + "\n"

    if feedback:
        prompt += f"\nFeedback from previous attempt: {feedback}\n"
        prompt += "Please revise your assessment based on this feedback.\n"

    prompt += "\nRespond with ONLY a JSON object (tool call, final decision, or escalation)."
    return prompt


def parse_llm_response(content: str) -> Dict[str, Any]:
    """Parse and validate the LLM JSON response.

    Handles markdown fences, extra whitespace, and validates required fields.
    NEW: Extracts confidence, reasoning, and escalate_to_human fields.

    Raises:
        ValueError: If response cannot be parsed or is missing required fields.
    """
    content = content.strip()

    # Strip markdown fences: ```json ... ``` or ``` ... ```
    if content.startswith("```"):
        content = content.split("\n", 1)[-1]
    if content.endswith("```"):
        content = content.rsplit("```", 1)[0]
    content = content.strip()

    action = json.loads(content)

    # NEW: Handle escalation
    if action.get("escalate_to_human"):
        return {
            "escalate_to_human": True,
        }

    # Handle tool call
    if "tool_name" in action:
        return {
            "tool_name": str(action["tool_name"]).strip(),
            "tool_query": str(action.get("tool_query", "")).strip(),
        }

    # Handle final decision - NEW: extract confidence and reasoning
    required = {"verdict", "severity", "response_action"}
    if not required.issubset(action.keys()):
        raise ValueError(f"Missing fields: {required - action.keys()}")

    result = {
        "verdict": str(action["verdict"]).strip(),
        "severity": str(action["severity"]).strip(),
        "response_action": str(action["response_action"]).strip(),
    }
    
    # NEW: Extract optional confidence and reasoning
    confidence = action.get("confidence")
    if confidence is not None:
        try:
            result["confidence"] = float(confidence)
        except (ValueError, TypeError):
            pass  # Ignore invalid confidence
    
    reasoning = action.get("reasoning")
    if reasoning:
        result["reasoning"] = str(reasoning).strip()
    
    return result


def get_model_action(
    client: OpenAI,
    observation,
    feedback: str = "",
    episode_info: Optional[Dict] = None,
) -> Dict[str, Any]:
    """
    Call the LLM to get a triage decision, with retry on parse failure.

    If the first response has invalid JSON, retry with
    the error message appended so the LLM can self-correct.
    """
    user_prompt = build_user_prompt(observation, feedback, episode_info)
    last_error = None

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ]
            # On retry, append the parse error so the LLM can fix it
            if last_error:
                messages.append({
                    "role": "user",
                    "content": (
                        f"Your previous response could not be parsed: {last_error}\n"
                        "Please respond with ONLY a valid JSON object, no other text."
                    ),
                })

            completion = client.chat.completions.create(
                model=MODEL_NAME,
                messages=messages,
                temperature=TEMPERATURE,
                max_tokens=MAX_TOKENS,
                stream=False,
            )

            content = (completion.choices[0].message.content or "").strip()
            return parse_llm_response(content)

        except Exception as exc:
            last_error = str(exc)
            if attempt < MAX_RETRIES:
                print(
                    f"[DEBUG] Attempt {attempt}/{MAX_RETRIES} parse failed: {exc}, retrying...",
                    flush=True,
                )

    # All retries exhausted — fall back to safe default with escalation
    print(f"[DEBUG] All {MAX_RETRIES} attempts failed: {last_error}, using fallback escalation", flush=True)
    return {"escalate_to_human": True}


def _action_to_string(action: Dict[str, Any]) -> str:
    """Convert action dict to string representation."""
    return json.dumps(action, sort_keys=True)


# ── Main inference loop ─────────────────────────────────────────────────────
def main() -> None:
    """
    Main inference loop matching hackathon STDOUT format.

    Environment Variables Used:
    - API_BASE_URL: LLM API endpoint
    - MODEL_NAME: Model identifier for inference
    - API_KEY: Authentication token for API
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
        success = False
        avg_score = 0.0

        try:
            for episode in range(5):
                # FIXED: Use deterministic seed (not hash-dependent)
                # Use episode number + task offset for reproducibility
                task_offset = {"task_easy_verdict": 1000, "task_medium_verdict_severity": 2000, "task_hard_full_triage": 3000}
                tuned_seed = episode + task_offset.get(task_name, 0)
                obs = env.reset(task_name=task_name, seed=tuned_seed)
                done = False
                feedback = ""
                episode_reward = 0.0

                while not done:
                    # NEW: Extract episode_info for escalation budget display
                    episode_info = getattr(obs, "episode_info", None)
                    if not episode_info and hasattr(obs, "state"):
                        # Try to get from state if not directly available
                        state = obs.state if isinstance(obs.state, dict) else {}
                        if "episode_info" in state:
                            episode_info = state["episode_info"]
                    
                    # Call the LLM (with feedback and episode_info)
                    action = get_model_action(client, obs, feedback=feedback, episode_info=episode_info)
                    obs = env.step(action)

                    reward = getattr(obs, "reward", 0.0)
                    done = getattr(obs, "done", False)
                    error = None

                    episode_reward = reward
                    steps_taken += 1

                    log_step(
                        step=steps_taken,
                        action=_action_to_string(action),
                        reward=reward,
                        done=done,
                        error=error,
                    )

                    # FIXED: Extract feedback properly from observation
                    # Feedback can be at top level or in state
                    if not done:
                        feedback = getattr(obs, "feedback", "")
                        if not feedback and hasattr(obs, "state"):
                            state = obs.state if isinstance(obs.state, dict) else obs.state or {}
                            feedback = state.get("feedback", "")

                rewards.append(episode_reward)

            avg_score = sum(rewards) / len(rewards) if rewards else 0.0
            avg_score = min(max(avg_score, 0.0), 1.0)
            success = avg_score >= 0.5
            all_task_scores.append(avg_score)

        finally:
            log_end(
                success=success,
                steps=steps_taken,
                score=avg_score,
                rewards=rewards,
            )

    elapsed = round(perf_counter() - start, 3)


if __name__ == "__main__":
    main()
