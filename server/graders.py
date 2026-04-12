"""Deterministic graders for SOC triage tasks."""

from __future__ import annotations

from typing import Dict


VALID_VERDICTS = {"TP", "FP", "Benign", "NeedsMoreData"}
VALID_SEVERITIES = {"critical", "high", "medium", "low"}
VALID_ACTIONS = {"block", "isolate", "escalate", "ignore"}


def _safe(action: Dict[str, str], key: str, default: str = "") -> str:
    value = action.get(key, default)
    return str(value).strip()


def grade_easy(action: Dict[str, str], truth: Dict[str, str]) -> float:
    """Task 1: verdict only."""
    verdict = _safe(action, "verdict")
    if verdict not in VALID_VERDICTS:
        return 0.0
    return 1.0 if verdict == truth["expected_verdict"] else 0.0


def grade_medium(action: Dict[str, str], truth: Dict[str, str]) -> float:
    """Task 2: verdict + severity with partial credit."""
    verdict = _safe(action, "verdict")
    severity = _safe(action, "severity")

    score = 0.0
    if verdict in VALID_VERDICTS and verdict == truth["expected_verdict"]:
        score += 0.65
    if severity in VALID_SEVERITIES and severity == truth["expected_severity"]:
        score += 0.35

    return max(0.0, min(1.0, score))


def grade_hard(action: Dict[str, str], truth: Dict[str, str]) -> float:
    """Task 3: full triage with safety penalties."""
    verdict = _safe(action, "verdict")
    severity = _safe(action, "severity")
    response = _safe(action, "response_action")

    score = 0.0
    if verdict in VALID_VERDICTS and verdict == truth["expected_verdict"]:
        score += 0.45
    if severity in VALID_SEVERITIES and severity == truth["expected_severity"]:
        score += 0.25
    if response in VALID_ACTIONS and response == truth["expected_action"]:
        score += 0.20

    if (
        truth["expected_severity"] == "critical"
        and verdict != truth["expected_verdict"]
    ):
        score -= 0.40

    if (
        truth["expected_verdict"] in {"FP", "Benign"}
        and response in {"block", "isolate"}
    ):
        score -= 0.20

    # Policy adherence: valid action format gets a small deterministic signal.
    if response in VALID_ACTIONS:
        score += 0.10

    return max(0.0, min(1.0, score))
