# Copyright (c) 2026. All rights reserved.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

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
        return 0.01
    if verdict == truth["expected_verdict"]:
        return 0.99
        
    expected = truth["expected_verdict"]
    # Partial credit for "close" verdicts
    if expected == "TP" and verdict == "NeedsMoreData":
        return 0.5
    if expected == "NeedsMoreData" and verdict in {"TP", "FP"}:
        return 0.5
        
    return 0.01


def grade_medium(action: Dict[str, str], truth: Dict[str, str]) -> float:
    """Task 2: verdict + severity with partial credit."""
    verdict = _safe(action, "verdict")
    severity = _safe(action, "severity")

    score = 0.0
    if verdict in VALID_VERDICTS and verdict == truth["expected_verdict"]:
        score += 0.65
    if severity in VALID_SEVERITIES and severity == truth["expected_severity"]:
        score += 0.35

    return max(0.01, min(0.99, score))


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

    return max(0.01, min(0.99, score))
