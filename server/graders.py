# Copyright (c) 2026. All rights reserved.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Deterministic graders for SOC triage tasks with granular partial credit."""

from __future__ import annotations

from typing import Dict, Set


VALID_VERDICTS = {"TP", "FP", "Benign", "NeedsMoreData"}
VALID_SEVERITIES = {"critical", "high", "medium", "low"}
VALID_ACTIONS = {"block", "isolate", "escalate", "ignore"}

# Severity ranking for adjacency scoring
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# Action categories for appropriateness scoring
CONTAINMENT_ACTIONS: Set[str] = {"block", "isolate"}
PASSIVE_ACTIONS: Set[str] = {"escalate", "ignore"}


def _safe(action: Dict[str, str], key: str, default: str = "") -> str:
    value = action.get(key, default)
    return str(value).strip()


def _grade_verdict(verdict: str, expected: str) -> float:
    """Grade verdict with granular partial credit.
    
    Returns score between 0.0 and 1.0 based on verdict similarity.
    """
    if verdict not in VALID_VERDICTS:
        return 0.0
    if verdict == expected:
        return 1.0
    
    # Partial credit matrix for verdict similarity
    # TP and NeedsMoreData are closer (both indicate potential threat)
    # FP and Benign are closer (both indicate non-threat)
    similarity_map = {
        ("TP", "NeedsMoreData"): 0.5,
        ("NeedsMoreData", "TP"): 0.5,
        ("FP", "Benign"): 0.6,
        ("Benign", "FP"): 0.6,
        ("TP", "FP"): 0.0,
        ("FP", "TP"): 0.0,
        ("NeedsMoreData", "Benign"): 0.3,
        ("Benign", "NeedsMoreData"): 0.3,
        ("TP", "Benign"): 0.0,
        ("Benign", "TP"): 0.0,
        ("FP", "NeedsMoreData"): 0.3,
        ("NeedsMoreData", "FP"): 0.3,
    }
    
    return similarity_map.get((verdict, expected), 0.1)


def _grade_severity(severity: str, expected: str) -> float:
    """Grade severity with adjacency-based partial credit.
    
    Returns score between 0.0 and 1.0. Closer severity levels get partial credit.
    """
    if severity not in VALID_SEVERITIES:
        return 0.0
    if severity == expected:
        return 1.0
    
    # Calculate rank difference for partial credit
    rank_diff = abs(SEVERITY_RANK[severity] - SEVERITY_RANK[expected])
    
    # Adjacent severities get 0.5, two levels apart get 0.2
    if rank_diff == 1:
        return 0.5
    elif rank_diff == 2:
        return 0.2
    else:
        return 0.0


def _grade_action(action: str, expected: str, severity: str, verdict: str) -> float:
    """Grade response action with contextual appropriateness.
    
    Considers both exact match and appropriateness given severity/verdict.
    """
    if action not in VALID_ACTIONS:
        return 0.0
    if action == expected:
        return 1.0
    
    # Context-appropriate action scoring
    score = 0.0
    
    # Check if action is in same category (containment vs passive)
    action_containment = action in CONTAINMENT_ACTIONS
    expected_containment = expected in CONTAINMENT_ACTIONS
    
    if action_containment == expected_containment:
        score += 0.3  # Same category gets partial credit
    
    # Severity-appropriate action bonus
    if severity in {"critical", "high"} and action in CONTAINMENT_ACTIONS:
        score += 0.2  # Containment is appropriate for high severity
    elif severity in {"low", "medium"} and action in PASSIVE_ACTIONS:
        score += 0.2  # Passive action is appropriate for lower severity
    
    # Verdict-appropriate action
    if verdict in {"FP", "Benign"} and action == "ignore":
        score += 0.3  # Ignore is appropriate for benign
    elif verdict == "TP" and action in CONTAINMENT_ACTIONS:
        score += 0.3  # Containment is appropriate for true positives
    elif verdict == "NeedsMoreData" and action == "escalate":
        score += 0.4  # Escalation is appropriate when more data needed
    
    return min(score, 0.7)  # Cap partial credit at 0.7


def grade_easy(action: Dict[str, str], truth: Dict[str, str]) -> float:
    """Task 1: verdict only with improved partial credit."""
    verdict = _safe(action, "verdict")
    expected = truth.get("expected_verdict", "")
    
    score = _grade_verdict(verdict, expected)
    
    # Scale to 0.01-0.99 range
    return max(0.01, min(0.99, score))


def grade_medium(action: Dict[str, str], truth: Dict[str, str]) -> float:
    """Task 2: verdict + severity with granular partial credit."""
    verdict = _safe(action, "verdict")
    severity = _safe(action, "severity")
    
    expected_verdict = truth.get("expected_verdict", "")
    expected_severity = truth.get("expected_severity", "")
    
    # Weight components
    verdict_score = _grade_verdict(verdict, expected_verdict)
    severity_score = _grade_severity(severity, expected_severity)
    
    # Combined score: 65% verdict, 35% severity
    score = (verdict_score * 0.65) + (severity_score * 0.35)
    
    # Bonus for valid inputs
    if verdict in VALID_VERDICTS and severity in VALID_SEVERITIES:
        score += 0.05
    
    return max(0.01, min(0.99, score))


def grade_hard(action: Dict[str, str], truth: Dict[str, str]) -> float:
    """Task 3: full triage with granular partial credit and safety penalties."""
    verdict = _safe(action, "verdict")
    severity = _safe(action, "severity")
    response = _safe(action, "response_action")
    
    expected_verdict = truth.get("expected_verdict", "")
    expected_severity = truth.get("expected_severity", "")
    expected_action = truth.get("expected_action", "")
    
    # Grade each component
    verdict_score = _grade_verdict(verdict, expected_verdict)
    severity_score = _grade_severity(severity, expected_severity)
    action_score = _grade_action(response, expected_action, severity, verdict)
    
    # Base score weights: 45% verdict, 25% severity, 20% action
    score = (verdict_score * 0.45) + (severity_score * 0.25) + (action_score * 0.20)
    
    # Safety penalties (only apply to final score, not component scores)
    
    # Critical false negative: Missing a critical threat
    if expected_severity == "critical" and verdict_score < 0.5:
        score -= 0.40
    
    # High severity false negative
    if expected_severity == "high" and verdict_score < 0.5:
        score -= 0.25
    
    # Disruptive overreaction: Containment on benign activity
    if expected_verdict in {"FP", "Benign"} and response in CONTAINMENT_ACTIONS:
        score -= 0.20
    
    # Correlated alert bonus: Proper escalation for complex scenarios
    if truth.get("related_alerts") and response == "escalate" and verdict == "TP":
        score += 0.10
    
    # Policy adherence bonus
    if response in VALID_ACTIONS:
        score += 0.10
    
    return max(0.01, min(0.99, score))
