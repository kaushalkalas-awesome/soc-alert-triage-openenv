"""Utility helpers for SOC alert simulation data."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class AlertCase:
    """Single synthetic SOC alert case with expected ground truth."""

    alert_id: str
    ip: str
    user: str
    activity: str
    event_time: str
    threat_intel: str
    behavior_pattern: str
    expected_verdict: str
    expected_severity: str
    expected_action: str
    task_level: str


def build_case_bank() -> List[AlertCase]:
    """Return deterministic dataset spanning easy, medium, and hard tasks."""
    return [
        AlertCase(
            alert_id="A-1001",
            ip="45.8.22.10",
            user="finance.svc",
            activity="Repeated failed login attempts from TOR exit node",
            event_time="2026-04-08T09:11:00Z",
            threat_intel="IP appears in known brute-force feed (confidence 0.95)",
            behavior_pattern="Unusual source geo and velocity for this account",
            expected_verdict="TP",
            expected_severity="high",
            expected_action="isolate",
            task_level="easy",
        ),
        AlertCase(
            alert_id="A-1002",
            ip="10.44.12.8",
            user="backup-agent",
            activity="PowerShell execution at 02:00 UTC",
            event_time="2026-04-08T02:00:00Z",
            threat_intel="No external intelligence hits",
            behavior_pattern="Matches known maintenance schedule",
            expected_verdict="FP",
            expected_severity="low",
            expected_action="ignore",
            task_level="easy",
        ),
        AlertCase(
            alert_id="A-2001",
            ip="185.77.1.210",
            user="ceo.mail",
            activity="OAuth token refresh and mailbox rule creation",
            event_time="2026-04-08T13:44:00Z",
            threat_intel="Infrastructure linked to phishing kit (confidence 0.82)",
            behavior_pattern="Mailbox rules are unusual for this user",
            expected_verdict="TP",
            expected_severity="critical",
            expected_action="escalate",
            task_level="medium",
        ),
        AlertCase(
            alert_id="A-2002",
            ip="172.16.5.55",
            user="build.runner",
            activity="Bulk artifact download from internal registry",
            event_time="2026-04-08T10:05:00Z",
            threat_intel="Internal IP range, no known malicious indicators",
            behavior_pattern="In line with weekly release pipeline",
            expected_verdict="Benign",
            expected_severity="low",
            expected_action="ignore",
            task_level="medium",
        ),
        AlertCase(
            alert_id="A-3001",
            ip="94.131.98.6",
            user="hr.portal",
            activity="Impossible travel + privileged access request + data staging",
            event_time="2026-04-08T15:24:00Z",
            threat_intel="C2 overlap with active ransomware campaign (0.91)",
            behavior_pattern="Sequence matches pre-exfiltration kill chain",
            expected_verdict="TP",
            expected_severity="critical",
            expected_action="block",
            task_level="hard",
        ),
        AlertCase(
            alert_id="A-3002",
            ip="203.0.113.45",
            user="legal.docs",
            activity="Large outbound transfer to sanctioned domain lookalike",
            event_time="2026-04-08T18:18:00Z",
            threat_intel="Domain has newly observed typo-squat indicators",
            behavior_pattern="Transfer volume 40x baseline",
            expected_verdict="NeedsMoreData",
            expected_severity="medium",
            expected_action="escalate",
            task_level="hard",
        ),
    ]


def task_to_levels(task_name: str) -> List[str]:
    """Map task name to allowed dataset levels."""
    mapping: Dict[str, List[str]] = {
        "task_easy_verdict": ["easy"],
        "task_medium_verdict_severity": ["easy", "medium"],
        "task_hard_full_triage": ["easy", "medium", "hard"],
    }
    if task_name not in mapping:
        raise ValueError(f"Unknown task: {task_name}")
    return mapping[task_name]
