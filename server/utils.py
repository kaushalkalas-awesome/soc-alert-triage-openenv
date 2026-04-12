# Copyright (c) 2026. All rights reserved.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Utility helpers for SOC alert simulation data."""

from __future__ import annotations

import random
import uuid
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


# Templates for procedural generation
EASY_TEMPLATES = [
    {
        "activity": "Repeated failed login attempts from TOR exit node",
        "threat_intel": "IP appears in known brute-force feed (confidence {conf})",
        "behavior_pattern": "Unusual source geo and velocity for this account",
        "expected_verdict": "TP",
        "expected_severity": "high",
        "expected_action": "isolate",
    },
    {
        "activity": "PowerShell execution at {time} UTC",
        "threat_intel": "No external intelligence hits",
        "behavior_pattern": "Matches known maintenance schedule",
        "expected_verdict": "FP",
        "expected_severity": "low",
        "expected_action": "ignore",
    },
    {
        "activity": "SSH brute-force with 500+ attempts in 10 minutes",
        "threat_intel": "IP in active botnet C2 list (confidence {conf})",
        "behavior_pattern": "Automated credential stuffing pattern detected",
        "expected_verdict": "TP",
        "expected_severity": "critical",
        "expected_action": "block",
    },
    {
        "activity": "Windows Update service downloading patches",
        "threat_intel": "No external intelligence hits",
        "behavior_pattern": "Matches Patch Tuesday schedule",
        "expected_verdict": "FP",
        "expected_severity": "low",
        "expected_action": "ignore",
    }
]

MEDIUM_TEMPLATES = [
    {
        "activity": "OAuth token refresh and mailbox rule creation",
        "threat_intel": "Infrastructure linked to phishing kit (confidence {conf})",
        "behavior_pattern": "Mailbox rules are unusual for this user",
        "expected_verdict": "TP",
        "expected_severity": "critical",
        "expected_action": "escalate",
    },
    {
        "activity": "Bulk artifact download from internal registry",
        "threat_intel": "Internal IP range, no known malicious indicators",
        "behavior_pattern": "In line with weekly release pipeline",
        "expected_verdict": "Benign",
        "expected_severity": "low",
        "expected_action": "ignore",
    },
    {
        "activity": "Bulk export of customer database via API",
        "threat_intel": "IP geo-locates to hosting provider in non-standard region",
        "behavior_pattern": "Export volume 15x normal; user accessed from new device",
        "expected_verdict": "TP",
        "expected_severity": "high",
        "expected_action": "isolate",
    },
    {
        "activity": "Scheduled report generation and email distribution",
        "threat_intel": "No external intelligence hits",
        "behavior_pattern": "Weekly HR report generation matches cron schedule",
        "expected_verdict": "FP",
        "expected_severity": "low",
        "expected_action": "ignore",
    }
]

HARD_TEMPLATES = [
    {
        "activity": "Impossible travel + privileged access request + data staging",
        "threat_intel": "C2 overlap with active ransomware campaign (confidence {conf})",
        "behavior_pattern": "Sequence matches pre-exfiltration kill chain",
        "expected_verdict": "TP",
        "expected_severity": "critical",
        "expected_action": "block",
    },
    {
        "activity": "Large outbound transfer to sanctioned domain lookalike",
        "threat_intel": "Domain has newly observed typo-squat indicators",
        "behavior_pattern": "Transfer volume {mult}x baseline",
        "expected_verdict": "NeedsMoreData",
        "expected_severity": "medium",
        "expected_action": "escalate",
    },
    {
        "activity": "Wire transfer approval from new device + MFA bypass attempt",
        "threat_intel": "IP linked to BEC campaign targeting finance sector ({conf})",
        "behavior_pattern": "User normally approves from office; this is first mobile approval",
        "expected_verdict": "TP",
        "expected_severity": "critical",
        "expected_action": "block",
    },
    {
        "activity": "Unusual spike in API calls with elevated error rates (HTTP 403)",
        "threat_intel": "Source IP rotates across known cloud proxy ranges",
        "behavior_pattern": "Pattern suggests API enumeration or fuzzing attempt",
        "expected_verdict": "NeedsMoreData",
        "expected_severity": "medium",
        "expected_action": "escalate",
    }
]

def generate_case(rng: random.Random, allowed_levels: List[str]) -> AlertCase:
    """Procedurally generate a random alert case based on allowed levels."""
    
    # Select task level
    level = rng.choice(allowed_levels)
    
    # Select template mapping
    if level == "easy":
        pool = EASY_TEMPLATES
    elif level == "medium":
        pool = MEDIUM_TEMPLATES
    else:
        pool = HARD_TEMPLATES
        
    template = rng.choice(pool)
    
    # Resolve dynamic fields
    conf = round(rng.uniform(0.70, 0.99), 2)
    time_str = f"{rng.randint(0, 23):02d}:{rng.choice(['00', '15', '30', '45'])}:00Z"
    mult = rng.randint(20, 80)
    
    activity = template["activity"].format(time=time_str, mult=mult)
    threat_intel = template["threat_intel"].format(conf=conf)
    
    # Generate random IPs and Users
    ip = f"{rng.randint(10, 203)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
    roles = ["finance", "admin", "dev", "hr", "sales", "ceo", "backup"]
    user_names = ["svc", "root", "intern", "system", "mail", "agent", "user"]
    user = f"{rng.choice(roles)}.{rng.choice(user_names)}"
    
    return AlertCase(
        alert_id=f"A-{rng.randint(1000, 9999)}",
        ip=ip,
        user=user,
        activity=activity,
        event_time=f"2026-04-{rng.randint(1, 30):02d}T{time_str}",
        threat_intel=threat_intel,
        behavior_pattern=template["behavior_pattern"],
        expected_verdict=template["expected_verdict"],
        expected_severity=template["expected_severity"],
        expected_action=template["expected_action"],
        task_level=level,
    )


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


# Max steps per task difficulty (used by environment)
TASK_MAX_STEPS: Dict[str, int] = {
    "task_easy_verdict": 1,
    "task_medium_verdict_severity": 2,
    "task_hard_full_triage": 3,
}
