# Copyright (c) 2026. All rights reserved.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Utility helpers for SOC alert simulation data."""

from __future__ import annotations

import random
import uuid
from dataclasses import dataclass
from typing import Dict, List, Optional


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
    # For correlated alert scenarios (hard tasks)
    related_alerts: Optional[List[Dict]] = None
    time_pressure: Optional[int] = None  # Seconds to decide (None = no pressure)


# Templates for procedural generation - EXPANDED for better variety
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
    },
    # NEW: Additional easy templates
    {
        "activity": "Malware signature detected in email attachment",
        "threat_intel": "File hash matches known trojan (confidence {conf})",
        "behavior_pattern": "User opened attachment from external sender",
        "expected_verdict": "TP",
        "expected_severity": "high",
        "expected_action": "isolate",
    },
    {
        "activity": "Database backup process completed successfully",
        "threat_intel": "No external intelligence hits",
        "behavior_pattern": "Scheduled nightly backup - normal operation",
        "expected_verdict": "Benign",
        "expected_severity": "low",
        "expected_action": "ignore",
    },
    {
        "activity": "Suspicious PowerShell downloading executable from Pastebin",
        "threat_intel": "URL identified as malware distribution point",
        "behavior_pattern": "Encoded command execution detected",
        "expected_verdict": "TP",
        "expected_severity": "critical",
        "expected_action": "block",
    },
    {
        "activity": "VPN login from employee home IP during work hours",
        "threat_intel": "No external intelligence hits",
        "behavior_pattern": "IP registered to employee - consistent with WFH policy",
        "expected_verdict": "Benign",
        "expected_severity": "low",
        "expected_action": "ignore",
    },
    {
        "activity": "RDP connection from foreign country at 3 AM local time",
        "threat_intel": "IP flagged in fraud database (confidence {conf})",
        "behavior_pattern": "Impossible travel - user logged in from office 2 hours ago",
        "expected_verdict": "TP",
        "expected_severity": "high",
        "expected_action": "isolate",
    },
    {
        "activity": "CI/CD pipeline deploying to staging environment",
        "threat_intel": "No external intelligence hits",
        "behavior_pattern": "Service account performing authorized deployment",
        "expected_verdict": "FP",
        "expected_severity": "low",
        "expected_action": "ignore",
    },
    {
        "activity": "USB device connected with autorun executable",
        "threat_intel": "Device serial matches known BadUSB (confidence {conf})",
        "behavior_pattern": "Unauthorized USB insertion on executive workstation",
        "expected_verdict": "TP",
        "expected_severity": "critical",
        "expected_action": "block",
    },
    {
        "activity": "Internal DNS query for known legitimate domain",
        "threat_intel": "No external intelligence hits",
        "behavior_pattern": "Standard corporate application communication",
        "expected_verdict": "Benign",
        "expected_severity": "low",
        "expected_action": "ignore",
    },
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
    },
    # NEW: Additional medium templates
    {
        "activity": "Lateral movement detected via SMB to domain controller",
        "threat_intel": "Technique matches APT29 TTPs (confidence {conf})",
        "behavior_pattern": "Admin tool usage outside maintenance window",
        "expected_verdict": "TP",
        "expected_severity": "high",
        "expected_action": "isolate",
    },
    {
        "activity": "User downloading multiple files from cloud storage",
        "threat_intel": "Domain is legitimate corporate SharePoint",
        "behavior_pattern": "User preparing for offline work - within normal range",
        "expected_verdict": "Benign",
        "expected_severity": "low",
        "expected_action": "ignore",
    },
    {
        "activity": "Privilege escalation via sudo exploit attempt",
        "threat_intel": "CVE-2021-3156 exploitation signature detected",
        "behavior_pattern": "Unusual command sequence for this service account",
        "expected_verdict": "TP",
        "expected_severity": "critical",
        "expected_action": "block",
    },
    {
        "activity": "Night shift employee accessing payroll system",
        "threat_intel": "No external intelligence hits",
        "behavior_pattern": "HR manager on scheduled night shift - authorized access",
        "expected_verdict": "FP",
        "expected_severity": "low",
        "expected_action": "ignore",
    },
    {
        "activity": "DLP alert: Credit card numbers in outbound email",
        "threat_intel": "Recipient domain is partner payment processor",
        "behavior_pattern": "Quarterly payment processing - expected pattern",
        "expected_verdict": "Benign",
        "expected_severity": "low",
        "expected_action": "ignore",
    },
    {
        "activity": "Kerberoasting attack detected on service accounts",
        "threat_intel": "TGS-REQ pattern matches attack tools (confidence {conf})",
        "behavior_pattern": "Multiple SPN requests in short timeframe",
        "expected_verdict": "TP",
        "expected_severity": "high",
        "expected_action": "escalate",
    },
    {
        "activity": "MFA bypass attempt via push notification fatigue",
        "threat_intel": "IP previously associated with account takeover",
        "behavior_pattern": "15+ MFA prompts in 2 minutes - automated attack",
        "expected_verdict": "TP",
        "expected_severity": "high",
        "expected_action": "block",
    },
    {
        "activity": "Developer pushing code to feature branch",
        "threat_intel": "No external intelligence hits",
        "behavior_pattern": "Normal development workflow - code review pending",
        "expected_verdict": "Benign",
        "expected_severity": "low",
        "expected_action": "ignore",
    },
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
    },
    # NEW: Additional hard templates with complex scenarios
    {
        "activity": "Supply chain compromise: Signed binary making C2 connection",
        "threat_intel": "Certificate valid but binary hash flagged by {conf} vendors",
        "behavior_pattern": "Legitimate software exhibiting anomalous network behavior",
        "expected_verdict": "TP",
        "expected_severity": "critical",
        "expected_action": "block",
    },
    {
        "activity": "Living-off-the-land: PowerShell downloading from CDN with legitimate cert",
        "threat_intel": "Domain used for both legitimate and malicious content",
        "behavior_pattern": "Script execution follows admin playbook but at unusual time",
        "expected_verdict": "NeedsMoreData",
        "expected_severity": "medium",
        "expected_action": "escalate",
    },
    {
        "activity": "Ransomware preparation: Shadow copy deletion + backup tampering",
        "threat_intel": "TTPs match Conti ransomware affiliate (confidence {conf})",
        "behavior_pattern": "Multi-stage attack across {mult} systems simultaneously",
        "expected_verdict": "TP",
        "expected_severity": "critical",
        "expected_action": "block",
    },
    {
        "activity": "Insider threat: Employee accessing competitor IP before resignation",
        "threat_intel": "No external intelligence hits",
        "behavior_pattern": "Data access pattern shifted 2 weeks before notice period",
        "expected_verdict": "TP",
        "expected_severity": "high",
        "expected_action": "isolate",
    },
    {
        "activity": "Zero-day exploitation attempt: Unknown pattern in web logs",
        "threat_intel": "Payload structure doesn't match known signatures",
        "behavior_pattern": "Sophisticated evasion - WAF bypass with encoding",
        "expected_verdict": "NeedsMoreData",
        "expected_severity": "high",
        "expected_action": "escalate",
    },
    {
        "activity": "Cryptocurrency mining on compromised cloud resources",
        "threat_intel": "Wallet address linked to mining pool (confidence {conf})",
        "behavior_pattern": "CPU/GPU utilization {mult}x baseline, obfuscated process names",
        "expected_verdict": "TP",
        "expected_severity": "high",
        "expected_action": "isolate",
    },
    {
        "activity": "Deepfake-enabled CEO fraud: Synthetic voice authorization",
        "threat_intel": "Audio analysis shows {conf} probability of deepfake",
        "behavior_pattern": "Urgent wire request outside normal approval process",
        "expected_verdict": "TP",
        "expected_severity": "critical",
        "expected_action": "block",
    },
    {
        "activity": "Novel persistence mechanism: WMI subscription with encoded payload",
        "threat_intel": "Technique described in recent threat research (confidence {conf})",
        "behavior_pattern": "Persistence established via legitimate admin tool",
        "expected_verdict": "TP",
        "expected_severity": "critical",
        "expected_action": "block",
    },
]

# Alert correlation scenarios for hard task multi-alert mode
CORRELATED_SCENARIOS = [
    {
        "name": "Ransomware Kill Chain",
        "time_pressure": 60,  # 60 seconds to decide
        "alerts": [
            {
                "activity": "PsExec execution on multiple workstations",
                "threat_intel": "Lateral movement tool usage detected",
                "behavior_pattern": "Admin tool used outside IT hours",
                "verdict": "TP",
                "severity": "high",
            },
            {
                "activity": "Shadow copy deletion via vssadmin",
                "threat_intel": "Ransomware preparation indicator",
                "behavior_pattern": "Backup deletion precedes encryption",
                "verdict": "TP",
                "severity": "critical",
            },
            {
                "activity": "Mass file modification with .locked extension",
                "threat_intel": "Encryption pattern matches known ransomware",
                "behavior_pattern": "Rapid file changes across network shares",
                "verdict": "TP",
                "severity": "critical",
            },
        ],
        "expected_collective_action": "block",
    },
    {
        "name": "BEC Campaign",
        "time_pressure": 45,
        "alerts": [
            {
                "activity": "Email rule created to forward invoices",
                "threat_intel": "Rule creation from new geolocation",
                "behavior_pattern": "Unusual mailbox automation",
                "verdict": "TP",
                "severity": "high",
            },
            {
                "activity": "Vendor payment detail change request",
                "threat_intel": "Domain similar to legitimate vendor",
                "behavior_pattern": "Urgent change with grammatical errors",
                "verdict": "TP",
                "severity": "critical",
            },
        ],
        "expected_collective_action": "block",
    },
    {
        "name": "Insider Data Exfiltration",
        "time_pressure": 90,
        "alerts": [
            {
                "activity": "Access to sensitive IP database",
                "threat_intel": "No external intelligence hits",
                "behavior_pattern": "Employee with resignation pending",
                "verdict": "TP",
                "severity": "high",
            },
            {
                "activity": "Large zip file creation on workstation",
                "threat_intel": "No external intelligence hits",
                "behavior_pattern": "Compression of confidential documents",
                "verdict": "TP",
                "severity": "high",
            },
            {
                "activity": "Upload to personal cloud storage",
                "threat_intel": "Consumer-grade storage service",
                "behavior_pattern": "Corporate data to personal account",
                "verdict": "TP",
                "severity": "critical",
            },
        ],
        "expected_collective_action": "isolate",
    },
]


def generate_case(rng: random.Random, allowed_levels: List[str], use_correlation: bool = False) -> AlertCase:
    """Procedurally generate a random alert case based on allowed levels.
    
    Args:
        rng: Random number generator
        allowed_levels: List of difficulty levels to sample from
        use_correlation: If True, generate a correlated multi-alert scenario
    """
    
    # For hard tasks, sometimes use correlated scenarios (30% chance)
    if use_correlation and "hard" in allowed_levels and rng.random() < 0.3:
        return generate_correlated_case(rng)
    
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
    behavior = template["behavior_pattern"].format(mult=mult)
    
    # Generate random IPs and Users
    ip = f"{rng.randint(10, 203)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
    roles = ["finance", "admin", "dev", "hr", "sales", "ceo", "backup", "security", "ops"]
    user_names = ["svc", "root", "intern", "system", "mail", "agent", "user", "admin", "bot"]
    user = f"{rng.choice(roles)}.{rng.choice(user_names)}"
    
    # Hard tasks sometimes have time pressure
    time_pressure = None
    if level == "hard" and rng.random() < 0.4:
        time_pressure = rng.randint(30, 120)  # 30-120 seconds
    
    return AlertCase(
        alert_id=f"A-{rng.randint(1000, 9999)}",
        ip=ip,
        user=user,
        activity=activity,
        event_time=f"2026-04-{rng.randint(1, 30):02d}T{time_str}",
        threat_intel=threat_intel,
        behavior_pattern=behavior,
        expected_verdict=template["expected_verdict"],
        expected_severity=template["expected_severity"],
        expected_action=template["expected_action"],
        task_level=level,
        time_pressure=time_pressure,
    )


def generate_correlated_case(rng: random.Random) -> AlertCase:
    """Generate a correlated multi-alert scenario for hard tasks."""
    scenario = rng.choice(CORRELATED_SCENARIOS)
    
    # Generate a base case from the first alert
    base_alert = scenario["alerts"][0]
    conf = round(rng.uniform(0.75, 0.98), 2)
    time_str = f"{rng.randint(0, 23):02d}:{rng.choice(['00', '15', '30', '45'])}:00Z"
    
    ip = f"{rng.randint(10, 203)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
    roles = ["finance", "admin", "dev", "hr", "sales", "ceo"]
    user_names = ["svc", "root", "intern", "system", "mail"]
    user = f"{rng.choice(roles)}.{rng.choice(user_names)}"
    
    # Build related alerts list
    related = []
    for i, alert in enumerate(scenario["alerts"][1:], 1):
        related.append({
            "alert_id": f"A-{rng.randint(1000, 9999)}-{i}",
            "activity": alert["activity"],
            "threat_intel": alert["threat_intel"],
            "behavior_pattern": alert["behavior_pattern"],
            "time_offset_minutes": i * rng.randint(5, 30),
        })
    
    return AlertCase(
        alert_id=f"A-{rng.randint(1000, 9999)}",
        ip=ip,
        user=user,
        activity=base_alert["activity"],
        event_time=f"2026-04-{rng.randint(1, 30):02d}T{time_str}",
        threat_intel=base_alert["threat_intel"].format(conf=conf),
        behavior_pattern=f"[CORRELATED: {scenario['name']}] {base_alert['behavior_pattern']}",
        expected_verdict="TP",  # Correlated scenarios are always true positives
        expected_severity="critical",  # Escalate due to pattern
        expected_action=scenario["expected_collective_action"],
        task_level="hard",
        related_alerts=related,
        time_pressure=scenario.get("time_pressure"),
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
