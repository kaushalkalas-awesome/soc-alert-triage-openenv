# Copyright (c) 2026. All rights reserved.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Attack Campaign System for Progressive Alert Scenarios.

This module implements multi-alert attack campaigns that unfold over time,
requiring the agent to detect early-stage indicators before damage occurs.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

try:
    from .utils import AlertCase
except ImportError:
    from utils import AlertCase


@dataclass
class CampaignAlert:
    """A single alert within an attack campaign."""
    
    alert_id: str
    activity: str
    threat_intel: str
    behavior_pattern: str
    expected_verdict: str
    expected_severity: str
    expected_action: str
    time_offset_minutes: int
    stage: str  # e.g., "recon", "initial_access", "persistence", "exfiltration"
    
    # Optional correlation with previous alerts
    correlation_hint: Optional[str] = None


@dataclass
class AttackCampaign:
    """A multi-stage attack campaign definition."""
    
    name: str
    description: str
    alerts: List[CampaignAlert]
    
    @property
    def total_alerts(self) -> int:
        return len(self.alerts)


# Define realistic attack campaigns
RANSOMWARE_CAMPAIGN = AttackCampaign(
    name="Ransomware Attack Chain",
    description="A multi-stage ransomware attack from initial access to encryption",
    alerts=[
        CampaignAlert(
            alert_id="A-CAMP-001",
            activity="Port scan detected from external IP",
            threat_intel="IP not in threat database but shows scanning behavior",
            behavior_pattern="Sequential port scanning pattern detected",
            expected_verdict="NeedsMoreData",
            expected_severity="medium",
            expected_action="escalate",
            time_offset_minutes=0,
            stage="recon",
            correlation_hint="Early reconnaissance activity",
        ),
        CampaignAlert(
            alert_id="A-CAMP-002",
            activity="Failed SSH authentication attempts",
            threat_intel="IP matches previous scan source",
            behavior_pattern="Brute force pattern: 50+ attempts in 5 minutes",
            expected_verdict="TP",
            expected_severity="high",
            expected_action="isolate",
            time_offset_minutes=30,
            stage="initial_access",
            correlation_hint="Correlates with earlier port scan",
        ),
        CampaignAlert(
            alert_id="A-CAMP-003",
            activity="Successful login from new geolocation",
            threat_intel="Login successful after brute force attempts",
            behavior_pattern="User logged in from unusual country",
            expected_verdict="TP",
            expected_severity="critical",
            expected_action="isolate",
            time_offset_minutes=35,
            stage="initial_access",
            correlation_hint="Same IP as brute force attempt",
        ),
        CampaignAlert(
            alert_id="A-CAMP-004",
            activity="PowerShell execution with encoded command",
            threat_intel="Encoded commands often used for evasion",
            behavior_pattern="Suspicious command execution post-login",
            expected_verdict="TP",
            expected_severity="critical",
            expected_action="isolate",
            time_offset_minutes=40,
            stage="execution",
            correlation_hint="Same user session as compromise",
        ),
        CampaignAlert(
            alert_id="A-CAMP-005",
            activity="Shadow copy deletion via vssadmin",
            threat_intel="Backup deletion is ransomware preparation indicator",
            behavior_pattern="Admin tool used for backup removal",
            expected_verdict="TP",
            expected_severity="critical",
            expected_action="block",
            time_offset_minutes=45,
            stage="impact",
            correlation_hint="Part of ongoing attack chain",
        ),
    ]
)

APT_CAMPAIGN = AttackCampaign(
    name="Advanced Persistent Threat",
    description="A stealthy APT campaign with dwell time and data exfiltration",
    alerts=[
        CampaignAlert(
            alert_id="A-APT-001",
            activity="Suspicious email attachment opened",
            threat_intel="Document contains macros",
            behavior_pattern="User opened attachment from unknown sender",
            expected_verdict="NeedsMoreData",
            expected_severity="medium",
            expected_action="escalate",
            time_offset_minutes=0,
            stage="initial_access",
        ),
        CampaignAlert(
            alert_id="A-APT-002",
            activity="Outbound connection to rare domain",
            threat_intel="Domain registered recently",
            behavior_pattern="Beacon-like traffic pattern detected",
            expected_verdict="TP",
            expected_severity="high",
            expected_action="isolate",
            time_offset_minutes=1440,  # 1 day later
            stage="command_control",
            correlation_hint="Possible C2 communication",
        ),
        CampaignAlert(
            alert_id="A-APT-003",
            activity="Lateral movement via SMB",
            threat_intel="Admin credentials used outside business hours",
            behavior_pattern="Access to multiple workstations",
            expected_verdict="TP",
            expected_severity="critical",
            expected_action="isolate",
            time_offset_minutes=2880,  # 2 days later
            stage="lateral_movement",
            correlation_hint="Lateral movement across network",
        ),
        CampaignAlert(
            alert_id="A-APT-004",
            activity="Large data transfer to external cloud",
            threat_intel="Volume 50x normal for this user",
            behavior_pattern="Sensitive file access followed by upload",
            expected_verdict="TP",
            expected_severity="critical",
            expected_action="block",
            time_offset_minutes=4320,  # 3 days later
            stage="exfiltration",
            correlation_hint="Data exfiltration in progress",
        ),
    ]
)

INSIDER_THREAT_CAMPAIGN = AttackCampaign(
    name="Insider Data Theft",
    description="An insider threat scenario with data staging and exfiltration",
    alerts=[
        CampaignAlert(
            alert_id="A-INS-001",
            activity="Unusual after-hours database access",
            threat_intel="Employee with resignation submitted",
            behavior_pattern="Accessing customer database at 2 AM",
            expected_verdict="TP",
            expected_severity="high",
            expected_action="escalate",
            time_offset_minutes=0,
            stage="collection",
        ),
        CampaignAlert(
            alert_id="A-INS-002",
            activity="Bulk export of customer records",
            threat_intel="Export size exceeds normal by 20x",
            behavior_pattern="Query patterns indicate bulk extraction",
            expected_verdict="TP",
            expected_severity="critical",
            expected_action="isolate",
            time_offset_minutes=60,
            stage="collection",
            correlation_hint="Same user as suspicious access",
        ),
        CampaignAlert(
            alert_id="A-INS-003",
            activity="Files copied to USB device",
            threat_intel="USB mass storage device connected",
            behavior_pattern="Large file copy to removable media",
            expected_verdict="TP",
            expected_severity="critical",
            expected_action="block",
            time_offset_minutes=120,
            stage="exfiltration",
            correlation_hint="Physical data exfiltration",
        ),
    ]
)

SUPPLY_CHAIN_CAMPAIGN = AttackCampaign(
    name="Supply Chain Compromise",
    description="Third-party software compromise affecting organization",
    alerts=[
        CampaignAlert(
            alert_id="A-SUP-001",
            activity="Update from vendor pushed to systems",
            threat_intel="Vendor reported compromise yesterday",
            behavior_pattern="Software update installation",
            expected_verdict="NeedsMoreData",
            expected_severity="high",
            expected_action="escalate",
            time_offset_minutes=0,
            stage="initial_access",
        ),
        CampaignAlert(
            alert_id="A-SUP-002",
            activity="Signed binary making C2 connection",
            threat_intel="Binary is legitimately signed but contacting suspicious IP",
            behavior_pattern="Network traffic from trusted application",
            expected_verdict="TP",
            expected_severity="critical",
            expected_action="isolate",
            time_offset_minutes=60,
            stage="command_control",
            correlation_hint="Related to recent update",
        ),
        CampaignAlert(
            alert_id="A-SUP-003",
            activity="Credential dumping attempt detected",
            threat_intel="LSASS access from signed process",
            behavior_pattern="Credential harvesting technique",
            expected_verdict="TP",
            expected_severity="critical",
            expected_action="block",
            time_offset_minutes=120,
            stage="credential_access",
            correlation_hint="Part of supply chain attack",
        ),
    ]
)

AVAILABLE_CAMPAIGNS = [
    RANSOMWARE_CAMPAIGN,
    APT_CAMPAIGN,
    INSIDER_THREAT_CAMPAIGN,
    SUPPLY_CHAIN_CAMPAIGN,
]


class CampaignManager:
    """Manages the progression through an attack campaign."""
    
    def __init__(self, campaign: AttackCampaign, rng: random.Random):
        self.campaign = campaign
        self.rng = rng
        self.current_index = 0
        self.is_active = True
        
    @property
    def total_alerts(self) -> int:
        return len(self.campaign.alerts)
    
    def has_more_alerts(self) -> bool:
        return self.current_index < len(self.campaign.alerts)
    
    def get_next_alert(self) -> AlertCase:
        """Get the next alert in the campaign as an AlertCase."""
        if not self.has_more_alerts():
            raise ValueError("No more alerts in campaign")
        
        campaign_alert = self.campaign.alerts[self.current_index]
        self.current_index += 1
        
        # Generate procedural details
        ip = f"{self.rng.randint(10, 203)}.{self.rng.randint(0, 255)}.{self.rng.randint(0, 255)}.{self.rng.randint(1, 254)}"
        roles = ["finance", "admin", "dev", "hr", "sales", "ceo"]
        user_names = ["svc", "user", "admin", "system"]
        user = f"{self.rng.choice(roles)}.{self.rng.choice(user_names)}"
        
        return AlertCase(
            alert_id=campaign_alert.alert_id,
            ip=ip,
            user=user,
            activity=campaign_alert.activity,
            event_time=f"2026-04-12T{self.rng.randint(0, 23):02d}:{self.rng.choice(['00', '15', '30', '45'])}:00Z",
            threat_intel=campaign_alert.threat_intel,
            behavior_pattern=campaign_alert.behavior_pattern,
            expected_verdict=campaign_alert.expected_verdict,
            expected_severity=campaign_alert.expected_severity,
            expected_action=campaign_alert.expected_action,
            task_level="hard",
        )
    
    def get_context(self) -> Dict[str, Any]:
        """Get campaign context for the current alert."""
        if self.current_index == 0:
            return {
                "campaign_name": self.campaign.name,
                "campaign_description": self.campaign.description,
                "alert_position": f"1/{self.total_alerts}",
                "stage": self.campaign.alerts[0].stage if self.campaign.alerts else "unknown",
            }
        
        # Get previous alert info for correlation
        prev_alert = self.campaign.alerts[self.current_index - 1] if self.current_index > 0 else None
        
        return {
            "campaign_name": self.campaign.name,
            "alert_position": f"{self.current_index}/{self.total_alerts}",
            "stage": self.campaign.alerts[self.current_index].stage if self.has_more_alerts() else "complete",
            "previous_alert_summary": prev_alert.activity if prev_alert else None,
            "correlation_hint": self.campaign.alerts[self.current_index].correlation_hint if self.has_more_alerts() else None,
        }


def get_campaign_for_task(rng: random.Random) -> CampaignManager:
    """Get a random campaign manager for hard tasks."""
    campaign = rng.choice(AVAILABLE_CAMPAIGNS)
    return CampaignManager(campaign, rng)
