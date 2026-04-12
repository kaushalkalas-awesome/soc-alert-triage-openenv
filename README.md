---
title: SOC Alert Triage OpenEnv
emoji: 🛡️
colorFrom: blue
colorTo: indigo
sdk: docker
pinned: false
app_port: 7860
base_path: /docs
tags:
  - openenv
---

# 🛡️ SOC Alert Triage OpenEnv

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)
![OpenEnv Supported](https://img.shields.io/badge/OpenEnv-Supported-FF6F00)
![Status: Beta](https://img.shields.io/badge/Status-Beta-orange)

**SOC Alert Triage OpenEnv** is a generic, interactive training and benchmarking environment built upon the OpenEnv framework. It is designed to evaluate Large Language Models (LLMs) and autonomous agents on their ability to perform complex, multi-step cybersecurity alert triage mirroring the workflows of human Security Operations Center (SOC) analysts.

---

## 📖 Table of Contents

- [Overview & Capabilities](#-overview--capabilities)
- [Environment Architecture](#-environment-architecture)
  - [Observation Space](#observation-space)
  - [Action Space & MCP Tool Calling](#action-space--mcp-tool-calling)
  - [Task Tiers & Multi-Step Logic](#task-tiers--multi-step-logic)
- [Grading Engine & Reward Function](#-grading-engine--reward-function)
- [Installation & Quick Start](#-installation--quick-start)
- [Baseline Scores](#-baseline-scores)
- [Hackathon Inference Runner](#-hackathon-inference-runner)
- [OpenEnv Verification](#-openenv-verification)

---

## 🎯 Overview & Capabilities

Modern SOC teams process an overwhelming volume of security alerts with limited analyst bandwidth. The capability to accurately triage anomalies—minimizing Mean-Time-To-Respond (MTTR) while preventing catastrophic false negatives—is critical.

This environment trains and benchmarks agents against those rigorous expectations using:

*   **Procedural Alert Generation:** 36+ unique alert templates (12 per difficulty tier) are dynamically synthesized across random IP addresses, user patterns, and temporal variations. Test data cannot be memorized.
*   **Alert Correlation Scenarios:** Hard tasks include correlated multi-alert patterns (ransomware kill chains, BEC campaigns, insider threats) that require holistic analysis.
*   **Alert Fatigue Simulation:** Time pressure mechanics simulate real-world SOC stress—agents must make high-stakes decisions within time windows (30-120 seconds).
*   **Iterative Multi-Step Reasoning:** The environment fosters self-correction. Agents receive targeted feedback on incorrect deductions and are afforded multiple steps to refine their triage hypotheses.
*   **Information Gathering (MCP Tools):** Rather than blindly guessing, agents can query synthetic Threat Intelligence, audit user history, or analyze payloads dynamically before rendering a final judgment.
*   **Granular Partial Credit:** Reward function provides meaningful signal even for imperfect answers through similarity-based scoring of verdicts, severities, and actions.

---

## 🏗️ Environment Architecture

### Observation Space

Upon invoking `reset()` or iterating via `step()`, the environment yields an observation state representing the SIEM (Security Information and Event Management) console:

```json
{
  "alert_id": "A-7294",
  "task_name": "task_hard_full_triage",
  "state": {
    "ip": "45.33.32.156",
    "user": "research.lab",
    "activity": "Cryptocurrency mining process detected on GPU cluster",
    "event_time": "2026-04-08T12:00:00Z",
    "threat_intel": "Mining pool address matches known cryptojacking infrastructure",
    "behavior_pattern": "GPU utilization spiked to 100% outside experiment hours",
    "tool_history": ["[Tool] check_user_history('research.lab') -> Profile matches...", "..."],
    "feedback": "Severity 'low' seems off. Consider the threat intel confidence.",
    "related_alerts": [
      {
        "alert_id": "A-7294-1",
        "activity": "Suspicious outbound connection to mining pool",
        "time_offset_minutes": 15
      }
    ],
    "time_pressure_seconds": 60,
    "alert_fatigue_warning": "HIGH PRIORITY: Time-sensitive alert. Recommend decision within 60 seconds."
  },
  "expected_action_schema": { ... }
}
```

*Note: `feedback`, `tool_history`, `related_alerts`, and `time_pressure` manifest dynamically as the episode progresses.*

### Action Space & MCP Tool Calling

The agent interacts via a structured JSON action dictionary. To support flexible workflows, the environment processes two distinct action variants seamlessly:

#### Option 1: Tool Execution (Information Gathering)
For environments lacking sufficient initial context, agents may invoke external checks:
```json
{
  "tool_name": "query_threat_intel",
  "tool_query": "45.33.32.156"
}
```
*Supported Tools:* `query_threat_intel`, `check_user_history`, `analyze_payload`

#### Option 2: Final Triage Decision
When sufficient confidence is achieved, the agent commits a final triage disposition:
```json
{
  "verdict": "TP", 
  "severity": "high", 
  "response_action": "isolate"
}
```
*Valid Options:* 
*   **Verdict**: `TP`, `FP`, `Benign`, `NeedsMoreData`
*   **Severity**: `critical`, `high`, `medium`, `low`
*   **Response Action**: `block`, `isolate`, `escalate`, `ignore`

---

### Task Tiers & Multi-Step Logic

The evaluation suite encompasses three progressive difficulty tiers:

#### 1. `task_easy_verdict` (Easy)
*   **Scope**: Formulate a basic `verdict` categorization (TP, FP, Benign, NeedsMoreData)
*   **Constraints**: 1 Step Maximum (No iteration)
*   **Alert Types**: Clear-cut scenarios (malware detection, brute force, scheduled maintenance)
*   **Success Criteria**: Exact verdict match
*   **Expected Baseline**: 75-85% accuracy with GPT-4o-mini

#### 2. `task_medium_verdict_severity` (Medium)
*   **Scope**: Assess both `verdict` and incident `severity`
*   **Constraints**: 2 Steps Maximum. Supports targeted feedback on the first failure.
*   **Alert Types**: Ambiguous scenarios requiring contextual judgment (DLP alerts, privilege escalation, lateral movement)
*   **Success Criteria**: Both verdict (65%) and severity (35%) weighted scoring with partial credit for adjacent severities
*   **Expected Baseline**: 60-70% weighted score with GPT-4o-mini

#### 3. `task_hard_full_triage` (Hard)
*   **Scope**: Comprehensive triage requiring `verdict`, `severity`, and strategic `response_action`
*   **Constraints**: 3 Steps Maximum. Risk-aware penalties are actively enforced.
*   **Alert Types**: 
    *   Complex multi-stage attacks (ransomware kill chains, supply chain compromises)
    *   Alert correlation scenarios requiring holistic analysis
    *   Novel attack patterns (zero-days, deepfake fraud)
    *   Insider threat detection
*   **Time Pressure**: 30-120 second decision windows for 40% of alerts (alert fatigue simulation)
*   **Success Criteria**: Full triage (45% verdict, 25% severity, 20% action) with safety penalties for false negatives and disruptive overreactions
*   **Expected Baseline**: 50-65% weighted score with GPT-4o-mini

---

## ⚖️ Grading Engine & Reward Function

The deterministic grading engine returns normalized rewards (`[0.01, 0.99]`). Multi-step episodes operate on a "best-reward" strategy, actively incentivizing exploration and correction.

### Granular Partial Credit System

| Component | Scoring Logic |
| :--- | :--- |
| **Verdict** | Exact: 1.0 • TP/NeedsMoreData: 0.5 • FP/Benign: 0.6 • Adjacent: 0.1-0.3 |
| **Severity** | Exact: 1.0 • Adjacent level: 0.5 • Two levels: 0.2 • Otherwise: 0.0 |
| **Action** | Exact: 1.0 • Same category: 0.3 • Context-appropriate: 0.2-0.4 |

### Task Weighting

| Task | Verdict | Severity | Action | Bonus/Penalty |
| :--- | :---: | :---: | :---: | :--- |
| **Easy** | 100% | - | - | Valid input: +0.05 |
| **Medium** | 65% | 35% | - | Valid input: +0.05 |
| **Hard** | 45% | 25% | 20% | Policy: +0.10, Correlated: +0.10 |

### Safety Penalties (Hard Task)

| Violation | Penalty | Rationale |
| :--- | :---: | :--- |
| **Critical False Negative** | -0.40 | Missing critical threats has high organizational cost |
| **High Severity False Negative** | -0.25 | Missing high-severity threats is costly |
| **Disruptive Overreaction** | -0.20 | Blocking benign users impacts productivity |

*Episodes terminate early automatically if an agent achieves a perfect `0.99`.*

---

## 🚀 Installation & Quick Start

### 🐳 Option A: Using Docker (Recommended)

```bash
# Clone the repository
git clone <repository-url> && cd soc_alert_triage_openenv

# Build and deploy the container
docker build -t soc-openenv:latest .
docker run --rm -p 7860:7860 soc-openenv:latest

# Verify environment health
curl http://localhost:7860/health
# Expected: {"status":"healthy","service":"soc_openenv"}
```

### 💻 Option B: Local Python Environment

```bash
# Initialize and activate a virtual environment (Python 3.10+)
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Boot the OpenEnv ASGI server
uvicorn server.app:app --host 0.0.0.0 --port 7860
```

---

## 📊 Baseline Scores

The following baseline scores were obtained using `gpt-4o-mini` with the provided `inference.py` script:

| Task | Metric | Score | Notes |
| :--- | :--- | :--- | :--- |
| **task_easy_verdict** | Average Reward | 0.82 | 5 episodes, clear binary classification |
| **task_medium_verdict_severity** | Medium Reward | 0.68 | 5 episodes, weighted partial credit |
| **task_hard_full_triage** | Average Reward | 0.58 | 5 episodes, with correlation scenarios |
| **Overall** | Mean Score | 0.69 | Balanced across all difficulty tiers |

### Score Interpretation

- **0.90-0.99**: Expert-level SOC analyst performance
- **0.70-0.89**: Competent analyst performance
- **0.50-0.69**: Junior analyst performance
- **0.01-0.49**: Below acceptable threshold

### Running Baseline

```bash
# Set environment variables
export API_BASE_URL="https://api.openai.com/v1"
export MODEL_NAME="gpt-4o-mini"
export API_KEY="your-api-key"

# Run baseline
python inference.py
```

---

## 🤖 Hackathon Inference Runner

The `inference.py` script serves as the primary benchmark execution runner and conforms entirely to the mandatory parsing and STDOUT logging requirements format required for automated grading.

**Enterprise Readiness Features Built-in:**
*   **Self-Healing JSON parsing:** Automatically catches and injects parse-failures as feedback context, allowing the LLM to instantly correct hallucinated formatting.
*   **Quota Fallback Tolerance:** Proactively intercepts `HTTP 402/429` (Rate-Limit / Depleted Credits) errors and deploys a safe fallback action rather than crashing the testing suite. 
*   **Multi-Step Self-Correction:** Leverages environment feedback to refine decisions across episode steps.
*   **Tool Calling Support:** Automatically handles tool execution vs final decision actions.

### Configuration
```bash
# Required Environment Variables
export API_BASE_URL="https://api.openai.com/v1" # Or designated LiteLLM proxy
export MODEL_NAME="gpt-4o-mini"
export API_KEY="your-api-authorization-token"
```

### Execution
```bash
python inference.py
```

---

## 🔍 OpenEnv Verification

This environment fully complies with the `OpenEnv` spec interface. 
*   Manifest: `openenv.yaml` (`spec_version: 1`, `type: space`)
*   Server Instance: `server.environment:SocAlertTriageEnvironment`
*   Network Port: `:7860` 

For optional manual verification or integration into an external harness, see the local `client.py` structure.

### Running Tests

```bash
# Install test dependencies
pip install pytest pytest-asyncio

# Run test suite
pytest tests/ -v
```

---

## 🏆 Novelty & Contributions

This environment introduces several novel features for SOC simulation:

1. **Alert Correlation Patterns**: Multi-alert scenarios requiring holistic analysis (30% of hard tasks)
2. **Alert Fatigue Mechanics**: Time pressure simulation for realistic SOC stress modeling
3. **Granular Partial Credit**: Similarity-based scoring for meaningful reward signals
4. **Safety-First Penalties**: Explicit penalties for high-risk errors (false negatives, overreactions)
5. **Tool-Augmented Decision Making**: Information gathering before commitment

---

## 📄 License

MIT License - See LICENSE file for details.

## 🤝 Contributing

Contributions welcome! Please ensure:
- All tests pass (`pytest tests/`)
- Code follows existing style patterns
- New alert templates maintain balance across verdict types
- Documentation is updated for new features
