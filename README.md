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
- [Hackathon Inference Runner](#-hackathon-inference-runner)
- [OpenEnv Verification](#-openenv-verification)

---

## 🎯 Overview & Capabilities

Modern SOC teams process an overwhelming volume of security alerts with limited analyst bandwidth. The capability to accurately triage anomalies—minimizing Mean-Time-To-Respond (MTTR) while preventing catastrophic false negatives—is critical.

This environment trains and benchmarks agents against those rigorous expectations using:

*   **Procedural Alert Generation:** Alerts are dynamically synthesized across random IP addresses, user patterns, and temporal variations. Test data cannot be memorized.
*   **Iterative Multi-Step Reasoning:** The environment fosters self-correction. Agents receive targeted feedback on incorrect deductions and are afforded multiple steps to refine their triage hypotheses.
*   **Information Gathering (MCP Tools):** Rather than blindly guessing, agents can query synthetic Threat Intelligence, audit user history, or analyze payloads dynamically before rendering a final judgment.

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
    "feedback": "Severity 'low' seems off. Consider the threat intel confidence."
  },
  "expected_action_schema": { ... }
}
```

*Note: `feedback` and `tool_history` manifest dynamically as the episode progresses.*

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

1. **`task_easy_verdict` (Easy)**
   * **Scope**: Formulate a basic `verdict` categorization.
   * **Constraints**: 1 Step Maximum (No iteration).
2. **`task_medium_verdict_severity` (Medium)**
   * **Scope**: Asses both `verdict` and incident `severity`.
   * **Constraints**: 2 Steps Maximum. Supports targeted feedback on the first failure.
3. **`task_hard_full_triage` (Hard)**
   * **Scope**: Comprehensive triage requiring `verdict`, `severity`, and strategic `response_action`.
   * **Constraints**: 3 Steps Maximum. Risk-aware penalties are actively enforced.

---

## ⚖️ Grading Engine & Reward Function

The deterministic grading engine returns normalized rewards (`[0.0, 1.0]`). Multi-step episodes operate on a "best-reward" strategy, actively incentivizing exploration and correction.

| Criterion | Logic & Weighting |
| :--- | :--- |
| **Easy** | **1.00** Exact match |
| | **0.50** Partial Credit *(e.g., `TP` mistaken for `NeedsMoreData`)* |
| **Medium** | **0.65** `verdict` + **0.35** `severity` |
| **Hard** | **0.45** `verdict` + **0.25** `severity` + **0.20** `action` <br> + **0.10** Syntax & Adherence Bonus |
| **Penalties** | **-0.40** Missed Critical Incident *(False Negative)* <br> **-0.20** Disruptive Overreaction *(Blocking a Benign user)* |

*Episodes terminate early automatically if an agent achieves a perfect `1.0`.*

---

## 🚀 Installation & Quick Start

### 🐳 Option A: Using Docker (Recommended)

```bash
# Clone the repository
git clone <repository-url> && cd soc_openenv

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
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Boot the OpenEnv ASGI server
uvicorn server.app:app --host 0.0.0.0 --port 7860
```

---

## 🤖 Hackathon Inference Runner

The `inference.py` script serves as the primary benchmark execution runner and conforms entirely to the mandatory parsing and STDOUT logging requirements format required for automated grading.

**Enterprise Readiness Features Built-in:**
*   **Self-Healing JSON parsing:** Automatically catches and injects parse-failures as feedback context, allowing the LLM to instantly correct hallucinated formatting.
*   **Quota Fallback Tolerance:** Proactively intercepts `HTTP 402/429` (Rate-Limit / Depleted Credits) errors and deploys a safe fallback action rather than crashing the testing suite. 

### Configuration
```bash
# Required Environment Variables
export API_BASE_URL="https://api.openai.com/v1" # Or designated LiteLLM proxy
export MODEL_NAME="gpt-4o-mini"
export API_KEY="your-api-authorization-token"
```

### Execution
```bash
python3 inference.py
```

---

## 🔍 OpenEnv Verification

This environment fully complies with the `OpenEnv` spec interface. 
*   Manifest: `openenv.yaml` (`spec_version: 1`, `type: space`)
*   Server Instance: `server.environment:SocAlertTriageEnvironment`
*   Network Port: `:7860` 

For optional manual verification or integration into an external harness, see the local `client.py` structure.
