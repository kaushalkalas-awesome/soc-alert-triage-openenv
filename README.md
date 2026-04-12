# SOC Alert Triage OpenEnv

An OpenEnv-style training environment where an AI agent learns to triage cybersecurity alerts like a SOC analyst.

## 1) Environment Description

This environment simulates real SOC alert analysis workflows:
- ingest an alert and context,
- decide whether it is true or false positive,
- assign severity,
- choose the operational response.

### Real-world utility
- SOC teams process high alert volume with limited analyst bandwidth.
- Faster and safer triage reduces mean-time-to-respond (MTTR) and breach risk.
- This setup trains and benchmarks alert triage decision quality.

## 2) Observation Space

`reset()` returns an observation object:
- `alert_id`
- `task_name`
- `state`:
  - `ip`
  - `user`
  - `activity`
  - `event_time`
  - `threat_intel`
  - `behavior_pattern`
- `expected_action_schema`

## 3) Action Space

The agent submits a dictionary:
- `verdict`: `TP | FP | Benign | NeedsMoreData`
- `severity`: `critical | high | medium | low`
- `response_action`: `block | isolate | escalate | ignore`

## 4) Task Definitions (Exactly 3)

1. `task_easy_verdict` (Easy, target >= 0.85)  
   Agent predicts verdict only.

2. `task_medium_verdict_severity` (Medium, target >= 0.70)  
   Agent predicts verdict + severity.

3. `task_hard_full_triage` (Hard, target >= 0.75)  
   Agent predicts verdict + severity + response action with risk-aware penalties.

## 5) Grader & Reward Design

All graders are deterministic and return score in `[0, 1]`.

- Easy: verdict correctness.
- Medium: weighted partial credit:
  - verdict `0.65`
  - severity `0.35`
- Hard: weighted partial credit + penalties:
  - verdict `0.45`
  - severity `0.25`
  - response action `0.20`
  - policy-valid action bonus `0.10`
  - false-negative on critical threat penalty `-0.40`
  - disruptive overreaction on benign/FP penalty `-0.20`

## 6) OpenEnv Interface Compliance

OpenEnv app manifest (`openenv.yaml`):

- `spec_version: 1`
- `type: space`
- `runtime: fastapi`
- `app: server.app:app`
- `port: 7860`

Environment class:

- `server.environment:SocAlertTriageEnvironment`

Client class:

- `client:SocAlertTriageEnv`

Server wiring follows OpenEnv's `create_app(...)` pattern used by official examples.

## 7) Docker (Recommended)

```bash
cd soc_openenv
docker build -t soc-openenv:latest .
docker run --rm -p 7860:7860 soc-openenv:latest
curl http://localhost:7860/health
```

On Server health success response will be: `{"status":"healthy","service":"soc_openenv"}`

## 8) Without Docker

```bash
cd soc_openenv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn server.app:app --host 0.0.0.0 --port 7860
```

## 9) Quick Start (Demo)

For a quick demo, simply update `llm_api_key` in `scenario_config.json` and run:

```bash
python client.py --scenario scenario_config.json
```

The existing config includes sample scenarios for all three difficulty tiers.

### Configure Scenario

To customize for your use case, edit `scenario_config.json` and update these fields:

**LLM variables:**
- `llm_api_key` - Your OpenAI/Anthropic/Google API key (or set via env var)
- `llm_model` - Model name (e.g., `gpt-4o-mini`, `claude-3-5-sonnet-20241022`)
- `llm_provider` - Provider: `openai`, `anthropic`, or `google`

**Scenario variables:**
- `system_prompt` - Instructions for agent behavior
- `user_prompt` - Task template for the agent
- `tasks` - List of task configurations with difficulty tiers
- `verifiers` - Validation rules for task completion

### Run Client

Run scenario-based benchmark:

```bash
python client.py --scenario scenario_config.json
```

Output will be saved to `response_output/` folder with execution details and results.

Interactive single-step mode:

```bash
python client.py --task task_easy_verdict --seed 42
```

## 10) Required Environment Variables

- `API_BASE_URL` - LLM API endpoint
- `MODEL_NAME` - Model identifier for inference
- `HF_TOKEN` - Authentication token for API

Example:

```bash
export API_BASE_URL="https://api.openai.com/v1"
export MODEL_NAME="gpt-4o-mini"
export HF_TOKEN="your_token"
```

## 11) Baseline Inference

`inference.py`:
- initializes OpenAI client using required env vars,
- runs 3 tasks over multiple episodes,
- prints structured logs:
  - `[START]`
  - `[STEP]`
  - `[END]`

```bash
python inference.py
```

## 12) Hugging Face Space

1. Create Docker Space.
2. Upload this project.
3. Add secrets:
   - `API_BASE_URL`
   - `MODEL_NAME`
   - `HF_TOKEN`
4. Add tag: `openenv`.
