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

Environment class: `soc_env.env:SocAlertTriageEnv`

- `reset() -> (observation, info)`
- `step(action) -> (next_observation, reward, terminated, truncated, info)`
- `state() -> dict`

## 7) Setup & Local Run

```bash
cd soc_openenv
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest -q
python inference.py
```

## 8) Required Environment Variables

- `API_BASE_URL`
- `MODEL_NAME`
- `HF_TOKEN`

Example:

```bash
export API_BASE_URL="https://api.openai.com/v1"
export MODEL_NAME="gpt-4o-mini"
export HF_TOKEN="your_token"
```

## 9) Baseline Inference

`inference.py`:
- initializes OpenAI client using required env vars,
- runs 3 tasks over multiple episodes,
- prints structured logs:
  - `[START]`
  - `[STEP]`
  - `[END]`

## 10) Docker & Hugging Face Space

Build and run:

```bash
docker build -t soc-openenv .
docker run -p 7860:7860 soc-openenv
```

Service endpoints:
- `GET /health` for health checks
- `GET /run` for quick benchmark demo

For HF Space:
1. Create Docker Space.
2. Upload this project.
3. Add secrets:
   - `API_BASE_URL`
   - `MODEL_NAME`
   - `HF_TOKEN`
4. Add tag: `openenv`.
