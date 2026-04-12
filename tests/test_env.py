from server.environment import SocAlertTriageEnvironment


def test_reset_and_state():
    env = SocAlertTriageEnvironment()
    obs = env.reset(seed=1, task_name="task_easy_verdict")
    assert obs.state is not None
    assert obs.task_name == "task_easy_verdict"
    snapshot = env.state
    assert snapshot.current_case is not None


def test_step_contract():
    env = SocAlertTriageEnvironment()
    obs = env.reset(seed=1, task_name="task_hard_full_triage")
    action = {"verdict": "TP", "severity": "high", "response_action": "isolate"}
    next_obs = env.step(action)
    assert isinstance(next_obs.reward, float)
    assert 0.0 <= next_obs.reward <= 1.0
    assert next_obs.done is True
    assert next_obs.state is not None
