from server.environment import SocAlertTriageEnvironment


def test_reset_and_state():
    env = SocAlertTriageEnvironment()
    obs = env.reset(seed=1, task_name="task_easy_verdict")
    assert obs.state is not None
    assert obs.task_name == "task_easy_verdict"
    snapshot = env.state
    assert snapshot.current_case is not None


def test_step_contract_easy():
    """Easy tasks complete in 1 step."""
    env = SocAlertTriageEnvironment()
    obs = env.reset(seed=1, task_name="task_easy_verdict")
    action = {"verdict": "TP", "severity": "high", "response_action": "isolate"}
    next_obs = env.step(action)
    assert isinstance(next_obs.reward, float)
    assert 0.0 <= next_obs.reward <= 1.0
    assert next_obs.done is True
    assert next_obs.state is not None


def test_multistep_hard():
    """Hard tasks support multiple steps with feedback-driven refinement."""
    env = SocAlertTriageEnvironment()
    obs = env.reset(seed=1, task_name="task_hard_full_triage")

    # Step 1: intentionally wrong answer
    action1 = {"verdict": "Benign", "severity": "low", "response_action": "ignore"}
    obs1 = env.step(action1)
    assert isinstance(obs1.reward, float)
    assert obs1.done is False  # Not done yet — 3 steps allowed

    # Step 2: corrected answer
    action2 = {"verdict": "TP", "severity": "critical", "response_action": "block"}
    obs2 = env.step(action2)
    assert isinstance(obs2.reward, float)

    # Step 3: final step — must be done
    if not obs2.done:
        action3 = {"verdict": "TP", "severity": "critical", "response_action": "block"}
        obs3 = env.step(action3)
        assert obs3.done is True
        # Best reward should be carried forward
        assert obs3.reward >= obs1.reward


def test_early_termination_on_perfect():
    """Episode ends early if agent achieves a perfect score."""
    env = SocAlertTriageEnvironment()
    obs = env.reset(seed=42, task_name="task_hard_full_triage")

    # Get the ground truth from the case
    case = env.current_case
    perfect_action = {
        "verdict": case.expected_verdict,
        "severity": case.expected_severity,
        "response_action": case.expected_action,
    }
    obs_next = env.step(perfect_action)
    assert obs_next.reward >= 0.99  # Allow float precision tolerance
    assert obs_next.done is True  # Ends early despite max_steps=3


def test_case_bank_size():
    """Verify generated case bank has sufficient coverage."""
    import random
    from server.utils import generate_case
    rng = random.Random(42)
    cases = [generate_case(rng, ["easy", "medium", "hard"]) for _ in range(30)]
    assert len(cases) == 30
    easy = [c for c in cases if c.task_level == "easy"]
    medium = [c for c in cases if c.task_level == "medium"]
    hard = [c for c in cases if c.task_level == "hard"]
    assert len(easy) > 0
    assert len(medium) > 0
    assert len(hard) > 0
