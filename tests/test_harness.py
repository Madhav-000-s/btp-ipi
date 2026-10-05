"""End-to-end, offline: the oracle agent is fully hijackable, so no-defense ASR must be high and the
oracle envelope must drive it to zero without losing utility. If these break, the harness is broken."""
import pandas as pd

from ipi.runner import Runner

BASE = {
    "suites": ["banking"],
    "user_tasks": {"banking": ["user_task_0", "user_task_3", "user_task_4"]},
    "injection_tasks": {"banking": ["injection_task_0", "injection_task_1", "injection_task_4"]},
    "model": {"provider": "oracle", "name": "gullible-oracle"},
    "attacks": ["important_instructions"],
    "workers": 1,
}


def run(tmp_path, defenses, **kw):
    cfg = {**BASE, "run_name": "t", "out_dir": str(tmp_path), "defenses": defenses, **kw}
    return pd.read_csv(Runner(cfg).run(), keep_default_na=False)


def test_no_defense_is_hijacked(tmp_path):
    df = run(tmp_path, ["none"])
    att = df[df.injection_task != ""]
    assert att.attack_success.mean() > 0.8
    assert df[df.injection_task == ""].utility.mean() == 1.0


def test_oracle_envelope_blocks_without_utility_loss(tmp_path):
    df = run(tmp_path, [{"name": "envelope", "extractor": "oracle", "pin": "all"}])
    assert df[df.injection_task != ""].attack_success.sum() == 0
    assert df[df.injection_task == ""].utility.mean() == 1.0


def test_resume_skips_done(tmp_path):
    run(tmp_path, ["none"])
    df = run(tmp_path, ["none"])  # second call must not duplicate rows
    assert len(df) == 3 + 9


def test_adaptive_loop_respects_budget(tmp_path):
    df = run(tmp_path, [{"name": "envelope", "extractor": "oracle", "pin": "all"}],
             attacks=[{"name": "template_adaptive", "budget": 3}], benign=False)
    assert (df.attempts == 3).all()  # never succeeds -> uses whole budget
