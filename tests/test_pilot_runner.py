"""M6 pilot runner — generator path end-to-end over synthetic fixtures."""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.attackers import scan  # noqa: E402
from tools.attackers.benign import ssh_session  # noqa: E402


def _pilot_dir() -> tuple[Path, Path]:
    d = Path(tempfile.mkdtemp())
    events = scan.generate()[:10] + ssh_session.generate()[:5]
    (d / "gen.eve.jsonl").write_text(
        "".join(json.dumps(e, sort_keys=True) + "\n" for e in events))
    cfg = yaml.safe_load((Path(__file__).parent /
                          "fixtures/valid_config.yaml").read_text())
    cfg["audit_store"] = {"path": str(d / "audit.sqlite")}
    cp = d / "pilot.yaml"
    cp.write_text(yaml.safe_dump(cfg))
    return d, cp


def test_run_pilot_requires_audit_store_fail_closed(tmp_path):
    """§8/D5 optionality honored: missing audit_store ⇒ clear ConfigError,
    never a KeyError and never a silently-unpersisted run."""
    import pytest
    from sentinel.config.loader import ConfigError
    from sentinel.pilot.runner import run_pilot

    cfg = yaml.safe_load(Path(__file__).parent.joinpath("fixtures", "valid_config.yaml").read_text())
    for key in ("audit_store",):
        cfg.pop(key, None)
    p = tmp_path / "cfg.yaml"
    p.write_text(yaml.safe_dump(cfg))
    with pytest.raises(ConfigError, match="audit_store\\.path"):
        run_pilot(p, tmp_path)


def test_run_pilot_smoke_generator_path():
    from sentinel.pilot.runner import run_pilot
    d, cp = _pilot_dir()
    kpis = run_pilot(cp, d)
    assert kpis["fp_rate"]["benign_injections"] == 5   # Q2: measurable by construction
    assert kpis["mttd_seconds"]["n"] >= 0              # honest zeros allowed
    assert set(kpis) >= {"incidents", "decisions_by_outcome",
                         "mttd_seconds", "mttd_replay_seconds",
                         "fp_rate", "actions_recorded", "rollbacks"}


def test_runner_never_blends_mttd_names_q1():
    from sentinel.pilot.runner import run_pilot
    d, cp = _pilot_dir()
    kpis = run_pilot(cp, d)
    assert "mttd_seconds" in kpis and "mttd_replay_seconds" in kpis
    assert "mttd" not in kpis                          # no blended single name


def test_run_pilot_writes_attack_report(tmp_path):
    from sentinel.pilot.runner import run_pilot
    d, cp = _pilot_dir()
    output = tmp_path / "reports"
    result = run_pilot(cp, d, report_dir=output)
    assert result["report"]["latest_html"].endswith("latest.html")
    report_html = (output / "latest.html").read_text(encoding="utf-8")
    assert "تقرير Sentinel للهجمات والقرارات" in report_html
    assert "لم يعثر التقرير على CVE" in report_html
    assert '"executed": false' in (output / Path(result["report"]["json"]).name).read_text(encoding="utf-8")
