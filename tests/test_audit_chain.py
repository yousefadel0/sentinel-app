"""Phase 6 — tamper-evident audit chain."""
from __future__ import annotations

import sqlite3

from sentinel.auditstore.store import Store
from sentinel.cli import main


def _store(tmp_path):
    s = Store(tmp_path / "a.sqlite")
    for i in range(3):
        s.record_decision(case_id="live", incident_id=f"inc-{i}",
                          outcome="notify_only", score=0.5, base_score=0.5,
                          tier="A", cap_applied=None, would="w",
                          recommendation={}, audit_events=[])
    s.record_llm_pair(case_id="c", prompt_verbatim="p", response_verbatim="r",
                      status="ok", elapsed_ms=3, digest="d")
    s.record_kpi_event(case_id="c", name="mttd", value=1.5)
    return s


def _raw(tmp_path):
    """Attacker with file access: opens SQLite directly and drops triggers."""
    c = sqlite3.connect(tmp_path / "a.sqlite")
    for (name,) in c.execute("SELECT name FROM sqlite_master WHERE type='trigger'"
                             ).fetchall():
        c.execute(f"DROP TRIGGER {name}")
    return c


def test_clean_store_verifies_and_exposes_head(tmp_path):
    s = _store(tmp_path)
    rep = s.verify_chain()
    assert rep["ok"] and rep["entries"] == 6      # meta + 3 decisions + pair + kpi
    assert rep["entries"] == s.chain_head()["seq"] and rep["problems"] == []
    s.close()


def test_edited_row_detected(tmp_path):
    s = _store(tmp_path)
    s.close()
    c = _raw(tmp_path)
    c.execute("UPDATE decisions SET outcome='log_only' WHERE id=2")
    c.commit()
    c.close()
    rep = Store(tmp_path / "a.sqlite").verify_chain()
    assert not rep["ok"] and any("content altered" in p for p in rep["problems"])


def test_deleted_row_detected(tmp_path):
    s = _store(tmp_path)
    s.close()
    c = _raw(tmp_path)
    c.execute("DELETE FROM decisions WHERE id=1")
    c.commit()
    c.close()
    rep = Store(tmp_path / "a.sqlite").verify_chain()
    assert not rep["ok"] and any("deleted" in p for p in rep["problems"])


def test_row_inserted_behind_the_api_detected(tmp_path):
    s = _store(tmp_path)
    s.close()
    c = _raw(tmp_path)
    c.execute("INSERT INTO decisions (ts,case_id,incident_id,outcome,score,"
              "base_score,tier,would) VALUES ('t','x','forged','auto_act',1,1,'A','w')")
    c.commit()
    c.close()
    rep = Store(tmp_path / "a.sqlite").verify_chain()
    assert not rep["ok"] and any("not in chain" in p for p in rep["problems"])


def test_spliced_chain_entry_detected(tmp_path):
    s = _store(tmp_path)
    s.close()
    c = _raw(tmp_path)
    c.execute("DELETE FROM audit_chain WHERE seq=3")
    c.commit()
    c.close()
    assert not Store(tmp_path / "a.sqlite").verify_chain()["ok"]


def test_tail_truncation_only_caught_by_anchored_head(tmp_path):
    s = _store(tmp_path)
    anchor = s.chain_head()["hash"]
    s.close()
    c = _raw(tmp_path)
    c.execute("DELETE FROM audit_chain WHERE seq=(SELECT MAX(seq) FROM audit_chain)")
    c.execute("DELETE FROM kpis_events")
    c.commit()
    c.close()
    s2 = Store(tmp_path / "a.sqlite")
    assert s2.verify_chain()["ok"]                       # honest limitation
    rep = s2.verify_chain(expect_head=anchor)
    assert not rep["ok"] and "anchored" in rep["problems"][-1]


def test_legacy_rows_reported_not_failed(tmp_path):
    s = _store(tmp_path)
    s.close()
    c = _raw(tmp_path)
    c.execute("DELETE FROM audit_chain")                 # simulate pre-chain db
    c.commit()
    c.close()
    rep = Store(tmp_path / "a.sqlite").verify_chain()
    assert rep["ok"] and rep["legacy_unchained"] == 6 and rep["entries"] == 0


def test_cli_verify_exit_codes(tmp_path, capsys):
    s = _store(tmp_path)
    s.close()
    assert main(["ctl", "audit", "verify", str(tmp_path / "a.sqlite")]) == 0
    c = _raw(tmp_path)
    c.execute("UPDATE decisions SET score=0 WHERE id=1")
    c.commit()
    c.close()
    assert main(["ctl", "audit", "verify", str(tmp_path / "a.sqlite")]) == 1
    assert main(["ctl", "audit", "verify", str(tmp_path / "nope")]) == 1


def test_example_config_is_valid_including_commented_blocks():
    """config.example.yaml must boot-validate, and so must its optional
    notifiers/siem blocks once uncommented (docs that do not validate rot)."""
    from pathlib import Path

    import yaml

    from sentinel.config.loader import load_config
    path = Path(__file__).parents[1] / "config.example.yaml"
    assert load_config(path)["autonomy_level"] == 0
    lines = path.read_text(encoding="utf-8").splitlines()
    start = next(i for i, l in enumerate(lines) if l.startswith("# notifiers:"))
    uncommented = "\n".join(lines[:start] + [l[2:] for l in lines[start:]])
    cfg = yaml.safe_load(uncommented)
    tmp = path.parent / ".example-uncommented.tmp.yaml"
    try:
        tmp.write_text(yaml.safe_dump(cfg), encoding="utf-8")
        loaded = load_config(tmp)
    finally:
        tmp.unlink(missing_ok=True)
    assert loaded["notifiers"][1]["approvals"] is True
    assert loaded["siem"]["outbound"]["endpoint"].startswith("syslog+udp://")
