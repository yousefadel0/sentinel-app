"""M6 replay-path + delivery-chain tests (GAP 1 & GAP 2).

T1  virtual-clock replay MTTD lands in mttd_replay_seconds only (Q1);
T2  ddos-class incident proven via committed slice+manifest through
    run_pilot (GAP 2 — no silent deferral);
T3  shadow-always under --no-dry-run (G2/P5): zero executed actions;
T4  zero-SIEM e2e: pipeline completes with all sockets disabled;
T5  append-only immutability enforced by the real SQLite file itself;
T6  G7: verbatim LLM pairs persisted IN the audit store, byte-exact.
"""
from __future__ import annotations

import json
import os
import socket
import sqlite3
import sys
import tempfile
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.attackers.benign import ssh_session          # noqa: E402
from tools.make_fixtures import build_slice             # noqa: E402


def _write_eve(path: Path, events) -> None:
    path.write_text(
        "".join(json.dumps(e, sort_keys=True) + chr(10) for e in events))


def _pilot_dir(*, autonomy_level: int | None = None):
    """Replay capture dir: committed ddos slice + benign background."""
    d = Path(tempfile.mkdtemp())
    events, manifest = build_slice(seed=42, attack_events=40)
    _write_eve(d / "ddos.eve.jsonl", events)
    _write_eve(d / "benign.eve.jsonl", ssh_session.generate()[:5])
    (d / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True))
    cfg = yaml.safe_load((Path(__file__).parent /
                          "fixtures/valid_config.yaml").read_text())
    cfg["audit_store"] = {"path": str(d / "audit.sqlite")}
    if autonomy_level is not None:
        cfg["autonomy_level"] = autonomy_level
    cp = d / "pilot.yaml"
    cp.write_text(yaml.safe_dump(cfg))
    return d, cp, d / "manifest.json"


# ---------------------------------------------------------------- T1 --- #
def test_t1_replay_mttd_virtual_clock_gap1():
    from sentinel.pilot.runner import run_pilot

    d, cp, mp = _pilot_dir()
    kpis = run_pilot(cp, d, mp)
    rep = kpis["mttd_replay_seconds"]
    gen = kpis["mttd_seconds"]
    assert rep["n"] >= 1                       # GAP 1: replay KPI wired
    assert rep["avg"] > 0.0                    # plausible nonzero
    assert rep["avg"] <= 80.0                  # slice span (40 x 2 s)
    assert gen["n"] == 0                       # generator path untouched
    assert "mttd" not in kpis                  # Q1: never blended


# ---------------------------------------------------------------- T2 --- #
def test_t2_ddos_incident_via_slice_manifest_gap2():
    from sentinel.auditstore.store import Store
    from sentinel.pilot.runner import run_pilot

    d, cp, mp = _pilot_dir()
    kpis = run_pilot(cp, d, mp)
    db = d / "audit.sqlite"
    st = Store(db)
    try:
        rows = st.query_kpi_events("mttd") if hasattr(st, "query_kpi_events")             else st._conn.execute(
                "SELECT name, value, detail FROM kpis_events "
                "WHERE name='mttd'").fetchall()
        mttd_rows = [(r[0], r[1], json.loads(r[2])) for r in rows]
        replay_rows = [m for m in mttd_rows if m[2].get("path") == "replay"]
        assert replay_rows, "no replay-path mttd event recorded"
        fams = {m[2].get("family") for m in replay_rows}
        assert fams == {"ddos_volumetric"}     # ddos-class proven
        n_decisions = st._conn.execute(
            "SELECT COUNT(*) FROM decisions").fetchone()[0]
        assert n_decisions >= 1                # a decision was actually made
    finally:
        st.close()


# ---------------------------------------------------------------- T3 --- #
def test_t3_shadow_always_under_no_dry_run():
    """--no-dry-run accepted but pilot executes NOTHING (G2/P5)."""
    from sentinel.auditstore.store import Store
    from sentinel.pilot.runner import main

    d, cp, mp = _pilot_dir(autonomy_level=3)   # max autonomy on purpose
    rc = main(["--config", str(cp), "--capture-dir", str(d),
               "--manifest", str(mp), "--no-dry-run"])
    assert rc == 0
    st = Store(d / "audit.sqlite")
    try:
        n_actions = st._conn.execute(
            "SELECT COUNT(*) FROM actions").fetchone()[0]
        n_rollbacks = st._conn.execute(
            "SELECT COUNT(*) FROM rollbacks").fetchone()[0]
        assert n_actions == 0 and n_rollbacks == 0
    finally:
        st.close()


# ---------------------------------------------------------------- T4 --- #
def test_t4_zero_siem_e2e_all_sockets_disabled(monkeypatch):
    """Pipeline completes with every socket call forbidden."""
    from sentinel.pilot.runner import run_pilot

    def _no_socket(*a, **k):
        raise AssertionError("network use attempted in offline pilot")

    monkeypatch.setattr(socket, "socket", _no_socket)
    monkeypatch.setattr(socket, "create_connection", _no_socket)
    d, cp, mp = _pilot_dir()
    kpis = run_pilot(cp, d, mp)
    assert kpis["mttd_replay_seconds"]["n"] >= 1


# ---------------------------------------------------------------- T5 --- #
def test_t5_append_only_immutability_real_sqlite_file():
    """Existing audit rows can never be UPDATEd or DELETEd via the real
    file; INSERTs still work. Row-level triggers fire per existing row,
    so each mutation attempt targets a seeded row."""
    from sentinel.auditstore.store import Store
    from sentinel.brain.audit import PromptResponsePair
    from sentinel.pilot.runner import StorePairSink, run_pilot

    d, cp, mp = _pilot_dir()
    run_pilot(cp, d, mp)
    db_path = d / "audit.sqlite"
    assert db_path.exists() and db_path.stat().st_size > 0
    # seed one llm_pair so its trigger has a row to guard
    st = Store(db_path)
    StorePairSink(st).append_pair(PromptResponsePair(
        case_id="t5-seed", prompt_verbatim="P", response_verbatim="R",
        status="ok", elapsed_ms=1, endpoint_env_var="SENTINEL_LLM_API",
        temperature=0.1, ts="2026-01-15T00:00:00+00:00"))
    st.close()
    conn = sqlite3.connect(str(db_path))       # raw handle — no Store layer
    try:
        row = conn.execute(
            "SELECT rowid FROM decisions LIMIT 1").fetchone()
        assert row is not None
        try:
            conn.execute("UPDATE decisions SET case_id='tampered' "
                         "WHERE rowid=?", (row[0],))
            raise AssertionError("UPDATE on audit table was allowed")
        except sqlite3.IntegrityError as e:
            assert "append-only" in str(e)
        lp_row = conn.execute(
            "SELECT rowid FROM llm_pairs LIMIT 1").fetchone()
        assert lp_row is not None
        try:
            conn.execute("DELETE FROM llm_pairs WHERE rowid=?",
                         (lp_row[0],))
            raise AssertionError("DELETE on audit table was allowed")
        except sqlite3.IntegrityError as e:
            assert "append-only" in str(e)
        before = conn.execute(
            "SELECT COUNT(*) FROM kpis_events").fetchone()[0]
        conn.execute("INSERT INTO kpis_events (ts, case_id, name, value) "
                     "VALUES ('2026-01-15T00:00:00+00:00','t5','mttd',1.0)")
        conn.commit()
        after = conn.execute(
            "SELECT COUNT(*) FROM kpis_events").fetchone()[0]
        assert after == before + 1             # append still permitted
    finally:
        conn.close()


# ---------------------------------------------------------------- T7 --- #
def test_t7_g7_triage_branch_records_pairs_via_runner(monkeypatch):
    """G7 end-to-end: with SENTINEL_LLM_API set, run_pilot's bounded
    triage branch runs and persists verbatim pairs into the store."""
    from sentinel.auditstore.store import Store
    from sentinel.brain.client import LLMResponse
    from sentinel.pilot.runner import run_pilot

    VALID_BODY = json.dumps({
        "attack_type": "ddos_volumetric", "confidence": 0.9,
        "severity": 5, "affected_assets": ["10.0.0.4"],
        "recommended_action": "notify_only",
        "rationale": "volumetric spike on pinned asset"})

    class FakeLLM:
        _env_var = "SENTINEL_LLM_API"
        temperature = 0.1

        def __init__(self, *a, **k):
            pass

        def complete(self, prompt_verbatim):
            return LLMResponse(status=200, body=VALID_BODY, elapsed_ms=5)

    monkeypatch.setattr("sentinel.brain.client.LLMClient", FakeLLM)
    monkeypatch.setenv("SENTINEL_LLM_API", "http://127.0.0.1:9")
    d, cp, mp = _pilot_dir()
    kpis = run_pilot(cp, d, mp)
    assert kpis["llm_pairs"] >= 1             # int count from compute_kpis
    db_path = d / "audit.sqlite"
    st = Store(db_path)
    try:
        rows = st._conn.execute(
            "SELECT status, case_id FROM llm_pairs").fetchall()
        assert len(rows) >= 1
        assert all(r[0] == "ok" for r in rows)
        assert any(str(r[1]).startswith("pilot-") for r in rows)
    finally:
        st.close()


# ---------------------------------------------------------------- T6 --- #
def test_t6_g7_llm_pair_persisted_in_store_byte_exact():
    """Verbatim pair round-trips through the real store file; digest holds."""
    from sentinel.auditstore.store import Store
    from sentinel.brain.audit import PromptResponsePair
    from sentinel.pilot.runner import StorePairSink

    d = Path(tempfile.mkdtemp())
    db = d / "audit.sqlite"
    st = Store(db)
    sink = StorePairSink(st)
    pair = PromptResponsePair(
        case_id="pilot-t6",
        prompt_verbatim='{"incident":"i-1","ask":"triage"}',
        response_verbatim='{"verdict":"escalate_human","confidence":0.4}',
        status="ok", elapsed_ms=42,
        endpoint_env_var="SENTINEL_LLM_API", temperature=0.1,
        ts="2026-01-15T00:00:00+00:00")
    sink.append_pair(pair)
    st.close()

    st2 = Store(db)                            # reopen the REAL file
    try:
        rows = st2._conn.execute(
            "SELECT prompt_verbatim, response_verbatim, status, "
            "elapsed_ms, digest FROM llm_pairs").fetchall()
        assert len(rows) == 1
        got = rows[0]
        assert got[0] == pair.prompt_verbatim      # byte-exact verbatim
        assert got[1] == pair.response_verbatim    # byte-exact verbatim
        assert (got[2], got[3]) == ("ok", 42)
        stored_digest = got[4]
        assert stored_digest == pair.digest()      # digest matches
    finally:
        st2.close()
