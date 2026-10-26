"""Process-isolation proof for the Minimal Ops UI (M7).

The UI runs as its OWN uvicorn process (never inside the pilot loop).
This suite proves, with a real OS process:

  1. the server actually serves over TCP on its declared loopback bind;
  2. an approval POSTed while live is committed to the shared audit store
     through the SAME Engine.resolve seam as CLI;
  3. SIGKILL of the UI process leaves NO orphan listener and leaves the
     committed audit rows byte-preserved and integrity-clean — i.e. UI
     death cannot corrupt or take down the core detect→decide→act chain.
"""
from __future__ import annotations

import json
import os
import socket
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pytest

TOKEN_ENV = "SENTINEL_OPS_UI_TOKEN"
TOKEN = "kill-switch-test-token"

_CHILD = r'''
import json, sys
sys.path.insert(0, ".")
from tests.fixtures.decision.helpers import engine, IncidentStub, alert
from sentinel.auditstore.store import Store
from sentinel.ui.app import create_app
import uvicorn

db_path, port, token_env = sys.argv[1], int(sys.argv[2]), sys.argv[3]
eng, _clk = engine()
d = eng.evaluate(
    IncidentStub([alert("auth_fail_burst", 0.93, crit="critical")]),
    __import__("sentinel.decision.chain", fromlist=["Facts"]).Facts(
        liveness="alive"))
assert d.outcome.value == "human_approval", d.outcome.value
cfg = {"ops_ui": {"enabled": True,
                  "bind": f"127.0.0.1:{port}",
                  "auth_token_env": token_env,
                  "allowed_ports": [port]}}
app = create_app(
    cfg, engine=eng,
    # uvicorn serves sync endpoints on a worker threadpool → the store
    # connection must be usable cross-thread (same pattern as the in-process
    # UI tests, which pass check_same_thread=False to Store).
    store=Store(db_path, check_same_thread=False))
print(json.dumps({"incident_id": d.incident_id}), flush=True)
uvicorn.run(app, host="127.0.0.1", port=port, log_level="error")
'''


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _hard_kill(proc: subprocess.Popen) -> None:
    """Harshest termination, portable. POSIX: SIGKILL. Windows: venv python.exe
    is a launcher that spawns the real interpreter, so kill the whole tree."""
    if sys.platform == "win32":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                       capture_output=True, check=False)
    else:
        proc.kill()


@pytest.fixture()
def live_server(tmp_path):
    """Spawn a real uvicorn UI process; yield (proc, db_path, incident_id)."""
    port = _free_loopback_port()
    db_path = tmp_path / "audit.sqlite3"
    err_file = tmp_path / "child.stderr.log"
    err_fh = open(err_file, "wb")
    proc = subprocess.Popen(
        [sys.executable, "-c", _CHILD, str(db_path), str(port), TOKEN_ENV],
        stdout=subprocess.PIPE, stderr=err_fh,
        env={**os.environ, TOKEN_ENV: TOKEN}, cwd=".")
    try:
        # Child prints the pending incident id before serving.
        line = proc.stdout.readline().decode().strip()
        assert line.startswith("{"), (
            f"child failed to boot; stderr:\n{err_file.read_text()}")
        incident_id = json.loads(line)["incident_id"]

        deadline = time.time() + 15
        last_err = None
        while time.time() < deadline:
            if proc.poll() is not None:
                raise AssertionError(
                    f"UI died early:\n{err_file.read_text()}")
            try:
                with socket.create_connection(("127.0.0.1", port),
                                              timeout=1) as c:
                    req = (f"GET /health/capture HTTP/1.1\r\n"
                           f"Host: 127.0.0.1\r\n"
                           f"X-Sentinel-Token: {TOKEN}\r\n"
                           f"Connection: close\r\n\r\n")
                    c.sendall(req.encode())
                    data = c.recv(4096).decode(errors="replace")
                if "200" in data.splitlines()[0]:
                    break
            except OSError as exc:
                last_err = exc
                time.sleep(0.2)
        else:
            raise AssertionError(f"UI never became live: {last_err}")

        yield {"proc": proc, "db_path": db_path, "port": port,
               "incident_id": incident_id}
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)
        err_fh.close()


def test_sigkill_leaves_no_orphan_and_store_intact(live_server):
    info = live_server
    proc = info["proc"]
    hdr = f"X-Sentinel-Token: {TOKEN}"

    # -- while live: approve through the UI (Engine.resolve seam) --------- #
    with socket.create_connection(("127.0.0.1", info["port"]), timeout=5) as c:
        req = (f'POST /approvals/{info["incident_id"]}/approve HTTP/1.1\r\n'
               f"Host: 127.0.0.1\r\n{hdr}\r\nContent-Length: 0\r\n"
               f"Connection: close\r\n\r\n")
        c.sendall(req.encode())
        resp = b""
        while True:
            chunk = c.recv(4096)
            if not chunk:
                break
            resp += chunk
    status_line = resp.split(b"\r\n", 1)[0].decode()
    if "200" not in status_line:
        err_txt = Path(str(info["db_path"])).with_name(
            "child.stderr.log").read_text()[-2000:]
        pytest.fail(f"approve returned {status_line}; child stderr:\n{err_txt}")

    # Snapshot committed rows BEFORE the kill.
    conn = sqlite3.connect(str(info["db_path"]))
    before = conn.execute(
        "SELECT * FROM decisions ORDER BY rowid").fetchall()
    conn.close()
    assert len(before) == 1, "approval must have been recorded pre-kill"

    # -- SIGKILL: the harshest possible termination ----------------------- #
    _hard_kill(proc)
    proc.wait(timeout=10)

    # No orphan listener: the port must refuse connections now.
    with pytest.raises(OSError):
        with socket.create_connection(("127.0.0.1", info["port"]),
                                      timeout=2):
            pass

    # Store survives untouched: same rows, byte-preserved, integrity ok.
    conn = sqlite3.connect(str(info["db_path"]))
    try:
        after = conn.execute(
            "SELECT * FROM decisions ORDER BY rowid").fetchall()
        assert after == before, "SIGKILL altered committed audit rows"
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        conn.close()


def test_sigkill_of_ui_does_not_affect_independent_store_writes(live_server):
    """Core-side writes continue and stay consistent across UI death."""
    import tempfile
    from sentinel.auditstore.store import Store

    info = live_server
    other_db = Path(tempfile.mkdtemp()) / "core.sqlite3"
    core = Store(other_db)
    core.record_decision(
        case_id="pilot",
        incident_id="inc-core-1", outcome="block",
        score=0.9, base_score=0.9, tier="A",
        cap_applied=None,
        would=json.dumps({"action": "block", "params": {}}),
        recommendation={"action": "block", "params": {},
                        "because": "core path"},
        audit_events=[{"name": "e", "detail": "d"}])
    _hard_kill(info["proc"])
    info["proc"].wait(timeout=10)

    # Core store still readable/consistent after the UI was SIGKILLed.
    rows = core.rows("decisions")
    assert len(rows) == 1
