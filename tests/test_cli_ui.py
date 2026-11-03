"""`sentinel ui` — one-command launcher with actionable failures."""
from __future__ import annotations

import socket
import sys
import threading
import time
import urllib.request
from pathlib import Path

import pytest
import yaml

from sentinel.auditstore.store import Store
from sentinel.cli import main

CFG = Path(__file__).parent / "fixtures" / "valid_config.yaml"


def _cfg(tmp_path, ops_ui=None, store=True):
    cfg = yaml.safe_load(CFG.read_text())
    cfg.pop("ops_ui", None)
    if ops_ui is not None:
        cfg["ops_ui"] = ops_ui
    db = tmp_path / "a.sqlite"
    if store:
        Store(db).close()
    cfg["audit_store"] = {"path": str(db)}
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump(cfg))
    return p


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_requires_config(capsys):
    assert main(["ui"]) == 1
    assert "--config is required" in capsys.readouterr().err


def test_reports_missing_audit_store(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("SENTINEL_OPS_UI_TOKEN", "x")
    p = _cfg(tmp_path, store=False)
    assert main(["--config", str(p), "ui", "--port", "8080"]) == 1
    assert "Audit store not found" in capsys.readouterr().err


def test_reports_busy_port_in_plain_words(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("SENTINEL_OPS_UI_TOKEN", "x")
    p = _cfg(tmp_path, ops_ui={"enabled": False, "bind": "127.0.0.1:8080",
                               "auth_token_env": "SENTINEL_OPS_UI_TOKEN",
                               "allowed_ports": [8080]})
    holder = socket.socket()
    holder.bind(("127.0.0.1", 8080))
    holder.listen(1)
    try:
        assert main(["--config", str(p), "ui"]) == 1
    finally:
        holder.close()
    assert "already in use" in capsys.readouterr().err


def test_disallowed_port_is_refused_not_served(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("SENTINEL_OPS_UI_TOKEN", "x")
    p = _cfg(tmp_path)
    assert main(["--config", str(p), "ui", "--port", str(_free_port())]) == 1
    assert "refused to start" in capsys.readouterr().err


def test_missing_dependencies_message(tmp_path, capsys, monkeypatch):
    monkeypatch.setitem(sys.modules, "fastapi", None)
    p = _cfg(tmp_path)
    assert main(["--config", str(p), "ui"]) == 1
    assert 'pip install -e ".[ops-ui]"' in capsys.readouterr().err


def test_serves_with_generated_token_when_none_set(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("SENTINEL_OPS_UI_TOKEN", raising=False)
    p = _cfg(tmp_path, ops_ui={"enabled": False, "bind": "127.0.0.1:8080",
                               "auth_token_env": "SENTINEL_OPS_UI_TOKEN",
                               "allowed_ports": [8080]})
    if _port_busy(8080):
        pytest.skip("port 8080 busy on this machine")
    t = threading.Thread(target=main, args=(["--config", str(p), "ui"],),
                         daemon=True)
    t.start()
    import os
    for _ in range(100):
        if os.environ.get("SENTINEL_OPS_UI_TOKEN") and _port_busy(8080):
            break
        time.sleep(0.1)
    token = os.environ["SENTINEL_OPS_UI_TOKEN"]
    out = capsys.readouterr().out
    assert token in out and "random token was generated" in out
    req = urllib.request.Request("http://127.0.0.1:8080/ui/mode",
                                 headers={"X-Sentinel-Token": token})
    assert urllib.request.urlopen(req, timeout=5).status == 200
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen("http://127.0.0.1:8080/ui/mode", timeout=5)
    assert e.value.code == 401


def _port_busy(port):
    with socket.socket() as s:
        return s.connect_ex(("127.0.0.1", port)) == 0
