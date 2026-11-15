"""Real UI write paths: validated config, learning controls and reports."""
import json
from pathlib import Path

import yaml
from fastapi.testclient import TestClient

from sentinel.auditstore.store import Store
from sentinel.config.loader import load_config
from sentinel.learning import LearningProfile
from sentinel.ui.app import create_app

TOKEN = {"X-Sentinel-Token": "operations-test-token"}


def _client(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_OPS_UI_TOKEN", TOKEN["X-Sentinel-Token"])
    config = yaml.safe_load(Path("tests/fixtures/valid_config.yaml").read_text())
    config["ops_ui"]["enabled"] = True
    config["audit_store"] = {"path": str(tmp_path / "audit.sqlite")}
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    store = Store(tmp_path / "audit.sqlite", check_same_thread=False)
    LearningProfile(tmp_path / "learning.json")
    app = create_app(load_config(path), store=store, capture_dir=tmp_path,
                     report_dir=tmp_path / "reports", config_path=path)
    return TestClient(app), store, path


def test_login_and_new_pages_are_authenticated(tmp_path, monkeypatch):
    client, store, _ = _client(tmp_path, monkeypatch)
    assert client.get("/login").status_code == 200
    assert "audit.sqlite" not in client.get("/login").text
    for route in ("/ui/learning", "/ui/intel", "/ui/actions", "/ui/reports",
                  "/ui/guide", "/learning/export.json", "/audit/export.json"):
        assert client.get(route).status_code == 401
        assert client.get(route, headers=TOKEN).status_code == 200
    store.close()


def test_settings_save_to_validated_overlay_and_keep_dry_run(tmp_path, monkeypatch):
    client, store, path = _client(tmp_path, monkeypatch)
    form = {"auto_act_threshold": "0.95", "human_approval_threshold": "0.80",
            "report_threshold": "0.50", "approval_timeout_minutes": "15",
            "report_timeout_minutes": "30", "max_blocks_per_min": "4",
            "max_blocks_per_hour": "20", "default_ttl_min": "30",
            "protected_ips": "10.0.0.1, 10.0.0.4", "notifiers": "[]"}
    assert client.post("/settings/save", data=form, headers=TOKEN).status_code == 200
    assert load_config(path)["limits"]["max_blocks_per_min"] == 4
    assert (tmp_path / "ui-settings.yaml").is_file()
    assert yaml.safe_load(path.read_text())["limits"]["max_blocks_per_min"] == 5
    assert client.post("/settings/dry-run", data={"dry_run": "off"},
                       headers=TOKEN).status_code == 409
    assert client.post("/settings/dry-run", data={"dry_run": "on"},
                       headers=TOKEN).status_code == 200
    assert load_config(path)["enforcement_dry_run"] is True
    assert client.post("/settings/save", data={**form, "report_threshold": "0.99"},
                       headers=TOKEN).status_code == 422
    store.close()


def test_learning_repeat_changes_and_generate_report(tmp_path, monkeypatch):
    client, store, _ = _client(tmp_path, monkeypatch)
    for mode in ("active", "learning", "auto"):
        assert client.post("/learning/mode", data={"mode": mode},
                           headers=TOKEN).status_code == 200
    assert client.post("/learning/extend", data={"days": "2"},
                       headers=TOKEN).status_code == 200
    assert LearningProfile(tmp_path / "learning.json").export()["extend_days"] == 2
    assert client.post("/reports/generate", headers=TOKEN).status_code == 200
    report = client.get("/reports/latest.json", headers=TOKEN)
    assert report.status_code == 200
    assert json.loads(report.content)["incidents"] == []
    assert store.query("SELECT COUNT(*) FROM actions WHERE case_id='ops_ui'")[0][0] == 4
    store.close()
