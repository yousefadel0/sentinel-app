"""Own-model integration: OpenAI-compatible chat-completions style."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from sentinel.brain.client import LLMClient, SYSTEM_PROMPT, llm_client_from_cfg
from sentinel.brain.triage import triage_incident
from tests.fixtures.decision.helpers import alert

GOOD = {"attack_type": "brute_force", "confidence": 0.9, "severity": 4,
        "affected_assets": ["10.0.0.4"], "recommended_action": "escalate_human",
        "rationale": "many failed logins"}


class Fake(BaseHTTPRequestHandler):
    reply = None
    seen = []

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        Fake.seen.append((self.path, self.headers.get("Authorization"), body))
        out = json.dumps(Fake.reply(body)).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


@pytest.fixture()
def server():
    Fake.seen = []
    srv = HTTPServer(("127.0.0.1", 0), Fake)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


def chat(content):
    return {"choices": [{"message": {"role": "assistant", "content": content}}]}


def client(monkeypatch, port, **kw):
    monkeypatch.setenv("OWN_LLM", f"http://127.0.0.1:{port}/v1/chat/completions")
    monkeypatch.setenv("OWN_KEY", "k-123")
    return LLMClient("OWN_LLM", api_style="openai", model="our-model",
                     api_key_env="OWN_KEY", **kw)


def test_openai_style_request_shape_auth_and_prompt_data_only(monkeypatch, server):
    Fake.reply = lambda b: chat(json.dumps(GOOD))
    res, safe = triage_incident("case-1", [alert("auth_fail_burst", 0.9)],
                                client(monkeypatch, server))
    assert res is not None and res.attack_type == "brute_force"
    path, auth, body = Fake.seen[0]
    assert path == "/v1/chat/completions" and auth == "Bearer k-123"
    assert body["model"] == "our-model" and body["temperature"] <= 0.2
    assert body["messages"][0] == {"role": "system", "content": SYSTEM_PROMPT}
    user = json.loads(body["messages"][1]["content"])          # the SAFE input only
    assert set(user) <= {"case_id", "src_ip", "dst_ip", "ports", "protocol",
                         "direction", "vlan_tag", "baseline_deviation_sigma",
                         "signal_types", "geolocation", "asn", "packet_count",
                         "byte_count", "duration_seconds", "confidence_score",
                         "timestamps"}


def test_markdown_fenced_json_is_unwrapped_but_still_schema_checked(monkeypatch, server):
    Fake.reply = lambda b: chat("```json\n" + json.dumps(GOOD) + "\n```")
    res, _ = triage_incident("c", [alert("auth_fail_burst", 0.9)], client(monkeypatch, server))
    assert res is not None
    bad = dict(GOOD, recommended_action="rm -rf /")
    Fake.reply = lambda b: chat("```json\n" + json.dumps(bad) + "\n```")
    res, _ = triage_incident("c", [alert("auth_fail_burst", 0.9)], client(monkeypatch, server))
    assert res is None                                   # hostile output rejected


@pytest.mark.parametrize("reply", [
    {"error": "model overloaded"}, {"choices": []}, {"choices": [{"message": {}}]},
    chat("Sure, here is my analysis: it is a scan."), chat(""),
])
def test_unexpected_responses_degrade_silently(monkeypatch, server, reply):
    Fake.reply = lambda b: reply
    res, _ = triage_incident("c", [alert("scan", 0.9)], client(monkeypatch, server))
    assert res is None                                   # P4: rule-based path continues


def test_config_builds_the_right_client(monkeypatch):
    cfg = {"brain": {"llm_endpoint_env": "OWN_LLM", "timeout_s": 8, "hard_cutoff_s": 5}}
    monkeypatch.delenv("OWN_LLM", raising=False)
    assert llm_client_from_cfg(cfg) is None              # no endpoint => no LLM
    monkeypatch.setenv("OWN_LLM", "http://x/y")
    assert llm_client_from_cfg(cfg)._style == "raw"
    cfg["brain"].update(api_style="openai", model="m", api_key_env="K")
    c = llm_client_from_cfg(cfg)
    assert c._style == "openai" and c._model == "m"


def test_openai_style_requires_a_model():
    with pytest.raises(ValueError):
        LLMClient("X", api_style="openai")
    with pytest.raises(ValueError):
        LLMClient("X", api_style="soap")


def test_config_schema_accepts_and_validates_brain_style(tmp_path):
    import yaml
    from pathlib import Path
    from sentinel.config.loader import ConfigError, load_config
    cfg = yaml.safe_load((Path(__file__).parent / "fixtures/valid_config.yaml").read_text())
    cfg["brain"].update(api_style="openai", model="our-model", api_key_env="OWN_KEY")
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump(cfg))
    assert load_config(p)["brain"]["model"] == "our-model"
    del cfg["brain"]["model"]
    p.write_text(yaml.safe_dump(cfg))
    with pytest.raises(ConfigError):
        load_config(p)
