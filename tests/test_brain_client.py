"""LLMClient bounds (§8 brain block): temp clamp, deadlines, env endpoint."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.brain.client import LLMClient, default_transport  # noqa: E402


def _fake_transport(status=200, body='{"attack_type":"scan"}', delay_s=0.0):
    calls = []

    def transport(url, payload, deadline_s):
        calls.append({"url": url, "payload": json.loads(payload),
                      "deadline_s": deadline_s})
        if delay_s:
            import time
            time.sleep(delay_s)
        return status, body

    transport.calls = calls
    return transport


def test_temperature_clamped_range_enforced():
    with pytest.raises(ValueError, match="temperature"):
        LLMClient("SENTINEL_LLM_API", temperature=0.21)
    with pytest.raises(ValueError, match="temperature"):
        LLMClient("SENTINEL_LLM_API", temperature=-0.01)
    c = LLMClient("SENTINEL_LLM_API", temperature=0.2)
    assert c.temperature == 0.2


def test_deadline_ordering_validated():
    with pytest.raises(ValueError, match="hard_cutoff"):
        LLMClient("E", timeout_s=5, hard_cutoff_s=8)


def test_endpoint_resolved_from_env_at_call_time(monkeypatch):
    monkeypatch.setenv("SENTINEL_TEST_ENDPOINT", "http://127.0.0.1:9/mock")
    t = _fake_transport()
    c = LLMClient("SENTINEL_TEST_ENDPOINT", transport=t)
    c.complete('{"case_id":"x"}')
    assert t.calls[0]["url"] == "http://127.0.0.1:9/mock"


def test_missing_env_raises_for_triage_to_swallow(monkeypatch):
    monkeypatch.delenv("SENTINEL_MISSING_ENV", raising=False)
    c = LLMClient("SENTINEL_MISSING_ENV", transport=_fake_transport())
    with pytest.raises(RuntimeError, match="unset"):
        c.complete("{}")


def test_prompt_wrapped_verbatim_in_payload(monkeypatch):
    monkeypatch.setenv("E", "http://unit.test/llm")
    t = _fake_transport()
    c = LLMClient("E", transport=t, temperature=0.15, hard_cutoff_s=3,
                  timeout_s=8)
    c.complete('{"a":1}')
    sent = t.calls[0]["payload"]
    assert sent["prompt"] == '{"a":1}'
    assert sent["temperature"] == 0.15
    assert sent["hard_cutoff_s"] == 3


def test_hard_cutoff_passed_to_transport(monkeypatch):
    monkeypatch.setenv("E", "http://unit.test/llm")
    t = _fake_transport()
    c = LLMClient("E", transport=t, hard_cutoff_s=5, timeout_s=8)
    c.complete("{}")
    assert t.calls[0]["deadline_s"] == 5.0


def test_hang_abandoned_at_hard_cutoff(monkeypatch):
    """Wrapper-level hard cutoff: a hung transport is abandoned ~cutoff."""
    import time

    def hang(url, payload, deadline_s):
        time.sleep(10)          # would outlive the suite if not abandoned
        return 200, "{}"

    monkeypatch.setenv("E", "http://x")
    c = LLMClient("E", transport=hang, timeout_s=8, hard_cutoff_s=1)
    start = time.monotonic()
    with pytest.raises(TimeoutError, match="hard cutoff"):
        c.complete("{}")
    assert time.monotonic() - start < 5   # abandoned promptly, not at 10s


def test_default_transport_is_wired():
    assert callable(default_transport())
