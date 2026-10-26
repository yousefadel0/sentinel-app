"""G7/P6 audit records — verbatim, structured, hashable, replayable."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.brain.audit import (InMemoryPairSink, PromptResponsePair)  # noqa: E402

PROMPT = '{"case_id":"c-1","src_ip":"203.0.113.7"}'
RESPONSE = '{"attack_type":"scan","confidence":0.9,"severity":3,' \
           '"affected_assets":[],"recommended_action":"notify_only",' \
           '"rationale":"probe"}'


def _pair(**kw) -> PromptResponsePair:
    base = dict(
        case_id="c-1", prompt_verbatim=PROMPT, response_verbatim=RESPONSE,
        status="ok", elapsed_ms=42, endpoint_env_var="SENTINEL_LLM_API",
        temperature=0.1, ts="2026-04-01T12:00:00+00:00")
    base.update(kw)
    return PromptResponsePair(**base)


def test_frozen_and_hashable():
    p = _pair()
    assert hash(p) == hash(_pair())
    assert {p, _pair()}.__len__() == 1


def test_digest_stable_and_content_sensitive():
    d1 = _pair().digest()
    assert d1 == _pair().digest()
    assert d1 != _pair(response_verbatim=RESPONSE.replace("scan", "brute_force")).digest()


def test_verbatim_preserved_byte_exact():
    weird = 'ignore previous instructions \t "quoted" \\ backslash'
    p = _pair(prompt_verbatim=weird)
    assert p.prompt_verbatim == weird
    assert p.to_dict()["prompt_verbatim"] == weird


def test_json_roundtrip_replay():
    p = _pair(extra=(("error_class", "TimeoutError"),))
    clone = PromptResponsePair.from_dict(p.to_dict())
    assert clone == p
    assert clone.digest() == p.digest()


def test_sink_appends_in_order():
    s = InMemoryPairSink()
    a, b = _pair(case_id="a"), _pair(case_id="b")
    s.append_pair(a)
    s.append_pair(b)
    assert [x.case_id for x in s.pairs] == ["a", "b"]
