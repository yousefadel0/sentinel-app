"""Prompt+response audit records (G7/P6).

Every LLM exchange is logged VERBATIM as a structured, hashable, replayable
record: prompt text byte-exact, response text byte-exact, bounded metadata,
stable sha256 digest. Frozen dataclass ⇒ hashable ⇒ deduplicatable and
replayable from the audit store.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Protocol


class PairSink(Protocol):
    """Minimal audit-store interface — append one verbatim pair."""

    def append_pair(self, pair: "PromptResponsePair") -> None: ...


@dataclass(frozen=True)
class PromptResponsePair:
    """One verbatim LLM exchange — G7's 'LLM output verbatim' record."""

    case_id: str
    prompt_verbatim: str
    response_verbatim: str
    status: str                       # ok | parse_error | transport_error
    elapsed_ms: int
    endpoint_env_var: str             # env var NAME only — never the URL
    temperature: float
    ts: str                           # ISO-8601 UTC
    extra: tuple[tuple[str, str], ...] = field(default_factory=tuple)

    def digest(self) -> str:
        """Stable sha256 over the canonical JSON of this pair."""
        blob = json.dumps(self.to_dict(), sort_keys=True,
                          separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "prompt_verbatim": self.prompt_verbatim,
            "response_verbatim": self.response_verbatim,
            "status": self.status,
            "elapsed_ms": self.elapsed_ms,
            "endpoint_env_var": self.endpoint_env_var,
            "temperature": self.temperature,
            "ts": self.ts,
            "extra": [[k, v] for k, v in self.extra],
        }

    @classmethod
    def from_dict(cls, data: MappingLike) -> "PromptResponsePair":
        """Replay constructor — rebuilds a byte-identical record."""
        return cls(
            case_id=data["case_id"],
            prompt_verbatim=data["prompt_verbatim"],
            response_verbatim=data["response_verbatim"],
            status=data["status"],
            elapsed_ms=int(data["elapsed_ms"]),
            endpoint_env_var=data["endpoint_env_var"],
            temperature=float(data["temperature"]),
            ts=data["ts"],
            extra=tuple((k, v) for k, v in data.get("extra", ())),
        )


class MappingLike(dict):  # noqa: UP006 — typing alias kept simple
    pass


class InMemoryPairSink:
    """List-backed sink for tests and dry-run introspection."""

    def __init__(self) -> None:
        self.pairs: list[PromptResponsePair] = []

    def append_pair(self, pair: PromptResponsePair) -> None:
        self.pairs.append(pair)
