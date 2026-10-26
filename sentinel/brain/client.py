"""LLM HTTP client wrapper (§8 brain block).

Bounds enforced HERE, at the wrapper level — never trusted to callers:
    temperature clamped to [0.0, 0.2]
    timeout_s     (default 8)  — total request budget
    hard_cutoff_s (default 5)  — connect+read deadline surfaced to transport

Endpoint resolution: config names an ENV VAR (brain.llm_endpoint_env, e.g.
SENTINEL_LLM_API); the URL is read from that variable AT CALL TIME so tests
can point it at a local mock server and CI makes zero live API calls.

The transport is injectable: any callable (url, payload_bytes, deadline_s)
-> (status:int, body:str). Tests use fakes or a localhost mock; production
wires urllib. All network errors surface as exceptions for triage_incident
to swallow silently (P4).
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable

MIN_TEMP, MAX_TEMP = 0.0, 0.2


@dataclass(frozen=True)
class LLMResponse:
    """Raw transport outcome — parsed/validated only by output.parse_output."""

    status: int
    body: str
    elapsed_ms: int


Transport = Callable[[str, bytes, float], tuple[int, str]]


def _urllib_transport(url: str, payload: bytes, deadline_s: float
                      ) -> tuple[int, str]:
    """Production transport — stdlib only, hard deadline honored."""
    req = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type": "application/json"},
        method="POST")
    with urllib.request.urlopen(req, timeout=deadline_s) as resp:
        return int(resp.status), resp.read().decode("utf-8", "replace")


class LLMClient:
    """Bounded wrapper around a flash-tier endpoint (§5 model class)."""

    def __init__(
        self,
        endpoint_env_var: str,
        *,
        temperature: float = 0.1,
        timeout_s: int = 8,
        hard_cutoff_s: int = 5,
        transport: Transport | None = None,
    ) -> None:
        if not MIN_TEMP <= temperature <= MAX_TEMP:
            raise ValueError(
                f"temperature must be within [{MIN_TEMP},{MAX_TEMP}], "
                f"got {temperature}")
        if timeout_s < 1 or hard_cutoff_s < 1 or hard_cutoff_s > timeout_s:
            raise ValueError("require 1 <= hard_cutoff_s <= timeout_s")
        self._env_var = endpoint_env_var
        self._temperature = temperature
        self._timeout_s = timeout_s
        self._hard_cutoff_s = hard_cutoff_s
        self._transport = transport or _urllib_transport

    @property
    def temperature(self) -> float:
        return self._temperature

    def endpoint(self) -> str | None:
        """Resolve the endpoint URL from the configured env var, at call time."""
        value = os.environ.get(self._env_var)
        return value if value else None

    def complete(self, prompt_verbatim: str) -> LLMResponse:
        """POST the verbatim prompt; return raw body with elapsed time.

        Hard cutoff enforced HERE at the wrapper (contract point 7): the
        transport runs in a worker thread and is abandoned past
        hard_cutoff_s (TimeoutError), even if it hangs. A second bound
        rejects responses that exceeded timeout_s overall. Raises (never
        swallows) — triage_incident owns silent fallback.
        """
        url = self.endpoint()
        if url is None:
            raise RuntimeError(f"endpoint env var {self._env_var} unset")
        payload = json.dumps({
            "temperature": self._temperature,
            "hard_cutoff_s": self._hard_cutoff_s,
            "prompt": prompt_verbatim,
        }, separators=(",", ":")).encode("utf-8")

        import time
        from concurrent.futures import ThreadPoolExecutor
        from concurrent.futures import TimeoutError as FutureTimeout

        start = time.monotonic()
        executor = ThreadPoolExecutor(max_workers=1)
        try:
            future = executor.submit(self._transport, url, payload,
                                     float(self._hard_cutoff_s))
            try:
                status, body = future.result(timeout=float(self._hard_cutoff_s))
            except FutureTimeout:
                raise TimeoutError(
                    f"LLM call exceeded hard cutoff {self._hard_cutoff_s}s"
                ) from None
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

        elapsed_ms = int((time.monotonic() - start) * 1000)
        if elapsed_ms > self._timeout_s * 1000:
            raise TimeoutError(
                f"LLM call exceeded timeout {self._timeout_s}s")
        return LLMResponse(status=status, body=body, elapsed_ms=elapsed_ms)


def default_transport() -> Transport:
    """Expose the production transport for wiring/tests without importing
    internals elsewhere."""
    return _urllib_transport


def _unused(*_args: Any) -> None:  # pragma: no cover — keeps linters calm
    return None
