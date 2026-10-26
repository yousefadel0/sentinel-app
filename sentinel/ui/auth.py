"""Token auth for the Minimal Ops UI (M7).

Transport choice (P2, stated explicitly): HEADER-ONLY — every API route
requires ``X-Sentinel-Token`` to equal the value of the environment
variable named by ``ops_ui.auth_token_env``. No cookies, no sessions ⇒
CSRF-immune by construction; no SameSite machinery exists or is needed.

P1: comparison MUST be constant-time — ``hmac.compare_digest``, never
``==`` string compare, even on localhost (timing side-channels do not
care about bind address).

Fail-closed: if the token env var is unset/empty at startup the app
refuses to serve rather than degrading to "allow all".
"""
from __future__ import annotations

import hmac
import os

from fastapi import HTTPException, Request

#: Header carrying the operator token (header-only transport, P2).
TOKEN_HEADER = "X-Sentinel-Token"


class TokenAuth:
    """Header-token gate; one instance per app, bound at create_app time."""

    def __init__(self, token_env_var: str) -> None:
        self._expected = os.environ.get(token_env_var)
        if not self._expected:
            # Fail-closed: refuse to serve with auth disabled-by-accident.
            raise RuntimeError(
                f"ops_ui: token env var {token_env_var!r} is unset or empty; "
                "the Ops UI refuses to start without a token (fail-closed)"
            )
        self._env_var = token_env_var

    @property
    def env_var(self) -> str:
        return self._env_var

    def check(self, request: Request) -> None:
        """Raise 401 unless the header token matches, constant-time (P1)."""
        supplied = request.headers.get(TOKEN_HEADER, "")
        if not supplied or not hmac.compare_digest(supplied, self._expected):
            raise HTTPException(status_code=401, detail="unauthorized")
