"""Minimal Ops UI (M7) — isolated OPTIONAL module.

Pure observer by construction: every route reads existing SQLite tables
via ``sentinel.auditstore.Store`` / ``sentinel.pilot.kpi.compute_kpis``;
the detect→decide→act loop never imports anything here. Approvals enter
through the named seam ``Engine.resolve(approval_id, approved)`` — the
identical entry point as the CLI path. UI outage degrades gracefully to
CLI and NEVER affects the loop (test-proven).

Requires the optional ``ops-ui`` extra (fastapi+uvicorn); importing this
package without them raises ImportError honestly rather than half-working.
"""
from __future__ import annotations

try:  # fail-closed dependency probe (honest degradation, §9 style)
    import fastapi  # noqa: F401
    import uvicorn  # noqa: F401
except ImportError as _exc:  # pragma: no cover - exercised only w/o extra
    raise ImportError(
        "sentinel.ui requires the optional 'ops-ui' extra "
        f"(`pip install .[ops-ui]`): {_exc}"
    ) from None

__all__ = ["create_app"]
