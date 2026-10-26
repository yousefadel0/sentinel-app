#!/usr/bin/env bash
# Sentinel sandbox bootstrap — ephemeral-sandbox discipline (§9-I6):
# every tool install is committed here so nothing lives only in a session.
# Idempotent; safe to re-run. Docker build of the image happens at M6,
# this script covers plain-container dev environments.
set -u  # not -e: we report failures explicitly below

PY=${SENTINEL_PYTHON:-python3}

echo "[bootstrap] interpreter: $($PY --version)"

if ! "$PY" -c 'import sys; assert sys.version_info >= (3, 11)' 2>/dev/null; then
    echo "[bootstrap][ERROR] Python 3.11+ required by §8 pin; refusing." >&2
    exit 1
fi

"$PY" -m pip install --quiet --upgrade pip || { echo "[bootstrap][ERROR] pip upgrade failed" >&2; exit 1; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
"$PY" -m pip install --quiet -e "$REPO_ROOT[dev]" \
    || { echo "[bootstrap][ERROR] editable install with [dev] extras failed" >&2; exit 1; }

# --- M7 (§9-I6): Minimal Ops UI deps — optional extra, installed here so the
# sandbox can exercise the ui package; core CLI does not require them.
if ! "$PY" -c "import fastapi, uvicorn" >/dev/null 2>&1; then
    "$PY" -m pip install --quiet 'fastapi>=0.110' 'uvicorn>=0.29' 'httpx>=0.27' \
        || echo "[bootstrap][WARN] ops-ui deps install failed — sentinel.ui will refuse to import (honest degradation)"
fi

# --- M4: nftables userspace tooling (§9-I6 sandbox-first) -----------------
if command -v apt-get >/dev/null 2>&1; then
    if ! command -v nft >/dev/null 2>&1; then
        echo "[bootstrap] installing nftables via apt-get"
        apt-get update -qq \
            && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nftables \
            || echo "[bootstrap][WARN] nftables install failed — actuator will report health=down honestly"
    else
        echo "[bootstrap] nft already present: $(command -v nft)"
    fi
else
    echo "[bootstrap][WARN] no apt-get found; skipping nftables install (actuator degrades to health=down)"
fi

echo "[bootstrap] installed:"
command -v sentinel && sentinel --version
"$PY" -m pytest --version

command -v nft >/dev/null 2>&1 || echo "[bootstrap] nft: NOT PRESENT (honest degradation path)"

echo "[bootstrap] OK"
