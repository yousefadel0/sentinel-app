# Sentinel appliance image — single-image delivery per P1.
#
# Build:  docker build -f infra/Dockerfile -t sentinel:dev .
# Run:    docker run --rm sentinel:dev --version
# Live:   see docker-compose.yml (Suricata + Zeek + Sentinel on one SPAN NIC)
FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY sentinel ./sentinel

# ops-ui extra: the loopback-only Ops UI (`sentinel run --ui`) is optional but
# its dependencies ship in the image so enabling it is a config change only.
RUN pip install --no-cache-dir '.[ops-ui]'

# --- M4 (§9-I6): nftables userspace tooling committed in-image so the
# nftables_local actuator has its binary; kernel rules still require
# CAP_NET_ADMIN at deploy time. Honest degradation otherwise.
RUN apt-get update -qq \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends nftables \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONUNBUFFERED=1 \
    SENTINEL_CAPTURE_DIR=/logs

# Audit store, offsets and SIEM high-water mark live on this volume.
VOLUME ["/var/lib/sentinel"]

# Healthy = the daemon refreshed live-health.json within the last 60 s.
# (Source-level degradation is reported in that file / sentinel.prom; the
# container healthcheck only answers "is the loop alive?".)
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import os,sys,time; p=os.path.join(os.environ.get('SENTINEL_CAPTURE_DIR','/logs'),'live-health.json'); sys.exit(0 if time.time()-os.stat(p).st_mtime<60 else 1)"

# Capture NICs are attached at deploy time (SPAN/TAP, no IP — §3).
# Shadow-only daemon: root is only needed if nftables_local is later enabled.
ENTRYPOINT ["sentinel"]
CMD ["--help"]
