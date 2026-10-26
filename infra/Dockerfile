# Sentinel appliance image — single-image delivery per P1.
# COMMIT-ONLY ARTIFACT for M0 (built/tested at M6 packaging milestone).
#
# Build (later):   docker build -t sentinel:dev .
# Run (later):     docker run --rm sentinel:dev sentinel --version
FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY sentinel ./sentinel

RUN pip install --no-cache-dir .

# --- M4 (§9-I6): nftables userspace tooling committed in-image so the
# nftables_local actuator has its binary; kernel rules still require
# CAP_NET_ADMIN at deploy time. Honest degradation otherwise.
RUN apt-get update -qq \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends nftables \
    && rm -rf /var/lib/apt/lists/*

# Capture NICs are attached at deploy time (SPAN/TAP, no IP — §3).
# Runs as root so nftables actuator can operate in later milestones.
ENTRYPOINT ["sentinel"]
CMD ["--help"]
