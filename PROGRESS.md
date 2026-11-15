# Sentinel production progress

## Phases
- [x] P1 — Gap check against the requested product spec.
- [ ] P2 — Software paths implemented; live liveness/upstream contracts await the Linux site.
- [x] P3 — Env-backed configuration, validation, structured errors/logging, graceful cleanup and health.
- [x] P4 — Tier/timeout/detection tests and five dry-run attack simulations.
- [x] P5 — Compose, image, .env example, Linux launcher/systemd, README runbook.
- [ ] P6 — Full suite passed; image build requires a running Docker Linux engine.

## P1 initial gaps
- [x] Persisted, versioned, exportable 14-day baseline and automatic LEARNING-to-ACTIVE transition.
- [x] 95/80/50 confidence bands, 15/30-minute deadlines, modification and manual handling.
- [x] Local real-time ATT&CK candidate matching and observed-CVE NVD cache.
- [ ] Current live execution is fail-closed without a real liveness checker. A working enforcement point, reversible upstream actions, and restart recovery are unverified.
- [ ] Linux packaging has syntax validation only; fresh-host smoke test remains.

## Decisions
- Preserve existing changes and fail-closed enforcement while implementing missing behavior.
- ATT&CK is technique context, not proof of maliciousness. CVEs come only from evidence and NVD or another explicit vulnerability feed.
- An automatic fallback cannot bypass the protected-target rule, live-action gate, expiration, rate cap, or rollback requirement.
- Implemented a versioned JSON learning profile with atomic writes, fourteen observed days before automatic activation, manual mode/extension controls, feature counts, anomaly alerts, and an executor gate.
- Response bands now use confidence (95/80/50) with configurable timeouts; the score remains severity context. Every pending approval/report enters the deadline watch. A report timeout executes a configured ordered protective plan through the same enforcement gates.
- `site.protected_ips` is validated and enforced at the action gate alongside critical assets. The live SOAR webhook is withheld because it has no verified rollback contract; dry-run still reports intent.
- CLI refuses live mode with an empty explicit `site.protected_ips` list.
- Live decisions attach candidate ATT&CK technique IDs from an in-process local cache; refresh runs in a background thread, and curated IDs remain available offline. Observed Suricata CVE IDs attach to decision inputs and use an asynchronously refreshed local NVD cache.

## P2 remaining work
- [x] Durable pending approvals/deadlines across restart, engineer modify via authenticated Ops API, and manual handling via acknowledgement.
- [x] Configurable ordered safe fallback plan for the 50–80% timeout.
- [ ] Real source/flow liveness proof and reversible upstream integration (requires site topology/API). Live enforcement remains fail-closed.
- [x] Learning-profile writers use cross-process locking and atomic replacement; ACTIVE freezes the baseline without age pruning. Malformed profiles fail closed.

## Open issues
- User will run the Linux trial later; prepare and verify the package locally, then provide the exact Linux validation steps. Docker Desktop engine is unavailable here, so a container build is not yet proven.
- Sensor topology and actual firewall/SOAR API are not supplied. Live enforcement cannot be declared production-ready without them.
- Final Windows result: 569 passed, 4 skipped, 1 warning. `docker compose config --quiet` and both example config validations passed. `docker build` could not connect to Docker Desktop Linux Engine; no Linux build or live network trial was claimed.
