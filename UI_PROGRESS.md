# Sentinel UI progress

## Phases
- [x] 1. Truth audit: initial screenshots, source tracing, known attacks, approvals, timeout, learning and anomaly; before/after evidence in UI_AUDIT.md.
- [x] 2. Real data pages, validated settings overlay, SSE, baseline comparison, responsive SOC styling and browser retest.
- [x] 3. In-app Getting Started and GUIDE.md.
- [ ] 4. After screenshots and full tests passed; Compose config passed. Container build/up await a Docker Linux Engine or Linux host.

## Decisions
- Preserve the existing uncommitted production work and keep dry-run enabled throughout this task.
- Treat a control as real only when its browser action reaches a persisted API/DB path and its result is observed.
- Initial authenticated Chrome screenshots are in `audit/`; populated scan/brute/DDoS screenshots are in `audit/before-populated/`. `UI_AUDIT.md` records the initial classifications.
- Stock dry-run CLI downgraded all three simulated attacks to log-only because liveness was unknown. Simulation must expose truthful recommendation tiers without inventing live flow proof; the executor remains dry-run.
- Dry-run simulation preserves recommendation tiers with an explicit liveness-unverified audit event; no network action executed. Browser approve, deny and modify reached Engine.resolve; one-minute deadline reached `sentinel_timeout` and was withheld by learning observe-only.
- The authenticated headless Chrome pass reached all 11 current pages without JavaScript errors. In-progress captures are in `audit/in-progress/`.
- Added browser token entry at `/login`; authenticated data routes remain header gated. UI settings overlay persists beside audit.sqlite, is validated at boot, and takes effect after restart. Dry-run remains true.
- Browser exercised login, settings save, learning extend and repeated mode switches, on-demand report; a synthetic 14-day audit profile exercised auto Active and anomaly. After screenshots in `audit/after/`.
- Full pytest suite passed on Windows (4 platform skips); `docker compose config --quiet` passed. `docker compose build sentinel` failed because Docker Desktop Linux Engine is not running.

## Open issues
- Docker Desktop Linux Engine is unavailable locally; Compose syntax can be checked, but Linux `up` cannot be proven here.
- Live sensor and enforcement acceptance must be performed on the target Linux network; no real packet capture, firewall rule or SOAR receipt is claimed.
