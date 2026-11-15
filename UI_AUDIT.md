# Sentinel UI truth audit

Browser: headless Chrome via Playwright, authenticated `sentinel run --ui`, dry-run on. Initial screenshots: `audit/01-*.png` through `audit/07-mobile.png`; populated screenshots: `audit/before-populated/`.

| Screen / control | Initial status | Evidence |
|---|---|---|
| Overview KPIs, outcome/type charts, timeline | REAL with misleading labels | `analytics.overview` and `views.kpis` query SQLite; populated screenshot shows three simulated incidents. Readiness uses decision span rather than the learning baseline. |
| Incident list/filter/detail | REAL data, BROKEN confidence display | `analytics.incident_list` reads latest SQLite rows; browser shows scan/brute/DDoS, but displays severity-weighted score (17/78/40%) as “degree”, not event confidence. MITRE IDs require opening detail. |
| Approvals queue | REAL engine data, BROKEN/MISSING controls | `views.pending_queue` reads in-memory engine. Current CLI flow downgraded all simulated attacks to log-only because no live liveness proof; queue stayed empty. UI lacks modify button and hides countdown/manual handling for noncritical cases. Footer wrongly says timeout becomes notify-only. |
| Sources | REAL live-health file | `views.capture_health` reads daemon health JSON; replay fallback assigns packet drops a synthetic zero. |
| Audit/search/CSV | REAL decisions, partial | `views.audit_search`, `Store.verify_chain`, CSV export read SQLite. Actions, rollback and JSON export lack dedicated views. |
| Settings | REAL config snapshot, MOCK dry-run label | `views.settings_view` reads startup config; `pages.settings` hardcodes “dry-run enforced” regardless runtime state and offers no validated save. |
| Mode header | BROKEN | `/ui/mode` infers “live shadow” from health presence, not `LearningProfile.mode`; learning day/progress and actual dry-run state absent. |
| Reports | MISSING on-demand flow | `/reports/latest` serves a preexisting HTML file only; no generate button/API. |
| Learning, intel, actions, getting started | MISSING | No navigation pages or endpoints. |
| Live transport | MISSING | htmx polling only; no SSE/WebSocket. |

## Simulated flow evidence, initial state

- Wrote local Zeek `conn.log` samples for port scan, brute force and DDoS. SQLite `incident_context` recorded `T1046`, `T1110`, `T1498.001`, and the browser showed the three names and source addresses. All outcomes were `log_only` because liveness was `unknown`; therefore approval/timeout flows could not be exercised through the stock CLI UI yet.
- Anomaly, learning transition, approval/reject/modify/timeout, response rollback and report generation are pending browser verification. No result is claimed for them yet.

## Every mock or fake item found

- Hardcoded dry-run status in settings.
- Header mode text inferred from a health-file check rather than the persisted learning mode.
- Replay packet-drop count forced to zero without a sensor measurement.
- Static approval footer contradicts the configured timeout action.
- Readiness “14 days” derived from decision timestamps, not the baseline profile.
- The UI presents a severity-weighted score where a user expects detection confidence.

## After repairs (2026-11-09)

| Screen / flow | Status | Browser and data evidence |
|---|---|---|
| Login and header | REAL | `/login` accepts the actual token in headless Chrome; `/ui/mode` reads fresh `live-health.json` with learning mode, dry-run, source and notifier state. |
| Overview and feed | REAL | `analytics.overview`/`incident_list` read SQLite. Feed shows attack, persisted confidence, MITRE, source, tier and outcome. Timeline and breakdown use decision rows; source-target links use incident context. Daily log event count uses the versioned learning profile; unknown current volume is shown as `—`. |
| Incidents and approvals | REAL | Browser scan/brute/DDoS samples showed T1046/T1110/T1498.001. Browser approve and deny reached `Engine.resolve`; modify reached the same path with a validated action and TTL. A one-minute deadline recorded `sentinel_timeout`; executor recorded `withheld_autonomy` because learning remained observe-only. No live action executed. |
| Learning and anomaly | REAL with a stated test fixture | Browser extended learning and switched active/learning repeatedly. A separate **synthetic 14-day profile in audit/** demonstrated automatic Active and anomaly detection. The anomaly is named `Baseline anomaly`, confidence 55%, `report_wait`. It has **no MITRE ID** because a novel port alone does not establish an ATT&CK technique. |
| MITRE intel | REAL | Search/count/refresh time read the local ATT&CK cache (706 techniques in the audit run); CVE count reads the local CVE cache and is 0 when empty. |
| Actions, audit and reports | REAL | Actions/rollbacks query append-only SQLite; one-click rollback calls the executor for an active action. Audit filters, chain verification and CSV/JSON export query the store. Browser report generation wrote and downloaded a real snapshot. |
| Settings | REAL, restart required | Browser saved validated thresholds, limits, allowlist and notification definitions to `ui-settings.yaml`; reload reads the overlay. A guarded dry-run-off control requires confirmation and refuses while the safety gate is unmet. Dry-run stayed ON. |
| Getting Started and responsive layout | REAL content | Browser opened all 11 pages plus login with no JavaScript errors; screenshots are in `audit/after/`, including 390px mobile. `GUIDE.md` contains Linux, Docker and Windows run steps. |
| Live updates | REAL | Authenticated SSE `/ui/events` streams audit-head/mode changes; htmx refreshes the active view. The mode badge also polls every 20 seconds. |

Remaining verification limit: the local Docker Desktop Linux Engine is unavailable, so `docker compose config --quiet` passed but `docker compose build` and `up` could not be run here. No actual Linux sensor, firewall or SOAR execution was performed. The `audit/` 14-day baseline and attack rows are explicitly synthetic; they are not evidence of a real network's behavior.
