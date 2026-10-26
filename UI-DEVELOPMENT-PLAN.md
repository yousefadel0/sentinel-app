# Sentinel Ops UI — Development Plan

## 1. Objective

Turn the current minimal Ops UI into a clear, usable local dashboard for
reviewing Sentinel's capture inputs, decisions, approvals, audit history, and
pilot metrics. The UI must explain what the data means and whether it came
from replay or live capture. It must preserve Sentinel's fail-closed security
and decision pipeline.

This plan covers the Ops UI and its integration boundaries. It does not make
the file-replay pilot a live network sensor or authorize automatic
enforcement.

## 2. Current baseline

- The M7 UI is an optional FastAPI/HTMX module bound to loopback.
- Authenticated JSON routes expose capture health, approvals, recent
  decisions, and KPI counters.
- The original page places those JSON responses directly in the HTML, so the
  result is technically readable but not an operator-friendly dashboard.
- The supplied standalone launcher attaches a store but no decision engine;
  it is observer-only, so its approval queue is empty and approval writes
  return `409`.
- Capture health can describe file replay when the capture directory is
  passed. It does not prove live NIC capture.
- The audit store accumulates rows between pilot runs. KPI totals therefore
  represent the store, not just the latest run.
- The current user laptop checkout is `C:\Users\A\Desktop\sentinel-app`.
  The editing workspace available to this task is `D:\sentinel-app`; changes
  in the latter do not automatically update the laptop checkout.
- An Arabic, right-to-left dashboard draft is implemented in the task
  workspace: KPI cards, source cards, a recent-decisions table, a clear
  observer-only empty state, and separate HTML fragment routes. The original
  JSON API routes remain available. It has passed syntax checking, 33 focused
  auth/parity/bind tests, and a live local HTTP smoke check. Two process
  isolation tests use POSIX `SIGKILL` and are not portable to Windows. The
  draft has not yet been installed into the laptop checkout or visually
  confirmed in that browser.

## 3. Product and safety requirements

1. **Make state understandable:** distinguish capture sources, decisions,
   recommendations, approvals, and executed actions. Explain `log_only`,
   replay MTTD, sample counts, and cumulative totals in the UI.
2. **Represent evidence honestly:** show unknown values as unknown; zero is
   not interchangeable with unavailable. Identify replay data as replay and
   never present it as live capture.
3. **Preserve the API:** keep `/health/capture`, `/approvals`,
   `/incidents/recent`, and `/kpis` JSON response contracts stable while
   adding HTML views on separate routes.
4. **Keep the authorization boundary:** loopback-only bind, fail-closed
   header token auth, constant-time comparison, and no token in query
   strings. Keep the vendored HTMX file as the sole unauthenticated route
   unless a separately reviewed change is approved.
5. **Keep the decision boundary:** any approval must call
   `Engine.resolve(...)`; the UI must not score incidents, bypass validators,
   or execute an action itself.
6. **Keep the audit boundary:** approval decisions continue to write through
   `Store.record_decision`; audit tables remain append-only. Read views use
   SELECT-only queries.
7. **Degrade honestly:** missing store, engine, capture directory, or data
   produces a clear empty/unavailable state rather than fabricated values or
   a server crash.
8. **Use no new persistence layer:** the UI reads the existing audit store
   and capture files. It does not create a second operational database.

## 4. Work plan

### Phase 0 — Reconcile the working copy

**Tasks**

- Confirm the exact laptop checkout and inspect its current `sentinel/ui`
  files before copying anything.
- Preserve the existing `capture/audit.sqlite` and configuration. Do not
  regenerate or clear the audit store as part of a UI update.
- Compare the workspace draft with the laptop files and record the source
  revision or file hashes when Git metadata is unavailable.
- Stop the existing UI process before replacing its Python modules.

**Acceptance**

- The target checkout is confirmed to contain the same M7 UI/API baseline.
- Only intended UI source files are replaced; pilot data and configuration
  remain untouched.

### Phase 1 — Readable dashboard foundation

**Tasks**

- Render the landing page in Arabic RTL with responsive layout and clear
  section headings.
- Replace raw JSON-on-page output with human-readable KPI cards and tables.
- Add empty, unavailable, loading, and error states.
- Show recent decisions with time, incident identifier, outcome, score,
  tier, and the engine's recorded explanation.
- Show capture files by name and label their source as replay.
- Explain that totals are cumulative across the attached audit store.
- Preserve authenticated JSON API routes and add dedicated authenticated
  HTML-fragment routes for the dashboard.

**Acceptance**

- A user can identify incident count, outcome distribution, replay MTTD,
  benign sample denominator, actions recorded, actions executed, rollbacks,
  and LLM latency without parsing JSON.
- The UI labels replay data as replay and displays an explicit no-live-capture
  statement in replay mode.
- Existing JSON callers receive the same route shapes and values.

### Phase 2 — Approval workflow and observer mode

**Tasks**

- Render pending human approvals with score, outcome, deadline, and clear
  approve/deny controls only when a real engine is attached.
- Send approve/deny through the existing `Engine.resolve` seam and show a
  readable success/error message.
- Keep observer-only mode explicit when the engine is absent; hide or disable
  write controls and explain why they are unavailable.
- Show approval expiry or missing IDs as explicit states.

**Acceptance**

- Approve and deny retain the same audit-row semantics as the existing CLI
  path, with honest `case_id` provenance.
- No UI approval succeeds without an attached engine and store.
- A missing engine produces an observer message, not a fake empty live queue.

### Phase 3 — Audit and incident detail

**Tasks**

- Add a detail view for a selected incident with the complete decision
  explanation, audit-event sequence, recommendation, and provenance.
- Add a read-only audit-history view over existing tables, with bounded
  pagination and filters by time, outcome, tier, and case.
- Display prompt/response audit metadata only where appropriate; do not
  expose secrets or raw network payloads.
- Keep exports out of scope until their privacy and authorization behavior is
  defined.

**Acceptance**

- Operators can trace a displayed decision to its stored audit events without
  changing the audit store.
- User-controlled strings are HTML-escaped in every rendered view.
- Queries remain bounded and SELECT-only.

### Phase 4 — Usability and accessibility

**Tasks**

- Check RTL layout, keyboard navigation, visible focus, text contrast, and
  narrow-window behavior.
- Keep decision states distinguishable by both text and color.
- Add explicit UTC/local-time labeling and consistent timestamp formatting.
- Make refresh intervals visible and avoid flashing or replacing a section
  while an operator is acting on it.
- Keep the interface usable if HTMX polling fails; provide a clear retry or
  last-updated state.

**Acceptance**

- Primary content fits a laptop viewport without horizontal page scrolling;
  wide tables scroll inside their own containers.
- All important statuses have readable text and are not color-only.
- Polling does not duplicate writes or trigger approval actions.

### Phase 5 — Integration and operational launch

**Tasks**

- Provide one documented Windows launcher that loads the validated config,
  sets the token through the documented environment variable, attaches the
  audit store with `check_same_thread=False`, and passes the capture directory.
- Document that the standalone UI has no live decision engine unless one is
  explicitly injected by a supported host process.
- Document local browser access and header authentication without exposing
  the token to unrelated sites.
- Keep the existing loopback bind and allowed-port checks.

**Acceptance**

- A clean Windows setup can start the UI with Python 3.12 using the optional
  `ops-ui` dependencies.
- The launcher reports actionable startup failures and explains a
  successful quiet startup.
- No token is hard-coded into committed configuration or source.

### Phase 6 — Verification and release

**Tasks**

- Run the focused auth, bind, approval-parity, read-only, rendering, and
  process-isolation tests on supported platforms.
- Add platform-aware process-isolation coverage: use Windows process
  termination semantics on Windows and POSIX signals on POSIX.
- Test dashboard rendering with empty stores, populated stores, missing
  capture directories, stale replay files, special characters, and malformed
  optional values.
- Run a local end-to-end pass: start UI, run pilot, confirm the new decision
  appears, verify KPIs, stop the UI, and confirm the audit store remains
  intact.
- Update README and the M7 delivery notes so the documented UI matches the
  actual routes, launcher, and observer-mode limitations.

**Acceptance**

- Existing UI/API tests pass on the target platform; platform-specific
  failures are not counted as UI regressions without investigation.
- No unauthenticated operational route is introduced.
- A restart and a repeated pilot run do not corrupt the store; cumulative
  metric behavior is documented.
- The release notes list verified behavior separately from unresolved live
  capture or deployment work.

## 5. Suggested delivery sequence

1. Reconcile the laptop checkout and install the dashboard foundation.
2. Confirm browser rendering and current replay data on the user's machine.
3. Complete approval UX only for a supported engine-attached deployment.
4. Add audit/incident detail views.
5. Complete accessibility, Windows launcher, and documentation updates.
6. Run the platform-aware release verification and publish the closeout.

## 6. Explicitly out of scope for this UI plan

- Enabling live traffic capture or changing the Suricata/Zeek deployment.
- Changing scoring, correlation, playbooks, validators, autonomy, or
  actuator behavior.
- Enabling real network enforcement or changing the dry-run/shadow default.
- Exposing the UI on a routable address or weakening token authentication.
- Replacing the append-only SQLite audit store or deleting existing pilot
  records.

## 7. Open decisions before broader deployment

- Which supported host process will attach a live decision engine to the UI?
- Should the first release remain Arabic-only, or provide a language switch?
- What retention and pagination limits are expected for a production-sized
  audit store?
- Which browser access method will be supported for operators without
  requiring a broad header-injection extension?
- Which Windows and Linux versions are official deployment targets?
