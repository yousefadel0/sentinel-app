\# PROJECT: SENTINEL — Autonomous AI Network Defense Agent

\## Master Document v4.1 FINAL — single source of truth



You are my senior security engineer building this product WITH me.

Read fully at every session start. State the active milestone atop each reply.

Work ONE milestone per session. Ask — never guess.



────────────────────────────

TABLE OF CONTENTS

────────────────────────────

&#x20;1 Vision \& Principles     6 Decision Engine          11 Success Metrics

&#x20;2 Scope                   7 Guardrails               12 Working Protocol

&#x20;3 Architecture            8 Tech Stack \& Config

&#x20;3.1 Topology Handling     9 Build Environment

&#x20;4 Data Model              10 Milestones

&#x20;5 AI Brain Contract



════════════════════════════════════════════

1\. VISION \& PRODUCT PRINCIPLES

════════════════════════════════════════════

Sentinel is a portable, self-contained network defense SOFTWARE appliance.

Deployed as VM/Docker into any environment, it taps traffic via SPAN/TAP,

detects attacks in seconds, decides via a deterministic engine + bounded

LLM triage, and executes protective actions inside hard safety limits.



P1 PORTABLE BY DESIGN — zero hardcoded IPs/topology/credentials; every

&#x20;  deployment declares its world in config.yaml; ships as ONE Docker image.

P2 ADAPTER ARCHITECTURE — all integrations implement typed interfaces

&#x20;  (DataSource / Actuator). Core never knows vendor details.

P3 WIRE IS THE ANCHOR — primary visibility = own capture sensor (Suricata +

&#x20;  Zeek on SPAN), NOT the site SIEM. Full loop must work with ZERO SIEM.

P4 DEGRADES GRACEFULLY — LLM or connector down → rule-based fallback keeps

&#x20;  operating silently.

P5 SAFETY OVER AUTONOMY — dry-run default; doubt ⇒ notify, don't act;

&#x20;  autonomy earned per-deployment via evidence-gated ladder (L0→L3).

P6 AUDIT EVERYTHING — raw evidence → AI input → AI output → final decision:

&#x20;  fully reconstructable years later.



════════════════════════════════════════════

2\. SCOPE (v1)

════════════════════════════════════════════

IN:  port scan/recon · brute-force \& credential stuffing (SSH/web) ·

&#x20;    volumetric DoS/DDoS · C2 beaconing · DNS tunneling.

OUT: phishing/mail · EDR replacement · inline IPS (future opt-in) ·

&#x20;    multi-tenant console · cloud-native workloads (VM/cloud mirror

&#x20;    adapters allowed as DataSource types).



════════════════════════════════════════════

3\. ARCHITECTURE

════════════════════════════════════════════



┌─ INGESTION (capture NICs, no IP) ─┐  ┌─ CORE ─────────────────────┐  ┌─ ENFORCEMENT ────┐

│ capture\_interfaces\[] per config:  │  │ Normalizer → unified Alert │  │ Validator        │

│  Suricata eve.json stream         │─▶│ Correlator (incidents)     │─▶│ Actuators:       │

│  Zeek conn/dns/ssl/notice logs    │  │ Baseline engine            │  │  nftables local  │

│ Capture health monitor: heartbeat,│  │ Confidence tiers A/B/C     │  │  FW REST API     │

│  packet-drop counters, coverage % │  │ Decision Engine (+ liveness│  │  SOAR/webhook    │

└───────────────────────────────────┘  │  checks per §3.1)          │  └──────────────────┘

&#x20;                                       │ LLM triage (bounded role)  │

SIEM dual-role plane (PHASE-2 module,   └─────────┬──────────────────┘

NOT core dependency):                          Audit Store (SQLite append-only)

&#x20;INBOUND: identity/auth alerts                  + Notifier + approval channel

&#x20;(wire's blind spot: PtH/token theft/MFA fatigue)

&#x20;OUTBOUND: Sentinel verdicts pushed to customer SIEM for compliance.



DESIGN FACTS (immutable — do not "fix"):

• SPAN-based, NEVER inline — sensor failure cannot affect the data path.

• Wire sees allowed east-west traffic + TLS metadata (SNI/JA3) + flow timing;

&#x20; wire CANNOT see auth outcomes → that is what inbound SIEM enrichment adds.

• Placement doctrine: primary tap = Core/Distribution SPAN (east-west);

&#x20; secondary = Internet edge (north-south). Same-VLAN local switching and

&#x20; asymmetric paths are declared blind spots, never hidden (§3.1).

• Confidence tiers:

&#x20;   Tier A = wire evidence only     → auto-act at score ≥0.90

&#x20;   Tier B = wire + behavioral      → auto-throttle at ≥0.95, else human

&#x20;   Tier C = identity/external-fed  → NEVER auto-act; alert/human only



════════════════════════════════════════════

3.1 TOPOLOGY ASSUMPTIONS \& PRE-ACTION CHECKS

════════════════════════════════════════════

Blind spots must be DECLARED in config.yaml — validator enforces them.



NAT HANDLING (avoid blocking a NAT gateway instead of the real client):

&#x20;resolve real source via, in order:

&#x20;  1) nftables\_local adapter → parse /proc/net/nf\_conntrack for live bindings

&#x20;  2) firewall REST API session lookup if available

&#x20;  3) fallback: src\_ip private AND outside local subnets ⇒ treat as likely

&#x20;     NAT gateway → confidence penalty −0.15

&#x20;On mismatch: re-score with resolved real\_src before any decision.



PRE-ACTION VALIDATOR ORDER (every automated action passes ALL steps):

&#x20;1 NAT resolution (above)

&#x20;2 Liveness check vs Zeek conn state: target flow not alive ⇒

&#x20;    downgrade to log\_only + audit event "stale\_session\_drift"

&#x20;3 VLAN blind spot: alert.vlan ∉ monitored\_vlans ⇒ confidence −0.20 +

&#x20;    escalate\_to\_human + audit event "alert\_from\_blind\_spot\_vlan"

&#x20;4 CRITICAL\_ASSETS (G1): target ∈ allowlist and action aggressive ⇒

&#x20;    escalate\_to\_human. NO CODE-PATH EXCEPTIONS. Human-approved exceptions

&#x20;    may exist ONLY in operator-managed config WITH mandatory audit entry.

&#x20;5 Rate limiter (G4): breach ⇒ downgrade to notify\_only + internal alarm.

&#x20;6 Asymmetric routing: placement.asymmetric\_risk == high ⇒ block actions

&#x20;    downgraded to throttle\_src + audit "asymmetric\_routing\_risk".

&#x20;All passed ⇒ APPROVED.



════════════════════════════════════════════

4\. CORE DATA MODEL \& INTERFACES

════════════════════════════════════════════

{

&#x20; alert\_id, ts(iso8601),

&#x20; source:{adapter:"eve\_json|zeek\_conn|zeek\_dns|<future>", ref},

&#x20; src\_ip, dst\_ip, src\_port, dst\_port, protocol, vlan,

&#x20; asset\_hint:{resolved\_hostname, asset\_id,

&#x20;             criticality:critical|high|medium|low},

&#x20; signals:\["scan","auth\_fail\_burst","beacon\_periodic", ...],

&#x20; confidence\_raw 0..1, confidence\_tier A|B|C,

&#x20; meta{packet\_count, byte\_count, duration\_seconds, raw\_payload\_hash}

}



Adapter contract (ABC #1): DataSource.fetch() → list\[Alert] + health() →

&#x20;{status:healthy|degraded|down, heartbeat\_ts, packet\_drops,

&#x20; coverage\_percent, last\_alert\_ts}.

Actuator contract (ABC #2): execute(action) → ActionResult + rollback().

Nothing else in core knows adapter internals. NEVER return raw payloads —

hashes/summaries only.



════════════════════════════════════════════

5\. AI BRAIN CONTRACT (LLM-agnostic)

════════════════════════════════════════════

Model class: fast flash-tier endpoint, swappable via config env var.

temperature 0–0.2 · JSON-schema output ONLY · timeout 8s (hard cutoff 5s)

· rule pre-filter sends only ambiguous clusters (\~10% of alerts).



SAFE INPUT SCHEMA (anti prompt-injection — the ONLY fields ever sent):

&#x20;case\_id, src\_ip, dst\_ip, ports, protocol, direction, vlan\_tag,

&#x20;baseline\_deviation(σ), signal\_types\[](predefined enum only),

&#x20;geolocation, asn, counts/durations, confidence\_score, timestamps.

&#x20;NEVER raw payload strings, hex dumps, or free-text log excerpts.



LLM may ONLY:

&#x20;a) classify cluster → {attack\_type∈enum, confidence 0..1, severity 1..5,

&#x20;   affected\_assets\[], recommended\_action∈ALLOWED\_ACTIONS, ttl\_minutes≤60,

&#x20;   rationale}

&#x20;b) correlate N alerts → one-incident-or-not + reasoning

&#x20;c) narrate human-readable incident report for SOC review.

The LLM NEVER issues commands and is never the final authority; its output

is schema-validated then consumed by the deterministic Decision Engine.

Invalid/timeout/failure ⇒ rule-based path continues silently.

Every prompt+response pair logged to audit store verbatim.



ALLOWED\_ACTIONS v1: notify\_only | throttle\_src{ttl≤60,rate\_pps} |

&#x20;block\_ip\_temp{ttl≤60,scope} | quarantine\_asset{ttl≤60,isolation\_mode}

&#x20;| escalate\_human{reason,priority}



════════════════════════════════════════════

6\. DECISION ENGINE \& AUTONOMY LADDER

════════════════════════════════════════════

Deterministic, table-driven, unit-tested (100% coverage required).

score = f(detection\_confidence × asset\_criticality × threat\_severity)

&#x20;       adjusted by §3.1 penalties.

≥0.90 auto-act · 0.70–0.89 human approval (15-min timeout→notify-only)

· <0.70 log only. Auto-act ALWAYS after full §3.1 validator chain.



autonomy\_level per deployment (config, default 0):

&#x20;L0 shadow       : recommend "would do X because Y" — never touch network;

&#x20;                  collect FP data ≥14 days baseline

&#x20;L1 approve      : execute after explicit human OK

&#x20;L2 auto-critical: Tier A/B auto-throttle/auto-block high-score cases only

&#x20;L3 full-auto    : within rate limits + circuit breaker

UPGRADES: MANUAL operator actions gated on KPI evidence (§11). Never automatic.

AUTO-DOWNGRADE (rolling 14-day window):

&#x20;  FP% >5% → level−1 · FP% >8% → level−2 (floor L0) + immediate SOC alert.

&#x20;  Also: 3 consecutive rolled-back actions → level−1 (circuit breaker).



PLAYBOOKS v1:

&#x20;scan            → notify (throttle at L≥2)

&#x20;brute\_force     → block\_ip\_temp(src, ttl 30m)

&#x20;ddos\_volumetric → upstream call via webhook/SOAR; NEVER blind-block

&#x20;                  distributed sources locally

&#x20;c2\_beacon       → quarantine\_asset(dst, ttl 60m) + priority notify

&#x20;dns\_tunneling   → notify + proposed egress rule for human approval



════════════════════════════════════════════

7\. HARD GUARDRAILS

════════════════════════════════════════════

G1 CRITICAL\_ASSETS can never be targeted by any automated action.

&#x20;  Operator-approved exceptions live ONLY in config (human-set), each with

&#x20;  a mandatory audit entry — no code-path bypass ever exists.

G2 Dry-run DEFAULT everywhere; live needs explicit flag/config.

G3 All auto-blocks temporary: TTL ≤60 min, auto-expire scheduler,

&#x20;  one-command rollback (`sentinel ctl rollback`).

G4 Rate limits on auto-blocks: max\_blocks\_per\_min \& per\_hour in config;

&#x20;  breach ⇒ fallback to notify-only + internal health alarm.

G5 Circuit breaker as defined in §6.

G6 Validator between Decision Engine and EVERY actuator — full §3.1 chain.

&#x20;  Rejects anything else. No exceptions.

G7 Full audit trail: raw evidence hash, LLM output verbatim, decision path,

&#x20;  actor, timestamp.



════════════════════════════════════════════

8\. TECH STACK \& CONFIG (pinned — no silent substitutions)

════════════════════════════════════════════

Python 3.9+ (tested 3.9-3.14; was 3.11+) · SQLite (audit/state) · Docker single-image delivery · pytest

(≥85% core coverage; 100% on validator + decision engine) · Suricata +

Zeek local sensors · structlog-style JSON logging.

CORE stays CLI-only: minimal `sentinel ctl` command set + structured JSON

output. A Minimal Ops UI is allowed ONLY as an isolated optional module

(M7) — it queries existing data stores and MUST NOT introduce a new

backend/framework into core. No other web frameworks anywhere in v1.



config.yaml sketch (strictly validated at boot; refuse to start if invalid):

\---

site:

&#x20; name: customer-A

&#x20; critical\_assets:

&#x20;   - {ip: "10.0.0.4", hostname: "dc-01"}

&#x20;   - {ip: "10.0.0.5", hostname: "dns-primary"}

capture\_interfaces:

&#x20; - {name: edge\_span, type: af\_packet, iface: eth1}

&#x20; - {name: core\_span, type: af\_packet, iface: eth2}

placement:

&#x20; primary\_tap: core\_switch

&#x20; secondary\_tap: internet\_edge

&#x20; asymmetric\_risk: medium        # high|medium|low

monitored\_vlans: \[prod, mgmt]

unmapped\_vlans:  \[legacy\_lab]

has\_nat: true

brain: {llm\_endpoint\_env: SENTINEL\_LLM\_API, timeout\_s: 8, hard\_cutoff\_s: 5}

actuators:

&#x20; - type: nftables\_local

&#x20; - type: webhook\_soar

&#x20;   url: https://soar.local/hooks/sentinel

autonomy\_level: 0          # ALWAYS start shadow

limits: {max\_blocks\_per\_min: 5, max\_blocks\_per\_hour: 20, default\_ttl\_min: 30}

ops\_ui:                    # M7 module (optional)

&#x20; enabled: false            # never on by default

&#x20; bind: "127.0.0.1:8080"   # local/mgmt ONLY — never expose to routable nets

&#x20; auth\_token\_env: SENTINEL\_OPS\_UI\_TOKEN



════════════════════════════════════════════

9\. BUILD ENVIRONMENT \& EXECUTION MODES

════════════════════════════════════════════

I6 SANDBOX-FIRST MODE (default path — no dedicated lab required):

&#x20;  The full project is buildable inside ONE container — victim services

&#x20;  on loopback, Suricata/Zeek capturing lo/dummy0 interfaces, local

&#x20;  nftables actuator. This covers M0–M5 completely.

&#x20;  All tool installs MUST be committed as Dockerfiles/bootstrap scripts

&#x20;  in-repo (ephemeral-sandbox discipline: nothing lives only in a session).

&#x20;  Multi-container harness files ship to /infra for user-side execution

&#x20;  or DOCKER\_HOST at M6.



OPTIONAL ESXi LAB UPGRADE PATH (E0) — only if infra becomes available:

I1 Infra work ONLY through IaC committed under /infra (Terraform/govc).

&#x20;  NEVER ad-hoc destructive hypervisor commands; every apply user-reviewed.

I2 Least-privilege service account scoped to SENTINEL-LAB folder/pool only;

&#x20;  zero reach into production objects.

I3 Topology (VMs from templates + cloud-init, reproducible):

&#x20;    sentinel-appliance : Ubuntu, Suricata+Zeek capture NIC promiscuous

&#x20;    victim-server      : Ubuntu SSH/web target

&#x20;    attacker-kali      : hping3/nmap/hydra generators

&#x20;    gateway-firewall   : Linux nftables = actuator test target

&#x20;  Port groups: lab-net (isolated) · mirror-pg (promiscuous accept =

&#x20;  lab SPAN analog; covers traffic within its own group — declared limit).

I4 Snapshot after each successful build state; failed experiments revert.

I5 Dev-loop parity: everything must ALSO run on plain Docker via pcap

&#x20;  replay/dummy interfaces (ESXi never a prerequisite below M6).

E0 GATE: topology up/down with ONE command each, reproducible from git,

&#x20;  inventory diff before/after proves zero touch outside SENTINEL-LAB.



════════════════════════════════════════════

10\. MILESTONES — one per session, acceptance gates

════════════════════════════════════════════

M0 Scaffold \& contracts: repo layout, config loader+validator (full §8

&#x20;  schema incl. placement/vlans/has\_nat), structured logging, CLI

&#x20;  (--dry-run default true), DataSource/Actuator ABCs, pytest.

&#x20;  ✅ invalid config refuses boot w/ clear error; ABCs documented+importable.



M1 Capture layer FIRST-CLASS: Suricata deploy script + eve.json streaming

&#x20;  parser + Zeek log ingestion → Normalizer → Alert model (§4 fields incl.

&#x20;  vlan + tier assignment). Per-interface capture health: heartbeat,

&#x20;  packet-drop counters, coverage-map stub vs asset inventory. File/replay

&#x20;  adapters for dev fixtures.

&#x20;  ✅ fixtures → typed Alerts; health metrics reported per interface.



M2 Correlator (alerts→incidents) + Baseline engine: 14-day rolling window,

&#x20;  seasonal threshold multipliers from operator-maintained calendar.

&#x20;  ✅ correlator merges fixture chains into single incidents; baseline

&#x20;  thresholds shift correctly on seasonal override dates.



M3 Decision Engine complete in dry-run mode ("would do X because Y"):

&#x20;  scoring tables, tier logic A/B/C, playbooks-as-code, autonomy ladder,

&#x20;  FULL §3.1 pre-action chain (NAT resolve, liveness check vs zeek state,

&#x20;  blind-spot VLAN penalty, asymmetric downgrade).

&#x20;  ✅ decision table 100% unit-tested incl. allowlist-rejection cases.



M4 Validator module + nftables actuator (temp rules w/TTL scheduler +

&#x20;  rollback cmd) + webhook/SOAR actuator. Dry-run parity tests.

&#x20;  ✅ no code path reaches an actuator without passing validator

&#x20;  (test-proven).



M5 LLM brain integration: triage/correlation/narration against SAFE INPUT

&#x20;  SCHEMA (§5), schema validation, fallback path, prompt/response audit,

&#x20;  fuzzed-output tests.

&#x20;  ✅ fuzzed/invalid LLM output never alters any decision unvalidated;

&#x20;     payload-free prompts verified by test.



E0 ESXi lab bootstrap per §9 optional path (parallel to M1–M3 if used).

&#x20;  ✅ E0 GATE as above.



M6 Shadow pilot pack: full-loop harness — sandbox single-container OR the

&#x20;  /infra multi-container compose (attacker→capture→detect→gated action),

&#x20;  CICIDS2017 replay support, Docker packaging, KPI counters (MTTD,

&#x20;  FP-rate, actions, rollbacks), README runbook.

&#x20;  ✅ end-to-end attack contained in shadow mode with full audit trail,

&#x20;  ZERO SIEM present — proving P3.



M7 Minimal Ops UI (isolated optional module): FastAPI + htmx single-page

&#x20;  dashboard bound to localhost/mgmt only. Sections: capture health per

&#x20;  interface · pending approvals queue with Approve/Deny wired into the

&#x20;  existing 15-min timeout path · recent incidents · audit trail viewer ·

&#x20;  KPI counters (FP-rate, MTTD, actions, rollbacks). HARD RULES:

&#x20;  read-only everywhere except approval actions; every approval passes

&#x20;  the SAME §3.1 validator chain; token auth via env var; no internet

&#x20;  exposure; zero new data stores — pure queries over existing SQLite;

&#x20;  UI outage must NEVER affect the detect→decide→act loop (degrades

&#x20;  gracefully to CLI).

&#x20;  ✅ Gate: approving/denying from UI produces byte-identical audit entries

&#x20;     as CLI path; killing the UI server mid-flight leaves the decision

&#x20;     engine unaffected (test-proven); unauthenticated access → 401 on all

&#x20;     routes.



PHASE-2 (post-v1): Wazuh connector — inbound identity/auth enrichment into

&#x20;  incidents; outbound verdicts to customer SIEM.



════════════════════════════════════════════

11\. SUCCESS METRICS (upgrade gates)

════════════════════════════════════════════

FP-rate <5% over ≥14 days at current level · zero critical-asset

violations · MTTD seconds–minutes · MTTR <1 min auto actions · 100%

audited \& reversible.



════════════════════════════════════════════

12\. WORKING PROTOCOL

════════════════════════════════════════════

• One milestone per session; never touch later scope.

• Tests ship with code; untested actuator/validator logic = rejected.

• Surface all assumptions explicitly; no silent redesigns of §3/§8.

