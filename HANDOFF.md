# Sentinel — Handoff كامل للمشروع

> الحالة وقت الكتابة: **2026-11-17**، الإصدار `1.0.0rc1`، الفرع `main`، آخر commit `98a00d5`.
> الملف ده موجّه لأي حد هيستلم المشروع (مطوّر، أو صاحبك اللي هيشغّله، أو أي AI agent).
> المصطلحات التقنية وأسماء الملفات مكتوبة بالإنجليزي عن قصد.

---

## 0. الخلاصة في دقيقة

- **Sentinel** نظام دفاع شبكي ذاتي. بيقرا logs من **Suricata** و**Zeek** و**Wazuh**، ويكتشف الهجوم، ويحسب له **score** حقيقي من الأدلة. بعد كده بيقرر واحد من دول:
  - **يسجّل بس**.
  - **يبلّغ وينتظر**.
  - **يطلب موافقة بشرية**.
  - **تصعيد حرِج** فيه deadline، ولو محدش رد بينفّذ لوحده.
  - **ينفّذ أوتوماتيك** في حدود الحماية.
- أي قرار بيتسجّل في **audit store** (SQLite، append-only، وكل الصفوف مربوطة بـ hash chain).
- عنده **Ops UI** فيها 11 صفحة، وشغّالة على loopback بس، ومحمية بـ token.
- الحالة الحالية:
  - الكود شغّال ومتختبر: 573 test نجحوا و4 skipped، و`sentinel selftest` بيدّي 12/12.
  - اتجرّب في Docker وكان healthy.
  - **لسه ما اتجرّبش على traffic حقيقي** لأن مفيش sensors متركّبة.
  - فيه bug أساسي (§9.1) **بيمنع وضع التنفيذ الحقيقي (no-dry-run) إنه يشتغل صح**. علشان كده لازم يفضل `dry-run` لحد ما يتصلّح.

---

## ⭐ تحديث v1.1 (2026-11-18) — المراحل 1 إلى 6

| المرحلة | ما تم | أين |
|---|---|---|
| 1. الأساس | **liveness حقيقي** من flows الـ sensors (alive/stale/unknown)؛ unknown لا يُسكت الحادثة بل يصعّدها لإنسان؛ **حد أدنى للخطورة** `policy.min_risk_score` (0.20)؛ **كتم ضوضاء Suricata** (أحداث المحرك 2200000-2299999 + `suppress_signature_ids`)؛ قواعد Suricata في volume دائم + تحديث يومي | `sentinel/capture/liveness.py`، `decision/engine.py`، `capture/normalizer.py`، `infra/sentinel-rules-update.*` |
| 2. الحسابات والأمان | `ops_ui.auth_mode: accounts`: مستخدمون بأسماء، أدوار **مشاهد/محلل/مدير** مفروضة في السيرفر، كلمات مرور scrypt (12+)، **تحقق بخطوتين TOTP** إجباري من أول دخول، جلسات HttpOnly+SameSite=Strict مع CSRF، انتهاء بعد 30 دقيقة خمول، قفل بعد 5 محاولات، **كل دخول/خروج/فشل مسجّل** في سجل التدقيق؛ HTTPS عبر Caddy (profile `web`) + `infra/firewall.sh` | `ui/accounts.py`، `ui/account_routes.py`، `infra/caddy/Caddyfile` |
| 3. صندوق المهام | صفحة **مهامي** الافتراضية: الموافقات المنتظرة + المهاجمون مجمّعون حسب المصدر + الضوضاء مطوية؛ صفحة الحادثة: **ماذا حدث** + الأدلة بالترتيب (signature/sid/منافذ) + **اتصالات المصدر**؛ **تقرير قابل للطباعة/PDF** لكل حادثة | `ui/analytics.py:inbox`، `ui/pages.py` |
| 4. Telegram | رسالة عربية + أزرار **اعتماد/رفض/استلمت** من الموبايل، `allowed_user_ids` لتحديد من يقرر، اسم الشخص يُسجَّل، **ملخص يومي** `daily_summary_hour_utc` | `notify/*`، `daemon.py:_maybe_daily_summary` |
| 5. AI agent | رأي استشاري يظهر في صفحة الحادثة + صفحة **الذكاء الاصطناعي** (حالة، أزمنة، آخر الردود)؛ أي رد لا يطابق الصيغة لا يُعرض أبدًا | `ui/pages.py:ai_page` |
| 6. التسطيب | `sudo ./infra/install.sh` يسأل 7 أسئلة ويسطّب كل شيء + **نسخ احتياطي يومي** (14 يوم) | `infra/install.sh`، `infra/sentinel-backup.*` |

الاختبارات: **609 نجحت، 0 فشل، 4 تخطّي**، تغطية 85.9%، selftest 12/12. CI مثبّت على ubuntu-24.04.
ما زال مفتوحًا: تكامل FortiGate (المرحلة 7، مؤجلة بقرار)، وسياسة fallback لنطاق 50–80%.

## 1. الرؤية والمتطلبات (من صاحب المشروع)

| الحالة | السلوك المطلوب | الإعداد الحالي |
|---|---|---|
| score ≥ 95% والهدف آمن | النظام ينفّذ لوحده | `policy.auto_act_threshold: 0.95` |
| 80% – 95% | موافقة بشرية خلال 15 دقيقة | `human_approval_threshold: 0.80` و`approval_timeout_minutes: 15` |
| 50% – 80% | تقرير وانتظار، وبعد 30 دقيقة fallback (throttle) | `report_threshold: 0.50` و`report_timeout_minutes: 30` و`report_fallback_actions: [throttle_src]` ⚠️ **ده توسيع عمله Codex ومحتاج قرار (§10)** |
| أقل من 50% | تسجيل فقط | — |
| حرِج جدًا | بلاغ عاجل للمدير فيه deadline من 15 لـ 30 دقيقة، ولو محدش رد ينفّذ تلقائيًا | `critical_response: {enabled, min_score, deadline_minutes}` |

متطلبات تانية:
- **الأرقام لازم تبقى حقيقية**، ومفيش أي fake data. الـ confidence بيتحسب من الأدلة نفسها، والـ live مفصول عن الـ replay.
- صاحبك يقدر يشغّله "دايركت" بأمر واحد.
- صاحب المشروع عنده **AI model خاص بيه**، والنظام بيدعم أي endpoint متوافق مع OpenAI (§6.6).
- بيئة صاحبك فيها **FortiGate / FortiProxy**، والتكامل معاهم لسه ما اتعملش (§9.2).

---

## 2. المعمارية

```
 Sensors (SPAN/TAP)            Sentinel daemon                                   Outputs
┌──────────────┐   tail   ┌───────────────────────────────────────────────┐   ┌─────────────────┐
│ Suricata eve │────────▶ │ DataSource adapters ─▶ Detectors ─▶ Correlator │   │ Ops UI (FastAPI)│
│ Zeek conn/dns│ offsets  │        │                    │                  │──▶│ Notifiers       │
│ Wazuh alerts │ rotation │        ▼                    ▼                  │   │ Telegram approve│
└──────────────┘          │  confidence.py      DecisionEngine (score,     │   │ SIEM out (CEF)  │
                          │  (evidence-derived)  bands, G1–G7, validators) │   │ Actuators       │
                          │                             │                  │   │ (nftables/SOAR) │
                          │     Learning gate ─▶ Executor gates ─▶ Actuator│   └─────────────────┘
                          │     CriticalWatch (urgent notify + deadline)   │
                          │     AdvisoryTriage (LLM, advisory only)        │
                          │                 ▼                              │
                          │        Audit Store (SQLite + SHA-256 chain)    │
                          └───────────────────────────────────────────────┘
```

**مسار الحدث، خطوة بخطوة:**
1. `sentinel/capture/live.py` بيعمل tail للملفات، وبيحفظ offsets في `OffsetStore`، وبيتعامل مع rotation. الـ flag `--skip-history` بيتجاهل القديم.
2. الـ adapters بتحوّل كل سطر لـ event موحّد، وبتسجّل origin بتاعه (`live` أو `replay`).
3. الـ detectors السلوكية بتطلّع findings.
4. الـ Correlator بيجمّع findings نفس المصدر والهدف في incident واحد. الـ corroboration هنا بيستخدم **Noisy-OR** بين adapters مستقلة.
5. الـ `DecisionEngine` بيحسب الـ score ويحدد الـ band وبيطبّق الـ guardrails.
6. الـ `Executor` بيعدّي على بوابات الأمان (§4)، وبعدها ممكن الـ actuator يتنفّذ.
7. كل خطوة بتتكتب في الـ audit store، والـ UI بتقرا منه.

---

## 3. خريطة الكود

الحجم تقريبًا 12k سطر Python، و52 ملف test.

| المسار | الوظيفة |
|---|---|
| `sentinel/cli.py` | كل أوامر CLI (§7)، وبيرفض `--no-dry-run` الخطر. **فيه bug §9.1** (`build_daemon` من غير `liveness_check`) |
| `sentinel/daemon.py` | `Daemon` و`LockedEngine` و`AdvisoryTriage` و`build_daemon` و`_build_executor` و`_build_notifiers`. الدالة `_decide()` بتحسب liveness |
| `sentinel/capture/live.py` و `tail.py` و `eve_parser.py` و `zeek_logs.py` و `health.py` | live tail و offsets و rotation، و parsers، و `live-health.json` |
| `sentinel/capture/confidence.py` | confidence من الأدلة: Suricata severity، و Zeek notice = 0.80، و Wazuh rule.level، و `UNKNOWN_FLOOR = 0.40` |
| `sentinel/detectors/suite.py` و `dns.py` | `scan` و `auth_fail_burst` و `volume_spike` و `beacon_periodic` و `dns_tunneling` و `baseline_anomaly` (الأخير من Codex) |
| `sentinel/correlator/correlator.py` | تجميع الـ incidents |
| `sentinel/decision/engine.py` | الـ score والـ bands والـ tiers A/B/C والـ guardrails G1–G7 وسلسلة validators §3.1، ومعاها `ConfigView` و `resolve()` |
| `sentinel/actuation/executor.py` | بوابات التنفيذ، و `rollback_one`، و upstream rollback contract |
| `sentinel/actuators/nftables_local.py` | nftables بـ timeout sets (`blocked`/`throttled`/`quarantined`) في chains input و forward. اتجرّب على nft 1.1 حقيقي |
| `sentinel/actuators/webhook_soar.py` | webhook لـ SOAR خارجي. قيمة `supports_rollback = False` (§9.2) |
| `sentinel/escalation.py` | `CriticalWatch`: بلاغ عاجل، وتذكيرات، و `/ack`، وتنفيذ عند الـ deadline |
| `sentinel/learning.py` | فترة تعلّم 14 يوم (من Codex). مفيش تنفيذ إلا في وضع `active` |
| `sentinel/simulation.py` | محاكاة (من Codex) |
| `sentinel/auditstore/store.py` | SQLite، و triggers تمنع UPDATE و DELETE، و `audit_chain`، و `verify_chain()`، و `chain_head()` |
| `sentinel/ui/app.py` | الـ routes والحماية و write routes (§8) |
| `sentinel/ui/pages.py` | HTML الصفحات (عربي RTL، htmx) |
| `sentinel/ui/static/` | `htmx.min.js`، وده بيتشحن في الـ package عن طريق `package-data` |
| `sentinel/pilot/runner.py` | بيحوّل الـ config لـ `ConfigView` وبيتحقق من ترتيب الـ thresholds |
| `sentinel/config/loader.py` | strict schema validation |
| `sentinel/selftest.py` | 12 فحص في مجلد مؤقت |
| `sentinel/timeutil.py` | `parse_iso` متوافق مع Python 3.9 |
| `tests/` | 52 ملف. الـ marker اسمه `slow` |
| `infra/` | `sentinel.service` (systemd)، و `run-linux.sh`، و `bootstrap.sh`، و `suricata-deploy.sh`، و `zeek-deploy.sh` |
| `scripts/start.ps1` | تشغيل Windows بضغطة واحدة |
| `docker-compose.yml` و `infra/Dockerfile` | خدمة `sentinel`، و profile `capture` (Suricata + Zeek) |
| `docs/` | `index.html` (الدليل الكامل) و `Sentinel-Architecture.pdf/.html` |
| `START-HERE.md` و `GUIDE.md` و `ROADMAP.md` و `README.md` | أدلة. `GUIDE.md` كتبه Codex |

---

## 4. منطق القرار والأمان

### 4.1 الـ score
```
score = confidence × criticality_weight × (severity / 5) − penalties
```
- **confidence** بيتحسب من الدليل نفسه. مثال: Suricata severity 1 بيدّي 0.85، و Zeek notice بيدّي 0.80، والمجهول ليه حد أدنى 0.40. لو فيه أكتر من adapter مستقل شاف نفس الحاجة بنستخدم Noisy-OR.
- **criticality_weight** بيعلى لما الهدف يكون في `site.critical_assets`.
- الـ UI بتعرض تفاصيل الحساب تحت عنوان "لماذا هذه الدرجة"، وده من جدول `incident_inputs`.

### 4.2 الـ Bands (الـ outcome)
`auto_act` ≥ 0.95، بعده `human_approval` ≥ 0.80، بعده `report_wait` ≥ 0.50، وتحت كده `log_only`.
لو الـ score ≥ `critical_response.min_score` والـ critical مفعّل، الـ incident بيتحوّل لـ **critical escalation**: إشعار عاجل وتذكيرات، ولو مفيش `/ack` ولا قرار لحد الـ deadline بيتنفّذ `Engine.resolve(by_deadline=True)`.

### 4.3 الـ Guardrails والبوابات
- **G1–G7** في الـ engine. منها: G1 بيتطبّق على **هدف الـ action**، ومنها الـ protected IPs، والـ tiers، والـ caps.
- **ترتيب بوابات الـ Executor** (`actuation/executor.py`):
  1. `can_act` من الـ learning، ومش هيعدّي غير لو `mode == "active"`.
  2. الـ autonomy level (L0–L3). عند L0 مفيش تنفيذ.
  3. dry-run.
  4. dedupe.
  5. hourly cap. الافتراضي `max_blocks_per_hour` و `max_blocks_per_min`.
  6. الـ actuator نفسه.
  7. upstream rollback contract. أي actuator خارجي لازم يكون `supports_rollback`.
  8. liveness recheck. لو مفيش checker، الـ liveness بتبقى `unknown` والتنفيذ **بيترفض**. (§9.1)
  9. Validator.
- **ضمانات الـ CLI:**
  - `--no-dry-run` مرفوض لو `autonomy_level` = 0.
  - `--no-dry-run` مرفوض لو `site.protected_ips` فاضية.
- أي action ليه **TTL**، وتقدر ترجّع فيه عن طريق `ctl rollback`.
- الـ **LLM** دوره advisory بس. عمره ما بيرفع score ولا بينفّذ.

---

## 5. البيانات والـ Audit

الملف: `audit.sqlite`، ومساره بيتحدد من `audit_store.path`. الجداول:

| الجدول | المحتوى |
|---|---|
| `meta` | إصدار الـ schema |
| `decisions` | كل قرار: incident_id و outcome و score و reasons |
| `llm_pairs` | prompt و response للـ brain |
| `actions` | الـ actions المقترحة والمنفّذة (`executed`) |
| `rollbacks` | الـ rollbacks |
| `incident_context` | المصدر والهدف والدليل |
| `incident_inputs` | مدخلات الـ score، ومنها "لماذا هذه الدرجة" |
| `analyst_notes` | ملاحظات المحلل من الـ UI |
| `audit_chain` | SHA-256 chain على كل الصفوف |
| `kpis_events` | KPIs، منها decision latency من الأحداث الـ live بس |

- التحقق من السلسلة: `sentinel ctl audit verify [--expect-head <hash>]`.
- ملفات تانية في الـ data dir:
  - `live-health.json`: ده اللي بيستخدمه الـ healthcheck.
  - ملف الـ offsets.
  - ملف الـ learning profile.
  - ملف الـ UI overlay settings.

---

## 6. الإعدادات (Config)

الملفات المرجعية: `config.example.yaml` (للتشغيل المحلي) و `config.container.yaml` (للـ Docker).
الملف الفعلي `config.yaml` أو `pilot_config.yaml` **ما بيترفعش على git**.

### 6.1 المفاتيح الأساسية
- `site`: فيها `name`، و `critical_assets` (قائمة `{ip, hostname}`)، و `protected_ips`.
- `capture_interfaces` و `placement` و `monitored_vlans` و `unmapped_vlans` و `has_nat`.
- `autonomy_level`: من 0 لـ 3.
- `enforcement_dry_run`: الافتراضي `true`.
- `limits`: فيها `max_blocks_per_min` و `max_blocks_per_hour` و `default_ttl_min`.
- `actuators`: مثلًا `[{type: nftables_local}]` أو `webhook_soar`.
- `audit_store.path`.
- `ops_ui`: فيها `enabled`، و `bind` (`127.0.0.1:8080`)، و `auth_token_env`، و `allowed_ports`.

### 6.2 السياسة
```yaml
policy:
  auto_act_threshold: 0.95
  human_approval_threshold: 0.80
  report_threshold: 0.50            # Codex
  approval_timeout_minutes: 15
  report_timeout_minutes: 30        # Codex
  report_fallback_actions: [throttle_src]   # Codex — محتاج قرار
critical_response:
  enabled: true
  min_score: 0.80
  deadline_minutes: 15              # من 15 لـ 30 حسب الرؤية
```
الـ loader بيرفض الإعداد لو `human > auto` أو `report > human`.

### 6.3 الـ Learning
- `learning_days` الافتراضي 14.
- الأوامر: `ctl learning <PROFILE> status|mode auto|learning|active|extend`، والملف `learning.json` جنب `audit.sqlite`.
- لحد ما الوضع يبقى `active`، **مفيش تنفيذ** حتى لو الـ dry-run مقفول.

### 6.4 الـ Notifiers
- webhook: `slack` أو `teams` أو `generic`.
- `telegram`، وبيدعم `/approve` و `/deny` و `/ack`.
- **لسه ولا واحد منهم متظبّط.**

### 6.5 الـ SIEM
- **inbound**: Wazuh `alerts.json` (Tier C).
- **outbound**: CEF أو HTTPS.

### 6.6 الـ Brain (الموديل الخاص)
- `brain.llm_endpoint_env`: اسم متغير البيئة اللي فيه الـ URL، والافتراضي `SENTINEL_LLM_API`.
- `timeout_s` و `hard_cutoff_s`.
- أي API **متوافق مع OpenAI** (`/v1/chat/completions`) هيشتغل. لو الموديل الخاص بصيغة تانية محتاج adapter صغير، ولسه مستنيين الـ format (§10).

### 6.7 ملاحظة على `config.container.yaml`
- **مفيهوش block اسمه `critical_response`**.
- `critical_assets` و `protected_ips` فاضيين.
- لازم يتملوا قبل أي pilot.

---

## 7. أوامر CLI

```bash
sentinel selftest                              # 12 فحص، مش بيلمس بياناتك
sentinel ctl config validate config.yaml
sentinel run --config config.yaml --capture-dir <logs> --ui [--poll-interval 2] [--skip-history]
sentinel ui  --config config.yaml --store <audit.sqlite> --capture-dir <logs> --report-dir <dir> --port 8080
sentinel ctl audit verify <audit.sqlite> [--expect-head <hash>]
sentinel ctl rollback --all [--table blocked]
sentinel ctl learning <data>/learning.json status | mode <auto|learning|active> | extend <days>
sentinel ctl intel sync-attack
```
لو الـ dry-run مش متحدد صراحة، بيتقرا من `enforcement_dry_run` في الـ config.

---

## 8. الـ Ops UI

- **Auth**: header اسمه `X-Sentinel-Token`. صفحة `/login` بتحفظ الـ token في `sessionStorage`، وأي request من غيره بيرجع 401.
- **Bind**: loopback بس. من بره بتوصل بـ SSH tunnel:
  ```bash
  ssh -L 8080:127.0.0.1:8080 user@sensor
  ```
- **الصفحات (11 تبويب):** نظرة عامة، الحوادث (وفيها تفاصيل وشرح الدرجة)، الموافقات، الـ actions، التقارير، الـ audit (بحث وتصدير CSV/JSON)، الـ learning، الإعدادات، الصحة، الـ stream (`/ui/events`)، والعمليات.
- **Write routes** (من Codex). كلها محمية بـ `_guard`، وبتتسجّل بـ `_record_ui_change`:
  - `approvals/{id}/approve|deny|modify|ack`
  - `/incidents/{id}/annotate`
  - `/settings/save`: overlay محصور في `site.protected_ips` و `policy` و `limits` و `notifiers` و `enforcement_dry_run`.
  - `/settings/dry-run`
  - `/learning/mode`
  - `/learning/extend`
  - `/actions/rollback`
  - `/reports/generate`
  - ⚠️ راجع §9.4.

**الـ token:**
- اعمله بنفسك:
  ```bash
  openssl rand -hex 24
  ```
  أو في PowerShell:
  ```powershell
  [guid]::NewGuid().ToString('N')
  ```
- حطّه في `.env` كـ `SENTINEL_OPS_UI_TOKEN` (Docker) أو في `.sentinel-token` (Windows). الاتنين في `.gitignore`.
- القيمة `local-only-demo-change-me` **demo بس**، ولازم تتغيّر قبل أي استخدام حقيقي.

---

## 9. المشاكل المعروفة (مرتبة بالأولوية)

### 9.1 🔴 وضع التنفيذ الحقيقي بيسكّت النظام (Bug)
- **السبب:** `sentinel/cli.py` بينادي `build_daemon(...)` **من غير `liveness_check`**. علشان كده `daemon._decide()` بيحسب `liveness = "unknown"`.
- **النتيجة:**
  - لو dry-run مقفول، الـ engine بيحوّل القرار لـ `liveness_unknown_treated_stale` ومن ثم `log_only`. اتأكدنا من ده: brute force بـ score 0.78 على سيرفر حرِج اتسجّل بس، ومفيش approval ولا إشعار.
  - الـ Executor كمان بيرفض أي action.
- **في dry-run كله شغّال**، لأن `dry_run_simulation` بيسمح بالـ unknown. والـ selftest بيمرر `lambda ctx: "alive"`.
- **الحل المقترح:**
  1. liveness حقيقي من Zeek `conn.log`، بآخر ظهور للـ IP في نافذة زمنية.
  2. الـ liveness المجهولة تمنع **التنفيذ بس**، ومتمنعش التصعيد والإشعار.
  3. تصليح نص السبب الغلط في `decision/engine.py`، اللي بيقول "confidence fell below the 0.70 band" مع إن السبب الحقيقي liveness.
- **لحد ما يتصلّح: متشغّلش `--no-dry-run`.**

### 9.2 🔴 مفيش مسار تنفيذ شبكي فعلي
- `webhook_soar` قيمته `supports_rollback = False`، فالـ Executor بيرفض أي upstream action، ومنها DDoS.
- `nftables_local` على sensor متوصّل بـ SPAN **بيحمي الـ sensor نفسه بس**، مش الشبكة.
- **المطلوب:** actuator لـ **FortiGate** عن طريق REST API: address object و address group و policy، أو quarantine. ولازم يكون فيه rollback و TTL.

### 9.3 🟠 سياسة 50–80% (Codex)
`report_wait`، ولو محدش رد في 30 دقيقة بيعمل throttle تلقائي. ده **مش جزء من الرؤية الأصلية**، والرؤية بتقول إن أي حاجة أقل من 70–80% مش المفروض تنفّذ لوحدها. محتاج قرار: يتشال الـ fallback، أو يفضل.

### 9.4 🟠 الـ UI write routes (Codex)
- أي حد معاه الـ token يقدر يغيّر الـ thresholds و `protected_ips` و الـ dry-run، ويحوّل الـ learning لـ `active` (وده بيقفل فترة التعلّم بدري).
- كل ده محمي ومتسجّل، بس بيخالف تصميم "الإعدادات read-only من الـ UI".
- **المقترح:** فصل token للقراءة عن token للكتابة، أو تأكيد تاني، أو قفل `/learning/mode=active` و `/settings/dry-run=false` من الـ UI خالص.

### 9.5 🟡 Scan و DNS tunneling عمرهم ما يوصلوا لتنفيذ
أقصى score ليهم تقريبًا 0.40 و 0.60. لو مطلوب إنهم يوصلوا للموافقة، لازم نرفع الـ severity أو الـ weight.

### 9.6 🟡 الكشف ما اتجرّبش على traffic حقيقي
- مفيش sensors لسه، علشان كده الـ UI بتطلع أصفار. **ده طبيعي ومفيش fake data.**
- Telegram و Slack مش متظبّطين.

### 9.7 🟡 الـ CI
- 12 من 13 jobs ناجحين.
- الفاشل: `test (ubuntu-latest, 3.9)`، والسبب `The version '3.9' ... was not found for Ubuntu 26.04`. يعني `ubuntu-latest` بقى 26.04. **دي مشكلة infra، مش كود.**
- **الحل:** في `.github/workflows/ci.yml` نثبّت `ubuntu-24.04`، أو نشيل 3.9 من ubuntu.

### 9.8 🟡 فجوات قبل الـ production
- الـ audit DB بيكبر من غير حد ومن غير retention/archival.
- مفيش backup.
- مفيش HA.
- الـ token الـ demo.
- الـ repo **public**، وفيه ملفين docs فيهم مسار جهاز شخصي. الأفضل يتشالوا أو الـ repo يتحوّل private.

---

## 10. قرارات مستنية صاحب المشروع

1. نبدأ بتصليح §9.1 (liveness)؟ **وده المقترح كأول خطوة.**
2. سياسة 50–80% بالـ fallback التلقائي: تفضل ولا تتشال؟
3. نرفع severity الـ scan و DNS tunneling؟
4. تكامل FortiGate: نحتاج الإصدار ونوع الوصول (REST API token) وطريقة الـ deployment.
5. صيغة الـ API للموديل الخاص: OpenAI-compatible ولا غيرها؟
6. الـ repo يفضل public؟

---

## 11. التشغيل

### 11.1 Windows (تجربة و UI)
```powershell
powershell -ExecutionPolicy Bypass -File scripts\start.ps1
```
- السكريبت بيعمل venv، وبيسطّب `.[ops-ui]`، وبيعمل `.sentinel-token` لو مش موجود، وبيعمل validate، وبيشغّل `run --ui`.
- افتح `http://127.0.0.1:8080/login` وحط الـ token.
- لو Requestly شغّال، الـ header يبقى `X-Sentinel-Token: <token>`.

### 11.2 Linux (الإنتاج): Ubuntu Server 24.04 LTS + Docker
```bash
git clone https://github.com/yousefadel0/sentinel-app && cd sentinel-app
cp .env.example .env   # حط SENTINEL_OPS_UI_TOKEN=$(openssl rand -hex 24) و CAPTURE_IFACE=<SPAN iface>
# عدّل config.container.yaml (أو نسخة منه واكتب مسارها في SENTINEL_CONFIG_FILE):
# املأ critical_assets و protected_ips و critical_response
docker compose --profile capture up -d --build   # sentinel + suricata + zeek
docker compose ps                # لازم يطلع healthy
docker compose logs -f sentinel
```
- الـ compose بيستخدم `network_mode: host`، والـ volumes `sensor-logs` و `sentinel-data`، والـ image `python:3.11-slim`.
- **علشان يفضل شغّال بعد الـ reboot**، انسخ `infra/sentinel.service` لـ `/etc/systemd/system/`، وبعدين:
  ```bash
  systemctl enable --now sentinel
  ```
  الخدمة فيها `Restart=always`.
- **الـ sensor** لازم يكون عليه interface متوصّل بـ **SPAN/mirror port** من الـ switch أو الـ FortiGate. من غيره Suricata و Zeek مش هيشوفوا traffic.
- **الوصول للـ UI** بيبقى بـ SSH tunnel (§8).

### 11.3 التحقق بعد التشغيل
```bash
sentinel selftest                 # لازم 12/12
curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/ui/overview        # 401
curl -s -H "X-Sentinel-Token: $TOKEN" -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/ui/overview  # 200
sentinel ctl audit verify <audit.sqlite>
```

---

## 12. الاختبارات وحالة التحقق

| البند | النتيجة |
|---|---|
| `pytest` على Windows | **573 passed و 4 skipped** |
| `sentinel selftest` | 12/12، على Windows وجوه الـ Docker image |
| Docker compose | healthy. الـ `/login` بيرجع 200، ومن غير token 401، وبالـ token 200 |
| nftables | اتجرّب على nft 1.1 حقيقي في Docker |
| CI matrix | ubuntu و windows × Python 3.9 لـ 3.14، بالإضافة لـ image job. النتيجة 12 من 13 (§9.7) |
| Traffic حقيقي | ❌ لسه |
| Telegram / Slack | ❌ مش متظبّطين |
| `--no-dry-run` live | ❌ متعطّل بسبب §9.1 |

لتشغيل الاختبارات:
```bash
pip install -e ".[dev,ops-ui]"
```
```bash
pytest -q
```
لو عايز تستبعد البطيئين:
```bash
pytest -q -m "not slow"
```

---

## 13. تاريخ المشروع

| Commit | المحتوى |
|---|---|
| `1121b89` | v1.0.0-rc1: confidence من الأدلة، وفصل live عن replay، وشرح الـ score، وthresholds من الـ policy، و G1 على هدف الـ action، وتصعيد حرِج بـ deadline، و brain متوافق مع OpenAI، وتشغيل بضغطة واحدة، و docs |
| `b865d3d` | docs: حالة التحقق في الـ roadmap |
| `f2ec21f` | `sentinel selftest` (12 فحص) |
| `69caebf` | (Codex) learning phase، و report band، و liveness gate، وصفحات عمليات في الـ UI |
| `98a00d5` | شحن `ui/static` في الـ package (كان بيكسر الـ UI في Docker)، وصفحة `docs/index.html` |

**مين عمل إيه:**
- Claude: الأساس، والمعمارية، والـ pipeline، والـ engine، والـ audit، والـ UI الأساسية، والـ Docker، والـ docs، والـ selftest.
- Codex: `learning.py`، و `REPORT_WAIT` بالـ fallback، والـ liveness gate، ومنع `--no-dry-run` لو `protected_ips` فاضية، والـ UI write routes، و `simulation.py`، و `baseline_anomaly`، و `GUIDE.md`.

---

## 14. الخطوات الجاية (مرتبة)

1. **تصليح §9.1**: liveness من Zeek، والتصعيد ميتأثرش بيها، وتصليح النص الغلط، وإضافة tests.
2. **تصليح الـ CI** (§9.7). سطر واحد.
3. **ملء `config.container.yaml`**: `critical_assets` و `protected_ips` و `critical_response`.
4. **تركيب sensor على Ubuntu 24.04** + SPAN، وتشغيل `--profile capture`، ويفضل **أسبوعين learning + dry-run** نراقب فيهم الأرقام الحقيقية.
5. **ظبط Telegram** (approve/deny/ack) واختبار تصعيد حرِج كامل.
6. **FortiGate actuator** بـ rollback و TTL (§9.2).
7. **قرارات §10** وتعديل الـ policy على أساسها.
8. **Hardening**: فصل tokens القراءة والكتابة، و audit retention، و backup، وتغيير الـ demo token، ومراجعة إن الـ repo public.
9. بعد كل ده، و بعد ما الأرقام الحقيقية تثبت، نبدأ نجرّب `--no-dry-run` على `autonomy_level: 1`.

---

## 15. قواعد لازم أي حد يستلم يلتزم بيها

- **متشغّلش `--no-dry-run`** قبل ما §9.1 يتصلّح، ومن غير `protected_ips`.
- **متعملش commit لأسرار**: `.env` و `.sentinel-token` و `config.yaml` و `pilot_config.yaml` و `audit/` و `*.sqlite` كلهم في `.gitignore`.
- **الـ repo public**: متعملش push لـ `audit/` ولا لـ `refs/codex/*` ولا لأي بيانات شبكة حقيقية.
- **متمسحش بيانات**: `capture/` و `data/` و `audit.sqlite` فيهم أدلة. والـ audit append-only عن قصد.
- **مفيش fake data**. لو الـ UI طالعة أصفار، معناها إن مفيش logs، مش إن فيه حاجة بايظة.
- أي تغيير في منطق القرار لازم ييجي معاه test، ولازم `selftest` يفضل 12/12.
