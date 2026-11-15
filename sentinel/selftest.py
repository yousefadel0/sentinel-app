"""`sentinel selftest` — proves the whole pipeline works on THIS machine.

Runs in a throw-away temporary folder: nothing touches your capture folder,
your audit store, or the network. It feeds a small simulated attack through
the real daemon code and checks every stage, then prints PASS / FAIL.
"""
from __future__ import annotations

import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

_CFG = {
    "site": {"name": "selftest",
             "critical_assets": [{"ip": "10.0.0.4", "hostname": "dc-01"}]},
    "capture_interfaces": [{"name": "t", "type": "af_packet", "iface": "eth0"}],
    "placement": {"primary_tap": "core", "secondary_tap": "edge",
                  "asymmetric_risk": "medium"},
    "monitored_vlans": ["prod"], "unmapped_vlans": [], "has_nat": False,
    "brain": {"llm_endpoint_env": "SENTINEL_LLM_API", "timeout_s": 8,
              "hard_cutoff_s": 5},
    "actuators": [{"type": "nftables_local"}],
    "autonomy_level": 0,
    "limits": {"max_blocks_per_min": 5, "max_blocks_per_hour": 20,
               "default_ttl_min": 30},
    "policy": {"auto_act_threshold": 0.95, "human_approval_threshold": 0.70},
    "critical_response": {"enabled": True, "min_score": 0.80,
                          "deadline_minutes": 15},
}


def run() -> list[tuple[str, bool, str]]:
    results: list[tuple[str, bool, str]] = []

    def check(name: str, ok: bool, detail: str = "") -> bool:
        results.append((name, bool(ok), detail))
        return bool(ok)

    from sentinel.auditstore.store import Store
    from sentinel.config.loader import load_config
    from sentinel.daemon import build_daemon

    with tempfile.TemporaryDirectory(prefix="sentinel-selftest-") as tmp:
        tmp_path = Path(tmp)
        cfg_dict = dict(_CFG, audit_store={"path": str(tmp_path / "audit.sqlite")})
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(yaml.safe_dump(cfg_dict), encoding="utf-8")
        try:
            cfg = load_config(cfg_file)
        except Exception as exc:
            check("config validation", False, str(exc)[:160])
            return results
        check("config validation", True, "strict schema accepted")

        store = Store(tmp_path / "audit.sqlite", check_same_thread=False)
        # Synthetic proof only: the self-test exercises decision plumbing,
        # while production wiring still has no live liveness checker.
        daemon = build_daemon(cfg, tmp_path, store, dry_run=True,
                              liveness_check=lambda ctx: "alive")

        now = datetime.now(timezone.utc)
        hdr = ("#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
               "#types\ttime\taddr\tport\taddr\tport\tstring\n")
        rows = "".join(
            f"{(now - timedelta(seconds=60 - i * 1.5)).timestamp():.6f}\t"
            f"198.51.100.77\t5000\t10.0.0.4\t22\ttcp\n" for i in range(40))
        (tmp_path / "conn.log").write_text(hdr + rows, encoding="utf-8")
        alert = {"timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.%f+0000"),
                 "event_type": "alert", "src_ip": "203.0.113.50", "src_port": 4000,
                 "dest_ip": "10.0.0.4", "dest_port": 80, "proto": "TCP",
                 "alert": {"signature": "ET SCAN test", "severity": 1}}
        (tmp_path / "eve.json").write_text(json.dumps(alert) + "\n", encoding="utf-8")

        try:
            daemon.run_once()
        except Exception as exc:
            check("daemon cycle", False, f"{type(exc).__name__}: {exc}")
            store.close()
            return results
        check("daemon cycle", True, "read logs, detected, decided")

        decisions = store.rows("decisions")
        by_outcome = {r["outcome"] for r in decisions}
        check("detection + decision", len(decisions) >= 2,
              f"{len(decisions)} decisions: {sorted(by_outcome)}")
        pending = [r for r in decisions if r["outcome"] == "human_approval"]
        check("80-95% confidence asks a human",
              bool(pending), "no human_approval decision" if not pending else "approval queued")
        check("approval queue filled", bool(daemon._engine.pending_approvals()))

        ctx = store.rows("incident_context")
        inputs = [json.loads(r["inputs"]) for r in store.rows("incident_inputs")]
        sev1 = [i for i in inputs if "eve_json" in i.get("confidence_sources", {})]
        check("incident context recorded", len(ctx) >= 2,
              f"{len(ctx)} incidents with source/target/evidence")
        check("confidence derived from evidence (Suricata severity 1 -> 0.85)",
              any(abs(i["confidence"] - 0.85) < 1e-6 for i in sev1),
              f"{[i['confidence'] for i in sev1]}")
        executed = [r for r in store.rows("actions") if r["executed"]]
        check("nothing executed in dry-run", not executed,
              "no action touched the network")
        chain = store.verify_chain()
        check("audit hash chain intact", chain["ok"] and chain["entries"] > 0,
              f"{chain['entries']} chained entries")

        try:
            from fastapi.testclient import TestClient

            from sentinel.ui.app import create_app
            import os
            os.environ.setdefault("SENTINEL_SELFTEST_TOKEN", "selftest")
            ui_cfg = dict(cfg)
            ui_cfg["ops_ui"] = {"enabled": True, "bind": "127.0.0.1:8080",
                                "auth_token_env": "SENTINEL_SELFTEST_TOKEN",
                                "allowed_ports": [8080]}
            client = TestClient(create_app(ui_cfg, engine=daemon._engine,
                                           store=store, capture_dir=tmp_path))
            hdr_ok = {"X-Sentinel-Token": "selftest"}
            r1 = client.get("/ui/overview", headers=hdr_ok)
            r2 = client.get("/ui/overview")
            check("dashboard serves data", r1.status_code == 200 and "الحوادث" in r1.text)
            check("dashboard rejects requests without the token", r2.status_code == 401)
            inc = decisions[0]["incident_id"]
            r3 = client.get(f"/ui/incident/{inc}", headers=hdr_ok)
            check("score explanation shown", "لماذا هذه الدرجة" in r3.text)
        except ImportError:
            check("dashboard", False,
                  'UI dependencies missing: pip install -e ".[ops-ui]"')
        store.close()
    return results


def main() -> int:
    print("Sentinel self-test (temporary folder, nothing touches your data)\n")
    results = run()
    width = max(len(n) for n, _, _ in results)
    for name, ok, detail in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name.ljust(width)}  {detail}")
    failed = [n for n, ok, _ in results if not ok]
    print()
    if failed:
        print(f"FAILED: {len(failed)} check(s) did not pass.")
        return 1
    print(f"ALL {len(results)} CHECKS PASSED - the pipeline works on this machine.")
    return 0
