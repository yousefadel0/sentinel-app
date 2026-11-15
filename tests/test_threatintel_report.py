from __future__ import annotations

import json

from sentinel.threatintel.attack import (
    AttackIntel, enrich_mapping, load_attack_catalog, map_incident,
)
from sentinel.threatintel.report import new_report, render_report, write_report
from sentinel.threatintel.vulnerabilities import CveIntel, extract_cve_ids


def test_attack_mapping_is_candidate_and_uses_known_technique_ids():
    mapped = map_incident(["auth_fail_burst"])
    assert mapped is not None
    assert mapped.attack_type == "Brute force"
    assert mapped.technique_ids == ("T1110",)
    assert mapped.confidence == "candidate"
    assert map_incident(["unknown_signal"]) is None


def test_enrichment_falls_back_without_inventing_catalog_descriptions(tmp_path):
    mapping = map_incident(["volume_spike"])
    enriched = enrich_mapping(mapping, load_attack_catalog(tmp_path / "missing.json"))
    assert enriched["techniques"][0]["id"] == "T1498.001"
    assert enriched["techniques"][0]["description"] == ""
    assert "not synced" in enriched["techniques"][0]["source"]


def test_local_attack_lookup_refreshes_off_path_and_keeps_offline_mapping(tmp_path):
    calls = []

    def sync(path):
        calls.append(path)
        path.write_text(json.dumps({"source": "local", "techniques": {
            "T1110": {"id": "T1110", "name": "Brute Force"}}}))

    intel = AttackIntel(tmp_path / "attack.json", clock=lambda: 100_000,
                        sync=sync)
    assert intel.match(["auth_fail_burst"])["technique_ids"] == ["T1110"]
    intel.maybe_refresh()
    intel._worker.join(timeout=2)
    assert calls and intel.match(["auth_fail_burst"])["catalog_source"] == "local"
    intel.maybe_refresh()
    assert len(calls) == 1


def test_extract_cve_ids_from_evidence_and_deduplicate():
    ids = extract_cve_ids({"alert": {"signature": "CVE-2024-12345"},
                           "metadata": {"note": "CVE-2024-12345 and CVE-2023-9999"}})
    assert ids == ["CVE-2023-9999", "CVE-2024-12345"]


def test_cve_match_uses_local_cache_then_refreshes_off_path(tmp_path):
    clock = [100_000.0]
    intel = CveIntel(tmp_path / "cve.json", clock=lambda: clock[0],
                     lookup=lambda cve: {"cve_id": cve, "found": True,
                                         "description": "known"})
    signal = ["signature_hit", "cve:CVE-2024-12345"]
    assert intel.match(signal)[0]["found"] is None
    intel._worker.join(timeout=2)
    assert intel.match(signal)[0]["description"] == "known"
    assert (tmp_path / "cve.json").is_file()


def test_report_writes_json_html_and_escapes_evidence(tmp_path):
    report = new_report(
        run_id="run-test", mode="replay", capture_files=["events.jsonl"],
        incidents=[{
            "incident_id": "inc-1", "attack_type": "<script>alert(1)</script>",
            "mitre_attack": {"techniques": []}, "vulnerabilities": [],
            "signals": ["scan"], "evidence_refs": ["events.jsonl#1"],
            "decision": {"outcome": "log_only", "score": 0.4,
                         "reason": "logged", "action_summary": "No action", "executed": False},
        }], kpis={"incidents": 1}, attack_catalog_source="offline", nvd_enabled=False)
    html = render_report(report)
    assert "&lt;script&gt;" in html
    assert "لم يعثر التقرير على CVE" in html
    paths = write_report(report, tmp_path)
    assert (tmp_path / "latest.html").is_file()
    assert json.loads(open(paths["json"], encoding="utf-8").read())["run_id"] == "run-test"
