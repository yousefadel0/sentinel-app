"""Self-contained, local JSON + HTML attack reports."""
from __future__ import annotations

import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _e(value: Any) -> str:
    return html.escape(str(value if value is not None else "—"), quote=True)


def render_report(report: dict[str, Any]) -> str:
    incidents = []
    for item in report.get("incidents", []):
        mapping = item.get("mitre_attack") or {}
        technique_html = "".join(
            '<li><a rel="noreferrer" href="' + _e(t.get("url")) + '"><b>' +
            _e(t.get("id")) + ' — ' + _e(t.get("name")) + '</b></a>' +
            (f'<p>{_e(t.get("description"))}</p>' if t.get("description") else "") +
            (f'<small>التكتيك: {_e(", ".join(t.get("tactics", [])))}</small>'
             if t.get("tactics") else "") + '</li>'
            for t in mapping.get("techniques", []))
        vulns = "".join(
            '<li><a rel="noreferrer" href="' + _e(v.get("url")) + '">' +
            _e(v.get("cve_id")) + '</a> · ' +
            _e((v.get("cvss") or {}).get("severity") or "بدون تقييم CVSS") +
            (f'<p>{_e(v.get("description"))}</p>' if v.get("description") else "") +
            '</li>' for v in item.get("vulnerabilities", []))
        outcome = item.get("decision", {})
        incidents.append(
            '<article class="incident"><header><div><span class="tag">' +
            _e(item.get("attack_type", "غير مصنف")) + '</span><h2>' +
            _e(item.get("incident_id")) + '</h2></div><span class="outcome">' +
            _e(outcome.get("outcome")) + '</span></header><div class="grid">' +
            '<p><b>الفترة</b><br>' + _e(item.get("first_seen")) + ' → ' +
            _e(item.get("last_seen")) + '</p><p><b>المصدر والهدف</b><br>' +
            _e(item.get("src_ip")) + ' → ' + _e(item.get("dst_ip")) +
            '</p><p><b>الإشارات</b><br>' + _e(", ".join(item.get("signals", []))) +
            '</p><p><b>قرار Sentinel</b><br>' + _e(outcome.get("outcome")) +
            ' · درجة ' + _e(outcome.get("score")) + ' · فئة ' +
            _e(outcome.get("tier")) + '</p></div><p class="reason"><b>لماذا؟</b> ' +
            _e(outcome.get("reason")) + '</p><p class="reason"><b>ما الذي فعله؟</b> ' +
            _e(outcome.get("action_summary")) + '</p><details><summary>سياق MITRE ATT&CK'
            '</summary><p>مطابقة مرشحة من إشارات الشبكة، وليست إثباتًا لهوية مهاجم أو تقنية مؤكدة.</p>'
            f'<ul>{technique_html}</ul></details><details><summary>الثغرات المرتبطة بالأدلة</summary>'
            + (f'<ul>{vulns}</ul>' if vulns else
               '<p>لم يعثر التقرير على CVE في الأدلة. Sentinel لا يستنتج ثغرة من نوع الهجوم وحده؛ '
               'يلزم CVE أو جرد منتج/إصدار متأثر.</p>') + '</details><p class="evidence"><b>مراجع الأدلة:</b> ' +
            _e(", ".join(item.get("evidence_refs", []))) + '</p></article>')
    errors = "".join(f'<li>{_e(error)}</li>' for error in report.get("enrichment_errors", []))
    return ('<!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            '<title>تقرير Sentinel</title><style>'
            'body{margin:0;background:#0b1220;color:#e7eef9;font:15px/1.7 "Segoe UI",Tahoma,Arial,sans-serif}'
            'main{max-width:1150px;margin:auto;padding:28px 18px}a{color:#8fc5ff}.summary,.incident{background:#111c2e;border:1px solid #2a3a52;border-radius:14px;padding:20px;margin:14px 0}'
            '.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:8px}.grid p{background:#17253a;padding:12px;border-radius:8px;overflow-wrap:anywhere}'
            'h1{font-size:30px}h2{font-size:17px;overflow-wrap:anywhere}header{display:flex;justify-content:space-between;gap:12px;align-items:flex-start}.tag,.outcome{padding:4px 9px;background:#203656;border-radius:20px}.reason{background:#0e1929;padding:12px;border-radius:8px}.evidence,small{color:#a9bad2}details{border-top:1px solid #2a3a52;padding:10px 0}li{margin:8px 0}p{overflow-wrap:anywhere}'
            '@media(max-width:560px){header{flex-direction:column}main{padding:16px 12px}}'
            '</style><main><h1>تقرير Sentinel للهجمات والقرارات</h1>'
            '<section class="summary"><p><b>رقم التشغيل:</b> ' + _e(report.get("run_id")) +
            ' · <b>وقت الإنشاء:</b> ' + _e(report.get("generated_at")) +
            '</p><p><b>مصدر التحليل:</b> ' + _e(report.get("mode")) +
            ' · <b>الحوادث:</b> ' + _e(len(report.get("incidents", []))) +
            ' · <b>القرارات الكلية في سجل التدقيق:</b> ' +
            _e(report.get("kpis", {}).get("incidents")) + '</p>'
            '<p>هذا التقرير وصفي. معلومات ATT&CK سياق استخباراتي، ولا تغيّر قرار المحرك أو تنفّذ إجراءات.</p>'
            '</section>' + ("".join(incidents) or '<p class="summary">لم تُكتشف حوادث في هذا التشغيل.</p>') +
            (f'<section class="summary"><h2>ملاحظات إثراء البيانات</h2><ul>{errors}</ul></section>' if errors else "") +
            '<p class="evidence">مصادر إثراء البيانات وروابطها محفوظة داخل كل بند.</p></main></html>')


def write_report(report: dict[str, Any], report_dir: str | Path) -> dict[str, str]:
    root = Path(report_dir)
    root.mkdir(parents=True, exist_ok=True)
    run_id = str(report["run_id"])
    safe_id = re.sub(r"[^A-Za-z0-9_.-]", "_", run_id)
    json_path = root / f"{safe_id}.json"
    html_path = root / f"{safe_id}.html"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str),
                         encoding="utf-8")
    html_path.write_text(render_report(report), encoding="utf-8")
    latest = root / "latest.html"
    latest.write_text(render_report(report), encoding="utf-8")
    return {"json": str(json_path), "html": str(html_path), "latest_html": str(latest)}


def new_report(*, run_id: str, mode: str, capture_files: list[str],
               incidents: list[dict[str, Any]], kpis: dict[str, Any],
               attack_catalog_source: str, nvd_enabled: bool) -> dict[str, Any]:
    return {
        "report_version": 1, "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": mode, "capture_files": capture_files,
        "knowledge_sources": {
            "attack": attack_catalog_source,
            "vulnerability": "NIST NVD API 2.0" if nvd_enabled else "CVE identifiers from event evidence; NVD lookup disabled",
        },
        "kpis": kpis, "incidents": incidents,
    }
