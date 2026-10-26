"""Read-only CVE extraction and NVD 2.0 enrichment."""
from __future__ import annotations

import json
import os
import re
from typing import Any
from urllib.parse import urlencode
from urllib.request import Request, urlopen

CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def extract_cve_ids(value: Any) -> list[str]:
    """Return only CVE identifiers found in event metadata/signatures."""
    blob = json.dumps(value, ensure_ascii=False, default=str)
    return sorted({match.upper() for match in CVE_PATTERN.findall(blob)})


def lookup_nvd_cve(cve_id: str, *, api_key: str | None = None,
                   timeout: float = 15) -> dict[str, Any]:
    """Fetch one CVE from the current NVD 2.0 API, returning bounded fields."""
    cve = cve_id.upper()
    if not CVE_PATTERN.fullmatch(cve):
        raise ValueError(f"invalid CVE identifier: {cve_id!r}")
    headers = {"User-Agent": "Sentinel-Defensive-Report/1.0",
               "Accept": "application/json"}
    key = api_key or os.environ.get("NVD_API_KEY")
    if key:
        headers["apiKey"] = key
    req = Request(f"{NVD_CVE_API}?{urlencode({'cveId': cve})}", headers=headers)
    with urlopen(req, timeout=timeout) as response:
        data = json.loads(response.read())
    rows = data.get("vulnerabilities") or []
    if not rows:
        return {"cve_id": cve, "found": False,
                "source": "NIST National Vulnerability Database",
                "url": f"https://nvd.nist.gov/vuln/detail/{cve}"}
    item = rows[0].get("cve", {})
    descriptions = item.get("descriptions") or []
    description = next((d.get("value", "") for d in descriptions
                        if d.get("lang") == "en"), "")
    cvss = None
    metrics = item.get("metrics") or {}
    for field in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(field) or []
        if entries:
            metric = entries[0].get("cvssData", {})
            cvss = {"version": metric.get("version"),
                    "score": metric.get("baseScore"),
                    "severity": metric.get("baseSeverity") or entries[0].get("baseSeverity")}
            break
    cwes = sorted({d.get("value", "") for weakness in item.get("weaknesses", [])
                   for d in weakness.get("description", [])
                   if d.get("lang") == "en" and d.get("value", "").startswith("CWE-")})
    affected = []
    def walk(node: Any) -> None:
        if isinstance(node, dict):
            crit = node.get("criteria")
            if crit and str(crit).startswith("cpe:"):
                affected.append({"cpe": str(crit),
                                 "vulnerable": bool(node.get("vulnerable", False))})
            for child in node.values():
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)
    walk(item.get("configurations", []))
    return {
        "cve_id": cve, "found": True,
        "description": description[:4000], "cvss": cvss,
        "cwes": cwes, "affected_products": affected[:100],
        "published": item.get("published"), "last_modified": item.get("lastModified"),
        "source": "NIST National Vulnerability Database API 2.0",
        "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
    }
