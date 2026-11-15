"""Read-only CVE extraction and NVD 2.0 enrichment."""
from __future__ import annotations

import json
import os
import re
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from sentinel.logging_setup import get_logger

CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
log = get_logger("sentinel.threatintel.cve")


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


class CveIntel:
    """Observed CVE IDs resolve from a local cache; NVD refresh stays off path."""

    def __init__(self, path: str | Path, *, lookup=None,
                 clock=None, refresh_seconds: int = 86400) -> None:
        self.path = Path(path)
        self._lookup = lookup or lookup_nvd_cve
        self._clock = clock or time.time
        self._refresh_seconds = max(3600, int(refresh_seconds))
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self._cache = ({key: row for key, row in data.items()
                            if isinstance(key, str) and CVE_PATTERN.fullmatch(key)
                            and isinstance(row, dict)
                            and isinstance(row.get("updated_at"), (int, float))
                            and isinstance(row.get("value"), dict)}
                           if isinstance(data, dict) else {})
        except (OSError, ValueError):
            self._cache = {}
        self._attempts: dict[str, float] = {}
        self._pending: set[str] = set()
        self._lock = threading.RLock()
        self._worker: threading.Thread | None = None

    def match(self, signals: list[str] | tuple[str, ...]) -> list[dict[str, Any]]:
        ids = extract_cve_ids(signals)[:100]
        now = self._clock()
        with self._lock:
            result = []
            for cve in ids:
                row = self._cache.get(cve)
                result.append(dict(row["value"]) if isinstance(row, dict) and
                              isinstance(row.get("value"), dict) else
                              {"cve_id": cve, "found": None})
                updated = row.get("updated_at", 0) if isinstance(row, dict) else 0
                if now - updated >= self._refresh_seconds and \
                        now - self._attempts.get(cve, 0) >= self._refresh_seconds:
                    self._pending.add(cve)
            if self._pending and (self._worker is None or not self._worker.is_alive()):
                self._worker = threading.Thread(target=self._refresh, daemon=True,
                                                name="nvd-cve-refresh")
                self._worker.start()
            return result

    def _refresh(self) -> None:
        while True:
            with self._lock:
                if not self._pending:
                    self._worker = None
                    return
                cve = self._pending.pop()
                self._attempts[cve] = self._clock()
            try:
                value = self._lookup(cve)
            except Exception as exc:
                log.warning("cve_refresh_failed", cve_id=cve,
                            error=type(exc).__name__)
                continue  # last good cache remains available offline
            with self._lock:
                self._cache[cve] = {"updated_at": self._clock(), "value": value}
                if len(self._cache) > 10_000:
                    oldest = min(self._cache, key=lambda k: self._cache[k].get("updated_at", 0))
                    del self._cache[oldest]
                try:
                    self.path.parent.mkdir(parents=True, exist_ok=True)
                    temp = self.path.with_suffix(self.path.suffix + ".tmp")
                    temp.write_text(json.dumps(self._cache, sort_keys=True), encoding="utf-8")
                    os.replace(temp, self.path)
                except OSError as exc:
                    log.warning("cve_cache_write_failed", error=type(exc).__name__)
