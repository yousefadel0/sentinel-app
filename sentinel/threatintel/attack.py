"""Curated ATT&CK mappings plus an optional official STIX 2.1 catalog cache.

The mapping from Sentinel signal families to ATT&CK is a candidate mapping,
not proof that an adversary used a technique. Full ATT&CK context is read
from MITRE's official public STIX data when the catalog has been synced.
"""
from __future__ import annotations

import json
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.request import Request, urlopen
from typing import Any

from sentinel.logging_setup import get_logger

ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
log = get_logger("sentinel.threatintel.attack")


@dataclass(frozen=True)
class AttackMapping:
    attack_type: str
    technique_ids: tuple[str, ...]
    rationale: str
    confidence: str


ATTACK_MAPPINGS: dict[str, AttackMapping] = {
    "scan": AttackMapping("Network service discovery", ("T1046",),
                           "Network scanning signal; validate against event evidence.", "candidate"),
    "brute_force": AttackMapping("Brute force", ("T1110",),
                                 "Repeated authentication failures; subtype is not inferred.", "candidate"),
    "ddos_volumetric": AttackMapping("Network denial of service", ("T1498.001",),
                                     "Volumetric traffic signal suggests direct network flooding.", "candidate"),
    "c2_beacon": AttackMapping("Application layer protocol (possible C2)", ("T1071",),
                               "Beacon-like timing alone does not identify the protocol.", "low"),
    "dns_tunneling": AttackMapping("Application layer protocol: DNS", ("T1071.004",),
                                    "DNS tunneling signal; confirm the traffic contents and context.", "candidate"),
}

_SIGNAL_FAMILY = {
    "scan": "scan", "auth_fail_burst": "brute_force",
    "volume_spike": "ddos_volumetric", "ddos_volumetric": "ddos_volumetric",
    "beacon_periodic": "c2_beacon", "dns_tunneling": "dns_tunneling",
}


def map_incident(signals: list[str] | tuple[str, ...]) -> AttackMapping | None:
    """Return the first recognized candidate family from observed signals."""
    for signal in signals:
        family = _SIGNAL_FAMILY.get(str(signal))
        if family:
            return ATTACK_MAPPINGS[family]
    return None


def _compact_stix_object(obj: dict[str, Any]) -> dict[str, Any] | None:
    refs = obj.get("external_references") or []
    ext_id = next((r.get("external_id") for r in refs
                   if r.get("source_name") == "mitre-attack" and r.get("external_id")), None)
    if not ext_id or obj.get("type") != "attack-pattern":
        return None
    if obj.get("revoked") or obj.get("x_mitre_deprecated"):
        return None
    phases = [p.get("phase_name", "") for p in obj.get("kill_chain_phases", [])
              if p.get("kill_chain_name") == "mitre-attack"]
    return {
        "id": str(ext_id), "name": str(obj.get("name", "")),
        "description": str(obj.get("description", "")),
        "detection": str(obj.get("x_mitre_detection", "")),
        "tactics": phases,
        "url": f'https://attack.mitre.org/techniques/{str(ext_id).replace(".", "/")}/',
        "source": "MITRE ATT&CK Enterprise STIX 2.1",
    }


def sync_attack_catalog(path: str | Path, *, timeout: float = 30) -> dict[str, Any]:
    """Download and validate the official MITRE Enterprise ATT&CK STIX bundle."""
    req = Request(ATTACK_STIX_URL, headers={"User-Agent": "Sentinel-Defensive-Report/1.0"})
    with urlopen(req, timeout=timeout) as response:
        bundle = json.loads(response.read())
    objects = bundle.get("objects") if isinstance(bundle, dict) else None
    if not isinstance(objects, list):
        raise ValueError("MITRE response is not a STIX bundle with an objects list")
    techniques = [compact for obj in objects if isinstance(obj, dict)
                  if (compact := _compact_stix_object(obj))]
    indexed = {item["id"]: item for item in techniques}
    required = {tech for mapping in ATTACK_MAPPINGS.values()
                for tech in mapping.technique_ids}
    missing = sorted(required - indexed.keys())
    if missing:
        raise ValueError(f"MITRE catalog is missing mapped techniques: {', '.join(missing)}")
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    temp = out.with_suffix(out.suffix + ".tmp")
    temp.write_text(json.dumps({
        "source": "MITRE ATT&CK Enterprise STIX 2.1",
        "source_url": ATTACK_STIX_URL,
        "spec_version": bundle.get("spec_version"),
        "object_count": len(indexed),
        "techniques": indexed,
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(out)
    return {"path": str(out), "techniques": len(indexed),
            "mapped_techniques": sorted(required)}


def load_attack_catalog(path: str | Path | None = None) -> dict[str, Any]:
    """Load the compact cache; absent or invalid cache yields an honest fallback."""
    if path is None:
        return {}
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        techniques = data.get("techniques")
        return data if isinstance(techniques, dict) else {}
    except (OSError, json.JSONDecodeError, AttributeError):
        return {}


def enrich_mapping(mapping: AttackMapping | None,
                   catalog: dict[str, Any]) -> dict[str, Any] | None:
    if mapping is None:
        return None
    catalog_techniques = catalog.get("techniques", {})
    techniques = []
    for technique_id in mapping.technique_ids:
        item = catalog_techniques.get(technique_id)
        if item is None:
            # Useful offline fallback: never present invented descriptions.
            item = {
                "id": technique_id,
                "name": mapping.attack_type,
                "description": "",
                "detection": "",
                "tactics": [],
                "url": f'https://attack.mitre.org/techniques/{technique_id.replace(".", "/")}/',
                "source": "MITRE ATT&CK technique reference; catalog not synced",
            }
        techniques.append(item)
    return {
        **asdict(mapping),
        "technique_ids": list(mapping.technique_ids),
        "techniques": techniques,
        "catalog_source": catalog.get("source", "curated technique IDs; offline mode"),
    }


class AttackIntel:
    """Nonblocking, local ATT&CK lookup with a scheduled best-effort refresh."""

    def __init__(self, path: str | Path, *, refresh_seconds: int = 86400,
                 clock=None, sync=None) -> None:
        self.path = Path(path)
        self.refresh_seconds = max(3600, int(refresh_seconds))
        self._clock = clock or time.time
        self._sync = sync or sync_attack_catalog
        self._catalog = load_attack_catalog(self.path)
        self._attempted_at = 0.0
        self._worker: threading.Thread | None = None

    def match(self, signals: list[str] | tuple[str, ...]) -> dict[str, Any] | None:
        """O(number of signals) lookup; no network or disk access on this path."""
        mapping = map_incident(signals)
        return enrich_mapping(mapping, self._catalog)

    def maybe_refresh(self) -> None:
        now = self._clock()
        if self._worker is not None and self._worker.is_alive():
            return
        try:
            age = now - self.path.stat().st_mtime
        except OSError:
            age = self.refresh_seconds
        if age < self.refresh_seconds or now - self._attempted_at < self.refresh_seconds:
            return
        self._attempted_at = now
        self._worker = threading.Thread(target=self._refresh, daemon=True,
                                        name="attack-catalog-refresh")
        self._worker.start()

    def _refresh(self) -> None:
        try:
            self._sync(self.path)
            catalog = load_attack_catalog(self.path)
            if catalog:
                self._catalog = catalog
        except Exception as exc:
            # Keep the last good cache or curated offline mapping.
            log.warning("attack_catalog_refresh_failed", error=type(exc).__name__)
