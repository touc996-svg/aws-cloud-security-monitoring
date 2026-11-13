"""Reviewed MITRE ATT&CK mapping table: provider finding type -> technique IDs.

Only types present in data/mitre_mapping.json are mapped; everything else stays
unmapped and is reported in the coverage summary. Nothing is inferred.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

DEFAULT_MAPPING = Path(__file__).resolve().parent / "data" / "mitre_mapping.json"
_TECH_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


class MappingError(ValueError):
    pass


class MitreMapper:
    def __init__(self, entries: list[dict[str, Any]]):
        for i, e in enumerate(entries):
            for key in ("cloud", "finding_type", "match", "techniques", "justification", "source"):
                if not e.get(key):
                    raise MappingError(f"mapping entry {i} missing '{key}'")
            if e["match"] not in ("exact", "prefix"):
                raise MappingError(f"mapping entry {i}: match must be exact|prefix")
            bad = [t for t in e["techniques"] if not _TECH_RE.match(t)]
            if bad:
                raise MappingError(f"mapping entry {i}: invalid technique id(s) {bad}")
        self.entries = entries

    @classmethod
    def load(cls, path: Path | str | None = None) -> "MitreMapper":
        data = json.loads(Path(path or DEFAULT_MAPPING).read_text(encoding="utf-8"))
        return cls(data["mappings"])

    def lookup(self, cloud: str, finding_type: str) -> list[str]:
        out: set[str] = set()
        for e in self.entries:
            if e["cloud"] != cloud:
                continue
            if (e["match"] == "exact" and finding_type == e["finding_type"]) or (
                e["match"] == "prefix" and finding_type.startswith(e["finding_type"])
            ):
                out.update(e["techniques"])
        return sorted(out)

    @staticmethod
    def types_of(finding: dict) -> list[str]:
        types = []
        if isinstance(finding.get("finding_type"), str):
            types.append(finding["finding_type"])
        ft = finding.get("finding_types")
        if isinstance(ft, list):
            types.extend(t for t in ft if isinstance(t, str))
        return types

    def apply(self, finding: dict) -> tuple[list[str], list[str]]:
        """Return (techniques added, unmapped types) and update finding in place."""
        existing = list(finding.get("mitre_techniques") or [])
        found: set[str] = set()
        unmapped = []
        for t in self.types_of(finding):
            techs = self.lookup(finding["cloud"], t)
            if techs:
                found.update(techs)
            else:
                unmapped.append(t)
        finding["mitre_techniques"] = sorted(set(existing) | found)
        return sorted(found), unmapped


def coverage(findings: list[dict], mapper: MitreMapper) -> dict[str, Any]:
    """Coverage over distinct (cloud, finding_type) pairs seen in the data."""
    seen: dict[tuple[str, str], bool] = {}
    for f in findings:
        for t in mapper.types_of(f):
            key = (f["cloud"], t)
            seen[key] = seen.get(key, False) or bool(mapper.lookup(f["cloud"], t))
    mapped = sorted(f"{c}:{t}" for (c, t), ok in seen.items() if ok)
    unmapped = sorted(f"{c}:{t}" for (c, t), ok in seen.items() if not ok)
    total = len(seen)
    return {
        "distinct_types": total,
        "mapped": mapped,
        "unmapped": unmapped,
        "coverage_pct": round(100.0 * len(mapped) / total, 1) if total else None,
    }
