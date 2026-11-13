"""Threat-intel enrichment: pluggable providers + an offline indicator-file provider.

No network access anywhere in this module. Subclass `IntelProvider` to add
another source; the pipeline only depends on `match_observables`.
"""
from __future__ import annotations

import csv
import ipaddress
import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

_IP_RE = re.compile(r"(?<![\w.:])(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]*:[0-9a-fA-F:]+)(?![\w:])")
_DOMAIN_RE = re.compile(r"(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w-])", re.I)
_HASH_RE = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})(?![0-9a-fA-F])")
VALID_TYPES = {"ip", "domain", "hash"}


@dataclass(frozen=True)
class Observable:
    value: str  # normalized
    type: str
    field: str  # path within the finding where it was seen


@dataclass(frozen=True)
class IntelMatch:
    indicator: str
    type: str
    provider: str
    source: str
    confidence: int
    field: str
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = {
            "indicator": self.indicator,
            "type": self.type,
            "provider": self.provider,
            "source": self.source,
            "confidence": self.confidence,
            "field": self.field,
        }
        if self.description:
            d["description"] = self.description
        return d


def _walk(obj: Any, path: str) -> Iterator[tuple[str, str]]:
    if isinstance(obj, dict):
        for k in sorted(obj):
            yield from _walk(obj[k], f"{path}.{k}" if path else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk(v, f"{path}[{i}]")
    elif isinstance(obj, str):
        yield path, obj


def extract_observables(finding: dict) -> list[Observable]:
    """IPs, domains and hashes found in raw_payload and evidence (deduplicated)."""
    seen: dict[tuple[str, str], Observable] = {}
    parts = [("raw_payload", finding.get("raw_payload", {})), ("evidence", finding.get("evidence", []))]
    for root, obj in parts:
        for path, text in _walk(obj, root):
            for m in _IP_RE.finditer(text):
                try:
                    ip = str(ipaddress.ip_address(m.group(0)))
                except ValueError:
                    continue
                seen.setdefault(("ip", ip), Observable(ip, "ip", path))
            for m in _DOMAIN_RE.finditer(text):
                d = m.group(0).lower().rstrip(".")
                seen.setdefault(("domain", d), Observable(d, "domain", path))
            for m in _HASH_RE.finditer(text):
                h = m.group(0).lower()
                seen.setdefault(("hash", h), Observable(h, "hash", path))
    return [seen[k] for k in sorted(seen)]


class IntelProvider(ABC):
    name = "provider"

    @abstractmethod
    def match_observables(self, observables: list[Observable]) -> list[IntelMatch]:
        """Return matches for the given observables. Must not perform network I/O
        unless the provider is explicitly an online one (none ship in this repo)."""


class LocalFileProvider(IntelProvider):
    """Indicators loaded from a local CSV or JSON file.

    CSV columns: indicator,type,source,confidence[,description]
    JSON: a list of such objects, or {"indicators": [...]}.
    `type` is ip|domain|hash (inferred when omitted); `confidence` is 0-100.
    Domain indicators also match their subdomains. Bad rows are collected in
    `rejected` (never silently ignored).
    """

    def __init__(self, path: Path | str, name: str | None = None):
        self.path = Path(path)
        self.name = name or f"local:{self.path.name}"
        self.rejected: list[dict[str, Any]] = []
        self._index: dict[tuple[str, str], dict[str, Any]] = {}
        self._load()

    @staticmethod
    def _infer_type(value: str) -> str | None:
        try:
            ipaddress.ip_address(value)
            return "ip"
        except ValueError:
            pass
        if _HASH_RE.fullmatch(value):
            return "hash"
        if _DOMAIN_RE.fullmatch(value):
            return "domain"
        return None

    def _rows(self) -> list[dict[str, Any]]:
        text = self.path.read_text(encoding="utf-8")
        if self.path.suffix.lower() == ".json":
            data = json.loads(text)
            rows = data.get("indicators") if isinstance(data, dict) else data
            if not isinstance(rows, list):
                raise ValueError("JSON indicator file must be a list or {'indicators': [...]}")
            return rows
        return list(csv.DictReader(text.splitlines()))

    def _load(self) -> None:
        for n, row in enumerate(self._rows(), start=1):
            try:
                if not isinstance(row, dict):
                    raise ValueError("row is not an object")
                value = str(row.get("indicator", "")).strip()
                if not value:
                    raise ValueError("missing indicator")
                itype = str(row.get("type") or "").strip().lower() or self._infer_type(value)
                if itype not in VALID_TYPES:
                    raise ValueError(f"unknown/uninferable type {itype!r}")
                source = str(row.get("source") or "").strip()
                if not source:
                    raise ValueError("missing source")
                conf = int(float(row.get("confidence")))
                if not 0 <= conf <= 100:
                    raise ValueError("confidence must be 0-100")
                if itype == "ip":
                    value = str(ipaddress.ip_address(value))
                else:
                    value = value.lower().rstrip(".")
                entry = {"source": source, "confidence": conf, "description": str(row.get("description") or "")}
                key = (itype, value)
                if key not in self._index or conf > self._index[key]["confidence"]:
                    self._index[key] = entry
            except (ValueError, TypeError) as exc:
                self.rejected.append({"row": n, "reason": str(exc), "data": row})

    def __len__(self) -> int:
        return len(self._index)

    def match_observables(self, observables: list[Observable]) -> list[IntelMatch]:
        out = []
        for ob in observables:
            if ob.type == "domain":
                labels = ob.value.split(".")
                candidates = [".".join(labels[i:]) for i in range(len(labels) - 1)]
            else:
                candidates = [ob.value]
            for cand in candidates:
                e = self._index.get((ob.type, cand))
                if e:
                    out.append(IntelMatch(cand, ob.type, self.name, e["source"], e["confidence"], ob.field, e["description"]))
                    break
        return out


def enrich(finding: dict, providers: list[IntelProvider]) -> list[dict]:
    """Attach `threat_intel` matches to the finding (in place) and return them."""
    obs = extract_observables(finding)
    matches = [m for p in providers for m in p.match_observables(obs)]
    uniq = {(m.indicator, m.type, m.source, m.provider): m for m in matches}
    result = [uniq[k].to_dict() for k in sorted(uniq)]
    if result:
        finding["threat_intel"] = result
    return result
