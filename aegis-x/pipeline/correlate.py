"""Correlate merged findings into incidents with a transparent score.

Two findings are linked when they are close in time (gap between their
[first_seen, last_seen] intervals <= window) AND the weights of the keys they
share reach `min_link_score`. Every link records the shared keys. Incidents are
connected components of links, so chaining is possible (A-B and B-C => A,B,C).
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Iterator

from .common import SEVERITY_ORDER, SEVERITY_RANK, first_seen_of, last_seen_of, parse_ts, sha256_of

# Weights of shared keys. Account and technique are weak on their own.
WEIGHTS = {"resource_id": 3, "principal": 3, "threat_intel_indicator": 3, "account_id": 1, "mitre_technique": 1}
SEVERITY_POINTS = {"critical": 40, "high": 30, "medium": 20, "low": 10, "informational": 0}
_PRINCIPAL_KEYS = {
    "principalemail", "userprincipalname", "principalid", "username",
    "accesskeyid", "callidentity", "initiatedby", "upn", "accountupn",
}


@dataclass
class CorrelationConfig:
    window_minutes: int = 120
    min_link_score: int = 2
    min_members: int = 2


def _walk_keys(obj: Any) -> Iterator[tuple[str, str]]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str) and k.lower() in _PRINCIPAL_KEYS and v.strip():
                yield k.lower(), v.strip().lower()
            else:
                yield from _walk_keys(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk_keys(v)


def principals_of(f: dict) -> set[str]:
    """Top-level `principal` if present, else best-effort identity fields in the raw payload."""
    out = set()
    if isinstance(f.get("principal"), str) and f["principal"].strip():
        out.add(f["principal"].strip().lower())
    for _, v in _walk_keys(f.get("raw_payload", {})):
        out.add(v)
    return out


def keys_of(f: dict) -> dict[str, set[str]]:
    keys: dict[str, set[str]] = {}
    if f.get("resource_id"):
        keys["resource_id"] = {f["resource_id"].lower()}
    if f.get("account_id"):
        keys["account_id"] = {f"{f['cloud']}/{f['account_id']}"}
    p = principals_of(f)
    if p:
        keys["principal"] = p
    ti = {m["indicator"] for m in f.get("threat_intel", [])}
    if ti:
        keys["threat_intel_indicator"] = ti
    mt = set(f.get("mitre_techniques", []))
    if mt:
        keys["mitre_technique"] = mt
    return keys


def _gap(a: dict, b: dict) -> timedelta:
    a0, a1 = parse_ts(first_seen_of(a)), parse_ts(last_seen_of(a))
    b0, b1 = parse_ts(first_seen_of(b)), parse_ts(last_seen_of(b))
    return max(timedelta(0), max(a0, b0) - min(a1, b1))


def link_findings(findings: list[dict], cfg: CorrelationConfig) -> list[dict]:
    """Return links: {a, b, score, gap_seconds, reasons: [{key, value, weight}]}."""
    keyed = {f["finding_id"]: keys_of(f) for f in findings}
    by_id = {f["finding_id"]: f for f in findings}
    pairs: dict[tuple[str, str], list[dict]] = {}
    index: dict[tuple[str, str], list[str]] = {}
    for fid, ks in keyed.items():
        for kind, vals in ks.items():
            for v in vals:
                index.setdefault((kind, v), []).append(fid)
    for (kind, v), fids in sorted(index.items()):
        for a, b in itertools.combinations(sorted(fids), 2):
            pairs.setdefault((a, b), []).append({"key": kind, "value": v, "weight": WEIGHTS[kind]})
    window = timedelta(minutes=cfg.window_minutes)
    links = []
    for (a, b), reasons in sorted(pairs.items()):
        gap = _gap(by_id[a], by_id[b])
        score = sum(r["weight"] for r in reasons)
        if gap <= window and score >= cfg.min_link_score:
            links.append({"a": a, "b": b, "score": score, "gap_seconds": int(gap.total_seconds()),
                          "reasons": sorted(reasons, key=lambda r: (r["key"], r["value"]))})
    return links


def _components(ids: list[str], links: list[dict]) -> list[list[str]]:
    parent = {i: i for i in ids}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for l in links:
        ra, rb = find(l["a"]), find(l["b"])
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)
    comps: dict[str, list[str]] = {}
    for i in ids:
        comps.setdefault(find(i), []).append(i)
    return [sorted(c) for c in comps.values()]


def score_incident(members: list[dict]) -> dict[str, Any]:
    highest = max((m["severity"] for m in members), key=SEVERITY_RANK.get)
    clouds = {m["cloud"] for m in members}
    strong_ti = any(t["confidence"] >= 70 for m in members for t in m.get("threat_intel", []))
    parts = {
        "highest_severity": SEVERITY_POINTS[highest],
        "cross_cloud": 15 if len(clouds) > 1 else 0,
        "member_count": min(5 * (len(members) - 1), 20),
        "high_confidence_threat_intel": 10 if strong_ti else 0,
    }
    return {"total": min(sum(parts.values()), 100), "components": parts}


def build_incident(member_ids: list[str], by_id: dict[str, dict], links: list[dict]) -> dict[str, Any]:
    members = [by_id[i] for i in member_ids]
    mset = set(member_ids)
    my_links = [l for l in links if l["a"] in mset and l["b"] in mset]
    timeline = sorted(
        ({"time": first_seen_of(m), "finding_id": m["finding_id"], "cloud": m["cloud"],
          "severity": m["severity"], "title": m["title"]} for m in members),
        key=lambda e: (parse_ts(e["time"]), e["finding_id"]),
    )
    evidence = sorted({(e["type"], e["ref"]) for m in members for e in m.get("evidence", [])})
    raw_refs = sorted({(r["finding_id"], r["payload_sha256"]) for m in members for r in m.get("source_records", [])})
    return {
        "incident_id": "inc-" + sha256_of(member_ids)[:16],
        "member_finding_ids": member_ids,
        "highest_severity": max((m["severity"] for m in members), key=SEVERITY_RANK.get),
        "clouds": sorted({m["cloud"] for m in members}),
        "accounts": sorted({f"{m['cloud']}/{m['account_id']}" for m in members if m.get("account_id")}),
        "first_seen": min((first_seen_of(m) for m in members), key=lambda t: (parse_ts(t), t)),
        "last_seen": max((last_seen_of(m) for m in members), key=lambda t: (parse_ts(t), t)),
        "mitre_techniques": sorted({t for m in members for t in m.get("mitre_techniques", [])}),
        "threat_intel_indicators": sorted({t["indicator"] for m in members for t in m.get("threat_intel", [])}),
        "score": score_incident(members),
        "grouping_reasons": my_links,
        "timeline": timeline,
        "evidence_refs": [{"type": t, "ref": r} for t, r in evidence],
        "raw_payload_refs": [{"finding_id": f, "payload_sha256": h} for f, h in raw_refs],
    }


def correlate(findings: list[dict], cfg: CorrelationConfig | None = None) -> tuple[list[dict], list[str]]:
    """Return (incidents, uncorrelated finding ids)."""
    cfg = cfg or CorrelationConfig()
    by_id = {f["finding_id"]: f for f in findings}
    ids = sorted(by_id)
    links = link_findings(findings, cfg)
    incidents, loose = [], []
    for comp in _components(ids, links):
        if len(comp) >= cfg.min_members:
            incidents.append(build_incident(comp, by_id, links))
        else:
            loose.extend(comp)
    incidents.sort(key=lambda i: (-i["score"]["total"], i["incident_id"]))
    return incidents, sorted(loose)
