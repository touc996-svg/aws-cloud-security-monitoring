"""Deduplicate / merge findings by finding_id and related_finding_ids.

Findings are nodes in a graph; an edge joins records with the same finding_id
or where one lists the other's id in related_finding_ids (a Security Hub record
pointing at its GuardDuty source is the same event). Each connected component
becomes one merged finding. The result does not depend on input order.
"""
from __future__ import annotations

from typing import Any

from .common import SEVERITY_RANK, first_seen_of, last_seen_of, parse_ts, sha256_of
from .ingest import Ingested


class _UF:
    def __init__(self):
        self.p: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            # deterministic root: lexicographically smaller id
            lo, hi = sorted((ra, rb))
            self.p[hi] = lo


def _source_records(item: Ingested) -> list[dict]:
    f = item.finding
    if isinstance(f.get("source_records"), list):  # already-merged input being re-ingested
        return [dict(r) for r in f["source_records"]]
    extra = {k: f[k] for k in ("source_product", "workflow_status", "compliance_status") if k in f}
    return [
        {
            **extra,
            "finding_id": f["finding_id"],
            "provider": f["provider"],
            "cloud": f["cloud"],
            "native_id": f.get("native_id"),
            "observed_at": f["observed_at"],
            "payload_sha256": sha256_of(f.get("raw_payload", {})),
            "source_file": item.source_file,
            "line": item.line,
            "evidence_refs": sorted({e["ref"] for e in f.get("evidence", [])}),
        }
    ]


def _primary_key(f: dict) -> tuple:
    # Prefer native (non-aggregated) records, then the most recently observed, then id.
    aggregated = 1 if f.get("related_finding_ids") else 0
    return (aggregated, _neg_ts(f.get("last_seen") or f["observed_at"]), f["finding_id"])


def _neg_ts(ts: str) -> float:
    return -parse_ts(ts).timestamp()


def _merge_status(statuses: list[str]) -> str | None:
    if not statuses:
        return None
    if "active" in statuses:
        return "active"
    if "archived" in statuses:
        return "archived"
    return "unknown"


def merge_group(items: list[Ingested]) -> dict[str, Any]:
    members = sorted((i.finding for i in items), key=_primary_key)
    primary = members[0]
    merged: dict[str, Any] = {k: v for k, v in primary.items()}

    ids = sorted({f["finding_id"] for f in members} | {
        i for f in members for i in (f.get("merged_from") or [])
    })
    firsts = [first_seen_of(f) for f in members]
    lasts = [last_seen_of(f) for f in members]
    merged["first_seen"] = min(firsts, key=lambda t: (parse_ts(t), t))
    merged["last_seen"] = max(lasts, key=lambda t: (parse_ts(t), t))
    merged["observed_at"] = min((f["observed_at"] for f in members), key=lambda t: (parse_ts(t), t))
    merged["severity"] = max((f["severity"] for f in members), key=SEVERITY_RANK.get)
    merged["mitre_techniques"] = sorted({t for f in members for t in f.get("mitre_techniques", [])})

    ev = {(e["type"], e["ref"]): e for f in members for e in f.get("evidence", [])}
    merged["evidence"] = [ev[k] for k in sorted(ev)]

    ti = {}
    for f in members:
        for m in f.get("threat_intel", []):
            ti[(m["indicator"], m["type"], m["source"])] = m
    if ti:
        merged["threat_intel"] = [ti[k] for k in sorted(ti)]

    related = {r for f in members for r in f.get("related_finding_ids", [])} - set(ids)
    if related:
        merged["related_finding_ids"] = sorted(related)
    else:
        merged.pop("related_finding_ids", None)

    for key in ("finding_types",):
        vals = sorted({v for f in members for v in f.get(key, [])})
        if vals:
            merged[key] = vals
    statuses = [f["status"] for f in members if "status" in f]
    st = _merge_status(statuses)
    if st:
        merged["status"] = st

    recs: dict[tuple, dict] = {}
    for it in items:
        for r in _source_records(it):
            recs[(r["finding_id"], r["payload_sha256"], r.get("source_file"), r.get("line"))] = r
    merged["source_records"] = [recs[k] for k in sorted(recs, key=lambda k: tuple(str(x) for x in k))]
    merged["merged_from"] = ids
    merged["raw_payload_count"] = len({(r["finding_id"], r["payload_sha256"]) for r in recs.values()})
    return merged


def deduplicate(items: list[Ingested]) -> list[dict[str, Any]]:
    uf = _UF()
    for it in items:
        fid = it.finding["finding_id"]
        uf.find(fid)
        for rid in it.finding.get("related_finding_ids", []):
            uf.union(fid, rid)
    groups: dict[str, list[Ingested]] = {}
    for it in items:
        groups.setdefault(uf.find(it.finding["finding_id"]), []).append(it)
    out = [merge_group(sorted(g, key=lambda i: (i.source_file, i.line))) for g in groups.values()]
    return sorted(out, key=lambda f: f["finding_id"])
