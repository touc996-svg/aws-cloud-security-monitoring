"""End-to-end orchestration and deterministic output writing."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .common import canonical_json
from .correlate import CorrelationConfig, correlate
from .dedupe import deduplicate
from .ingest import ingest, load_validator
from .intel import IntelProvider, LocalFileProvider, enrich
from .mitre import MitreMapper, coverage


@dataclass
class Result:
    findings: list[dict]
    incidents: list[dict]
    uncorrelated: list[str]
    quarantine: list[dict]
    summary: dict[str, Any]


def run(
    inputs: Iterable[Path | str],
    *,
    intel_files: Iterable[Path | str] = (),
    providers: list[IntelProvider] | None = None,
    mapping: Path | str | None = None,
    schema: Path | str | None = None,
    cfg: CorrelationConfig | None = None,
) -> Result:
    validator = load_validator(schema)
    items, quarantine = ingest(inputs, validator)
    mapper = MitreMapper.load(mapping)
    providers = list(providers or []) + [LocalFileProvider(p) for p in intel_files]

    for it in items:  # per-source-record enrichment, before merging
        mapper.apply(it.finding)
        enrich(it.finding, providers)

    merged = deduplicate(items)
    incidents, loose = correlate(merged, cfg)
    cov = coverage(merged, mapper)
    rejected = [
        {"provider": p.name, **r} for p in providers for r in getattr(p, "rejected", [])
    ]
    summary = {
        "input_records_valid": len(items),
        "input_records_quarantined": len(quarantine),
        "findings_after_dedup": len(merged),
        "duplicates_collapsed": len(items) - len(merged),
        "incidents": len(incidents),
        "uncorrelated_findings": len(loose),
        "clouds": sorted({f["cloud"] for f in merged}),
        "threat_intel_matches": sum(len(f.get("threat_intel", [])) for f in merged),
        "intel_indicator_rows_rejected": rejected,
        "mitre_coverage": cov,
        "correlation_config": vars(cfg or CorrelationConfig()),
    }
    return Result(merged, incidents, loose, quarantine, summary)


def write(result: Result, out_dir: Path | str) -> dict[str, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths = {
        "findings": out / "findings.merged.jsonl",
        "incidents": out / "incidents.json",
        "quarantine": out / "quarantine.jsonl",
        "summary": out / "summary.json",
    }
    paths["findings"].write_text("".join(canonical_json(f) + "\n" for f in result.findings), encoding="utf-8")
    paths["quarantine"].write_text("".join(canonical_json(q) + "\n" for q in result.quarantine), encoding="utf-8")
    doc = {"incidents": result.incidents, "uncorrelated_finding_ids": result.uncorrelated}
    paths["incidents"].write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    paths["summary"].write_text(json.dumps(result.summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return paths
