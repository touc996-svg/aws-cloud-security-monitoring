# AEGIS-X cross-cloud pipeline (workstream 5)

Offline, schema-driven Python. No network calls, no secrets, no live data.
Input: normalized findings (JSON Lines) matching `integrations/schemas/finding.schema.json`
from any cloud normalizer. The schema file is read, never modified.

```
ingest+validate -> MITRE map -> threat-intel enrich -> dedupe/merge -> correlate -> outputs
```

## Run (from `aegis-x/`)

```bash
pip install -r pipeline/requirements.txt
python -m pipeline path/to/findings_dir other.jsonl -o out/ --intel indicators.csv
python -m pytest pipeline -q
```

Options: `--intel` (repeatable, CSV/JSON), `--mapping`, `--schema`, `--window-minutes` (120),
`--min-link-score` (2), `--min-members` (2), `--fail-on-quarantine` (exit 2).

## Outputs (deterministic, no run timestamps)

| file | content |
|---|---|
| `findings.merged.jsonl` | deduped findings, valid against the finding schema (plus extra fields below) |
| `incidents.json` | incidents + `uncorrelated_finding_ids`; schema in `schemas/incident.schema.json` |
| `quarantine.jsonl` | every rejected line: source file, line, reason, schema errors, original text |
| `summary.json` | counts, MITRE coverage, rejected indicator rows, correlation config |

## Behaviour

- **Quarantine**: invalid JSON, non-objects, schema violations, and `date-time` fields lacking a timezone are quarantined, never dropped.
- **Dedup**: records are joined when they share `finding_id` or one lists the other in `related_finding_ids` (transitive). Merged record: primary = native (non-aggregated) record, latest `last_seen`; `first_seen` = earliest, `last_seen` = latest, `observed_at` = earliest, severity = highest, evidence/MITRE/threat-intel unioned, status active > archived > unknown. `merged_from` lists all ids; `source_records` keeps a reference (id, provider, native id, SHA-256 of the raw payload, source file+line, evidence refs, and `source_product`/`workflow_status`/`compliance_status` when present) for **every** input record. Only the primary's `raw_payload` is embedded; others are referenced by hash. Unresolvable `related_finding_ids` are preserved. Re-ingesting `findings.merged.jsonl` reproduces the same output (tested).
- **Correlation**: two findings link when the gap between their `[first_seen,last_seen]` intervals is within the window and shared-key weights reach `min_link_score`. Weights: resource_id 3, principal 3, shared threat-intel indicator 3, account 1 (per cloud), shared MITRE technique 1. Account alone never links. Incidents are connected components, so chains form (A–B, B–C ⇒ one incident). Each link lists its reasons (`grouping_reasons`). Incident score = highest-severity points (0–40) + cross-cloud 15 + member count (≤20) + high-confidence (≥70) intel 10, capped at 100, with the breakdown shown. Singletons are listed as uncorrelated.
- **Principal** is the optional top-level `principal` field, else identity-like keys found in `raw_payload` (e.g. `principalEmail`, `userPrincipalName`, `userName`, `accessKeyId`), lowercased. This is a heuristic; a first-class `principal` field in the schema would be better (see PR notes).
- **Threat intel**: `IntelProvider` interface; `LocalFileProvider` reads CSV (`indicator,type,source,confidence[,description]`) or JSON. IPs, domains (also match subdomains) and md5/sha1/sha256 hashes are extracted from `raw_payload` and `evidence`. Each match stores indicator, type, provider, source, confidence, field path. Malformed indicator rows are reported in `summary.json`.
- **MITRE**: `data/mitre_mapping.json` is an explicit table (cloud, type, exact|prefix, techniques, justification, source). Only a small, conservative set is mapped; all entries are `review_status: proposed` pending human analyst review. Unmapped types stay unmapped and are listed in coverage. Azure entries are intentionally absent until the Azure normalizer's `finding_type` vocabulary is on `main`.

## Known limitations

- Pairwise linking within a shared key is O(n²) per key bucket; fine for incident-scale data, not for millions of findings.
- Time-window chaining can merge long attack chains into one incident; tune `--window-minutes`.
- Merged records only embed the primary record's raw payload.
