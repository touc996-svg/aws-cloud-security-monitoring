#!/usr/bin/env python3
"""AEGIS-X offline demo: one attack, seen by three clouds, correlated into one incident.

No cloud account, credentials, network access or cost. It feeds sample provider
payloads (fake account IDs; 203.0.113.0/24 is a documentation-only IP range)
through the real normalizers and the real cross-cloud pipeline.

    pip install -r demo/requirements.txt
    python demo/run_demo.py            # run from the aegis-x directory
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
AEGIS = HERE.parent
sys.path[:0] = [str(AEGIS), str(AEGIS / "integrations")]

from aws import guardduty_normalizer, securityhub_normalizer  # noqa: E402
from azure import defender_normalizer  # noqa: E402
from gcp import scc_normalizer  # noqa: E402
from pipeline.correlate import CorrelationConfig  # noqa: E402
from pipeline.pipeline import run, write  # noqa: E402

DATA = HERE / "data"
BOLD, DIM, RESET = ("\033[1m", "\033[2m", "\033[0m") if sys.stdout.isatty() else ("", "", "")


def load(name):
    return json.loads((DATA / name).read_text())


def heading(text):
    print(f"\n{BOLD}{text}{RESET}")


def collect():
    """Normalize every sample payload with the real normalizers."""
    sources = [
        ("Amazon GuardDuty", "guardduty.json", lambda p: [guardduty_normalizer.normalize(p)]),
        ("AWS Security Hub", "securityhub.json", securityhub_normalizer.normalize_all),
        ("Microsoft Defender for Cloud", "defender.json", lambda p: [defender_normalizer.normalize(p)]),
        ("Google Security Command Center", "scc.json", lambda p: [scc_normalizer.normalize(p)]),
    ]
    records, per_source = [], []
    for label, fname, fn in sources:
        payload = load(fname)
        items = payload if isinstance(payload, list) else [payload]
        out = [r for p in items for r in fn(p)]
        per_source.append((label, len(items), len(out)))
        records.extend(out)
    return records, per_source


def main() -> int:
    heading("1. Normalize provider findings into one schema")
    records, per_source = collect()
    for label, n_in, n_out in per_source:
        print(f"   {label:<34} {n_in} payload(s) -> {n_out} normalized finding(s)")

    with tempfile.TemporaryDirectory() as tmp:
        inbox = Path(tmp) / "findings"
        inbox.mkdir()
        for cloud in sorted({r["cloud"] for r in records}):
            lines = "".join(json.dumps(r, sort_keys=True) + "\n" for r in records if r["cloud"] == cloud)
            (inbox / f"{cloud}.jsonl").write_text(lines)
        result = run([inbox], intel_files=[DATA / "threat-intel.csv"], cfg=CorrelationConfig())
        write(result, Path(tmp) / "out")

    s = result.summary
    heading("2. Validate, deduplicate, enrich")
    print(f"   records ingested ........ {s['input_records_valid']}  (quarantined: {s['input_records_quarantined']})")
    print(f"   duplicates collapsed .... {s['duplicates_collapsed']}  (Security Hub re-reports the GuardDuty finding)")
    print(f"   findings after dedup .... {s['findings_after_dedup']}")
    print(f"   threat-intel matches .... {s['threat_intel_matches']}  (offline indicator file)")

    heading("3. Correlate across clouds")
    if not result.incidents:
        print("   no incidents formed")
    by_id = {f["finding_id"]: f for f in result.findings}
    for inc in result.incidents:
        print(f"   {BOLD}{inc['incident_id']}{RESET}  severity={inc['highest_severity'].upper()}  "
              f"clouds={','.join(inc['clouds'])}  score={inc['score']['total']}")
        if inc.get("threat_intel_indicators"):
            print(f"   shared indicator: {', '.join(inc['threat_intel_indicators'])}")
        if inc.get("mitre_techniques"):
            print(f"   MITRE ATT&CK:     {', '.join(inc['mitre_techniques'])}")
        print("   timeline:")
        for fid in sorted(inc["member_finding_ids"], key=lambda i: by_id[i]["first_seen"]):
            f = by_id[fid]
            print(f"     {f['first_seen'][11:19]}Z  {f['cloud']:<5} {f['provider']:<24} {f['severity']:<8} {f['title'][:52]}")
        print(f"   {DIM}why grouped (shared keys, weight):{RESET}")
        seen = set()
        for link in inc["grouping_reasons"]:
            for r in link["reasons"]:
                key = (r["key"], r["value"])
                if key not in seen:
                    seen.add(key)
                    print(f"     {r['key']} = {r['value']}  (+{r['weight']})")
    if result.uncorrelated:
        heading("4. Left alone (no link to anything else)")
        for fid in result.uncorrelated:
            f = by_id[fid]
            print(f"   {f['cloud']:<5} {f['severity']:<8} {f['title'][:70]}")

    print(f"\n{DIM}Raw provider payloads are preserved on every finding; nothing was deployed or sent anywhere.{RESET}")
    return 0 if result.incidents else 1


if __name__ == "__main__":
    raise SystemExit(main())
