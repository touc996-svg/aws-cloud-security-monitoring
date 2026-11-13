"""CLI: python -m pipeline [options] INPUT [INPUT ...]  (run from the aegis-x directory)."""
from __future__ import annotations

import argparse
import sys

from .correlate import CorrelationConfig
from .pipeline import run, write


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m pipeline", description=__doc__)
    ap.add_argument("inputs", nargs="+", help="JSON Lines files or directories of normalized findings")
    ap.add_argument("-o", "--out", required=True, help="output directory")
    ap.add_argument("--intel", action="append", default=[], help="offline indicator file (CSV/JSON); repeatable")
    ap.add_argument("--mapping", help="MITRE mapping JSON (default: bundled table)")
    ap.add_argument("--schema", help="finding schema (default: aegis-x/integrations/schemas/finding.schema.json)")
    ap.add_argument("--window-minutes", type=int, default=120)
    ap.add_argument("--min-link-score", type=int, default=2)
    ap.add_argument("--min-members", type=int, default=2)
    ap.add_argument("--fail-on-quarantine", action="store_true", help="exit 2 if any record was quarantined")
    a = ap.parse_args(argv)
    try:
        res = run(
            a.inputs, intel_files=a.intel, mapping=a.mapping, schema=a.schema,
            cfg=CorrelationConfig(a.window_minutes, a.min_link_score, a.min_members),
        )
    except (FileNotFoundError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    paths = write(res, a.out)
    s = res.summary
    print(
        f"valid={s['input_records_valid']} quarantined={s['input_records_quarantined']} "
        f"findings={s['findings_after_dedup']} incidents={s['incidents']} "
        f"ti_matches={s['threat_intel_matches']} -> {a.out}"
    )
    for k, p in paths.items():
        print(f"  {k}: {p}")
    return 2 if (a.fail_on_quarantine and res.quarantine) else 0


if __name__ == "__main__":
    sys.exit(main())
