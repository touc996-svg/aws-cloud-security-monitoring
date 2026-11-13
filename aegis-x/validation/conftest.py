"""Shared fixtures for AEGIS-X workstream 7 validation (run from the aegis-x directory)."""
import json
import sys
from pathlib import Path

import pytest

AEGIS = Path(__file__).resolve().parents[1]
for p in (AEGIS, AEGIS / "integrations"):
    sys.path.insert(0, str(p))

FIXTURES = AEGIS / "integrations" / "tests" / "fixtures"
SCHEMA = AEGIS / "integrations" / "schemas" / "finding.schema.json"


class FakeS3:
    """In-memory stand-in for the S3 client used by the ingestion Lambda."""

    def __init__(self, fail_keys=()):
        self.objects: dict[str, bytes] = {}
        self.puts = 0
        self.fail_keys = set(fail_keys)

    def put_object(self, *, Bucket, Key, Body, ContentType=None):
        self.puts += 1
        if Key in self.fail_keys:
            raise RuntimeError(f"simulated S3 failure for {Key}")
        self.objects[Key] = Body


def load(name):
    return json.loads((FIXTURES / name).read_text())


def _values(doc):
    return list(doc.values()) if isinstance(doc, dict) else list(doc)


def collect_normalized():
    """Normalize every real-shaped fixture from all four sources through the real normalizers."""
    from aws import guardduty_normalizer, securityhub_normalizer
    from azure import defender_normalizer, sentinel_normalizer
    from gcp import scc_normalizer

    out, errors = [], []

    def run(fn, payloads, label):
        for i, payload in enumerate(payloads):
            try:
                res = fn(payload)
                out.extend(res if isinstance(res, list) else [res])
            except Exception as exc:  # noqa: BLE001 - recorded for the assertion message
                errors.append(f"{label}[{i}]: {type(exc).__name__}: {exc}")

    run(guardduty_normalizer.normalize, load("guardduty_findings.json"), "guardduty")
    run(securityhub_normalizer.normalize_all, [load("securityhub_findings.json")], "securityhub")
    run(sentinel_normalizer.normalize, _values(load("sentinel_records.json")), "sentinel")
    run(defender_normalizer.normalize, _values(load("defender_records.json")), "defender")
    run(scc_normalizer.normalize, load("gcp_scc_findings.json"), "scc")
    return out, errors


@pytest.fixture(scope="session")
def normalized():
    return collect_normalized()


@pytest.fixture()
def jsonl_dir(tmp_path, normalized):
    records, _ = normalized
    d = tmp_path / "in"
    d.mkdir()
    for cloud in sorted({r["cloud"] for r in records}):
        lines = "".join(json.dumps(r, sort_keys=True) + "\n" for r in records if r["cloud"] == cloud)
        (d / f"{cloud}.jsonl").write_text(lines)
    return d
