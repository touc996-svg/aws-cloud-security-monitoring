import copy
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aws.guardduty_normalizer import (  # noqa: E402
    NormalizationError,
    normalize,
    normalize_many,
    severity_label,
)

FIXTURE = ROOT / "tests" / "fixtures" / "guardduty_findings.json"
SCHEMA = json.loads((ROOT / "schemas" / "finding.schema.json").read_text())
NOW = datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc)


@pytest.fixture()
def findings():
    return json.loads(FIXTURE.read_text())


def test_schema_is_valid():
    Draft202012Validator.check_schema(SCHEMA)


def test_all_fixtures_validate_against_schema(findings):
    validator = Draft202012Validator(SCHEMA)
    for f in findings:
        errors = list(validator.iter_errors(normalize(f, now=NOW)))
        assert not errors, errors


@pytest.mark.parametrize(
    "score,label",
    [(0, "informational"), (0.9, "informational"), (1, "low"), (3.9, "low"),
     (4, "medium"), (6.9, "medium"), (7, "high"), (8.9, "high"),
     (9, "critical"), (10, "critical")],
)
def test_severity_bands(score, label):
    assert severity_label(score) == label


def test_preserves_raw_payload_and_native_fields(findings):
    original = copy.deepcopy(findings[0])
    out = normalize(findings[0], now=NOW)
    assert out["raw_payload"] == original
    assert findings[0] == original  # input not mutated
    assert out["native_id"] == original["id"]
    assert out["native_severity"] == original["severity"]
    assert out["finding_type"] == original["type"]


def test_identifiers_and_timestamps(findings):
    out = normalize(findings[0], now=NOW)
    assert out["finding_id"] == "aws:guardduty:803872867382:us-east-1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"
    assert out["observed_at"] == "2026-11-12T20:00:00.000Z"
    assert out["last_seen"] == "2026-11-12T20:30:00.000Z"
    assert out["ingested_at"] == "2026-11-13T12:00:00Z"
    assert normalize(findings[0], now=NOW)["finding_id"] == out["finding_id"]  # idempotent


def test_resource_id_per_resource_type(findings):
    assert normalize(findings[0], now=NOW)["resource_id"] == "i-99999999"
    assert normalize(findings[1], now=NOW)["resource_id"] == "ASIAEXAMPLEEXAMPLE"
    assert normalize(findings[2], now=NOW)["resource_id"] == "arn:aws:s3:::example-bucket"


def test_status_and_evidence(findings):
    a, b, c = normalize_many(findings, now=NOW)
    assert (a["status"], b["status"], c["status"]) == ("active", "archived", "unknown")
    assert a["evidence"] == [{"type": "provider_finding", "ref": findings[0]["arn"]}]


def test_eventbridge_envelope(findings):
    event = {"version": "0", "detail-type": "GuardDuty Finding", "source": "aws.guardduty",
             "account": "803872867382", "region": "us-east-1", "detail": findings[0]}
    out = normalize(event, now=NOW)
    assert out["native_id"] == findings[0]["id"]
    assert out["raw_payload"] == event  # full envelope preserved


@pytest.mark.parametrize("field", ["id", "accountId", "region", "type", "severity", "title"])
def test_missing_required_field_raises(findings, field):
    bad = copy.deepcopy(findings[0])
    del bad[field]
    with pytest.raises(NormalizationError, match=field):
        normalize(bad)


def test_bad_severity_and_missing_timestamp_raise(findings):
    bad = copy.deepcopy(findings[0])
    bad["severity"] = "high"
    with pytest.raises(NormalizationError, match="severity"):
        normalize(bad)
    bad = copy.deepcopy(findings[0])
    bad["service"] = {}
    del bad["createdAt"]
    with pytest.raises(NormalizationError, match="timestamp"):
        normalize(bad)


def test_non_object_payload_raises():
    with pytest.raises(NormalizationError):
        normalize("not a finding")  # type: ignore[arg-type]


def test_cli_emits_json_lines():
    proc = subprocess.run(
        [sys.executable, "-I", str(ROOT / "aws" / "guardduty_normalizer.py"), str(FIXTURE)],
        capture_output=True, text=True, check=True,
    )
    lines = proc.stdout.strip().splitlines()
    assert len(lines) == 3
    assert json.loads(lines[2])["severity"] == "critical"
