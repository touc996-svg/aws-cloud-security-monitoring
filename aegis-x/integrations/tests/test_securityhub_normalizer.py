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

from aws.guardduty_normalizer import NormalizationError  # noqa: E402
from aws.securityhub_normalizer import normalize, normalize_all  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "securityhub_findings.json"
SCHEMA = json.loads((ROOT / "schemas" / "finding.schema.json").read_text())
NOW = datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc)


@pytest.fixture()
def findings():
    return json.loads(FIXTURE.read_text())["Findings"]


def test_all_fixtures_validate_against_schema(findings):
    validator = Draft202012Validator(SCHEMA)
    for out in normalize_all({"Findings": findings}, now=NOW):
        assert not list(validator.iter_errors(out))


def test_severity_from_label_and_from_normalized_score(findings):
    a, b, c = normalize_all({"Findings": findings}, now=NOW)
    assert (a["severity"], b["severity"], c["severity"]) == ("high", "critical", "medium")


@pytest.mark.parametrize("score,label", [(0, "informational"), (1, "low"), (39, "low"), (40, "medium"),
                                          (69, "medium"), (70, "high"), (89, "high"), (90, "critical"), (100, "critical")])
def test_normalized_score_bands(findings, score, label):
    f = copy.deepcopy(findings[2])
    f["Severity"] = {"Normalized": score}
    assert normalize(f, now=NOW)["severity"] == label


def test_raw_payload_preserved_and_input_not_mutated(findings):
    original = copy.deepcopy(findings[0])
    out = normalize(findings[0], now=NOW)
    assert out["raw_payload"] == original and findings[0] == original
    assert out["native_id"] == original["Id"]
    assert out["native_severity"] == original["Severity"]


def test_guardduty_sourced_finding_links_to_guardduty_id(findings):
    out = normalize(findings[0], now=NOW)
    assert out["related_finding_ids"] == ["aws:guardduty:803872867382:us-east-1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2"]
    assert normalize(findings[1], now=NOW)["related_finding_ids"] == []


def test_fields_status_and_evidence(findings):
    a, b, _ = normalize_all({"Findings": findings}, now=NOW)
    assert a["observed_at"] == "2026-11-12T21:00:00.000Z" and a["last_seen"] == "2026-11-12T21:05:00.000Z"
    assert (a["status"], b["status"]) == ("active", "archived")
    assert b["observed_at"] == "2026-11-12T22:00:00.000Z"  # falls back to CreatedAt
    assert b["compliance_status"] == "FAILED" and b["resource_id"] == "arn:aws:s3:::example-bucket"
    assert any(e["type"] == "remediation_guidance" for e in b["evidence"])
    assert a["ingested_at"] == "2026-11-13T12:00:00Z"
    assert b["region"] == "us-east-1" and b["source_product"] == "Security Hub"


def test_finding_id_is_deterministic(findings):
    assert normalize(findings[0], now=NOW)["finding_id"] == normalize(findings[0], now=NOW)["finding_id"]


def test_eventbridge_batch_and_single_contract(findings):
    event = {"detail-type": "Security Hub Findings - Imported", "source": "aws.securityhub",
             "detail": {"findings": findings[:2]}}
    assert len(normalize_all(event, now=NOW)) == 2
    with pytest.raises(NormalizationError, match="normalize_all"):
        normalize(event, now=NOW)
    single = {"detail-type": "Security Hub Findings - Imported", "detail": {"findings": findings[:1]}}
    assert normalize(single, now=NOW)["native_id"] == findings[0]["Id"]


def test_camel_case_input_also_works(findings):
    def lower(v):
        if isinstance(v, dict):
            return {k[:1].lower() + k[1:]: lower(x) for k, x in v.items()}
        if isinstance(v, list):
            return [lower(x) for x in v]
        return v
    a = normalize(findings[1], now=NOW)
    b = normalize(lower(findings[1]), now=NOW)
    for key in ("raw_payload", "native_severity"):  # intentionally the untouched originals
        a.pop(key), b.pop(key)
    assert a == b


@pytest.mark.parametrize("field", ["Id", "AwsAccountId", "Title", "Severity", "Resources"])
def test_missing_required_field_raises(findings, field):
    bad = copy.deepcopy(findings[0])
    del bad[field]
    with pytest.raises(NormalizationError):
        normalize(bad)


def test_unusable_severity_timestamp_and_input_raise(findings):
    bad = copy.deepcopy(findings[0]); bad["Severity"] = {"Label": "WEIRD"}
    with pytest.raises(NormalizationError, match="severity"):
        normalize(bad)
    bad = copy.deepcopy(findings[0])
    for k in ("FirstObservedAt", "CreatedAt"):
        del bad[k]
    with pytest.raises(NormalizationError, match="timestamp"):
        normalize(bad)
    with pytest.raises(NormalizationError):
        normalize("nope")  # type: ignore[arg-type]
    with pytest.raises(NormalizationError):
        normalize_all({"detail-type": "Security Hub Findings - Imported", "detail": {}})


def test_cli_emits_json_lines():
    proc = subprocess.run([sys.executable, "-I", str(ROOT / "aws" / "securityhub_normalizer.py"), str(FIXTURE)],
                          capture_output=True, text=True, check=True)
    lines = proc.stdout.strip().splitlines()
    assert len(lines) == 3 and json.loads(lines[1])["severity"] == "critical"
