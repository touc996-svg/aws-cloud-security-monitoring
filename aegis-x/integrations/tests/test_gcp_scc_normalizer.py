import base64
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

from gcp.scc_normalizer import (  # noqa: E402
    NormalizationError,
    normalize,
    normalize_many,
    severity_label,
)

FIXTURE = ROOT / "tests" / "fixtures" / "gcp_scc_findings.json"
SCHEMA = json.loads((ROOT / "schemas" / "finding.schema.json").read_text())
NOW = datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc)


@pytest.fixture()
def findings():
    return json.loads(FIXTURE.read_text())


def snake(value):
    import re

    if isinstance(value, dict):
        return {re.sub(r"(?<!^)(?=[A-Z])", "_", k).lower(): snake(v) for k, v in value.items()}
    if isinstance(value, list):
        return [snake(v) for v in value]
    return value


def test_all_fixtures_validate_against_schema(findings):
    validator = Draft202012Validator(SCHEMA)
    for f in findings:
        errors = list(validator.iter_errors(normalize(f, now=NOW)))
        assert not errors, errors


def test_gcloud_list_result_full_mapping(findings):
    out = normalize(findings[0], now=NOW)
    assert out["cloud"] == "gcp" and out["provider"] == "security-command-center"
    assert out["finding_id"] == (
        "gcp:security-command-center:acme-prod-1:us-central1:5678901234/a1b2c3d4e5f6"
    )
    assert out["native_id"] == findings[0]["finding"]["name"]
    assert out["native_severity"] == "HIGH" and out["severity"] == "high"
    assert out["account_id"] == "acme-prod-1"
    assert out["resource_id"].startswith("//compute.googleapis.com/projects/acme-prod-1")
    assert out["observed_at"] == "2026-11-10T08:15:30.123456789Z"
    assert out["first_seen"] == "2026-11-10T08:16:02.500Z"
    assert out["status"] == "active" and out["native_state"] == "ACTIVE"
    assert out["finding_type"] == out["title"] == "Persistence: IAM Anomalous Grant"
    assert out["ingested_at"] == "2026-11-13T12:00:00Z"
    assert [e["type"] for e in out["evidence"]] == ["provider_finding", "external_uri"]


def test_mitre_only_from_provided_fields(findings):
    # copied verbatim, deduplicated; attackExposure contributes nothing
    assert normalize(findings[0], now=NOW)["mitre_techniques"] == ["ACCOUNT_MANIPULATION", "T1098"]
    assert normalize(findings[1], now=NOW)["mitre_techniques"] == []


def test_raw_payload_preserved_and_input_untouched(findings):
    before = copy.deepcopy(findings[0])
    out = normalize(findings[0], now=NOW)
    assert out["raw_payload"] == before and findings[0] == before
    out["raw_payload"]["finding"]["severity"] = "LOW"
    assert findings[0]["finding"]["severity"] == "HIGH"


def test_notification_message_envelope(findings):
    msg = {"notificationConfigName": "organizations/111222333444/notificationConfigs/aegis", **findings[0]}
    out = normalize(msg, now=NOW)
    assert out["finding_id"] == normalize(findings[0], now=NOW)["finding_id"]
    assert out["raw_payload"] == msg


def test_pubsub_push_envelope(findings):
    inner = {"notificationConfigName": "x", **findings[0]}
    data = base64.b64encode(json.dumps(inner).encode()).decode()
    push = {"message": {"data": data, "messageId": "1"}, "subscription": "projects/p/subscriptions/s"}
    out = normalize(push, now=NOW)
    assert out["native_id"] == findings[0]["finding"]["name"]
    assert out["raw_payload"] == push


def test_bad_push_data_rejected():
    with pytest.raises(NormalizationError, match="base64"):
        normalize({"message": {"data": "!!!not-base64!!!"}})


def test_snake_case_keys(findings):
    out = normalize(snake(findings[0]), now=NOW)
    ref = normalize(findings[0], now=NOW)
    for key in ("finding_id", "native_id", "severity", "observed_at", "first_seen", "status",
                "mitre_techniques", "resource_id", "account_id"):
        assert out[key] == ref[key]
    assert out["raw_payload"] == snake(findings[0])  # raw keys not rewritten


def test_native_values_not_key_folded():
    f = {"finding": {"name": "projects/p/sources/1/findings/F", "category": "C",
                     "severity": "MEDIUM", "createTime": "2026-01-01T00:00:00Z",
                     "state": "ACTIVE"}}
    out = normalize(f, now=NOW)
    assert out["native_severity"] == "MEDIUM" and out["native_id"] == "projects/p/sources/1/findings/F"


def test_bare_finding(findings):
    assert normalize(findings[0]["finding"], now=NOW)["account_id"] == "acme-prod-1"


def test_idempotent_finding_id(findings):
    a = normalize(findings[0], now=NOW)
    b = normalize(findings[0], now=datetime(2030, 1, 1, tzinfo=timezone.utc))
    assert a["finding_id"] == b["finding_id"]


def test_inactive_and_unspecified_severity(findings):
    out = normalize(findings[1], now=NOW)
    assert out["status"] == "archived" and out["severity"] == "informational"
    assert out["native_severity"] == "SEVERITY_UNSPECIFIED"
    assert out["region"] == "global"
    assert out["first_seen"] == out["last_seen"] == out["observed_at"] == "2026-11-09T01:00:00Z"


def test_muted_is_archived_and_region_from_location(findings):
    out = normalize(findings[2], now=NOW)
    assert out["status"] == "archived" and out["native_state"] == "ACTIVE"
    assert out["region"] == "europe-west1"
    assert out["account_id"] == "acme-dev"  # from resourceName, no resource object
    assert out["observed_at"] == "2026-11-01T00:00:00Z"


def test_state_muted_enum_and_unknown_state():
    base = {"name": "projects/p/sources/1/findings/F", "category": "C", "createTime": "2026-01-01T00:00:00Z"}
    assert normalize({"finding": {**base, "state": "MUTED"}}, now=NOW)["status"] == "archived"
    assert normalize({"finding": {**base, "state": "STATE_UNSPECIFIED"}}, now=NOW)["status"] == "unknown"
    assert normalize({"finding": base}, now=NOW)["status"] == "unknown"
    assert "native_severity" not in normalize({"finding": base}, now=NOW)


@pytest.mark.parametrize(
    "native,label",
    [("CRITICAL", "critical"), ("HIGH", "high"), ("MEDIUM", "medium"), ("LOW", "low"),
     ("SEVERITY_UNSPECIFIED", "informational"), (None, "informational"), ("high", "high")],
)
def test_severity_enum(native, label):
    assert severity_label(native) == label


def test_unknown_severity_rejected(findings):
    bad = copy.deepcopy(findings[0])
    bad["finding"]["severity"] = "SEVERE"
    with pytest.raises(NormalizationError, match="severity"):
        normalize(bad)


@pytest.mark.parametrize(
    "mutate,match",
    [
        (lambda f: f["finding"].pop("name"), "name"),
        (lambda f: f["finding"].pop("category"), "category"),
        (lambda f: (f["finding"].pop("eventTime"), f["finding"].pop("createTime")), "timestamp"),
        (lambda f: f["finding"].update(eventTime="yesterday"), "eventTime"),
        (lambda f: f["finding"].update(name="bogus/name"), "finding name"),
    ],
)
def test_invalid_findings(findings, mutate, match):
    bad = copy.deepcopy(findings[0])
    mutate(bad)
    with pytest.raises(NormalizationError, match=match):
        normalize(bad)


def test_non_object_rejected():
    with pytest.raises(NormalizationError):
        normalize([1])  # type: ignore[arg-type]
    with pytest.raises(NormalizationError):
        normalize({"finding": "x"})


def test_normalize_many(findings):
    assert len(normalize_many(findings, now=NOW)) == 3


def test_cli_roundtrip(findings, tmp_path):
    p = tmp_path / "in.json"
    p.write_text(json.dumps({"listFindingsResults": findings}))
    r = subprocess.run([sys.executable, str(ROOT / "gcp" / "scc_normalizer.py"), str(p)],
                       capture_output=True, text=True, check=False)
    assert r.returncode == 0, r.stderr
    lines = [json.loads(line) for line in r.stdout.splitlines()]
    assert len(lines) == 3 and all(l["cloud"] == "gcp" for l in lines)
    p.write_text(json.dumps([{"finding": {}}]))
    r = subprocess.run([sys.executable, str(ROOT / "gcp" / "scc_normalizer.py"), str(p)],
                       capture_output=True, text=True, check=False)
    assert r.returncode == 1 and "error:" in r.stderr
