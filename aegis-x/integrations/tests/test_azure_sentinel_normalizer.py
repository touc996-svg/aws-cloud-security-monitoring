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

from azure.sentinel_normalizer import NormalizationError, normalize, normalize_many  # noqa: E402

RECORDS = json.loads((ROOT / "tests" / "fixtures" / "sentinel_records.json").read_text())
SCHEMA = json.loads((ROOT / "schemas" / "finding.schema.json").read_text())
NOW = datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc)
SUB = "00000000-1111-2222-3333-444444444444"


@pytest.mark.parametrize("name", list(RECORDS))
def test_all_fixtures_validate_against_schema(name):
    out = normalize(RECORDS[name], now=NOW)
    assert not list(Draft202012Validator(SCHEMA).iter_errors(out))
    assert out["cloud"] == "azure" and out["provider"] == "sentinel"


@pytest.mark.parametrize("name", list(RECORDS))
def test_raw_payload_preserved_and_input_not_mutated(name):
    original = copy.deepcopy(RECORDS[name])
    out = normalize(RECORDS[name], now=NOW)
    assert out["raw_payload"] == original
    assert RECORDS[name] == original


@pytest.mark.parametrize("name", list(RECORDS))
def test_idempotent(name):
    assert normalize(RECORDS[name], now=NOW) == normalize(copy.deepcopy(RECORDS[name]), now=NOW)


def test_arm_incident():
    out = normalize(RECORDS["incident_arm"], now=NOW)
    assert out["finding_id"] == f"azure:sentinel:{SUB}:westeurope:5f2a1c0e-0b1d-4a55-9a77-0123456789ab"
    assert out["native_id"] == "5f2a1c0e-0b1d-4a55-9a77-0123456789ab"
    assert out["native_severity"] == "High" and out["severity"] == "high"
    assert out["account_id"] == out["subscription_id"] == SUB
    assert out["resource_id"] == RECORDS["incident_arm"]["id"]
    assert out["status"] == "active"
    assert out["finding_type"] == "SecurityIncident"
    assert out["mitre_tactics"] == ["InitialAccess", "Persistence"]
    assert out["mitre_techniques"] == ["T1078", "T1137"]
    assert out["observed_at"] == "2026-11-01T08:00:00Z"  # firstActivity, 7-digit fraction trimmed
    assert out["last_seen"] == "2026-11-01T08:12:00Z"
    assert out["ingested_at"] == "2026-11-13T12:00:00Z"
    assert "tenant_id" not in out


def test_incident_without_azure_mitre_data_gets_none():
    out = normalize(RECORDS["incident_arm_no_mitre"], now=NOW)
    assert out["mitre_tactics"] == [] and out["mitre_techniques"] == []
    assert out["severity"] == "informational" and out["status"] == "archived"
    assert out["region"] == "global"
    assert out["observed_at"] == "2026-11-02T00:00:00Z"


def test_incident_table_row_uses_url_for_subscription_and_resource():
    out = normalize(RECORDS["incident_table_row"], now=NOW)
    assert out["account_id"] == SUB
    assert out["tenant_id"] == "81b0daa5-5660-4a8d-85f2-b4c5c868766f"
    assert out["resource_id"].startswith(f"/subscriptions/{SUB}/") and out["resource_id"].endswith("0123456789ab")
    assert out["native_severity"] == "Medium" and out["severity"] == "medium"
    assert out["mitre_techniques"] == ["T1528"]
    refs = [e["ref"] for e in out["evidence"] if e["type"] == "related_alert"]
    assert refs == ["11111111-aaaa-bbbb-cccc-000000000001", "11111111-aaaa-bbbb-cccc-000000000002"]


def test_alert_table_row_mitre_from_azure_fields_only():
    out = normalize(RECORDS["alert_table_row"], now=NOW)
    assert out["native_id"] == "cccccccc-0b1d-4a55-9a77-0123456789ab"
    assert out["title"] == "Suspicious PowerShell command line"
    assert out["finding_type"] == "MDATP_Suspicious_PS"
    assert out["mitre_tactics"] == ["Execution", "DefenseEvasion"]
    assert out["mitre_techniques"] == ["T1059", "T1027", "T1059.001"]
    # affected resource is in another subscription than the workspace: the resource wins
    assert out["account_id"] == "99999999-1111-2222-3333-444444444444"
    assert out["resource_id"].endswith("virtualMachines/vm-web01")
    assert out["observed_at"] == "2026-11-04T11:58:00.500000Z"


def test_alert_without_tactics_gets_empty_lists():
    out = normalize(RECORDS["alert_table_row_no_mitre"], now=NOW)
    assert out["mitre_tactics"] == [] and out["mitre_techniques"] == []
    assert out["status"] == "archived" and out["severity"] == "informational"
    assert out["account_id"] == SUB
    assert out["resource_id"] == "unknown"


def test_arm_alert_entity():
    out = normalize(RECORDS["alert_arm"], now=NOW)
    assert out["resource_id"].endswith("storageAccounts/stdata01")
    assert out["mitre_tactics"] == ["Collection"] and out["mitre_techniques"] == ["T1530"]
    assert out["finding_type"] == "STORAGE_UnusualAccess"


@pytest.mark.parametrize("native,label", [("Informational", "informational"), ("Low", "low"),
                                           ("Medium", "medium"), ("High", "high"), ("high", "high")])
def test_severity_names(native, label):
    rec = copy.deepcopy(RECORDS["incident_arm"])
    rec["properties"]["severity"] = native
    out = normalize(rec, now=NOW)
    assert out["severity"] == label and out["native_severity"] == native


def test_unknown_severity_rejected():
    rec = copy.deepcopy(RECORDS["incident_arm"])
    rec["properties"]["severity"] = "Critical"
    with pytest.raises(NormalizationError):
        normalize(rec)


def test_pascal_vs_camel_keys_give_same_result():
    rec = copy.deepcopy(RECORDS["alert_table_row"])
    lower = {k[:1].lower() + k[1:]: v for k, v in rec.items()}
    a, b = normalize(rec, now=NOW), normalize(lower, now=NOW)
    a.pop("raw_payload"), b.pop("raw_payload")
    assert a == b


@pytest.mark.parametrize("bad", [None, [], "x", {}, {"Title": "t"}, {"IncidentName": "x", "Title": "t"}])
def test_bad_payloads(bad):
    with pytest.raises(NormalizationError):
        normalize(bad)


def test_bad_timestamp_and_missing_account():
    rec = copy.deepcopy(RECORDS["incident_arm"])
    rec["properties"].update(firstActivityTimeUtc="nope")
    with pytest.raises(NormalizationError):
        normalize(rec)
    row = {"IncidentName": "x", "Title": "t", "Severity": "Low", "CreatedTime": "2026-11-01T00:00:00Z"}
    with pytest.raises(NormalizationError, match="subscription or tenant"):
        normalize(row)


def test_normalize_many():
    outs = normalize_many(RECORDS.values(), now=NOW)
    assert len(outs) == len(RECORDS)
    assert len({o["finding_id"] for o in outs}) == len(outs)


def test_cli_emits_json_lines(tmp_path):
    f = tmp_path / "in.json"
    f.write_text(json.dumps({"value": [RECORDS["incident_arm"], RECORDS["alert_arm"]]}))
    proc = subprocess.run([sys.executable, str(ROOT / "azure" / "sentinel_normalizer.py"), str(f)],
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert len(proc.stdout.strip().splitlines()) == 2
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    proc = subprocess.run([sys.executable, str(ROOT / "azure" / "sentinel_normalizer.py"), str(bad)],
                          capture_output=True, text=True)
    assert proc.returncode == 1
