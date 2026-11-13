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

from azure.defender_normalizer import NormalizationError, normalize, normalize_many  # noqa: E402

RECORDS = json.loads((ROOT / "tests" / "fixtures" / "defender_records.json").read_text())
SCHEMA = json.loads((ROOT / "schemas" / "finding.schema.json").read_text())
NOW = datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc)
SUB = "00000000-1111-2222-3333-444444444444"


@pytest.mark.parametrize("name", list(RECORDS))
def test_all_fixtures_validate_against_schema(name):
    out = normalize(RECORDS[name], now=NOW)
    assert not list(Draft202012Validator(SCHEMA).iter_errors(out))
    assert out["cloud"] == "azure" and out["provider"] == "defender-for-cloud"


@pytest.mark.parametrize("name", list(RECORDS))
def test_raw_preserved_not_mutated_idempotent(name):
    original = copy.deepcopy(RECORDS[name])
    out = normalize(RECORDS[name], now=NOW)
    assert out["raw_payload"] == original and RECORDS[name] == original
    assert out == normalize(copy.deepcopy(RECORDS[name]), now=NOW)


def test_alert():
    out = normalize(RECORDS["alert"], now=NOW)
    assert out["finding_id"] == f"azure:defender-for-cloud:{SUB}:centralus:2517000000000000000_abc"
    assert out["native_id"] == "2517000000000000000_abc"
    assert out["native_severity"] == "High" and out["severity"] == "high"
    assert out["resource_id"].endswith("virtualMachines/vm-web01")
    assert out["account_id"] == SUB and out["region"] == "centralus"
    assert out["finding_type"] == "VM_SuspiciousScreenSaver"
    assert out["mitre_tactics"] == ["Persistence"]
    assert out["mitre_techniques"] == ["T1546", "T1546.002"]
    assert out["observed_at"] == "2026-11-07T14:00:00.123456Z"
    assert out["status"] == "active"


def test_microsoft_specific_intent_is_not_mapped():
    out = normalize(RECORDS["alert_microsoft_specific_intent"], now=NOW)
    assert out["mitre_tactics"] == [] and out["mitre_techniques"] == []
    assert out["status"] == "archived" and out["severity"] == "low"
    assert out["region"] == "westeurope"
    assert out["resource_id"] == RECORDS["alert_microsoft_specific_intent"]["id"]  # no AzureResource id given


def test_unhealthy_assessment():
    out = normalize(RECORDS["assessment_unhealthy"], now=NOW)
    assert out["native_id"] == "4fb67663-9ab9-475d-b026-8c544cced439"
    assert out["native_severity"] == "Medium" and out["severity"] == "medium"
    assert out["status"] == "active"
    assert out["resource_id"].endswith("storageAccounts/stdata01")
    assert out["finding_type"] == "SecurityAssessment:BuiltIn"
    assert out["mitre_tactics"] == [] and out["mitre_techniques"] == []
    assert out["observed_at"] == "2026-10-21T06:30:00Z"
    assert out["description"] == "Enforce HTTPS on storage accounts."
    assert out["region"] == "global"


def test_same_assessment_on_two_resources_has_distinct_finding_ids():
    a = normalize(RECORDS["assessment_unhealthy"], now=NOW)
    b = normalize(RECORDS["assessment_healthy"], now=NOW)
    assert a["native_id"] == b["native_id"] and a["finding_id"] != b["finding_id"]
    assert b["status"] == "archived"


def test_assessment_resource_id_case_insensitive_hash():
    rec = copy.deepcopy(RECORDS["assessment_unhealthy"])
    rec["properties"]["resourceDetails"]["Id"] = rec["properties"]["resourceDetails"]["Id"].upper()
    assert normalize(rec, now=NOW)["finding_id"] == normalize(RECORDS["assessment_unhealthy"], now=NOW)["finding_id"]


def test_resource_graph_row_with_top_level_subscription():
    rec = copy.deepcopy(RECORDS["assessment_unhealthy"])
    rec["subscriptionId"] = SUB
    rec["tenantId"] = "81b0daa5-5660-4a8d-85f2-b4c5c868766f"
    out = normalize(rec, now=NOW)
    assert out["tenant_id"] == "81b0daa5-5660-4a8d-85f2-b4c5c868766f" and out["account_id"] == SUB


def test_assessment_without_expanded_metadata_rejected():
    rec = copy.deepcopy(RECORDS["assessment_unhealthy"])
    del rec["properties"]["metadata"]
    with pytest.raises(NormalizationError, match="metadata.severity"):
        normalize(rec)


@pytest.mark.parametrize("native,label", [("Informational", "informational"), ("Low", "low"),
                                           ("Medium", "medium"), ("High", "high")])
def test_severity_names(native, label):
    rec = copy.deepcopy(RECORDS["alert"])
    rec["properties"]["severity"] = native
    out = normalize(rec, now=NOW)
    assert out["severity"] == label and out["native_severity"] == native


@pytest.mark.parametrize("bad", [None, [], "x", {}, {"properties": {"alertType": "x"}}])
def test_bad_payloads(bad):
    with pytest.raises(NormalizationError):
        normalize(bad)


def test_cli(tmp_path):
    f = tmp_path / "in.json"
    f.write_text(json.dumps({"value": [RECORDS["alert"], RECORDS["assessment_unhealthy"]]}))
    proc = subprocess.run([sys.executable, str(ROOT / "azure" / "defender_normalizer.py"), str(f)],
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert len(proc.stdout.strip().splitlines()) == 2


def test_normalize_many():
    assert len(normalize_many(RECORDS.values(), now=NOW)) == len(RECORDS)
