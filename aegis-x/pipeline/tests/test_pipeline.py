import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from pipeline.correlate import CorrelationConfig
from pipeline.dedupe import deduplicate
from pipeline.ingest import DEFAULT_SCHEMA, ingest, load_validator
from pipeline.intel import IntelProvider, LocalFileProvider, extract_observables
from pipeline.mitre import MappingError, MitreMapper
from pipeline.pipeline import run, write

FX = Path(__file__).parent / "fixtures"
INCIDENT_SCHEMA = Path(__file__).parent.parent / "schemas" / "incident.schema.json"
VALID_INPUTS = [FX / "aws.jsonl", FX / "azure.jsonl", FX / "gcp.jsonl"]
G1 = "aws:guardduty:111111111111:us-east-1:g1"
SH1 = "aws:securityhub:111111111111:us-east-1:sh-1"


@pytest.fixture(scope="module")
def result():
    return run(VALID_INPUTS + [FX / "invalid.jsonl"], intel_files=[FX / "intel.csv", FX / "intel.json"])


def by_id(res):
    return {f["finding_id"]: f for f in res.findings}


# ---- ingest / quarantine -------------------------------------------------
def test_quarantine_reports_every_bad_line_with_reason():
    good, bad = ingest([FX / "invalid.jsonl"])
    assert good == []
    assert len(bad) == 6
    reasons = " | ".join(b["reason"] + " ".join(b.get("errors", [])) for b in bad)
    assert "invalid JSON" in reasons
    assert "not a JSON object" in reasons
    assert "finding_id" in reasons  # missing required
    assert "naive ts" not in reasons and "no timezone" in reasons
    assert all(b["line"] > 0 and b["raw_line"] for b in bad)


def test_ingest_accepts_directory_and_counts_all_lines():
    good, bad = ingest([FX])
    assert len(good) == 6 + 2 + 1 and len(bad) == 6


def test_missing_input_is_an_error():
    with pytest.raises(FileNotFoundError):
        ingest([FX / "nope.jsonl"])


# ---- dedup ---------------------------------------------------------------
def test_same_id_and_related_ids_collapse(result):
    f = by_id(result)
    assert SH1 not in f  # collapsed into the GuardDuty record
    m = f[G1]
    assert m["merged_from"] == [G1, SH1]
    assert m["first_seen"] == "2026-11-10T09:58:00Z"  # earliest (from Security Hub)
    assert m["last_seen"] == "2026-11-10T10:35:00Z"  # latest (g1 re-emission)
    assert len(m["source_records"]) == 3  # g1, g1 re-emitted, sh-1 all referenced
    assert m["raw_payload_count"] == 3
    assert {r["finding_id"] for r in m["source_records"]} == {G1, SH1}


def test_dedup_is_order_independent():
    good, _ = ingest(VALID_INPUTS)
    a = deduplicate(good)
    b = deduplicate(list(reversed(good)))
    assert a == b


def test_related_pointing_to_unknown_id_is_kept_not_dropped():
    good, _ = ingest([FX / "aws.jsonl"])
    sh = next(g for g in good if g.finding["provider"] == "securityhub")
    sh.finding["related_finding_ids"] = ["aws:guardduty:999:us-east-1:missing"]
    merged = {f["finding_id"]: f for f in deduplicate(good)}
    assert SH1 in merged and "aws:guardduty:999:us-east-1:missing" in merged[SH1]["related_finding_ids"]


# ---- MITRE ---------------------------------------------------------------
def test_mitre_mapping_applied_and_unmapped_left_alone(result):
    f = by_id(result)
    assert f[G1]["mitre_techniques"] == ["T1071"]
    assert f["aws:guardduty:111111111111:us-east-1:g2"]["mitre_techniques"] == ["T1562.008"]
    assert f["aws:guardduty:111111111111:us-east-1:g4"]["mitre_techniques"] == []
    cov = result.summary["mitre_coverage"]
    assert "aws:Policy:S3/BucketPublicAccessGranted" in cov["unmapped"]
    assert "gcp:Persistence: IAM Anomalous Grant" in cov["mapped"]
    assert "azure:Suspicious sign-in" in cov["unmapped"]
    assert 0 < cov["coverage_pct"] < 100


def test_bundled_mapping_is_well_formed():
    m = MitreMapper.load()
    assert all(e["justification"] and e["source"] for e in m.entries)


def test_mapping_rejects_bad_entries():
    with pytest.raises(MappingError):
        MitreMapper([{"cloud": "aws", "finding_type": "x", "match": "exact", "techniques": ["bogus"], "justification": "j", "source": "s"}])
    with pytest.raises(MappingError):
        MitreMapper([{"cloud": "aws", "finding_type": "x", "match": "exact", "techniques": ["T1046"], "source": "s"}])


# ---- threat intel --------------------------------------------------------
def test_enrichment_records_source_and_confidence(result):
    ti = by_id(result)[G1]["threat_intel"]
    srcs = {(t["source"], t["confidence"]) for t in ti if t["indicator"] == "203.0.113.50"}
    assert srcs == {("example-feed", 90), ("second-feed", 55)}
    assert all(t["provider"].startswith("local:") and t["field"] for t in ti)


def test_domain_indicator_matches_subdomain_and_hash_inferred(result):
    gcp = by_id(result)["gcp:scc:proj-1:c1"]
    assert [(t["indicator"], t["confidence"]) for t in gcp["threat_intel"]] == [("example.net", 60)]


def test_bad_indicator_rows_are_reported_not_ignored(result):
    rej = result.summary["intel_indicator_rows_rejected"]
    reasons = " ".join(r["reason"] for r in rej)
    assert len(rej) == 2 and "confidence" in reasons


def test_observable_extraction_and_no_false_ip():
    obs = extract_observables({"raw_payload": {"a": "v1.2.3.4.5 and 10.0.0.300 and 203.0.113.9"}, "evidence": []})
    assert [o.value for o in obs if o.type == "ip"] == ["203.0.113.9"]


def test_custom_provider_plugs_in():
    class Fixed(IntelProvider):
        name = "fixed"

        def match_observables(self, observables):
            from pipeline.intel import IntelMatch
            return [IntelMatch(o.value, o.type, "fixed", "unit", 99, o.field) for o in observables if o.value == "203.0.113.50"]

    res = run([FX / "aws.jsonl"], providers=[Fixed()])
    assert by_id(res)[G1]["threat_intel"][0]["source"] == "unit"


# ---- correlation ---------------------------------------------------------
def test_cross_cloud_incident(result):
    assert len(result.incidents) == 1
    inc = result.incidents[0]
    assert inc["clouds"] == ["aws", "azure", "gcp"]
    assert inc["highest_severity"] == "critical"
    assert set(inc["member_finding_ids"]) == {
        G1,
        "aws:guardduty:111111111111:us-east-1:g2",
        "azure:defender:sub-1111:a1",
        "azure:defender:sub-1111:a2",
        "gcp:scc:proj-1:c1",
    }
    # out-of-window same-resource finding and unrelated account stay out
    assert set(result.uncorrelated) == {
        "aws:guardduty:111111111111:us-east-1:g3",
        "aws:guardduty:111111111111:us-east-1:g4",
    }
    keys = {(r["key"], r["value"]) for l in inc["grouping_reasons"] for r in l["reasons"]}
    assert ("threat_intel_indicator", "203.0.113.50") in keys  # aws<->azure via shared C2 IP
    assert ("principal", "deploy-bot@example.com") in keys  # azure<->gcp via identity, case-insensitive
    assert [t["time"] for t in inc["timeline"]] == sorted(t["time"] for t in inc["timeline"])
    assert inc["score"]["components"]["cross_cloud"] == 15
    assert inc["evidence_refs"] and inc["raw_payload_refs"]


def test_window_controls_grouping():
    tight = run(VALID_INPUTS, intel_files=[FX / "intel.csv"], cfg=CorrelationConfig(window_minutes=1))
    # g1 (until 10:35) overlaps g2 (10:30) so that link survives; cross-cloud links do not
    assert all(i["clouds"] == ["aws"] for i in tight.incidents)
    wide = run(VALID_INPUTS, intel_files=[FX / "intel.csv"], cfg=CorrelationConfig(window_minutes=60 * 48))
    ids = {m for i in wide.incidents for m in i["member_finding_ids"]}
    assert "aws:guardduty:111111111111:us-east-1:g3" in ids  # same resource, now within window


def test_account_alone_is_not_enough(tmp_path):
    rows = []
    for n in (1, 2):
        rows.append({"finding_id": f"aws:x:{n}", "cloud": "aws", "provider": "x", "severity": "low", "title": "t",
                     "account_id": "1", "resource_id": f"r{n}", "observed_at": "2026-11-10T10:00:00Z"})
    p = tmp_path / "a.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in rows))
    assert run([p]).incidents == []


# ---- determinism / schema ------------------------------------------------
def test_outputs_validate_and_are_deterministic(tmp_path):
    outs = []
    for name in ("one", "two"):
        res = run(VALID_INPUTS + [FX / "invalid.jsonl"], intel_files=[FX / "intel.csv", FX / "intel.json"])
        outs.append(write(res, tmp_path / name))
    for key in outs[0]:
        assert outs[0][key].read_bytes() == outs[1][key].read_bytes(), key

    fv = Draft202012Validator(json.loads(DEFAULT_SCHEMA.read_text()))
    lines = outs[0]["findings"].read_text().splitlines()
    assert lines
    for line in lines:
        assert not list(fv.iter_errors(json.loads(line)))
    iv = Draft202012Validator(json.loads(INCIDENT_SCHEMA.read_text()))
    doc = json.loads(outs[0]["incidents"].read_text())
    assert not list(iv.iter_errors(doc)) and doc["incidents"]
    q = [json.loads(l) for l in outs[0]["quarantine"].read_text().splitlines()]
    assert len(q) == 6


def test_reingesting_merged_output_is_a_fixed_point(tmp_path):
    first = run(VALID_INPUTS, intel_files=[FX / "intel.csv"])
    write(first, tmp_path / "1")
    second = run([tmp_path / "1" / "findings.merged.jsonl"], intel_files=[FX / "intel.csv"])
    write(second, tmp_path / "2")
    for name in ("findings.merged.jsonl", "incidents.json"):
        assert (tmp_path / "1" / name).read_bytes() == (tmp_path / "2" / name).read_bytes(), name


def test_cli_end_to_end(tmp_path):
    aegis = Path(__file__).resolve().parents[2]
    cmd = [sys.executable, "-m", "pipeline", str(FX), "-o", str(tmp_path), "--intel", str(FX / "intel.csv")]
    p = subprocess.run(cmd, cwd=aegis, capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    assert "quarantined=6" in p.stdout and (tmp_path / "incidents.json").exists()
    p = subprocess.run(cmd + ["--fail-on-quarantine"], cwd=aegis, capture_output=True, text=True)
    assert p.returncode == 2
    p = subprocess.run([sys.executable, "-m", "pipeline", "/nonexistent", "-o", str(tmp_path)], cwd=aegis, capture_output=True, text=True)
    assert p.returncode == 1
