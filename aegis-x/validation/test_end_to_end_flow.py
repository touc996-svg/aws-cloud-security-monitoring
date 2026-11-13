"""Detection -> normalization -> pipeline -> incidents, across all four sources."""
import json

from jsonschema import Draft202012Validator

from conftest import SCHEMA
from pipeline.pipeline import run, write


def test_every_fixture_normalizes_without_error(normalized):
    records, errors = normalized
    # Some Sentinel/Defender fixtures are deliberate negative cases; none may crash in an unhandled way.
    unexpected = [e for e in errors if "NormalizationError" not in e]
    assert not unexpected, unexpected
    assert len(records) >= 15


def test_all_three_clouds_and_every_provider_present(normalized):
    records, _ = normalized
    assert {r["cloud"] for r in records} == {"aws", "azure", "gcp"}
    providers = {r["provider"] for r in records}
    assert {"guardduty", "securityhub", "sentinel", "defender-for-cloud", "security-command-center"} <= providers


def test_every_normalized_record_is_schema_valid_and_keeps_raw(normalized):
    records, _ = normalized
    validator = Draft202012Validator(json.loads(SCHEMA.read_text()))
    for r in records:
        assert not list(validator.iter_errors(r)), r["finding_id"]
        assert r["raw_payload"], f"raw payload lost for {r['finding_id']}"
        assert r["native_id"], f"native id lost for {r['finding_id']}"


def test_finding_ids_are_unique_per_source_record(normalized):
    records, _ = normalized
    ids = [r["finding_id"] for r in records]
    assert len(ids) == len(set(ids))


def test_pipeline_accepts_everything_the_normalizers_emit(jsonl_dir):
    res = run([jsonl_dir])
    assert res.summary["input_records_quarantined"] == 0, res.quarantine
    assert set(res.summary["clouds"]) == {"aws", "azure", "gcp"}


def test_guardduty_securityhub_duplicate_is_collapsed(jsonl_dir):
    res = run([jsonl_dir])
    gd = "aws:guardduty:803872867382:us-east-1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2"
    assert res.summary["duplicates_collapsed"] >= 1
    surviving = [f for f in res.findings if f["finding_id"] == gd or gd in f.get("related_finding_ids", [])]
    assert len(surviving) == 1, "the same event must exist once after dedup"


def test_incidents_only_reference_real_findings(jsonl_dir):
    res = run([jsonl_dir])
    known = {f["finding_id"] for f in res.findings}
    for inc in res.incidents:
        assert set(inc["member_finding_ids"]) <= known
    assert set(res.uncorrelated) <= known


def test_bad_input_is_quarantined_not_lost(jsonl_dir):
    (jsonl_dir / "bad.jsonl").write_text('{"not": "a finding"}\nnot json at all\n')
    res = run([jsonl_dir])
    assert res.summary["input_records_quarantined"] == 2
    assert all(q.get("reason") for q in res.quarantine)


def test_pipeline_output_is_byte_identical_across_runs(jsonl_dir, tmp_path):
    for name in ("a", "b"):
        write(run([jsonl_dir]), tmp_path / name)
    for fname in ("findings.merged.jsonl", "incidents.json", "quarantine.jsonl", "summary.json"):
        assert (tmp_path / "a" / fname).read_bytes() == (tmp_path / "b" / fname).read_bytes(), fname
