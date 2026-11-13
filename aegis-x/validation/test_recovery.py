"""Recovery behaviour: redelivery, partial failure, DLQ replay and rebuilding from storage."""
import json
import shutil

import pytest

from aws.lambda_handler import IngestionError, handler, object_key
from conftest import FakeS3, load
from pipeline.pipeline import run, write


@pytest.fixture(autouse=True)
def bucket(monkeypatch):
    monkeypatch.setenv("FINDINGS_BUCKET", "test-findings")


def gd_event(i=0):
    return {"version": "0", "source": "aws.guardduty", "detail-type": "GuardDuty Finding",
            "detail": load("guardduty_findings.json")[i]}


def sh_event(n=3):
    return {"version": "0", "source": "aws.securityhub", "detail-type": "Security Hub Findings - Imported",
            "detail": {"findings": load("securityhub_findings.json")["Findings"][:n]}}


def _without_ingested_at(body):
    rec = json.loads(body)
    rec.pop("ingested_at")
    return rec


def test_redelivering_the_same_event_is_idempotent():
    """Same key, no duplicates. Known behaviour: ingested_at is refreshed on every delivery,
    so replays rewrite the object with a newer ingested_at and nothing else changed."""
    s3 = FakeS3()
    handler(gd_event(), s3_client=s3)
    first = dict(s3.objects)
    handler(gd_event(), s3_client=s3)
    assert set(s3.objects) == set(first) and len(s3.objects) == 1 and s3.puts == 2
    key = next(iter(first))
    assert _without_ingested_at(s3.objects[key]) == _without_ingested_at(first[key])


def test_partial_failure_stores_the_rest_then_raises_for_the_dlq():
    event = sh_event()
    keys = [object_key(f"aws:securityhub:803872867382:us-east-1:{f['Id']}") for f in event["detail"]["findings"]]
    s3 = FakeS3(fail_keys=[keys[1]])
    with pytest.raises(IngestionError):
        handler(event, s3_client=s3)
    assert set(s3.objects) == {keys[0], keys[2]}  # one failure never blocks the others


def test_dlq_replay_after_fix_completes_without_duplicates():
    event = sh_event()
    s3 = FakeS3()
    broken = FakeS3(fail_keys=[object_key(f"aws:securityhub:803872867382:us-east-1:{event['detail']['findings'][0]['Id']}")])
    with pytest.raises(IngestionError):
        handler(event, s3_client=broken)
    handler(event, s3_client=s3)            # replay the original event from the DLQ
    handler(event, s3_client=s3)            # replay twice: still no duplicates
    assert len(s3.objects) == 3


def test_unroutable_and_malformed_events_raise_instead_of_vanishing():
    s3 = FakeS3()
    for bad in ({"source": "aws.ec2", "detail-type": "x"}, {"source": "aws.guardduty", "detail-type": "GuardDuty Finding", "detail": {}}):
        with pytest.raises(Exception):
            handler(bad, s3_client=s3)
    assert not s3.objects


def test_missing_bucket_config_fails_loudly(monkeypatch):
    monkeypatch.delenv("FINDINGS_BUCKET")
    with pytest.raises(IngestionError):
        handler(gd_event(), s3_client=FakeS3())


def test_pipeline_rebuilds_identical_results_from_object_store(tmp_path):
    """Lose all derived state; rebuild from the stored findings and get the same answer."""
    s3 = FakeS3()
    handler(gd_event(0), s3_client=s3)
    handler(gd_event(1), s3_client=s3)
    handler(sh_event(), s3_client=s3)

    src = tmp_path / "findings"  # same path both times: pipeline output records the source file path

    def restore():
        if src.exists():
            shutil.rmtree(src)
        src.mkdir()
        for key, body in sorted(s3.objects.items()):  # S3 objects are .jsonl, one finding each
            (src / key.split("/")[-1]).write_bytes(body)
            assert json.loads(body)["finding_id"]

    restore()
    write(run([src]), tmp_path / "before")
    shutil.rmtree(src)                       # lose all derived/local state
    restore()                                # rebuild purely from the object store
    write(run([src]), tmp_path / "after")
    for fname in ("findings.merged.jsonl", "incidents.json", "summary.json"):
        assert (tmp_path / "before" / fname).read_bytes() == (tmp_path / "after" / fname).read_bytes(), fname
