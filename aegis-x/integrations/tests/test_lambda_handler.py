import copy
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aws import lambda_handler as lh  # noqa: E402
from aws.guardduty_normalizer import NormalizationError  # noqa: E402

BUCKET = "aegis-x-findings-test"


def gd_detail(fid="f" * 32, **over):
    detail = {
        "schemaVersion": "2.0",
        "accountId": "111122223333",
        "region": "us-east-1",
        "id": fid,
        "arn": f"arn:aws:guardduty:us-east-1:111122223333:detector/d/finding/{fid}",
        "type": "Recon:EC2/PortProbeUnprotectedPort",
        "resource": {"resourceType": "Instance", "instanceDetails": {"instanceId": "i-0abc"}},
        "severity": 5.0,
        "title": "Port probe",
        "description": "d",
        "createdAt": "2026-11-12T20:00:00.000Z",
        "updatedAt": "2026-11-12T20:30:00.000Z",
        "service": {"archived": False},
    }
    detail.update(over)
    return detail


def gd_event(**kw):
    return {"source": "aws.guardduty", "detail-type": "GuardDuty Finding", "detail": gd_detail(**kw)}


class StubS3:
    def __init__(self, fail_keys=()):
        self.objects = {}
        self.calls = []
        self.fail_keys = set(fail_keys)

    def put_object(self, **kwargs):
        self.calls.append(kwargs)
        if any(k in kwargs["Key"] for k in self.fail_keys):
            raise RuntimeError("AccessDenied")
        self.objects[(kwargs["Bucket"], kwargs["Key"])] = kwargs["Body"]


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("FINDINGS_BUCKET", BUCKET)


def test_guardduty_event_written_as_jsonl():
    s3 = StubS3()
    result = lh.handler(gd_event(), None, s3_client=s3)
    assert result["stored"] == 1
    (bucket, key), body = next(iter(s3.objects.items()))
    assert bucket == BUCKET
    assert key == result["keys"][0]
    assert key.startswith("findings/") and key.endswith(".jsonl")
    assert body.endswith(b"\n") and body.count(b"\n") == 1
    record = json.loads(body)
    assert record["provider"] == "guardduty"
    assert record["finding_id"].endswith("f" * 32)
    assert s3.calls[0]["ContentType"] == "application/x-ndjson"


def test_idempotent_same_key_on_redelivery():
    s3 = StubS3()
    lh.handler(gd_event(), None, s3_client=s3)
    lh.handler(gd_event(), None, s3_client=s3)
    assert len(s3.calls) == 2
    assert len(s3.objects) == 1
    assert s3.calls[0]["Key"] == s3.calls[1]["Key"]


def test_object_key_encodes_separators():
    key = lh.object_key("aws:securityhub:1:us-east-1:arn:aws:x/y/z")
    assert key.count("/") == 1  # only the prefix separator
    assert key == "findings/aws%3Asecurityhub%3A1%3Aus-east-1%3Aarn%3Aaws%3Ax%2Fy%2Fz.jsonl"


def test_unknown_event_raises_not_swallowed():
    with pytest.raises(NormalizationError, match="no normalizer registered"):
        lh.handler({"source": "aws.ec2", "detail-type": "EC2 Instance State-change Notification"}, None, s3_client=StubS3())


def test_non_dict_event_raises():
    with pytest.raises(NormalizationError):
        lh.handler("nope", None, s3_client=StubS3())  # type: ignore[arg-type]


def test_invalid_finding_raises_and_writes_nothing():
    s3 = StubS3()
    bad = gd_event()
    del bad["detail"]["title"]
    with pytest.raises(NormalizationError, match="title"):
        lh.handler(bad, None, s3_client=s3)
    assert s3.calls == []


def test_missing_bucket_env_raises(monkeypatch):
    monkeypatch.delenv("FINDINGS_BUCKET")
    with pytest.raises(lh.IngestionError, match="FINDINGS_BUCKET"):
        lh.handler(gd_event(), None, s3_client=StubS3())


def test_s3_failure_raises_ingestion_error():
    with pytest.raises(lh.IngestionError, match="AccessDenied"):
        lh.handler(gd_event(), None, s3_client=StubS3(fail_keys=["findings/"]))


SH_FIXTURE = ROOT / "tests" / "fixtures" / "securityhub_findings.json"


def sh_event(n=2):
    """EventBridge event carrying n real ASFF findings (fixture, ids made unique)."""
    base = json.loads(SH_FIXTURE.read_text())["Findings"][0]
    findings = []
    for i in range(n):
        f = copy.deepcopy(base)
        f["Id"] = f"{base['Id']}-copy{i}"
        findings.append(f)
    return {
        "source": "aws.securityhub",
        "detail-type": "Security Hub Findings - Imported",
        "detail": {"findings": findings},
    }


def test_securityhub_event_with_multiple_findings():
    s3 = StubS3()
    result = lh.handler(sh_event(2), None, s3_client=s3)
    assert result["stored"] == 2
    assert len(s3.objects) == 2
    for body in s3.objects.values():
        assert json.loads(body)["provider"] == "securityhub"


def test_partial_failure_attempts_all_then_raises():
    s3 = StubS3(fail_keys=["copy1"])
    with pytest.raises(lh.IngestionError, match="1 of 3"):
        lh.handler(sh_event(3), None, s3_client=s3)
    assert len(s3.calls) == 3
    assert len(s3.objects) == 2


def test_securityhub_invalid_asff_raises():
    event = sh_event(1)
    event["detail"]["findings"] = [{"Id": "x"}]
    with pytest.raises(NormalizationError, match="missing required"):
        lh.handler(event, None, s3_client=StubS3())


def test_securityhub_unavailable_degrades_to_error(monkeypatch):
    import aws

    # `from . import x` checks the package attribute before sys.modules, so remove both.
    monkeypatch.delattr(aws, "securityhub_normalizer", raising=False)
    monkeypatch.setitem(sys.modules, "aws.securityhub_normalizer", None)  # forces ImportError
    monkeypatch.setitem(sys.modules, "securityhub_normalizer", None)
    with pytest.raises(NormalizationError, match="not packaged"):
        lh.handler(sh_event(1), None, s3_client=StubS3())


def test_registry_routes():
    assert ("aws.guardduty", "GuardDuty Finding") in lh.REGISTRY
    assert ("aws.securityhub", "Security Hub Findings - Imported") in lh.REGISTRY
