"""Normalize Amazon GuardDuty findings into the AEGIS-X finding schema.

Pure functions, standard library only, no AWS calls. The original provider
payload is preserved unmodified in ``raw_payload`` and the native finding ID
and severity are kept alongside the normalized fields.

Accepts either a bare GuardDuty finding or an EventBridge envelope
(``detail-type`` == "GuardDuty Finding", finding under ``detail``).
"""

from __future__ import annotations

import copy
import json
import sys
from datetime import datetime, timezone
from typing import Any, Iterable

PROVIDER = "guardduty"
CLOUD = "aws"

_REQUIRED = ("id", "accountId", "region", "type", "severity", "title")


class NormalizationError(ValueError):
    """Raised when a payload is not a usable GuardDuty finding."""


def severity_label(score: float) -> str:
    """Map GuardDuty's numeric severity (0-10) to AEGIS-X labels.

    GuardDuty bands: Low 1.0-3.9, Medium 4.0-6.9, High 7.0-8.9, Critical 9.0-10.
    """
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 1.0:
        return "low"
    return "informational"


def extract_finding(payload: dict[str, Any]) -> dict[str, Any]:
    """Return the finding (keys folded to camelCase) from a bare finding or EventBridge event."""
    if not isinstance(payload, dict):
        raise NormalizationError("payload must be a JSON object")
    if payload.get("detail-type") == "GuardDuty Finding":
        detail = payload.get("detail")
        if not isinstance(detail, dict):
            raise NormalizationError("EventBridge event has no 'detail' object")
        return fold_keys(detail)
    return fold_keys(payload)


def fold_keys(value: Any) -> Any:
    """Return a copy with every dict key's first letter lower-cased.

    ``aws guardduty get-findings`` returns PascalCase keys (``AccountId``)
    while EventBridge events use camelCase (``accountId``). Folding lets one
    code path read both. Used on a working copy only; ``raw_payload`` is never
    folded.
    """
    if isinstance(value, dict):
        return {(k[:1].lower() + k[1:] if isinstance(k, str) else k): fold_keys(v) for k, v in value.items()}
    if isinstance(value, list):
        return [fold_keys(v) for v in value]
    return value


# resourceType -> ordered (detail key, field) candidates; lists use their first item.
_RESOURCE_ID_PATHS: dict[str, tuple[tuple[str, str], ...]] = {
    "Instance": (("instanceDetails", "instanceId"),),
    "AccessKey": (("accessKeyDetails", "accessKeyId"),),
    "S3Bucket": (("s3BucketDetails", "arn"),),
    "EKSCluster": (("eksClusterDetails", "arn"),),
    "ECSCluster": (("ecsClusterDetails", "arn"),),
    "KubernetesCluster": (("eksClusterDetails", "arn"), ("instanceDetails", "instanceId")),
    "Container": (("containerDetails", "id"), ("instanceDetails", "instanceId")),
    "RDSDBInstance": (("rdsDbInstanceDetails", "dbInstanceArn"),),
    "RDSLimitlessDB": (("rdsLimitlessDbDetails", "dbShardGroupArn"),),
}


def _first(detail: Any) -> dict[str, Any]:
    if isinstance(detail, list):
        detail = detail[0] if detail else {}
    return detail if isinstance(detail, dict) else {}


def _resource_id(finding: dict[str, Any]) -> str:
    resource = finding.get("resource") or {}
    rtype = resource.get("resourceType", "")
    for key, field in _RESOURCE_ID_PATHS.get(rtype, ()):
        value = _first(resource.get(key)).get(field)
        if value:
            return str(value)
    return finding.get("arn") or rtype or "unknown"


def _status(finding: dict[str, Any]) -> str:
    archived = (finding.get("service") or {}).get("archived")
    if archived is True:
        return "archived"
    if archived is False:
        return "active"
    return "unknown"


def normalize(payload: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
    """Convert one GuardDuty finding (or EventBridge event) to the AEGIS-X schema."""
    raw = copy.deepcopy(payload)
    finding = extract_finding(payload)

    missing = [k for k in _REQUIRED if finding.get(k) in (None, "")]
    if missing:
        raise NormalizationError(f"missing required GuardDuty fields: {', '.join(missing)}")

    try:
        score = float(finding["severity"])
    except (TypeError, ValueError) as exc:
        raise NormalizationError(f"invalid severity: {finding['severity']!r}") from exc

    service = finding.get("service") or {}
    first_seen = service.get("eventFirstSeen") or finding.get("createdAt")
    last_seen = service.get("eventLastSeen") or finding.get("updatedAt") or first_seen
    if not first_seen:
        raise NormalizationError("finding has no timestamp (eventFirstSeen/createdAt)")

    ingested = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)

    evidence = []
    if finding.get("arn"):
        evidence.append({"type": "provider_finding", "ref": finding["arn"]})

    return {
        "finding_id": f"{CLOUD}:{PROVIDER}:{finding['accountId']}:{finding['region']}:{finding['id']}",
        "cloud": CLOUD,
        "provider": PROVIDER,
        "native_id": finding["id"],
        "native_severity": finding["severity"],
        "severity": severity_label(score),
        "finding_type": finding["type"],
        "title": finding["title"],
        "description": finding.get("description", ""),
        "resource_id": _resource_id(finding),
        "account_id": finding["accountId"],
        "region": finding["region"],
        "observed_at": first_seen,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "ingested_at": ingested.isoformat().replace("+00:00", "Z"),
        "status": _status(finding),
        "mitre_techniques": [],
        "evidence": evidence,
        "raw_payload": raw,
    }


def normalize_many(payloads: Iterable[dict[str, Any]], *, now: datetime | None = None) -> list[dict[str, Any]]:
    return [normalize(p, now=now) for p in payloads]


def _load(stream) -> list[dict[str, Any]]:
    data = json.load(stream)
    if isinstance(data, dict) and isinstance(data.get("Findings"), list):
        return data["Findings"]  # `aws guardduty get-findings` output (PascalCase)
    return data if isinstance(data, list) else [data]


def main(argv: list[str]) -> int:
    """CLI: python guardduty_normalizer.py [file|-]  -> JSON Lines on stdout."""
    path = argv[1] if len(argv) > 1 else "-"
    stream = sys.stdin if path == "-" else open(path, encoding="utf-8")
    try:
        for finding in _load(stream):
            print(json.dumps(normalize(finding), separators=(",", ":")))
    except NormalizationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        if stream is not sys.stdin:
            stream.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
