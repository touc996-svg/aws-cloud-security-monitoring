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
    """Return the GuardDuty finding from a bare finding or EventBridge event."""
    if not isinstance(payload, dict):
        raise NormalizationError("payload must be a JSON object")
    if payload.get("detail-type") == "GuardDuty Finding":
        detail = payload.get("detail")
        if not isinstance(detail, dict):
            raise NormalizationError("EventBridge event has no 'detail' object")
        return detail
    return payload


def _resource_id(finding: dict[str, Any]) -> str:
    resource = finding.get("resource") or {}
    rtype = resource.get("resourceType", "")
    if rtype == "Instance":
        value = (resource.get("instanceDetails") or {}).get("instanceId")
    elif rtype == "AccessKey":
        value = (resource.get("accessKeyDetails") or {}).get("accessKeyId")
    elif rtype == "S3Bucket":
        buckets = resource.get("s3BucketDetails") or []
        value = buckets[0].get("arn") if buckets else None
    else:
        value = None
    return value or finding.get("arn") or rtype or "unknown"


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
        return data["Findings"]  # `aws guardduty get-findings` output
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
