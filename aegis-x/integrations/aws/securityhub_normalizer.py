"""Normalize AWS Security Hub (ASFF) findings into the AEGIS-X finding schema.

Pure functions, standard library only, no AWS calls. Accepts:
  * a single ASFF finding,
  * an EventBridge "Security Hub Findings - Imported" event (``detail.findings``),
  * the output of ``aws securityhub get-findings`` (``{"Findings": [...]}``).

The original payload is preserved unmodified in ``raw_payload``. Security Hub
aggregates GuardDuty (and other) findings, so for GuardDuty-sourced findings the
equivalent ``aws:guardduty:...`` id is listed in ``related_finding_ids`` so a
pipeline can deduplicate across the two sources.
"""

from __future__ import annotations

import copy
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:  # package import (tests, Lambda)
    from .guardduty_normalizer import NormalizationError, fold_keys
except ImportError:  # script execution: python aws/securityhub_normalizer.py
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from guardduty_normalizer import NormalizationError, fold_keys  # type: ignore

PROVIDER = "securityhub"
CLOUD = "aws"
EVENT_DETAIL_TYPE = "Security Hub Findings - Imported"

_REQUIRED = ("id", "awsAccountId", "title", "severity", "resources")
_SEVERITY = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFORMATIONAL": "informational",
}
_GD_FINDING_ARN = re.compile(r"^arn:[^:]+:guardduty:([^:]+):(\d+):detector/[^/]+/finding/([0-9a-fA-F]+)$")


def extract_findings(payload: Any) -> list[dict[str, Any]]:
    """Return raw ASFF findings from any supported input shape (not folded)."""
    if not isinstance(payload, dict):
        raise NormalizationError("payload must be a JSON object")
    if payload.get("detail-type") == EVENT_DETAIL_TYPE:
        detail = payload.get("detail")
        findings = detail.get("findings") if isinstance(detail, dict) else None
        if not isinstance(findings, list) or not findings:
            raise NormalizationError("EventBridge event has no detail.findings")
        return findings
    if isinstance(payload.get("Findings"), list):
        return payload["Findings"]
    return [payload]


def _severity(finding: dict[str, Any]) -> tuple[str, Any]:
    sev = finding.get("severity") or {}
    label = str(sev.get("label", "")).upper()
    if label in _SEVERITY:
        return _SEVERITY[label], sev
    normalized = sev.get("normalized")
    if isinstance(normalized, (int, float)) and not isinstance(normalized, bool):
        # ASFF Normalized is 0-100: INFORMATIONAL 0, LOW 1-39, MEDIUM 40-69, HIGH 70-89, CRITICAL 90-100
        n = float(normalized)
        if n >= 90:
            return "critical", sev
        if n >= 70:
            return "high", sev
        if n >= 40:
            return "medium", sev
        if n >= 1:
            return "low", sev
        return "informational", sev
    raise NormalizationError(f"finding has no usable severity label or normalized score: {sev!r}")


def _resource(finding: dict[str, Any]) -> dict[str, Any]:
    resources = finding.get("resources")
    if not isinstance(resources, list) or not resources or not isinstance(resources[0], dict):
        raise NormalizationError("finding has no resources")
    return resources[0]


def _related_ids(finding: dict[str, Any]) -> list[str]:
    match = _GD_FINDING_ARN.match(str(finding.get("id", "")))
    if match:
        region, account, native = match.groups()
        return [f"aws:guardduty:{account}:{region}:{native}"]
    return []


def _normalize_one(raw_finding: dict[str, Any], raw_payload: Any, now: datetime | None) -> dict[str, Any]:
    finding = fold_keys(raw_finding)
    missing = [k for k in _REQUIRED if finding.get(k) in (None, "", [])]
    if missing:
        raise NormalizationError(f"missing required Security Hub fields: {', '.join(missing)}")

    severity, _ = _severity(finding)
    # keep the provider's own value exactly as sent (not the key-folded copy)
    native_severity = raw_finding.get("Severity", raw_finding.get("severity"))
    resource = _resource(finding)
    account = finding["awsAccountId"]
    region = finding.get("region") or resource.get("region") or "unknown"

    first_seen = finding.get("firstObservedAt") or finding.get("createdAt")
    last_seen = finding.get("lastObservedAt") or finding.get("updatedAt") or first_seen
    if not first_seen:
        raise NormalizationError("finding has no timestamp (firstObservedAt/createdAt)")

    record_state = str(finding.get("recordState", "")).upper()
    status = {"ACTIVE": "active", "ARCHIVED": "archived"}.get(record_state, "unknown")

    evidence = [{"type": "provider_finding", "ref": finding["id"]}]
    remediation_url = ((finding.get("remediation") or {}).get("recommendation") or {}).get("url")
    if remediation_url:
        evidence.append({"type": "remediation_guidance", "ref": remediation_url})

    ingested = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    types = finding.get("types") or []

    out: dict[str, Any] = {
        "finding_id": f"{CLOUD}:{PROVIDER}:{account}:{region}:{finding['id']}",
        "cloud": CLOUD,
        "provider": PROVIDER,
        "native_id": finding["id"],
        "native_severity": native_severity,
        "severity": severity,
        "finding_type": types[0] if types else (finding.get("generatorId") or "unknown"),
        "finding_types": types,
        "title": finding["title"],
        "description": finding.get("description", ""),
        "resource_id": resource.get("id") or "unknown",
        "resource_type": resource.get("type", ""),
        "account_id": account,
        "region": region,
        "observed_at": first_seen,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "ingested_at": ingested.isoformat().replace("+00:00", "Z"),
        "status": status,
        "source_product": finding.get("productName") or "",
        "workflow_status": (finding.get("workflow") or {}).get("status", ""),
        "compliance_status": (finding.get("compliance") or {}).get("status", ""),
        "related_finding_ids": _related_ids(finding),
        "mitre_techniques": [],
        "evidence": evidence,
        "raw_payload": copy.deepcopy(raw_payload),
    }
    return out


def normalize_all(payload: Any, *, now: datetime | None = None) -> list[dict[str, Any]]:
    """Normalize every finding in a supported input.

    Each record's ``raw_payload`` is the single original ASFF finding it came
    from (an EventBridge envelope is not repeated per finding).
    """
    findings = extract_findings(payload)
    return [_normalize_one(f, f, now) for f in findings]


def normalize(payload: Any, *, now: datetime | None = None) -> dict[str, Any]:
    """Normalize exactly one finding (same contract as the GuardDuty normalizer).

    Raises NormalizationError if the input holds more than one finding; use
    ``normalize_all`` for EventBridge batches and ``get-findings`` output.
    """
    findings = extract_findings(payload)
    if len(findings) != 1:
        raise NormalizationError(f"expected one finding, got {len(findings)}; use normalize_all")
    return _normalize_one(findings[0], findings[0], now)


def main(argv: list[str]) -> int:
    """CLI: python securityhub_normalizer.py [file|-]  -> JSON Lines on stdout."""
    path = argv[1] if len(argv) > 1 else "-"
    stream = sys.stdin if path == "-" else open(path, encoding="utf-8")
    try:
        data = json.load(stream)
        items = data if isinstance(data, list) else [data]
        for item in items:
            for record in normalize_all(item):
                print(json.dumps(record, separators=(",", ":")))
    except NormalizationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        if stream is not sys.stdin:
            stream.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
