"""EventBridge -> Lambda entry point for the AEGIS-X AWS ingestion path.

Dispatches on the event ``source`` / ``detail-type`` to a normalizer registry,
then writes each normalized finding as one JSON Lines object to S3, keyed by
``finding_id`` so redeliveries and retries overwrite rather than duplicate.

Failures are never swallowed: every finding is attempted, then a single
``IngestionError`` is raised so Lambda's async retry and the SQS dead-letter
queue receive the original event.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Callable
from urllib.parse import quote

try:  # package import (tests, Lambda: handler is aws.lambda_handler.handler)
    from . import guardduty_normalizer
    from .guardduty_normalizer import NormalizationError, fold_keys
except ImportError:  # pragma: no cover - run as a loose script
    import guardduty_normalizer  # type: ignore
    from guardduty_normalizer import NormalizationError, fold_keys  # type: ignore

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

KEY_PREFIX = "findings/"

Normalizer = Callable[[dict[str, Any]], list[dict[str, Any]]]


class IngestionError(RuntimeError):
    """One or more findings in an event could not be normalized or stored."""


def _guardduty(payload: dict[str, Any]) -> list[dict[str, Any]]:
    return [guardduty_normalizer.normalize(payload)]


def _securityhub(payload: dict[str, Any]) -> list[dict[str, Any]]:
    # securityhub_normalizer ships in a separate PR; degrade to a routed error
    # (event goes to the DLQ) rather than failing at import time for GuardDuty.
    try:
        try:
            from . import securityhub_normalizer
        except ImportError:
            import securityhub_normalizer  # type: ignore
    except ImportError as exc:
        raise NormalizationError("securityhub_normalizer is not packaged with this function") from exc
    # An EventBridge event can carry several findings, so use normalize_all.
    return securityhub_normalizer.normalize_all(payload)


# (event source, detail-type) -> normalizer returning a list of findings.
REGISTRY: dict[tuple[str, str], Normalizer] = {
    ("aws.guardduty", "GuardDuty Finding"): _guardduty,
    ("aws.securityhub", "Security Hub Findings - Imported"): _securityhub,
}


def object_key(finding_id: str) -> str:
    """Deterministic S3 key; percent-encodes ARN separators so ids stay one path segment."""
    return f"{KEY_PREFIX}{quote(finding_id, safe='')}.jsonl"


def write_finding(client: Any, bucket: str, record: dict[str, Any]) -> str:
    """Store one record as a single JSON line. Re-writing the same id overwrites (idempotent)."""
    key = object_key(record["finding_id"])
    body = json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n"
    client.put_object(
        Bucket=bucket,
        Key=key,
        Body=body.encode("utf-8"),
        ContentType="application/x-ndjson",
    )
    return key


def normalize_event(event: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(event, dict):
        raise NormalizationError("event must be a JSON object")
    route = (event.get("source"), event.get("detail-type"))
    normalizer = REGISTRY.get(route)  # type: ignore[arg-type]
    if normalizer is None:
        raise NormalizationError(f"no normalizer registered for source/detail-type {route!r}")
    return normalizer(event)


def handler(event: dict[str, Any], context: Any = None, *, s3_client: Any = None) -> dict[str, Any]:
    bucket = os.environ.get("FINDINGS_BUCKET", "")
    if not bucket:
        raise IngestionError("FINDINGS_BUCKET is not set")

    records = normalize_event(event)  # NormalizationError propagates -> retry -> DLQ

    client = s3_client
    if client is None:
        import boto3  # available in the Lambda runtime; imported lazily for tests

        client = boto3.client("s3")

    written: list[str] = []
    failures: list[str] = []
    for record in records:
        try:
            written.append(write_finding(client, bucket, record))
        except Exception as exc:  # noqa: BLE001 - collected and re-raised below
            logger.error("failed to store finding %s: %s", record.get("finding_id"), exc)
            failures.append(f"{record.get('finding_id')}: {exc}")

    if failures:
        raise IngestionError(f"{len(failures)} of {len(records)} findings failed: {'; '.join(failures)}")

    logger.info("stored %d finding(s)", len(written))
    return {"stored": len(written), "keys": written}


__all__ = ["REGISTRY", "IngestionError", "NormalizationError", "fold_keys", "handler", "object_key", "write_finding"]
