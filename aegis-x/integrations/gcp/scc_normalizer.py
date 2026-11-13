"""Normalize Google Cloud Security Command Center (SCC) findings into the AEGIS-X schema.

Pure functions, standard library only, no GCP calls. The original provider
payload is preserved unmodified in ``raw_payload``. Native values (finding
name, severity, state) are read from the original payload, never from a
key-folded copy; camelCase and snake_case keys are both accepted.

Accepted inputs:
  * a bare SCC ``Finding``;
  * a ``gcloud scc findings list --format=json`` item / REST ``ListFindingsResult``
    (``{"finding": {...}, "resource": {...}}``);
  * a Pub/Sub ``NotificationMessage`` (``{"notificationConfigName", "finding", "resource"}``);
  * a Pub/Sub push envelope whose ``message.data`` is the base64 NotificationMessage.

MITRE: only ``mitreAttack.primaryTechniques`` / ``additionalTechniques`` as SCC
supplies them are copied (verbatim, deduplicated). SCC may return enum names
rather than ``Txxxx`` IDs; no mapping is invented. ``attackExposure`` carries a
risk score, not techniques, so it contributes nothing to ``mitre_techniques``.
"""

from __future__ import annotations

import base64
import binascii
import copy
import json
import re
import sys
from datetime import datetime, timezone
from typing import Any, Iterable

PROVIDER = "security-command-center"
CLOUD = "gcp"

_SEVERITY = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "SEVERITY_UNSPECIFIED": "informational",
}
_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")
_NAME = re.compile(r"^(organizations|folders|projects)/([^/]+)/sources/([^/]+)/(?:locations/[^/]+/)?findings/([^/]+)$")


class NormalizationError(ValueError):
    """Raised when a payload is not a usable SCC finding."""


def _snake(key: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", key).lower()


def _get(obj: Any, key: str, default: Any = None) -> Any:
    """Read ``key`` (camelCase) or its snake_case twin from a dict."""
    if not isinstance(obj, dict):
        return default
    if key in obj:
        return obj[key]
    return obj.get(_snake(key), default)


def severity_label(native: Any) -> str:
    """Map the SCC severity enum to AEGIS-X labels (absent == SEVERITY_UNSPECIFIED)."""
    if native in (None, ""):
        return "informational"
    label = _SEVERITY.get(str(native).upper())
    if label is None:
        raise NormalizationError(f"unknown SCC severity: {native!r}")
    return label


def _status(finding: dict[str, Any]) -> str:
    """ACTIVE -> active; INACTIVE or MUTED (state or the separate mute field) -> archived."""
    state = str(_get(finding, "state") or "").upper()
    if state in ("INACTIVE", "MUTED") or str(_get(finding, "mute") or "").upper() == "MUTED":
        return "archived"
    if state == "ACTIVE":
        return "active"
    return "unknown"


def _unwrap(payload: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return (finding, resource) as found in the original payload (no copies, no key changes)."""
    if not isinstance(payload, dict):
        raise NormalizationError("payload must be a JSON object")
    message = payload.get("message")
    if isinstance(message, dict) and isinstance(message.get("data"), str):
        try:
            decoded = json.loads(base64.b64decode(message["data"], validate=True))
        except (binascii.Error, ValueError) as exc:
            raise NormalizationError("Pub/Sub message.data is not base64-encoded JSON") from exc
        return _unwrap(decoded)
    if "finding" in payload:
        finding = payload["finding"]
        if not isinstance(finding, dict):
            raise NormalizationError("'finding' must be an object")
        resource = _get(payload, "resource")
        return finding, resource if isinstance(resource, dict) else {}
    resource = payload.get("resource")
    return payload, resource if isinstance(resource, dict) else {}


def _parse_name(name: str) -> tuple[str, str, str, str]:
    m = _NAME.match(name)
    if not m:
        raise NormalizationError(f"unrecognized finding name: {name!r}")
    return m.group(1), m.group(2), m.group(3), m.group(4)


def _account_id(finding: dict[str, Any], resource: dict[str, Any], name_parts: tuple[str, str, str, str]) -> str:
    # SCC's projectDisplayName is the project ID.
    value = _get(resource, "projectDisplayName")
    if value:
        return str(value)
    m = re.search(r"/projects/([^/]+)", str(_get(finding, "resourceName") or ""))
    if m:
        return m.group(1)
    if name_parts[0] == "projects":
        return name_parts[1]
    m = re.search(r"/projects/([^/]+)$", str(_get(resource, "project") or ""))
    if m:
        return m.group(1)
    return name_parts[1]  # organization/folder ID as last resort


def _region(resource_name: str) -> str:
    m = re.search(r"/(?:locations|regions)/([^/]+)", resource_name)
    if m:
        return m.group(1)
    m = re.search(r"/zones/([^/]+)", resource_name)
    if m:
        zone = m.group(1)
        return re.sub(r"-[a-z]$", "", zone)
    return "global"


def _techniques(finding: dict[str, Any]) -> list[str]:
    mitre = _get(finding, "mitreAttack")
    out: list[str] = []
    for key in ("primaryTechniques", "additionalTechniques"):
        for tech in _get(mitre, key) or []:
            if isinstance(tech, str) and tech and tech not in out:
                out.append(tech)
    return out


def _timestamp(value: Any, label: str) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str) or not _TS.match(value):
        raise NormalizationError(f"invalid {label}: {value!r}")
    return value


def normalize(payload: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
    """Convert one SCC finding (bare, list result, notification or push envelope) to AEGIS-X."""
    raw = copy.deepcopy(payload)
    finding, resource = _unwrap(payload)

    name = _get(finding, "name")
    category = _get(finding, "category")
    missing = [k for k, v in (("name", name), ("category", category)) if not v]
    if missing:
        raise NormalizationError(f"missing required SCC fields: {', '.join(missing)}")
    name_parts = _parse_name(str(name))

    event_time = _timestamp(_get(finding, "eventTime"), "eventTime")
    create_time = _timestamp(_get(finding, "createTime"), "createTime")
    if not (event_time or create_time):
        raise NormalizationError("finding has no timestamp (eventTime/createTime)")
    first_seen = create_time or event_time
    last_seen = event_time or create_time
    observed_at = event_time or create_time

    resource_name = str(_get(finding, "resourceName") or _get(resource, "name") or "")
    native_severity = _get(finding, "severity")
    ingested = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    account = _account_id(finding, resource, name_parts)
    region = _region(resource_name)
    _, _, source_id, finding_id = name_parts

    evidence = [{"type": "provider_finding", "ref": str(_get(finding, "canonicalName") or name)}]
    if _get(finding, "externalUri"):
        evidence.append({"type": "external_uri", "ref": str(_get(finding, "externalUri"))})

    out: dict[str, Any] = {
        "finding_id": f"{CLOUD}:{PROVIDER}:{account}:{region}:{source_id}/{finding_id}",
        "cloud": CLOUD,
        "provider": PROVIDER,
        "native_id": name,
        "severity": severity_label(native_severity),
        "finding_type": category,
        "title": category,
        "description": _get(finding, "description") or "",
        "resource_id": resource_name or "unknown",
        "account_id": account,
        "region": region,
        "observed_at": observed_at,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "ingested_at": ingested.isoformat().replace("+00:00", "Z"),
        "status": _status(finding),
        "mitre_techniques": _techniques(finding),
        "evidence": evidence,
        "raw_payload": raw,
    }
    if native_severity is not None:
        out["native_severity"] = native_severity
    if _get(finding, "state") is not None:
        out["native_state"] = _get(finding, "state")
    return out


def normalize_many(payloads: Iterable[dict[str, Any]], *, now: datetime | None = None) -> list[dict[str, Any]]:
    return [normalize(p, now=now) for p in payloads]


def _load(stream) -> list[dict[str, Any]]:
    data = json.load(stream)
    if isinstance(data, dict):
        for key in ("listFindingsResults", "list_findings_results"):
            if isinstance(data.get(key), list):
                return data[key]  # REST response
    return data if isinstance(data, list) else [data]


def main(argv: list[str]) -> int:
    """CLI: python scc_normalizer.py [file|-]  -> JSON Lines on stdout."""
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
