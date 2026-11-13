"""Normalize Microsoft Defender for Cloud alerts and assessments into the AEGIS-X schema.

Pure functions, standard library only, no Azure calls. The original payload is
preserved unmodified in ``raw_payload``; native id and severity come from the
original payload.

Accepted shapes (ARM/REST or Azure Resource Graph rows, case-insensitive keys):
  * ``Microsoft.Security/locations/alerts``  -> security alerts
  * ``Microsoft.Security/assessments``       -> recommendations (fetch with ``$expand=metadata``
    so ``metadata.severity`` is present; Azure only exposes assessment severity there)

MITRE data is copied only from what Azure provides: ``techniques``/``subTechniques``
and ``intent``. ``intent`` is kept as a tactic only when it is itself a MITRE ATT&CK
tactic name; Microsoft-specific values (Unknown, PreAttack, Probing, Exploitation)
are not mapped. Assessments carry no MITRE data.
"""

from __future__ import annotations

import copy
import hashlib
import re
import sys
from datetime import datetime
from typing import Any, Iterable

try:
    from ._common import (CLOUD, NormalizationError, as_list, ci, flatten, ingested_at, make_id,
                          merge_unique, parse_ts, pick, run_cli, severity_label, subscription_from)
except ImportError:  # pragma: no cover
    from _common import (CLOUD, NormalizationError, as_list, ci, flatten, ingested_at, make_id,  # type: ignore
                         merge_unique, parse_ts, pick, run_cli, severity_label, subscription_from)

PROVIDER = "defender-for-cloud"
__all__ = ["NormalizationError", "normalize", "normalize_many", "severity_label", "main"]

# Azure's `intent` enum values (no spaces) that are MITRE ATT&CK enterprise tactic names.
_MITRE_TACTICS = {
    "InitialAccess", "Execution", "Persistence", "PrivilegeEscalation", "DefenseEvasion",
    "CredentialAccess", "Discovery", "LateralMovement", "Collection", "CommandAndControl",
    "Exfiltration", "Impact", "ResourceDevelopment", "Reconnaissance",
}
_LOCATION_RE = re.compile(r"/locations/([^/]+)/alerts/", re.IGNORECASE)


def _alert_status(value: Any) -> str:
    s = str(value or "").replace(" ", "").lower()
    if s in {"resolved", "dismissed"}:
        return "archived"
    if s in {"active", "inprogress", "new"}:
        return "active"
    return "unknown"


def _assessment_status(code: Any) -> str:
    s = str(code or "").lower()
    if s == "unhealthy":
        return "active"
    if s == "healthy":
        return "archived"  # control passes; kept for completeness, not an open finding
    return "unknown"  # NotApplicable or absent


def _is_assessment(top: dict, f: dict) -> bool:
    id_ = str(top.get("id") or "").lower()
    return ("/assessments/" in id_ or str(top.get("type") or "").lower().endswith("/assessments")
            or "resourcedetails" in f)


def _finish(top, f, *, native_id, finding_id_native, sev, title, ftype, first, last, resource_id,
            account, region, status, tactics, techniques, evidence, raw, now):
    tenant = pick(f, "tenantid")
    account = account or (str(tenant) if tenant else None)
    if not account:
        raise NormalizationError("no subscription found in the resource ID or subscriptionId")
    out: dict[str, Any] = {
        "finding_id": make_id(PROVIDER, account, region, finding_id_native),
        "cloud": CLOUD,
        "provider": PROVIDER,
        "native_id": native_id,
        "native_severity": sev,
        "severity": severity_label(sev),
        "finding_type": ftype,
        "title": title,
        "description": str(pick(f, "description") or ""),
        "resource_id": resource_id,
        "account_id": account,
        "region": region,
        "observed_at": first,
        "first_seen": first,
        "last_seen": last,
        "ingested_at": ingested_at(now),
        "status": status,
        "mitre_techniques": techniques,
        "mitre_tactics": tactics,
        "evidence": evidence,
        "raw_payload": raw,
    }
    sub = subscription_from(resource_id, top.get("id"), pick(f, "subscriptionid"))
    if sub:
        out["subscription_id"] = sub
    if tenant:
        out["tenant_id"] = str(tenant)
    return out


def _alert(top, f, raw, now):
    arm_id = top.get("id") if isinstance(top.get("id"), str) else None
    native_id = pick(f, "systemalertid", "name")
    title = pick(f, "alertdisplayname", "displayname")
    sev = pick(f, "severity")
    missing = [n for n, v in (("systemAlertId/name", native_id), ("alertDisplayName", title), ("severity", sev)) if not v]
    if missing:
        raise NormalizationError(f"missing required Defender alert fields: {', '.join(missing)}")
    first = parse_ts(pick(f, "starttimeutc", "timegeneratedutc"), "startTimeUtc/timeGeneratedUtc")
    last = parse_ts(pick(f, "endtimeutc", "processingendtimeutc") or first, "endTimeUtc")

    azure_resources = []
    for ident in f.get("resourceidentifiers") or []:
        ident = ci(ident)
        if str(ident.get("type", "")).lower() == "azureresource" and ident.get("azureresourceid"):
            azure_resources.append(str(ident["azureresourceid"]))
    resource_id = azure_resources[0] if azure_resources else (arm_id or "unknown")

    m = _LOCATION_RE.search(arm_id or "")
    region = (m.group(1) if m else str(pick(top, "location") or "global")).lower()
    account = subscription_from(resource_id, arm_id, pick(f, "subscriptionid"))

    intent = [t for t in as_list(pick(f, "intent")) if t in _MITRE_TACTICS]
    techniques = merge_unique(as_list(pick(f, "techniques")), as_list(pick(f, "subtechniques")))

    evidence = []
    if arm_id:
        evidence.append({"type": "provider_finding", "ref": arm_id})
    uri = pick(f, "alerturi")
    if uri:
        evidence.append({"type": "portal_link", "ref": str(uri)})
    evidence += [{"type": "affected_resource", "ref": r} for r in azure_resources]

    return _finish(top, f, native_id=str(native_id), finding_id_native=str(native_id), sev=sev,
                   title=str(title), ftype=str(pick(f, "alerttype") or "SecurityAlert"), first=first,
                   last=last, resource_id=resource_id, account=account, region=region,
                   status=_alert_status(pick(f, "status")), tactics=intent, techniques=techniques,
                   evidence=evidence, raw=raw, now=now)


def _assessment(top, f, raw, now):
    arm_id = top.get("id") if isinstance(top.get("id"), str) else None
    native_id = pick(f, "name")
    title = pick(f, "displayname")
    meta = ci(f.get("metadata"))
    sev = pick(meta, "severity")
    missing = [n for n, v in (("name", native_id), ("displayName", title),
                              ("metadata.severity (use $expand=metadata)", sev)) if not v]
    if missing:
        raise NormalizationError(f"missing required Defender assessment fields: {', '.join(missing)}")
    details = ci(f.get("resourcedetails"))
    resource_id = pick(details, "id", "resourceid")
    if not resource_id and arm_id and "/providers/microsoft.security/assessments/" in arm_id.lower():
        resource_id = arm_id[: arm_id.lower().index("/providers/microsoft.security/assessments/")]
    if not resource_id:
        raise NormalizationError("assessment has no resource (resourceDetails.Id)")
    resource_id = str(resource_id)

    status = ci(f.get("status"))
    first = parse_ts(pick(status, "statuschangedate", "firstevaluationdate"),
                     "status.statusChangeDate/firstEvaluationDate")
    last = parse_ts(pick(status, "statuschangedate", "firstevaluationdate"), "status.statusChangeDate")
    account = subscription_from(arm_id, resource_id, pick(f, "subscriptionid"))
    region = str(pick(top, "location") or "global").lower()
    # The assessment `name` is the recommendation definition GUID, shared by every resource,
    # so the finding_id adds a stable hash of the (case-insensitive) assessed resource.
    digest = hashlib.sha256(resource_id.lower().encode()).hexdigest()[:16]
    kind = pick(meta, "assessmenttype")

    evidence = []
    if arm_id:
        evidence.append({"type": "provider_finding", "ref": arm_id})
    links = ci(f.get("links"))
    if links.get("azureportaluri"):
        evidence.append({"type": "portal_link", "ref": str(links["azureportaluri"])})
    evidence.append({"type": "affected_resource", "ref": resource_id})

    if not pick(f, "description") and pick(meta, "description"):
        f = dict(f, description=pick(meta, "description"))
    return _finish(top, f, native_id=str(native_id), finding_id_native=f"assessment-{native_id}-{digest}",
                   sev=sev, title=str(title), ftype=f"SecurityAssessment:{kind}" if kind else "SecurityAssessment",
                   first=first, last=last, resource_id=resource_id, account=account, region=region,
                   status=_assessment_status(pick(status, "code")), tactics=[], techniques=[],
                   evidence=evidence, raw=raw, now=now)


def normalize(payload: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
    """Convert one Defender for Cloud alert or assessment to the AEGIS-X schema."""
    raw = copy.deepcopy(payload)
    top, f = flatten(payload)
    if _is_assessment(top, f):
        return _assessment(top, f, raw, now)
    id_ = str(top.get("id") or "").lower()
    if "/alerts/" in id_ or any(k in f for k in ("alerttype", "alertdisplayname", "systemalertid")):
        return _alert(top, f, raw, now)
    raise NormalizationError("payload is neither a Defender for Cloud alert nor an assessment")


def normalize_many(payloads: Iterable[dict[str, Any]], *, now: datetime | None = None) -> list[dict[str, Any]]:
    return [normalize(p, now=now) for p in payloads]


def main(argv: list[str]) -> int:
    return run_cli(normalize, argv)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
