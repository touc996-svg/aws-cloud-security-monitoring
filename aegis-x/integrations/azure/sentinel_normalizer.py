"""Normalize Microsoft Sentinel incidents and alerts into the AEGIS-X finding schema.

Pure functions, standard library only, no Azure calls. The original payload is
preserved unmodified in ``raw_payload``; native id and severity come from the
original payload.

Accepted shapes (case-insensitive keys, so one code path reads all of them):
  * ARM/REST incident  (``Microsoft.SecurityInsights/incidents``, fields under ``properties``)
  * ARM/REST alert     (``kind: "SecurityAlert"`` entity)
  * Log Analytics ``SecurityIncident`` / ``SecurityAlert`` table rows

MITRE tactics/techniques are copied only from fields Azure supplies
(``AdditionalData.tactics/techniques`` on incidents; ``Tactics``/``Techniques``/
``SubTechniques`` on alerts). Nothing is inferred from alert names or types.
"""

from __future__ import annotations

import copy
import re
import sys
from datetime import datetime
from typing import Any, Iterable

try:  # package import (tests) or direct script execution
    from ._common import (CLOUD, NormalizationError, as_list, ci, flatten, ingested_at, make_id,
                          merge_unique, parse_ts, pick, run_cli, severity_label, subscription_from)
except ImportError:  # pragma: no cover
    from _common import (CLOUD, NormalizationError, as_list, ci, flatten, ingested_at, make_id,  # type: ignore
                         merge_unique, parse_ts, pick, run_cli, severity_label, subscription_from)

PROVIDER = "sentinel"
__all__ = ["NormalizationError", "normalize", "normalize_many", "severity_label", "main"]

_ARCHIVED = {"closed", "resolved", "dismissed"}
_ACTIVE = {"new", "active", "inprogress"}


def _status(value: Any) -> str:
    s = str(value or "").replace(" ", "").lower()
    if s in _ARCHIVED:
        return "archived"
    if s in _ACTIVE:
        return "active"
    return "unknown"


def _kind(top: dict, f: dict) -> str:
    id_ = str(top.get("id") or "").lower()
    if str(top.get("kind") or "").lower() == "securityalert" or "/alerts/" in id_ and "/incidents/" not in id_:
        return "alert"
    if "/incidents/" in id_ or "incidentname" in f or "incidentnumber" in f:
        return "incident"
    if any(k in f for k in ("systemalertid", "alertname", "alertdisplayname", "alertseverity")):
        return "alert"
    if "title" in f and "severity" in f:
        return "incident"
    raise NormalizationError("payload is neither a Sentinel incident nor a Sentinel alert")


def _arm_resource_id(top: dict) -> str | None:
    rid = top.get("id")
    return rid if isinstance(rid, str) and rid.startswith("/") else None


def _alert_resource_id(f: dict) -> str | None:
    rid = pick(f, "resourceid", "azureresourceid")
    if rid:
        return str(rid)
    for ident in f.get("resourceidentifiers") or []:
        ident = ci(ident)
        if str(ident.get("type", "")).lower() == "azureresource" and ident.get("azureresourceid"):
            return str(ident["azureresourceid"])
    return None


def _common(top, f, native_id, severity_native, title, first, last, resource_id, arm_id,
            subscription, status, ftype, tactics, techniques, evidence, raw, now):
    region = str(pick(top, "location") or pick(f, "location") or "global")
    tenant = pick(f, "tenantid")
    account = subscription or (str(tenant) if tenant else None)
    if not account:
        raise NormalizationError("no subscription or tenant found (need a resource ID, "
                                 "WorkspaceSubscriptionId, IncidentUrl or TenantId)")
    out: dict[str, Any] = {
        "finding_id": make_id(PROVIDER, account, region, native_id),
        "cloud": CLOUD,
        "provider": PROVIDER,
        "native_id": native_id,
        "native_severity": severity_native,
        "severity": severity_label(severity_native),
        "finding_type": ftype,
        "title": title,
        "description": str(pick(f, "description") or ""),
        "resource_id": resource_id or arm_id or "unknown",
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
    if subscription:
        out["subscription_id"] = subscription
    if tenant:
        out["tenant_id"] = str(tenant)
    return out


def _incident(top, f, raw, now):
    native_id = pick(f, "incidentname", "name")
    title = pick(f, "title")
    sev = pick(f, "severity")
    missing = [n for n, v in (("incident id (IncidentName/name)", native_id), ("Title", title), ("Severity", sev)) if not v]
    if missing:
        raise NormalizationError(f"missing required Sentinel incident fields: {', '.join(missing)}")
    extra = ci(f.get("additionaldata"))
    first = parse_ts(pick(f, "firstactivitytimeutc", "firstactivitytime", "createdtimeutc", "createdtime",
                          "timegenerated"), "FirstActivityTime/CreatedTime")
    last = parse_ts(pick(f, "lastactivitytimeutc", "lastactivitytime", "lastmodifiedtimeutc",
                         "lastmodifiedtime") or first, "LastActivityTime")
    arm_id = _arm_resource_id(top)
    url = pick(f, "incidenturl")
    subscription = subscription_from(arm_id, url)
    resource_id = None
    if not arm_id and isinstance(url, str):  # portal URL embeds the incident's ARM resource ID
        m = re.search(r"(/subscriptions/.+)$", url, re.IGNORECASE)
        resource_id = m.group(1) if m else None
    evidence = []
    if arm_id:
        evidence.append({"type": "provider_finding", "ref": arm_id})
    if url:
        evidence.append({"type": "portal_link", "ref": str(url)})
    evidence += [{"type": "related_alert", "ref": a} for a in as_list(pick(f, "alertids"))]
    return _common(top, f, str(native_id), sev, str(title), first, last, resource_id, arm_id, subscription,
                   _status(pick(f, "status")), "SecurityIncident",
                   as_list(extra.get("tactics")), as_list(extra.get("techniques")), evidence, raw, now)


def _alert(top, f, raw, now):
    native_id = pick(f, "systemalertid", "name", "vendororiginalid", "providerAlertId".lower())
    title = pick(f, "alertdisplayname", "displayname", "friendlyname", "alertname")
    sev = pick(f, "alertseverity", "severity")
    missing = [n for n, v in (("SystemAlertId", native_id), ("DisplayName/AlertName", title), ("AlertSeverity", sev)) if not v]
    if missing:
        raise NormalizationError(f"missing required Sentinel alert fields: {', '.join(missing)}")
    first = parse_ts(pick(f, "starttime", "starttimeutc", "timegenerated", "timegeneratedutc"),
                     "StartTime/TimeGenerated")
    last = parse_ts(pick(f, "endtime", "endtimeutc", "processingendtime") or first, "EndTime")
    arm_id = _arm_resource_id(top)
    resource_id = _alert_resource_id(f)
    subscription = subscription_from(resource_id, pick(f, "workspacesubscriptionid"), arm_id)
    evidence = []
    if arm_id:
        evidence.append({"type": "provider_finding", "ref": arm_id})
    link = pick(f, "alertlink")
    if link:
        evidence.append({"type": "portal_link", "ref": str(link)})
    if resource_id:
        evidence.append({"type": "affected_resource", "ref": resource_id})
    techniques = merge_unique(as_list(pick(f, "techniques")), as_list(pick(f, "subtechniques")))
    return _common(top, f, str(native_id), sev, str(title), first, last, resource_id, arm_id, subscription,
                   _status(pick(f, "status")), str(pick(f, "alerttype") or "SecurityAlert"),
                   as_list(pick(f, "tactics")), techniques, evidence, raw, now)


def normalize(payload: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
    """Convert one Sentinel incident or alert to the AEGIS-X schema."""
    raw = copy.deepcopy(payload)
    top, f = flatten(payload)
    if _kind(top, f) == "incident":
        return _incident(top, f, raw, now)
    return _alert(top, f, raw, now)


def normalize_many(payloads: Iterable[dict[str, Any]], *, now: datetime | None = None) -> list[dict[str, Any]]:
    return [normalize(p, now=now) for p in payloads]


def main(argv: list[str]) -> int:
    return run_cli(normalize, argv)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
