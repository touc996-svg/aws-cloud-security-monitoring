"""Helpers shared by the Azure normalizers. Pure functions, standard library only.

Azure payloads reach us in several shapes with different key casing:
ARM/REST (``properties.alertDisplayName``), Log Analytics table rows
(``AlertName``) and Resource Graph rows. Instead of key-folding a copy of the
payload (which would risk native values being read from the altered copy),
fields are looked up case-insensitively and the *original* values are used.
"""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

CLOUD = "azure"


class NormalizationError(ValueError):
    """Raised when a payload is not a usable Azure security record."""


# Azure's severity names (Sentinel and Defender for Cloud). Azure has no "Critical".
_SEVERITY = {
    "informational": "informational",
    "low": "low",
    "medium": "medium",
    "high": "high",
}


def severity_label(native: Any) -> str:
    """Map an Azure severity name (Informational/Low/Medium/High) to AEGIS-X labels."""
    label = _SEVERITY.get(str(native).strip().lower()) if native is not None else None
    if label is None:
        raise NormalizationError(f"invalid severity: {native!r}")
    return label


def ci(value: Any) -> dict[Any, Any]:
    """Shallow case-insensitive view: lower-cased keys, original (unfolded) values."""
    if isinstance(value, str):  # Log Analytics 'dynamic' columns may arrive as JSON text
        try:
            value = json.loads(value)
        except ValueError:
            return {}
    if not isinstance(value, dict):
        return {}
    return {(k.lower() if isinstance(k, str) else k): v for k, v in value.items()}


def pick(view: dict[Any, Any], *names: str) -> Any:
    """First non-empty value among the (lower-case) ``names``."""
    for name in names:
        value = view.get(name)
        if value not in (None, "", [], {}):
            return value
    return None


def flatten(payload: Any) -> tuple[dict[Any, Any], dict[Any, Any]]:
    """Return (top-level view, merged top-level + ``properties`` view)."""
    if not isinstance(payload, dict):
        raise NormalizationError("payload must be a JSON object")
    top = ci(payload)
    props = ci(top.get("properties"))
    merged = {k: v for k, v in top.items() if k != "properties"}
    merged.update(props)
    return top, merged


def as_list(value: Any) -> list[str]:
    """Coerce Azure list-ish fields (list, JSON array text, 'A, B' text) to a list of str."""
    if value is None:
        return []
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        if text.startswith("["):
            try:
                value = json.loads(text)
            except ValueError:
                value = text.strip("[]").split(",")
        else:
            value = text.split(",")
    if not isinstance(value, (list, tuple)):
        value = [value]
    out: list[str] = []
    for item in value:
        item = str(item).strip().strip('"')
        if item and item not in out:
            out.append(item)
    return out


def merge_unique(*lists: Iterable[str]) -> list[str]:
    out: list[str] = []
    for items in lists:
        for item in items:
            if item not in out:
                out.append(item)
    return out


_GUID_RE = re.compile(r"[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
_SUB_RE = re.compile(r"/subscriptions/([^/\s]+)", re.IGNORECASE)


def subscription_from(*candidates: Any) -> str | None:
    """Subscription GUID (lower-cased) from the first Azure resource ID / URL that has one."""
    for cand in candidates:
        if isinstance(cand, str):
            if _GUID_RE.fullmatch(cand.strip()):  # a bare subscription GUID
                return cand.strip().lower()
            m = _SUB_RE.search(cand)
            if m:
                return m.group(1).lower()
    return None


def parse_ts(value: Any, field: str) -> str:
    """Return an RFC 3339 UTC timestamp. Azure emits up to 7 fractional digits; trim to 6."""
    if isinstance(value, datetime):
        dt = value
    else:
        if not isinstance(value, str) or not value.strip():
            raise NormalizationError(f"missing timestamp: {field}")
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        text = re.sub(r"(\.\d{6})\d+", r"\1", text)
        try:
            dt = datetime.fromisoformat(text)
        except ValueError as exc:
            raise NormalizationError(f"invalid timestamp in {field}: {value!r}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def ingested_at(now: datetime | None) -> str:
    return (now or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def make_id(provider: str, account: str, region: str, native_id: str) -> str:
    return f"{CLOUD}:{provider}:{account}:{region.lower()}:{native_id}"


def _load(stream) -> list[dict[str, Any]]:
    data = json.load(stream)
    if isinstance(data, dict) and isinstance(data.get("value"), list):
        return data["value"]  # ARM list response
    return data if isinstance(data, list) else [data]


def run_cli(normalize: Callable[..., dict[str, Any]], argv: list[str]) -> int:
    """CLI: <module> [file|-]  -> JSON Lines on stdout."""
    path = argv[1] if len(argv) > 1 else "-"
    stream = sys.stdin if path == "-" else open(path, encoding="utf-8")
    try:
        for record in _load(stream):
            print(json.dumps(normalize(record), separators=(",", ":")))
    except (NormalizationError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        if stream is not sys.stdin:
            stream.close()
    return 0
