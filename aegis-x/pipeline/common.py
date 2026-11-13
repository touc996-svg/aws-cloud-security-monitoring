"""Shared helpers: timestamps, severity ordering, canonical JSON hashing."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}


def parse_ts(value: str) -> datetime:
    """Parse an RFC 3339 timestamp. Raises ValueError if invalid or timezone-naive."""
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00").replace("z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError(f"timestamp {value!r} has no timezone offset")
    return dt.astimezone(timezone.utc)


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_of(obj: Any) -> str:
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


def first_seen_of(f: dict) -> str:
    return f.get("first_seen") or f["observed_at"]


def last_seen_of(f: dict) -> str:
    return f.get("last_seen") or f.get("first_seen") or f["observed_at"]
