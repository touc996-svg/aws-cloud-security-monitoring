"""Ingest normalized findings from JSON Lines and validate against the schema.

Invalid input is never dropped silently: each rejected line becomes a quarantine
record carrying the source file, line number, a reason and the original text.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from jsonschema import Draft202012Validator

from .common import parse_ts

DEFAULT_SCHEMA = Path(__file__).resolve().parent.parent / "integrations" / "schemas" / "finding.schema.json"
JSONL_SUFFIXES = {".jsonl", ".ndjson"}
_TS_FIELDS = ("observed_at", "first_seen", "last_seen", "ingested_at")


@dataclass
class Ingested:
    finding: dict[str, Any]
    source_file: str
    line: int


def load_validator(schema_path: Path | str | None = None) -> Draft202012Validator:
    schema = json.loads(Path(schema_path or DEFAULT_SCHEMA).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def discover_files(inputs: Iterable[Path | str]) -> list[Path]:
    """Expand files/directories (recursive) into a sorted, de-duplicated file list."""
    found: dict[str, Path] = {}
    for item in inputs:
        p = Path(item)
        if p.is_dir():
            for child in p.rglob("*"):
                if child.is_file() and child.suffix.lower() in JSONL_SUFFIXES:
                    found[child.as_posix()] = child
        elif p.is_file():
            found[p.as_posix()] = p
        else:
            raise FileNotFoundError(f"input not found: {p}")
    return [found[k] for k in sorted(found)]


def _quarantine(source: str, line: int, reason: str, raw: str, errors: list[str] | None = None) -> dict:
    rec = {"source_file": source, "line": line, "reason": reason, "raw_line": raw}
    if errors:
        rec["errors"] = errors
    return rec


def validate_record(record: Any, validator: Draft202012Validator) -> list[str]:
    """Return a sorted list of problems (empty when valid)."""
    if not isinstance(record, dict):
        return ["record is not a JSON object"]
    problems = sorted(
        f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
        for e in validator.iter_errors(record)
    )
    # The schema's `format: date-time` is annotation-only without extra libraries,
    # so enforce RFC 3339 (with timezone) explicitly.
    for field in _TS_FIELDS:
        if field in record and isinstance(record[field], str):
            try:
                parse_ts(record[field])
            except ValueError as exc:
                problems.append(f"{field}: invalid date-time ({exc})")
    return problems


def ingest(
    inputs: Iterable[Path | str], validator: Draft202012Validator | None = None
) -> tuple[list[Ingested], list[dict]]:
    validator = validator or load_validator()
    good: list[Ingested] = []
    bad: list[dict] = []
    for path in discover_files(inputs):
        src = path.as_posix()
        with path.open(encoding="utf-8", errors="replace") as fh:
            for lineno, text in enumerate(fh, start=1):
                text = text.rstrip("\r\n")
                if not text.strip():
                    continue
                try:
                    record = json.loads(text)
                except json.JSONDecodeError as exc:
                    bad.append(_quarantine(src, lineno, f"invalid JSON: {exc.msg}", text))
                    continue
                problems = validate_record(record, validator)
                if problems:
                    bad.append(_quarantine(src, lineno, "schema validation failed", text, problems))
                else:
                    good.append(Ingested(record, src, lineno))
    return good, bad
