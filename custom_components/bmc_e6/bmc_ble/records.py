"""Record merge/dedup logic shared by coordinator and mini agent (no HA dependency)."""
from __future__ import annotations

from datetime import datetime


def json_safe_record(rec: dict) -> dict:
    """Copy a parsed record into JSON-storable form.

    Raw byte fields (recordDate_raw) have no consumer, and HA's storage layer
    rejects bytes — which fails the whole save silently.
    """
    out: dict = {}
    for key, value in rec.items():
        if isinstance(value, (bytes, bytearray)):
            continue
        out[key] = value.isoformat() if isinstance(value, datetime) else value
    return out


def validate_record_no(value) -> int:
    """recordNo must be a real int in the device's uint32 range.

    The upper bound matters: the value becomes the BLE resume cursor, and a cursor
    the wire builder rejects would abort every later round until the store is
    edited by hand.
    """
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > 0xFFFFFFFF:
        raise ValueError(f"invalid recordNo: {value!r}")
    return value


def merge_records(existing: dict, new_records: list[dict], source: str) -> tuple[dict, int, int | None]:
    """Merge by recordNo. Returns (merged, added, cursor).

    The whole batch is validated BEFORE any state is mutated, so a malformed
    item cannot leave a half-applied merge or break later max() calls.

    A recordNo already present is refreshed with the new payload (the device
    re-pushes its newest record, which may still be incomplete on first sight);
    only genuinely new recordNos count toward `added`.
    """
    prepared = [(validate_record_no(rec.get("recordNo")), rec) for rec in new_records]
    merged = dict(existing)
    added = 0
    for no, rec in prepared:
        item = dict(rec)
        item["source"] = source
        added += 0 if no in merged else 1
        merged[no] = item
    cursor = max(merged) if merged else None
    return merged, added, cursor


def restore_records(items) -> dict[int, dict]:
    """Rebuild the recordNo-keyed dict from persisted JSON (keys return as str).

    Malformed entries are dropped rather than raised: a corrupted store must not
    stop the integration from starting.
    """
    restored: dict[int, dict] = {}
    if not isinstance(items, list):
        return restored
    for item in items:
        if not isinstance(item, dict):
            continue
        try:
            restored[validate_record_no(item.get("recordNo"))] = item
        except ValueError:
            continue
    return restored
