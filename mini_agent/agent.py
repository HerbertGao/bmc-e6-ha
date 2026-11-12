#!/usr/bin/env python3
"""Mini-side backup agent (skeleton): fetch over BLE when HA has not succeeded.

Runs on any always-on machine with BLE in range of the ventilator. Reuses the
same bmc_ble protocol package as the HACS integration.

Flow: read HA last-success timestamp -> if stale beyond backup_after_hours,
download(cursor) -> POST new records to the HACS integration webhook.
Config is a local JSON (never committed): target_name, pem_path, ha_webhook_url,
cursor_file. See README.md in this directory.
"""
from __future__ import annotations

import fcntl
import json
import os
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "custom_components"))

from bmc_e6.bmc_ble import client  # noqa: E402


def load_config(path: Path) -> dict:
    cfg = json.loads(path.read_text())
    for key in ("target_name", "pem_path", "ha_webhook_url", "cursor_file", "push_secret"):
        if not cfg.get(key):
            raise SystemExit(f"missing config: {key}")
    return cfg


def pending_push(summaries: list[dict], next_cursor: int | None) -> list[dict]:
    """Only fully completed records are pushed (1090 seen => recordNo <= cursor).

    A cursor of None means nothing completed this round: push nothing and do
    not persist, so the next round resumes from the previous cursor instead of
    crashing on a null cursor file.
    """
    if next_cursor is None:
        return []
    return [r for r in summaries if r.get("recordNo") is not None and r["recordNo"] <= next_cursor]


def _target_url(webhook_url: str, target_name: str) -> str:
    parts = urllib.parse.urlsplit(webhook_url)
    query = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
    query["target_name"] = target_name
    return urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(query)))


def ha_is_healthy(webhook_url: str, target_name: str, push_secret: str,
                  after_hours: float = 2.0) -> bool:
    """Return true only when HA reports a recent successful BLE fetch.

    Authenticated like the push, so the skip-while-healthy path works instead of
    always seeing 403 from a secret-protected endpoint.
    """
    try:
        req = urllib.request.Request(
            _target_url(webhook_url, target_name),
            headers={"Authorization": f"Bearer {push_secret}"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = json.load(resp)
        age = status.get("last_success_age_s")
        return isinstance(age, (int, float)) and not isinstance(age, bool) and 0 <= age < after_hours * 3600
    except (OSError, ValueError, TypeError, AttributeError):
        return False


def push_records(webhook_url: str, target_name: str, records: list[dict], push_secret: str) -> None:
    """POST parsed summaries to the HACS integration webhook (dedupe by recordNo).

    The endpoint fails closed, so the shared secret is mandatory; a 4xx is
    surfaced rather than crashing the agent with a traceback.
    """
    data = json.dumps({"source": "mini_ble", "target_name": target_name, "records": records}, default=str).encode()
    req = urllib.request.Request(
        webhook_url,
        data=data,
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {push_secret}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp.read()
    except urllib.error.HTTPError as ex:
        body = ex.read().decode("utf-8", "replace")[:200]
        raise RuntimeError(f"push rejected: HTTP {ex.code} {body}") from ex


def write_cursor_atomic(path: Path, next_cursor: int) -> None:
    """flock-locked read/max/write/replace critical section (no cursor regression)."""
    lock_path = path.with_name(path.name + ".lock")
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        next_cursor = max(next_cursor, read_cursor(path))  # late writers cannot regress
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".tmp")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(json.dumps({"next_cursor": next_cursor}, indent=2))
            os.replace(tmp, path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def read_cursor(path: Path) -> int:
    """Tolerate corrupt files AND wrong JSON shapes: only a valid uint32 dict value wins."""
    if not path.exists():
        return 0
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return 0
    if not isinstance(data, dict):
        return 0
    value = data.get("next_cursor")
    if type(value) is int and 0 <= value <= 0xFFFFFFFF:  # bool excluded via type() is int
        return value
    return 0


async def run(cfg: dict) -> int:
    if ha_is_healthy(
        cfg["ha_webhook_url"],
        cfg["target_name"],
        cfg["push_secret"],
        float(cfg.get("backup_after_hours", 2)),
    ):
        print(json.dumps({"code": 0, "skipped": "ha_healthy"}, ensure_ascii=False))
        return 0

    cursor_file = Path(cfg["cursor_file"])
    cursor = read_cursor(cursor_file)
    ble = client.E6BleClient(cfg["target_name"], Path(cfg["pem_path"]))
    result = await ble.download(cursor, health_dir=ROOT / "archive")
    report = result["report"]
    to_push = pending_push(result["summaries"], result["next_cursor"])
    cursor = result["next_cursor"]
    ok = result["code"] == 0 and isinstance(cursor, int) and not isinstance(cursor, bool) and cursor >= 0
    # Success ONLY means: authenticated + bounded-normal exit + completed records
    # actually pushed and cursor persisted. Anything else is a failed backup.
    success = bool(report["auth"].get("authenticated")) and ok and bool(to_push)
    if success:
        push_records(cfg["ha_webhook_url"], cfg["target_name"], to_push, cfg["push_secret"])
        write_cursor_atomic(cursor_file, cursor)
    exit_code = 0 if success else (result["code"] or 1)
    print(json.dumps({"code": exit_code, "stop": report.get("stop_reason"),
                      "summaries": len(result["summaries"]), "next_cursor": result["next_cursor"]},
                     ensure_ascii=False))
    return exit_code


def main() -> int:
    import asyncio

    cfg = load_config(Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / "config.json"))
    return asyncio.run(run(cfg))


if __name__ == "__main__":
    raise SystemExit(main())
