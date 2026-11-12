#!/usr/bin/env python3
"""Device-independent BMC E5/E6 BLE download state machine (HA + mini agent).

Verified post-auth flow: one 9772 init, official 1700-family and 1406/1412/1416
ACKs, one empty queryWorkState at the official call site, official-cadence
heartbeat (wire 8 empty, device answers wire 9), one active downloadNewSummary
9820 state=1 after the 1416 ready ACK (official Dart user-sync path), 1092
answered with the official resume cursor (empty-DB 0 or max completed
recordNo), summary/event ACKs, multi-fragment event handling.
Read-only: no setters, no clear/OTA, no reconnect/resend, no other 9820 states.
Caps: 60s from connect, GATT writes <= 400, <=10 summaries or <=1MiB plaintext.
Scanning/connect/auth and evidence/health archiving live in client.py/callers.
"""
from __future__ import annotations

import asyncio
import hashlib
import struct
import time
from contextlib import suppress
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

from . import auth_frames as af
from . import protocol_cmds as pc
from .fragment import app_mtu_count, slice_write

TZ = ZoneInfo("Asia/Shanghai")
CHAR_FE64 = "0000fe64-0000-1000-8000-00805f9b34fb"
NOTIFY_WAIT = 8.0
SESSION_LIMIT_S = 60.0
GATT_WRITE_LIMIT = 400
MAX_SUMMARIES = 10
MAX_PLAINTEXT = 1024 * 1024
# Undecoded notification bytes we are willing to hold. A declared frame length is
# peer-supplied, so without this a bogus header can grow the buffer for the whole
# session.
MAX_NOTIFY_BUFFER = 64 * 1024
SLICE_MTU_COUNT = app_mtu_count(None, False)  # 20

# Official BaseNewDataProcessing.startHeartbeat: postDelayed 10s, then every 10s.
HEARTBEAT_FIRST_DELAY_S = 10.0
HEARTBEAT_INTERVAL_S = 10.0
HEARTBEAT_MAX = 5  # T+10/20/30/40/50 inside the 60s session cap


def heartbeat_due(connect_mono: float | None, sent_count: int) -> float | None:
    """monotonic deadline of the next heartbeat, or None when the budget is spent."""
    if connect_mono is None or sent_count >= HEARTBEAT_MAX:
        return None
    return connect_mono + HEARTBEAT_FIRST_DELAY_S + sent_count * HEARTBEAT_INTERVAL_S


def now():
    return datetime.now(TZ)


def ts():
    return now().strftime("%Y-%m-%d %H:%M:%S %Z")

def iso_ms():
    return now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " " + (now().tzname() or "")

def timeline_add(sess, direction, kind, cmd=None, extra=None):
    ev = {"t": iso_ms(), "dir": direction, "kind": kind}
    if cmd is not None:
        ev["cmd"] = cmd
    if extra:
        ev.update(extra)
    sess.timeline.append(ev)


def redact_hex(h: str) -> dict:
    h = (h or "").replace(" ", "").lower()
    info = {"len": len(h) // 2, "prefix4": h[:8] if h else ""}
    if len(h) >= 8:
        with suppress(ValueError):
            info.update({
                "start": int(h[0:2], 16),
                "alg": int(h[2:4], 16),
                "declared_len": int(h[4:8], 16),
            })
    return info


def semantic(parsed: dict) -> dict:
    out = {k: parsed[k] for k in (
        "start", "alg", "wire_len", "crc_ok", "command", "param1", "param2", "body_len"
    ) if k in parsed}
    out["payload_len"] = len(parsed.get("payload") or b"")
    payload = parsed.get("payload") or b""
    # Fragment-vs-retransmit evidence without archiving health payloads.
    out["payload_sha8"] = hashlib.sha256(payload).hexdigest()[:8] if payload else None
    return out


def is_tcc_or_permission(err: BaseException) -> str | None:
    msg = f"{type(err).__name__}: {err}"
    low = msg.lower()
    hints = ("bluetooth", "tcc", "not authorized", "unauthorized", "permission",
             "powered off", "cbmanager", "corebluetooth", "denied", "privacy")
    if any(h in low for h in hints):
        return msg
    return None


def format_write_error(ex: BaseException) -> dict:
    from bleak.exc import BleakGATTProtocolError  # pyright: ignore[reportMissingImports]  # bleak: Air venv only (proven on-device)
    info: dict[str, object] = {"type": type(ex).__name__, "message": str(ex)}
    if isinstance(ex, BleakGATTProtocolError):
        try:
            info["code"] = int(ex.args[0]) if ex.args else None
        except Exception:
            info["code"] = None
        try:
            code_name: Any = getattr(ex, "code", None)
            if hasattr(code_name, "name"):
                info["code_name"] = code_name.name
            else:
                info["code_name"] = str(code_name) if code_name is not None else None
        except Exception:
            info["code_name"] = None
    return info


class SessionLimits(Exception):
    pass


class Session:
    def __init__(self, report: dict):
        self.report = report
        self.gatt_writes = 0
        self.logical_sent = 0
        self.plaintext = 0
        self.connect_mono: float | None = None
        self.notify_blob = b""
        self.notify_event = asyncio.Event()
        self.aes_key: bytes | None = None  # bytes, wiped in finally
        self.range_min: int | None = None
        self.range_max: int | None = None
        self.got_1520 = False
        self.sent_9772 = False
        self.sent_9820 = False
        self.sent_1093 = False
        self.summaries = []  # private parsed records
        self.processed_dates = []
        self.received_cmds = []
        self.acks_sent = []
        self.skipped_acks = []
        self.unknown_cmds = []
        self.stop_now = None
        self.timeline = []
        self.sent_query_ws = False
        self.t_query_ws: str | None = None
        self.t_1520: str | None = None
        self.heartbeats_sent = 0
        self.resume_cursor = 0
        self.summary_param1 = {}
        self.completed_record_nos = set()

    def elapsed(self) -> float:
        if self.connect_mono is None:
            return 0.0
        return time.monotonic() - self.connect_mono

    def remaining(self) -> float:
        return SESSION_LIMIT_S - self.elapsed() if self.connect_mono is not None else SESSION_LIMIT_S

    def check_limits(self, extra_writes: int = 0, extra_plain: int = 0, extra_sum: int = 0):
        if self.connect_mono is not None and self.elapsed() >= SESSION_LIMIT_S:
            raise SessionLimits("session 60s cap")
        if self.gatt_writes + extra_writes > GATT_WRITE_LIMIT:
            raise SessionLimits(f"GATT write cap {GATT_WRITE_LIMIT}")
        if self.plaintext + extra_plain > MAX_PLAINTEXT:
            raise SessionLimits("plaintext cap 1MiB")
        if len(self.summaries) + extra_sum > MAX_SUMMARIES:
            raise SessionLimits("summary cap 10")

    def on_notify(self, _handle, data: bytearray):
        self.notify_blob += bytes(data)
        if len(self.notify_blob) > MAX_NOTIFY_BUFFER:
            self.stop_now = "notify buffer exceeded safe bound"
        self.notify_event.set()

    def pop_frames(self) -> list[bytes]:
        frames, self.notify_blob = pc.split_notify_frames(self.notify_blob)
        if self.notify_blob and self.notify_blob[0] != af.BLE_HEAD and len(self.notify_blob) >= 4:
            self.stop_now = "notify stream lost BLE_HEAD framing"
        return frames


async def write_sliced(client, char_uuid, wire: bytes, report_req: dict, sess: Session) -> bool:
    chunks = slice_write(wire, SLICE_MTU_COUNT)
    sess.check_limits(extra_writes=len(chunks))
    report_req["logical_frames"] = 1
    report_req["slice_mtu_count"] = SLICE_MTU_COUNT
    report_req["gatt_slices"] = len(chunks)
    report_req["slice_lens"] = [len(c) for c in chunks]
    report_req["write_type"] = "request"
    for i, chunk in enumerate(chunks):
        sess.check_limits(extra_writes=1)
        try:
            await client.write_gatt_char(char_uuid, chunk, response=True)
            sess.gatt_writes += 1
            report_req.setdefault("slices_ok", 0)
            report_req["slices_ok"] += 1
        except SessionLimits:
            raise
        except Exception as ex:
            report_req["result"] = "WRITE_FAIL"
            report_req["failed_slice_index"] = i
            report_req["error"] = format_write_error(ex)
            return False
    report_req["result"] = "WRITE_OK"
    sess.logical_sent += 1
    return True


async def wait_frames(sess: Session, timeout: float) -> list[bytes]:
    deadline = time.monotonic() + max(0.05, timeout)
    got: list[bytes] = []
    while time.monotonic() < deadline:
        got.extend(sess.pop_frames())
        if got:
            return got
        if sess.stop_now:
            return []
        sess.check_limits()
        sess.notify_event.clear()
        remaining = min(deadline - time.monotonic(), sess.remaining())
        if remaining <= 0:
            break
        try:
            await asyncio.wait_for(sess.notify_event.wait(), timeout=remaining)
        except TimeoutError:
            break
    got.extend(sess.pop_frames())
    return got


async def send_kind(client, sess: Session, kind: str, wire: bytes, wire_cmd: int, payload: bytes) -> bool:
    pc.assert_allowed_send(kind, wire_cmd, payload)
    req = {"kind": kind, "count": 1, "wire": redact_hex(wire.hex()), "wire_cmd": wire_cmd, "payload_len": len(payload), "t": iso_ms()}
    ok = await write_sliced(client, CHAR_FE64, wire, req, sess)
    sess.report["requests"].append(req)
    timeline_add(sess, "tx", kind, cmd=wire_cmd, extra={"ok": ok, "payload_len": len(payload)})
    return ok


async def send_heartbeat(client, sess: Session) -> bool:
    """Official startHeartbeat frame: wire 8 (TIME), param1=param2=0, empty, alg=5.

    Official keepalive cadence (non-therapy windows only).
    pc.assert_allowed_send forbids wire 8 in the shared module;
    this probe asserts the exact frame shape locally instead of widening the
    shared whitelist. Empty payload carries no time value (not a clock write).
    """
    if pc.WIRE_HEARTBEAT != 8:
        raise PermissionError("heartbeat wire mismatch")
    assert sess.aes_key is not None  # set before post-auth loop
    wire = pc.build_aes_frame(sess.aes_key, pc.WIRE_HEARTBEAT, 0, 0, b"")
    req = {"kind": "HEARTBEAT", "count": 1, "wire": redact_hex(wire.hex()),
           "wire_cmd": pc.WIRE_HEARTBEAT, "payload_len": 0, "t": iso_ms()}
    ok = await write_sliced(client, CHAR_FE64, wire, req, sess)
    sess.report["requests"].append(req)
    timeline_add(sess, "tx", "HEARTBEAT", cmd=pc.WIRE_HEARTBEAT, extra={"ok": ok, "payload_len": 0})
    return ok


def build_1093_resume(sess: Session, cursor: int):
    """Official 1093 cursor: empty-DB 0 (pc whitelist) or resume dataBaseNo-1.

    Resume cursor = our max COMPLETED recordNo (official
    getMinRecordNoOfSummariesWithoutEvents - 1 rule).
    pc only whitelists empty-DB 0; the resume frame is asserted locally
    (wire 1093, param1=1, BE uint32 cursor) instead of widening pc.
    """
    if not 0 <= cursor <= 0xFFFFFFFF:
        raise PermissionError("1093 cursor out of uint32 range")
    assert sess.aes_key is not None  # post-auth only
    if cursor == 0:
        return pc.build_1093_cursor0(sess.aes_key), "REPLY_1093_CURSOR0"
    wire = pc.build_aes_frame(sess.aes_key, pc.WIRE_SUMMARY_LAST_NO_REPLY, 1, 0, struct.pack(">I", cursor))
    return wire, "REPLY_1093_CURSOR_RESUME"


async def send_resume_1093(client, sess: Session, wire: bytes, cursor: int) -> bool:
    """Send the resume 1093 (cursor>=1). Local assert, not the pc whitelist."""
    if not 1 <= cursor <= 0xFFFFFFFF:
        raise PermissionError("resume cursor out of range")
    req = {"kind": "REPLY_1093_CURSOR_RESUME", "count": 1, "wire": redact_hex(wire.hex()),
           "wire_cmd": pc.WIRE_SUMMARY_LAST_NO_REPLY, "payload_len": 4, "cursor": cursor, "t": iso_ms()}
    ok = await write_sliced(client, CHAR_FE64, wire, req, sess)
    sess.report["requests"].append(req)
    timeline_add(sess, "tx", "REPLY_1093_CURSOR_RESUME", cmd=pc.WIRE_SUMMARY_LAST_NO_REPLY, extra={"ok": ok, "cursor": cursor})
    return ok


def wipe_key(key):
    if key is None:
        return
    if isinstance(key, bytearray):
        for i in range(len(key)):
            key[i] = 0
        return
    # bytes are immutable; caller should prefer bytearray


async def _cleanup(client, notified: bool, report: dict, sess: Session, code: int, aes_key_buf) -> int:
    steps = []
    try:
        if notified and client is not None:
            try:
                await client.stop_notify(CHAR_FE64)
                steps.append("StopNotify_ok")
            except Exception as ex:
                steps.append(f"StopNotify_{type(ex).__name__}")
        if client is not None:
            try:
                if client.is_connected:
                    await client.disconnect()
                    steps.append("Disconnect_issued")
                else:
                    steps.append("already_disconnected")
            except Exception as ex:
                steps.append(f"Disconnect_{type(ex).__name__}")
            try:
                still = bool(client.is_connected)
            except Exception:
                still = None
            steps.append(f"is_connected={still}")
            report["disconnect"] = {"ok": still is False, "steps": steps, "is_connected": still}
    finally:
        dates = [d.isoformat() for d in sess.processed_dates]
        report["read"] = {
            "summary_count": len(sess.summaries),
            "field_names": pc.SUMMARY_FIELD_NAMES if sess.summaries else [],
            "date_range": {"min": min(dates) if dates else None, "max": max(dates) if dates else None},
            "date_decoder": "BMCTime/NewSummaryInfo (year=byte+1900, hour raw, ms uint16 LE)",
            "range_from_1520": {"min": sess.range_min, "max": sess.range_max} if sess.got_1520 else None,
            "resume_cursor": sess.resume_cursor,
            "completed_record_nos": sorted(sess.completed_record_nos),
            "next_cursor": max(sess.completed_record_nos) if sess.completed_record_nos else None,
        }
        report["timeline"] = sess.timeline
        report["query_vs_1520"] = {
            "query_sent": sess.sent_query_ws,
            "t_query": sess.t_query_ws,
            "t_1520": sess.t_1520,
            "got_1520": sess.got_1520,
        }
        report["heartbeat"] = {
            "authorized": "official startHeartbeat cadence, empty wire 8 payload",
            "cadence": "first at connect+10s, every 10s, max 5 (official startHeartbeat)",
            "sent_count": sess.heartbeats_sent,
            "sent_t": report.get("heartbeat", {}).get("sent_t", []),
            "t_1520": sess.t_1520,
            "got_1520": sess.got_1520,
        }
        report["counts"] = {
            "logical_frames_sent": sess.logical_sent,
            "gatt_writes": sess.gatt_writes,
            "plaintext_bytes": sess.plaintext,
            "acks_sent": sess.acks_sent,
            "skipped_acks": sess.skipped_acks,
            "received_cmds": sess.received_cmds,
            "unknown_cmds": sess.unknown_cmds,
        }
        wipe_key(aes_key_buf)
        sess.aes_key = None
        report["ended"] = ts()
    return code


async def handle_incoming(client, sess: Session, parsed: dict) -> str | None:
    """Return a stop reason, or None to continue. May send ACKs."""
    assert sess.aes_key is not None  # post-auth only
    cmd = parsed["command"]
    payload = parsed.get("payload") or b""
    sess.received_cmds.append(cmd)
    sess.plaintext += int(parsed.get("body_len") or 0)
    timeline_add(sess, "rx", f"cmd_{cmd}", cmd=cmd, extra={"param1": parsed.get("param1"), "payload_len": len(payload), "crc_ok": parsed.get("crc_ok")})
    sess.check_limits()

    if cmd == pc.WIRE_9772_REPLY:
        sess.report.setdefault("init_9772_reply", {})["param1"] = parsed.get("param1")
        sess.report["init_9772_reply"]["crc_ok"] = parsed.get("crc_ok")
        if parsed.get("param1") != 1:
            return "9772 reply param1!=1; not retrying newDeviceConnect"
        return None

    if cmd in (pc.WIRE_1700, pc.WIRE_1702, pc.WIRE_1704, pc.WIRE_1720):
        kind = {1700: "ACK_1700", 1702: "ACK_1702", 1704: "ACK_1704", 1720: "ACK_1720"}[cmd]
        wire = pc.build_empty_ack(sess.aes_key, cmd)
        if not await send_kind(client, sess, kind, wire, pc.ack_wire(cmd), b""):
            return f"{kind} write failed; not resending"
        sess.acks_sent.append(kind)
        # Official onAllTargetsCompleted: exactly once when 1700/1702/1704/1720 are in; not again on 1416 ready().
        if pc.should_send_query_work_state(sess.received_cmds, sess.sent_query_ws):
            q = pc.build_query_work_state(sess.aes_key)
            if not await send_kind(client, sess, "QUERY_WORK_STATE", q, pc.WIRE_QUERY_WORK_STATE, b""):
                return "queryWorkState write failed; not resending"
            sess.sent_query_ws = True
            sess.t_query_ws = iso_ms()
            sess.report["query_work_state"] = {
                "sent": True,
                "t": sess.t_query_ws,
                "after_incoming": cmd,
                "call_site": "onAllTargetsCompleted once after fixed targets 1700/1702/1704/1720; not on 1416 ready()",
                "wire": 23172,
                "payload": "empty",
            }
        return None

    if cmd == pc.WIRE_1706:
        mode = pc.parse_1706_mode(payload)
        if mode is None:
            sess.skipped_acks.append({"cmd": 1706, "reason": "mode not parsed; not inventing ACK payload"})
            return None
        wire = pc.build_1706_mode_echo(sess.aes_key, mode)
        if not await send_kind(client, sess, "ACK_1706_MODE_ECHO", wire, pc.WIRE_1707, struct.pack("<I", mode)):
            return "ACK_1706 write failed; not resending"
        sess.acks_sent.append("ACK_1706_MODE_ECHO")
        return None

    if cmd == pc.WIRE_1708:
        # Device time push / read. Java does not ACK. We must not write time.
        sess.report.setdefault("received_notifications", []).append("1708_time_push_not_acked")
        return None

    if cmd == pc.WIRE_1520:
        rng = pc.parse_1520(payload)
        if rng is None:
            return "1520 payload too short; not inventing range"
        sess.range_min, sess.range_max = rng
        sess.got_1520 = True
        sess.t_1520 = iso_ms()
        sess.report["record_range_1520"] = {"min": sess.range_min, "max": sess.range_max, "t": sess.t_1520}
        if not sess.sent_9820:
            wire = pc.build_9820_state1(sess.aes_key)
            if not await send_kind(client, sess, "DOWNLOAD_9820_STATE1", wire, pc.WIRE_9820, bytes([1])):
                return "9820 write failed; not resending"
            sess.sent_9820 = True
        return None

    if cmd == pc.WIRE_SUMMARY_LAST_NO:
        if not sess.got_1520 and not sess.sent_9820:
            sess.skipped_acks.append({"cmd": 1092, "reason": "no 1520 range and no active 9820; not answering 1093"})
            return "1092 arrived without 1520 range or active download; stopping, not inventing cursor from guess"
        # Active Dart-path download: official empty-DB cursor 0 is valid without 1520.
        cursor = sess.resume_cursor
        wire, kind = build_1093_resume(sess, cursor)
        if cursor == 0:
            ok = await send_kind(client, sess, kind, wire, pc.WIRE_SUMMARY_LAST_NO_REPLY, struct.pack(">I", 0))
        else:
            ok = await send_resume_1093(client, sess, wire, cursor)
        if not ok:
            return "1093 write failed; not resending"
        sess.sent_1093 = True
        sess.acks_sent.append(f"{kind}_cursor={cursor}")
        return None

    if cmd == pc.WIRE_SUMMARY:
        try:
            sess.check_limits(extra_sum=1, extra_plain=0)
            rec = pc.parse_new_summary_info(payload)
        except (ValueError, SessionLimits) as ex:
            sess.skipped_acks.append({"cmd": 1030, "reason": type(ex).__name__})
            if isinstance(ex, SessionLimits):
                return str(ex)
            return "1030 parse failed; not ACKing unprocessed record"
        # processed
        sess.summaries.append(rec)
        sess.processed_dates.append(rec["recordDate"])
        sess.summary_param1[int(rec["recordNo"])] = int(parsed.get("param1") or 0)
        wire = pc.build_empty_ack(sess.aes_key, 1030)
        if not await send_kind(client, sess, "ACK_1030", wire, 1031, b""):
            return "1031 write failed; not resending"
        sess.acks_sent.append("ACK_1030")
        if len(sess.summaries) >= MAX_SUMMARIES:
            return "summary cap 10 reached after processing+ACK"
        return None

    if cmd == pc.WIRE_SUMMARY_END:
        # ACK only if we have been processing this transfer (at least sent 9820 or already have a summary)
        if not sess.sent_9820 and not sess.summaries:
            sess.skipped_acks.append({"cmd": 1090, "reason": "no download in progress"})
            return "1090 without download; not ACKing"
        wire = pc.build_empty_ack(sess.aes_key, 1090)
        if not await send_kind(client, sess, "ACK_1090", wire, 1091, b""):
            return "1091 write failed; not resending"
        sess.acks_sent.append("ACK_1090")
        p1 = int(parsed.get("param1") or 0)
        for no, sp1 in sess.summary_param1.items():
            if sp1 == p1:
                sess.completed_record_nos.add(no)
        # Official "读完了" when deviceRecordNo == summaryRecordNo
        last_no = sess.summaries[-1]["recordNo"] if sess.summaries else None
        if sess.got_1520 and last_no is not None and last_no == sess.range_max:
            return "download reached device max record; stopping after 1091"
        return None

    if pc.is_event_command(cmd):
        if not sess.summaries:
            sess.skipped_acks.append({"cmd": cmd, "reason": "event without processed summary; not ACKing"})
            return None
        wire = pc.build_empty_ack(sess.aes_key, cmd)
        if not await send_kind(client, sess, "ACK_EVENT", wire, pc.ack_wire(cmd), b""):
            return "event ACK write failed; not resending"
        sess.acks_sent.append(f"ACK_EVENT_{cmd}")
        return None

    # 1406/1412/1416: official pure transfer ACKs verified from distinguish (not setters).
    if cmd == 1406:
        p2 = int(parsed.get("param2") or 0) & 0xFFFF
        wire = pc.build_1406_ack(sess.aes_key, p2)
        if not await send_kind(client, sess, "ACK_1406", wire, 1407, b""):
            return "ACK_1406 write failed; not resending"
        sess.acks_sent.append(f"ACK_1406_param2={p2}")
        return None
    if cmd == 1412:
        wire = pc.build_1412_ack(sess.aes_key)
        if not await send_kind(client, sess, "ACK_1412", wire, 1413, b""):
            return "ACK_1412 write failed; not resending"
        sess.acks_sent.append("ACK_1412")
        return None
    if cmd == 1416:
        wire = pc.build_1416_ack(sess.aes_key)
        if not await send_kind(client, sess, "ACK_1416", wire, 1417, b""):
            return "ACK_1416 write failed; not resending"
        sess.acks_sent.append("ACK_1416")
        # Official ready() point, config push complete. Dart user-sync path:
        # proactively send downloadNewSummary 9820 state=1 exactly once
        # (official Java auto-path value).
        if not sess.sent_9820:
            wire = pc.build_9820_state1(sess.aes_key)
            if not await send_kind(client, sess, "DOWNLOAD_9820_STATE1", wire, pc.WIRE_9820, bytes([1])):
                return "active 9820 write failed; not resending"
            sess.sent_9820 = True
            sess.report["active_download"] = {
                "sent": True,
                "t": iso_ms(),
                "after_incoming": 1416,
                "call_site": "after 1416 ready ACK; official Dart downloadNewSummary path, state=1, once",
            }
        return None

    if cmd == pc.WIRE_QUERY_WORK_STATE_REPLY:
        # Not a distinguish case in official Java; no ACK. Record only.
        sess.report.setdefault("received_notifications", []).append("23173_query_work_state_reply_no_ack")
        return None

    cls = pc.classify_incoming(cmd)
    if cls["action"] == "ota_stop":
        return f"device sent OTA-related command {cmd}; not ACKing/sending upgrade data; stopping"
    if cls["action"] == "setter_reply_stop":
        return f"unexpected setter reply {cmd}; we sent no setter; stopping"
    if cls["action"] == "observe":
        sess.report.setdefault("received_notifications", []).append(f"cmd_{cmd}_observe_no_ack")
        return None

    # Unknown: never generic N+1. Keep waiting in budget for 1520.
    sess.unknown_cmds.append(cmd)
    sess.skipped_acks.append({"cmd": cmd, "reason": "unrecognized; not generic N+1"})
    return None



def no_1520_stop_message(sess: Session, prefix: str = "no 1520 range within budget") -> str:
    seq = sess.received_cmds
    notes = [
        "1520 is device-originated; Java has no request that elicits it.",
        "Official 1520 handler only uses already-received SysFlag SN (1702); that is a client-side gate, not a proof the device waits for -288.",
        "Official onAllTargetsCompleted queryWorkState (-288) was sent once at the official call site this session.",
        "Official startHeartbeat (wire 8 / TIME, empty) is sent on official cadence: first connect+10s, every 10s, max 5.",
        "This session ACKs official 1406/1412/1416 transfer confirms when those pushes arrive (missing from the prior runtime whitelist).",
    ]
    return (
        f"{prefix}. event_sequence={seq}. "
        f"acks={sess.acks_sent}. unknown={sess.unknown_cmds}. "
        + " static_prereq_notes: " + " | ".join(notes)
    )


def idle_stop_reason(sess: Session, idle_rounds: int) -> str | None:
    """Stop after 2 idle rounds once a download has produced something.

    Without 1520 and without summaries we keep waiting (t908 behavior).
    """
    if idle_rounds < 2 or not sess.sent_9820:
        return None
    if sess.summaries:
        return "idle after summaries; stopping"
    if sess.got_1520:
        return "1520+9820 sent but no summary frames before idle timeout; stopping"
    return None


async def post_auth(client, sess: Session) -> str:
    # One 9772 init read, not App auto-flow (no 20s retry).
    # Heartbeat follows official startHeartbeat:
    # first at connect+10s, then every 10s, max 5; scheduled inline in this
    # single-threaded loop so GATT writes never interleave with ACK slices.
    assert sess.aes_key is not None  # set after CONFIRM_KEY success
    wire = pc.build_9772(sess.aes_key)
    if not await send_kind(client, sess, "INIT_9772", wire, pc.WIRE_9772, b""):
        return "9772 write failed; not resending"
    sess.sent_9772 = True

    # Wait for 1520 (required before 9820) and process other official notifies.
    # After 9820, wait for summaries / 1090 / caps.
    idle_rounds = 0
    while True:
        try:
            sess.check_limits()
        except SessionLimits as ex:
            if not sess.got_1520:
                return no_1520_stop_message(sess, prefix=str(ex))
            return str(ex)
        due = heartbeat_due(sess.connect_mono, sess.heartbeats_sent)
        now_mono = time.monotonic()
        if due is not None and now_mono >= due:
            if not await send_heartbeat(client, sess):
                return "heartbeat write failed; not resending"
            sess.heartbeats_sent += 1
            sess.report.setdefault("heartbeat", {}).setdefault("sent_t", []).append(iso_ms())
            continue
        timeout = min(NOTIFY_WAIT, max(0.2, sess.remaining() - 1.0))
        if due is not None:
            timeout = min(timeout, max(0.05, due - now_mono))
        if timeout <= 0.2 and sess.remaining() <= 1.0:
            if not sess.got_1520:
                return no_1520_stop_message(sess, prefix="time cap approaching with no 1520")
            return "time cap approaching; stopping"
        frames = await wait_frames(sess, timeout)
        if sess.stop_now:
            return sess.stop_now
        if not frames:
            idle_rounds += 1
            if not sess.got_1520 and not sess.summaries:
                # keep waiting until time cap; check_limits will fire
                continue
            reason = idle_stop_reason(sess, idle_rounds)
            if reason:
                return reason
            continue
        idle_rounds = 0
        for frame in frames:
            try:
                parsed = af.parse_wire(1, 1, sess.aes_key, frame)
            except Exception as ex:
                sess.report["replies"].append({
                    "kind": "unparsed_postauth",
                    "wire": redact_hex(frame.hex()),
                    "error": type(ex).__name__,
                })
                return f"post-auth decrypt/parse failed: {type(ex).__name__}"
            if not parsed.get("crc_ok"):
                sess.report["replies"].append({"kind": "crc_fail", **semantic(parsed)})
                return "post-auth CRC failed; stopping"
            sem = semantic(parsed)
            sem["kind"] = f"cmd_{parsed['command']}"
            sess.report["replies"].append(sem)
            reason = await handle_incoming(client, sess, parsed)
            if reason:
                return reason

