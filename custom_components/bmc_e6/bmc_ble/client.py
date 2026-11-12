"""BLE client for BMC E5/E6 ventilators: scan, connect, auth, bounded download.

Device name (BMC_<SN>) and the protocol RSA key are supplied by the caller;
nothing device-specific is hardcoded here. The download itself is the verified
read-only flow in download.py. Evidence and health archives are optional and
written only under caller-selected directories (0600 files).
"""
from __future__ import annotations

import asyncio
import json
import os
import secrets
import struct
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, cast

from . import auth_frames as af
from . import protocol_cmds as pc
from .download import (
    CHAR_FE64,
    NOTIFY_WAIT,
    Session,
    SessionLimits,
    _cleanup,
    is_tcc_or_permission,
    post_auth,
    redact_hex,
    ts,
    wait_frames,
    wipe_key,
    write_sliced,
)
from .records import json_safe_record

SVC_FE60 = "0000fe60-0000-1000-8000-00805f9b34fb"
MFG_ID = 682
SCAN_TIMEOUT = 8.0
CONNECT_TIMEOUT = 20.0

# Stop reasons that are normal or bounded (everything else is a failure).
_OK_STOP_PREFIXES = (
    "idle after summaries",
    "download reached device max record",
    "summary cap",
    "GATT write cap",
    "plaintext cap",
    "time cap",
    "session 60s cap",
)


# Commands that prove the device actually served records. Checked against every
# captured session: all real downloads carry 1030/1090/1092, while every
# zero-summary session carries only the post-auth config push (1406/1412/1416/1706),
# which arrives before the download phase and therefore proves nothing.
_PROGRESS_CMDS = frozenset({1030, 1090, 1092})


# Bounded stops that only count as success when the download phase actually ran.
_NEEDS_PROGRESS_PREFIXES = ("time cap", "session 60s cap")


def exit_code(report: dict) -> int:
    """0 only for authenticated sessions ending in a normal/bounded stop.

    Whitelist (not a failure substring blacklist): unknown stop reasons, protocol
    errors, unexpected replies and idle timeouts all return non-zero. A budget
    stop also needs evidence that the download phase ran: a session that
    authenticated and then only saw the initial handshake spent the whole budget
    without fetching anything, and calling that healthy would hide a stalled
    device. A caught-up device still serves the phase (it re-pushes its newest
    record), so "nothing new" remains a success.
    """
    if not report["auth"].get("authenticated"):
        return 1
    reason = report.get("stop_reason") or ""
    if not reason.startswith(_OK_STOP_PREFIXES):
        return 1
    if reason.startswith(_NEEDS_PROGRESS_PREFIXES):
        received = set(report.get("counts", {}).get("received_cmds") or [])
        if not received & _PROGRESS_CMDS:
            return 1
    return 0


def match_score(dev, adv, target_name: str) -> tuple[int, dict]:
    """Score a discovered device: exact name > FE60 service > manufacturer 682."""
    name = (getattr(dev, "name", None) or getattr(adv, "local_name", None) or "") or ""
    uuids = [str(u).lower() for u in (getattr(adv, "service_uuids", None) or [])]
    fe60 = any("0000fe60-" in u or u.replace("-", "").endswith("fe60") for u in uuids)
    md = getattr(adv, "manufacturer_data", None) or {}
    mfg682 = MFG_ID in md
    info = {
        "name": name,
        "address": getattr(dev, "address", None),
        "rssi": getattr(adv, "rssi", None),
        "fe60": fe60,
        "mfg682": mfg682,
        "service_uuids": uuids,
    }
    score = 0
    if name == target_name:
        score += 10
    if fe60:
        score += 3
    if mfg682:
        score += 2
    return score, info


def model_from_name(name: str) -> str | None:
    """BMC_E6... -> E6, BMC_E5... -> E5 (E5 naming inferred, not yet on-device)."""
    if name.startswith("BMC_E6"):
        return "E6"
    if name.startswith("BMC_E5"):
        return "E5"
    return None


def is_supported_advertisement(name: str, service_uuids, manufacturer_data) -> bool:
    """True only for BMC E5/E6: BMC_ name + FE60 service + manufacturer 682."""
    if not name or not name.startswith("BMC_"):
        return False
    if model_from_name(name) is None:
        return False
    uuids = {str(u).lower() for u in (service_uuids or [])}
    fe60 = any("0000fe60-" in u or u.replace("-", "").endswith("fe60") for u in uuids)
    mfg = MFG_ID in (manufacturer_data or {})
    return fe60 and mfg


def char_props(ch) -> list[str]:
    props = getattr(ch, "properties", None)
    if props is None:
        return []
    if isinstance(props, (set, list, tuple)):
        return sorted(str(p) for p in props)
    return [str(props)]


def write_private(path: Path, text: str) -> Path:
    path.parent.mkdir(mode=0o700, exist_ok=True, parents=True)
    # Create with 0600 from the start (no umask-then-chmod race on secrets).
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)  # also fixes permissions of pre-existing files
    with os.fdopen(fd, "w") as f:
        f.write(text)
    return path


# Standard Device Information characteristics worth showing in HA (read-only).
DEVINFO_NAME = "00002a00-0000-1000-8000-00805f9b34fb"
_DEVICE_VERSION_CHARS = {
    "00002a24-0000-1000-8000-00805f9b34fb": "hw_version",  # Model Number (BT module code)
    "00002a28-0000-1000-8000-00805f9b34fb": "sw_version",  # Software Revision
}


async def read_device_name(client, report: dict) -> str | None:
    """Read the GATT device name (0x2A00) so identity can be re-checked post-connect.

    The advertisement often omits the local name (normal behind a proxy), in which
    case scanning falls back to FE60 + manufacturer 682 and could otherwise latch
    onto a different ventilator in range.
    """
    try:
        services = list(getattr(client, "services", None) or [])
        if not services and hasattr(client, "get_services"):
            # Service discovery may not have populated .services yet on some backends.
            try:
                await client.get_services()
            except Exception as ex:
                report["device_name_error"] = f"{type(ex).__name__}: {ex}"
            services = list(getattr(client, "services", None) or [])
        for svc in services:
            for ch in getattr(svc, "characteristics", None) or []:
                if str(ch.uuid).lower() != DEVINFO_NAME:
                    continue
                raw = await client.read_gatt_char(ch)
                return bytes(raw).decode("utf-8", "replace").strip("\x00").strip()
    except Exception as ex:  # unknown identity, never a crash
        report["device_name_error"] = f"{type(ex).__name__}: {ex}"
    return None


async def read_device_versions(client, report: dict) -> dict:
    """Best-effort read of the standard Device Information strings (no writes).

    The values are the Bluetooth module code and software revision, not the
    ventilator's marketing model, so they identify hardware only.
    """
    out: dict = {}
    try:
        for svc in getattr(client, "services", None) or []:
            for ch in getattr(svc, "characteristics", None) or []:
                key = _DEVICE_VERSION_CHARS.get(str(ch.uuid).lower())
                if key is None:
                    continue
                raw = await client.read_gatt_char(ch)
                text = bytes(raw).decode("utf-8", "replace").strip("\x00").strip()
                if text:
                    out[key] = text
    except Exception as ex:  # cosmetic only; never fail the download over it
        report["device_info_error"] = f"{type(ex).__name__}: {ex}"
    return out


def save_private_health(sess: Session, health_dir: Path) -> str | None:
    """Archive parsed summaries locally (0600). Never printed or uploaded."""
    if not sess.summaries:
        return None
    recs = [json_safe_record(s) for s in sess.summaries]
    from .download import now  # local import to keep module namespace clean

    path = health_dir / f"summaries-{now().strftime('%Y%m%d-%H%M%S')}.json"
    write_private(path, json.dumps({"field_names": pc.SUMMARY_FIELD_NAMES, "records": recs}, ensure_ascii=False, indent=2))
    return str(path)


def new_report(cursor: int) -> dict:
    return {
        "resume_cursor": cursor,
        "started": ts(),
        "whitelist": {
            "initiated": sorted(pc.INITIATED_ALLOWED) + ["HEARTBEAT wire8 empty (official cadence)"],
            "responses": sorted(pc.RESPONSE_ALLOWED),
            "forbidden_not_sent": [
                "getSystemTime/wire23468",
                "setSysSetup/10004/wire33464",
                "setTherapySetup/10006/wire33466",
                "clearDevice/9744",
                "setWorkState/9712",
                "OTA 1012/1014/1026",
                "invented 9820 states or 1093 cursors other than the official resume rule",
                "9772 retry / App 20s timeout loop",
            ],
        },
        "discovered": False,
        "rssi": None,
        "connect": None,
        "services": None,
        "fe64_properties": None,
        "mtu_size": None,
        "notify": None,
        "requests": [],
        "replies": [],
        "auth": {
            "verify_challenge_passed": False,
            "confirm_reply_received": False,
            "confirm_reply_passed": False,
            "authenticated": False,
        },
        "disconnect": None,
        "stop_reason": None,
        "permission": None,
    }


class E6BleClient:
    """One bounded download per call: scan -> connect -> auth -> download(cursor)."""

    def __init__(self, target_name: str, pem_path: Path, *,
                 scan_timeout: float = SCAN_TIMEOUT, connect_timeout: float = CONNECT_TIMEOUT):
        self.target_name = target_name
        self.pem_path = Path(pem_path)
        self.scan_timeout = scan_timeout
        self.connect_timeout = connect_timeout

    def _finish(self, report: dict, code: int, evidence_dir: Path | None) -> int:
        if evidence_dir is not None:
            write_private(evidence_dir / f"report-download-c{report.get('resume_cursor', 0)}.json",
                          json.dumps(report, ensure_ascii=False, indent=2, default=str))
        return code

    async def download(self, cursor: int = 0, *,
                       evidence_dir: Path | None = None, health_dir: Path | None = None,
                       scanner=None, client_factory=None,
                       want_device_info: bool = False) -> dict:
        """Return {code, report, summaries, next_cursor}. Read-only; bounded by download.py caps.

        scanner/client_factory allow HA to inject its adapter-routed scanner and
        BleakClient (ESPHome proxy support); defaults to plain bleak.
        """
        report = new_report(cursor)
        sess = Session(report)
        sess.resume_cursor = cursor

        async def finish(code: int) -> dict:
            # _cleanup (already run on connected paths) filled report["read"];
            # for early exits it has not run yet, so the read section may be absent.
            report.setdefault("read", {})
            if health_dir is not None:
                try:
                    report["read"]["private_archive"] = save_private_health(sess, health_dir)
                except Exception as ex:
                    report["read"]["health_archive_error"] = type(ex).__name__
            next_cursor = report["read"].get("next_cursor")
            if next_cursor is None and sess.completed_record_nos:
                next_cursor = max(sess.completed_record_nos)
            report["read"].setdefault("next_cursor", next_cursor)
            self._finish(report, code, evidence_dir)
            return {"code": code, "report": report, "summaries": sess.summaries,
                    "next_cursor": next_cursor}

        loop = asyncio.get_running_loop()
        try:
            chk = await loop.run_in_executor(None, af.self_check, self.pem_path)
        except Exception as ex:
            report["stop_reason"] = f"offline self-check failed: {type(ex).__name__}"
            return await finish(1)
        report["pre_frame_check"] = {"ok": bool(chk.get("ok")), "rsa_bits": chk.get("rsa_bits")}
        if not chk.get("ok"):
            report["stop_reason"] = "offline frame self-check not ok"
            return await finish(1)

        try:
            from bleak import BleakClient as DefaultBleakClient, BleakScanner
            client_cls = client_factory or DefaultBleakClient
        except Exception as ex:
            report["stop_reason"] = f"bleak import failed: {type(ex).__name__}: {ex}"
            return await finish(1)

        try:
            if scanner is not None:
                discovered = await scanner.discover(timeout=self.scan_timeout, return_adv=True)
            else:
                discovered = await BleakScanner.discover(timeout=self.scan_timeout, return_adv=True)
        except Exception as ex:
            perm = is_tcc_or_permission(ex)
            if perm:
                report["permission"] = perm
                report["stop_reason"] = "Bluetooth permission/TCC blocked scan; not bypassing"
            else:
                report["stop_reason"] = f"scan failed: {type(ex).__name__}: {ex}"
            return await finish(1)

        scan_log = []
        scored = []
        items = discovered.items() if isinstance(discovered, dict) else []
        import logging
        _log = logging.getLogger(__name__)
        _log.info("BLE scan returned type=%s count=%s", type(discovered).__name__, len(items))
        for _addr, pair in items:
            dev, adv = pair
            score, info = match_score(dev, adv, self.target_name)
            scan_log.append({k: info[k] for k in ("name", "address", "rssi", "fe60", "mfg682", "service_uuids")} | {"score": score})
            scored.append((score, dev, adv, info))
        _log.info("BLE scan candidates (names/addresses redacted): %s", [
            {k: e[k] for k in ("rssi", "fe60", "mfg682", "score")}
            for e in scan_log if e["score"] or (e["fe60"] and e["mfg682"])
        ])
        exact = [c for c in scored if c[3]["name"] == self.target_name]
        matched_by_name = bool(exact)
        if not exact:
            # HA often reports no local name (address shown instead), so fall back
            # to FE60 + manufacturer 682 — identity is then unconfirmed until the
            # GATT name read below succeeds.
            exact = [c for c in scored if c[3]["fe60"] and c[3]["mfg682"]]
            if exact:
                _log.info("matched FE60+mfg682 candidates: %d (identity unconfirmed)", len(exact))
        if evidence_dir is not None:
            write_private(evidence_dir / f"scan-download-c{cursor}.json", json.dumps(scan_log, ensure_ascii=False, indent=2))
        if not exact:
            report["stop_reason"] = "target not found in short scan"
            report["scan_count"] = len(scan_log)
            return await finish(1)
        if len({c[3]["address"] for c in exact}) > 1:
            report["stop_reason"] = "multiple advertisements matched the target name; not connecting"
            return await finish(1)
        _, dev, adv, info = exact[0]
        report["discovered"] = True
        report["rssi"] = info.get("rssi")
        report["device"] = {"name_matched": matched_by_name, "model": model_from_name(self.target_name),
                            "fe60": info.get("fe60"), "mfg682": info.get("mfg682")}

        n, e, d = await loop.run_in_executor(None, af.load_key, self.pem_path)
        num1 = secrets.randbelow(100)
        num2 = secrets.randbelow(100)
        aes_key_buf = bytearray(af.random_aes_key_24())
        sess.aes_key = bytes(aes_key_buf)
        v_wire = af.wrap_rsa(n, d, af.fill_crc_body(af.build_body(af.WIRE_VERIFY_SERVER, 0, 0, struct.pack(">II", num1, num2))))
        c_wire = af.wrap_rsa(n, d, af.fill_crc_body(af.build_body(af.WIRE_CONFIRM_KEY, 24, 1, bytes(aes_key_buf))))
        if len(v_wire) != 132 or len(c_wire) != 132:
            report["stop_reason"] = "pre-connect wire length mismatch"
            wipe_key(aes_key_buf)
            return await finish(1)

        client = None
        notified = False
        try:
            client = client_cls(dev, timeout=self.connect_timeout)
            try:
                await client.connect()
            except Exception as ex:
                perm = is_tcc_or_permission(ex)
                report["connect"] = {"ok": False, "error": type(ex).__name__, "message": str(ex)}
                report["stop_reason"] = f"connect failed: {type(ex).__name__}" if not perm else "Bluetooth permission/TCC blocked connect; not bypassing"
                if perm:
                    report["permission"] = perm
                wipe_key(aes_key_buf)
                return await finish(1)
            sess.connect_mono = time.monotonic()
            report["connect"] = {"ok": bool(client.is_connected), "started": ts()}
            if not client.is_connected:
                report["stop_reason"] = "connect returned but is_connected is false"
                code = await _cleanup(client, notified, report, sess, 1, aes_key_buf)
                return await finish(code)
            if want_device_info:
                report["device_versions"] = await read_device_versions(client, report)
            # The scan may have matched on FE60+682 alone, so confirm identity now.
            actual_name = await read_device_name(client, report)
            if actual_name is not None:
                report["device"]["name_matched"] = actual_name == self.target_name
                if actual_name != self.target_name:
                    report["stop_reason"] = "connected device name does not match target"
                    code = await _cleanup(client, notified, report, sess, 1, aes_key_buf)
                    return await finish(code)
            elif not matched_by_name:
                # No name in the advertisement and none readable over GATT: identity
                # cannot be proven, so leave the device alone.
                report["stop_reason"] = (
                    "device identity unconfirmed; no GATT name"
                    f" ({report.get('device_name_error') or 'not advertised'})"
                )
                code = await _cleanup(client, notified, report, sess, 1, aes_key_buf)
                return await finish(code)

            try:
                svcs = client.services
                getter = getattr(client, "get_services", None)
                if getter and (svcs is None or (hasattr(svcs, "__len__") and len(cast(Any, svcs)) == 0)):
                    svcs = await getter()
            except Exception as ex:
                report["services"] = {"ok": False, "error": type(ex).__name__, "message": str(ex)}
                report["stop_reason"] = "service discovery failed"
                code = await _cleanup(client, notified, report, sess, 1, aes_key_buf)
                return await finish(code)

            fe60 = fe64 = None
            for s in svcs:
                su = str(s.uuid).lower()
                if "0000fe60-" in su or su.replace("-", "").endswith("fe60"):
                    fe60 = s
                    for c in s.characteristics:
                        cu = str(c.uuid).lower()
                        if "0000fe64-" in cu or cu.replace("-", "").endswith("fe64"):
                            fe64 = c
            report["services"] = {"ok": bool(fe60 and fe64), "fe60": bool(fe60), "fe64": bool(fe64)}
            if fe64 is not None:
                report["fe64_properties"] = char_props(fe64)
            try:
                report["mtu_size"] = int(client.mtu_size)
            except Exception as ex:
                report["mtu_size"] = None
                report["mtu_size_error"] = f"{type(ex).__name__}: {ex}"
            if not fe60 or not fe64:
                report["stop_reason"] = "FE60/FE64 not found after connect; not writing"
                code = await _cleanup(client, notified, report, sess, 1, aes_key_buf)
                return await finish(code)
            props = set(report["fe64_properties"] or [])
            if "write" not in props:
                report["stop_reason"] = "FE64 properties do not include write (with response); not sending"
                code = await _cleanup(client, notified, report, sess, 1, aes_key_buf)
                return await finish(code)

            try:
                await client.start_notify(CHAR_FE64, sess.on_notify)
                notified = True
                report["notify"] = {"ok": True}
            except Exception as ex:
                report["notify"] = {"ok": False, "error": type(ex).__name__, "message": str(ex)}
                report["stop_reason"] = f"StartNotify FE64 failed: {type(ex).__name__}"
                code = await _cleanup(client, notified, report, sess, 1, aes_key_buf)
                return await finish(code)

            v_req = {"kind": "VERIFY_SERVER", "count": 1, "wire": redact_hex(v_wire.hex())}
            ok = await write_sliced(client, CHAR_FE64, v_wire, v_req, sess)
            report["requests"].append(v_req)
            if not ok:
                report["stop_reason"] = "VERIFY_SERVER GATT write failed; not resending"
                code = await _cleanup(client, notified, report, sess, 1, aes_key_buf)
                return await finish(code)
            sess.logical_sent = max(sess.logical_sent, 1)

            frames = await wait_frames(sess, min(NOTIFY_WAIT, sess.remaining()))
            if not frames:
                report["stop_reason"] = "VERIFY_SERVER write completed but no complete reply; CONFIRM_KEY not sent"
                code = await _cleanup(client, notified, report, sess, 1, aes_key_buf)
                return await finish(code)
            try:
                parsed = af.parse_wire(n, d, None, frames[0])
            except Exception as ex:
                report["replies"].append({"kind": "unparsed_verify_reply", "wire": redact_hex(frames[0].hex()), "error": type(ex).__name__})
                report["stop_reason"] = "VERIFY reply decrypt/parse failed; not sending CONFIRM_KEY"
                code = await _cleanup(client, notified, report, sess, 1, aes_key_buf)
                return await finish(code)
            if len(frames) > 1:
                sess.notify_blob = b"".join(frames[1:]) + sess.notify_blob

            from .download import semantic

            sem = semantic(parsed)
            sem["kind"] = "VERIFY_SERVER_REPLY"
            match = False
            p1_ok = parsed["param1"] == 1
            if len(parsed["payload"]) >= 8:
                r1, r2 = struct.unpack(">II", parsed["payload"][:8])
                match = (r1 - 1 == num1) and (r2 + 1 == num2)
            verify_ok = parsed["command"] == af.WIRE_VERIFY_SERVER_REPLY and p1_ok and match and parsed["crc_ok"]
            sem["param1_ok"] = p1_ok
            sem["challenge_match"] = match
            sem["passed"] = verify_ok
            report["replies"].append(sem)
            report["auth"]["verify_challenge_passed"] = verify_ok
            if not verify_ok:
                report["stop_reason"] = "VERIFY_SERVER_REPLY failed strict checks; CONFIRM_KEY not sent"
                code = await _cleanup(client, notified, report, sess, 1, aes_key_buf)
                return await finish(code)

            c_req = {"kind": "CONFIRM_KEY", "count": 1, "wire": redact_hex(c_wire.hex())}
            ok = await write_sliced(client, CHAR_FE64, c_wire, c_req, sess)
            report["requests"].append(c_req)
            if not ok:
                report["stop_reason"] = "CONFIRM_KEY GATT write failed; not resending"
                code = await _cleanup(client, notified, report, sess, 1, aes_key_buf)
                return await finish(code)

            frames2 = await wait_frames(sess, min(NOTIFY_WAIT, sess.remaining()))
            if not frames2:
                report["stop_reason"] = "CONFIRM_KEY write completed but no confirmation reply; not inferring auth success"
                code = await _cleanup(client, notified, report, sess, 1, aes_key_buf)
                return await finish(code)
            try:
                parsed2 = af.parse_wire(n, d, bytes(aes_key_buf), frames2[0])
                if len(frames2) > 1:
                    sess.notify_blob = b"".join(frames2[1:]) + sess.notify_blob
                ok2 = af.confirm_reply_ok(parsed2)
                sem2 = semantic(parsed2)
                sem2["kind"] = "CONFIRM_KEY_REPLY" if parsed2.get("command") == af.WIRE_CONFIRM_KEY_REPLY else f"cmd_{parsed2.get('command')}"
                sem2["passed"] = ok2
                sem2["param1_observed_not_criterion"] = parsed2.get("param1")
                report["replies"].append(sem2)
                report["auth"]["confirm_reply_received"] = parsed2.get("command") == af.WIRE_CONFIRM_KEY_REPLY
                report["auth"]["confirm_reply_passed"] = ok2
                report["auth"]["authenticated"] = bool(report["auth"]["verify_challenge_passed"] and ok2)
                if not report["auth"]["authenticated"]:
                    report["stop_reason"] = "CONFIRM decrypted but App success condition (cmd==3 and CRC) not met"
                    code = await _cleanup(client, notified, report, sess, 1, aes_key_buf)
                    return await finish(code)
            except Exception as ex:
                report["replies"].append({"kind": "unparsed_confirm_reply", "wire": redact_hex(frames2[0].hex()), "error": type(ex).__name__})
                report["stop_reason"] = "CONFIRM reply AES decrypt/parse failed; not inferring auth success"
                code = await _cleanup(client, notified, report, sess, 1, aes_key_buf)
                return await finish(code)

            try:
                reason = await post_auth(client, sess)
                report["stop_reason"] = reason
            except SessionLimits as ex:
                report["stop_reason"] = str(ex)
            # exit_code needs report["counts"], which _cleanup fills in, so the code
            # must be computed after the cleanup has run.
            await _cleanup(client, notified, report, sess, 0, aes_key_buf)
            return await finish(exit_code(report))
        except SessionLimits as ex:
            report["stop_reason"] = str(ex)
            if client is not None:
                await _cleanup(client, notified, report, sess, 0, aes_key_buf)
                return await finish(exit_code(report))
            wipe_key(aes_key_buf)
            return await finish(1)
        except Exception as ex:
            perm = is_tcc_or_permission(ex)
            if perm:
                report["permission"] = perm
                report["stop_reason"] = "Bluetooth permission/TCC error; not bypassing"
            else:
                report["stop_reason"] = f"exception {type(ex).__name__}: {ex}"
                report["traceback"] = traceback.format_exc()[-800:]
            if client is not None:
                code = await _cleanup(client, notified, report, sess, 1, aes_key_buf)
                return await finish(code)
            wipe_key(aes_key_buf)
            return await finish(1)
