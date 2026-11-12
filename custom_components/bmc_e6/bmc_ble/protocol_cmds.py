#!/usr/bin/env python3
"""Whitelist, AES command builders, ACK/cursor helpers, and NewSummaryInfo parse.

Does not send therapy/system/time setters, clear/OTA, heartbeat, or queryWorkState.
1700-family ACKs are N+1 transfer ACKs (empty, or 1706 mode echo), not host setters.
"""
from __future__ import annotations

import struct
from datetime import datetime
from typing import Optional

from . import auth_frames as af

CMD_OFFSET = 23460

# Host-initiated logical ids and their wire commands (i + 23460)
LOGICAL_9772 = 9772
WIRE_9772 = (LOGICAL_9772 + CMD_OFFSET) & 0xFFFF  # 33232
WIRE_9772_REPLY = 33233
LOGICAL_9820 = 9820
WIRE_9820 = (LOGICAL_9820 + CMD_OFFSET) & 0xFFFF  # 33280
WIRE_33281 = 33281

WIRE_SUMMARY = 1030
WIRE_SUMMARY_ACK = 1031
WIRE_SUMMARY_END = 1090
WIRE_SUMMARY_END_ACK = 1091
WIRE_SUMMARY_LAST_NO = 1092
WIRE_SUMMARY_LAST_NO_REPLY = 1093
WIRE_1520 = 1520

WIRE_1700, WIRE_1702, WIRE_1704, WIRE_1706, WIRE_1708, WIRE_1720 = 1700, 1702, 1704, 1706, 1708, 1720
WIRE_1701, WIRE_1703, WIRE_1705, WIRE_1707, WIRE_1721 = 1701, 1703, 1705, 1707, 1721

# Official host setters (FORBIDDEN). MessageToBytes(10004/10006) => wire 33464/33466.
LOGICAL_SET_SYS_SETUP = 10004
LOGICAL_SET_THERAPY_SETUP = 10006
WIRE_SET_SYS_SETUP = (LOGICAL_SET_SYS_SETUP + CMD_OFFSET) & 0xFFFF  # 33464
WIRE_SET_THERAPY_SETUP = (LOGICAL_SET_THERAPY_SETUP + CMD_OFFSET) & 0xFFFF  # 33466
WIRE_SET_SYS_SETUP_REPLY = 33465
WIRE_SET_THERAPY_SETUP_REPLY = 33467

LOGICAL_CLEAR_DEVICE = 9744
LOGICAL_SET_WORK_STATE = 9712
LOGICAL_QUERY_WORK_STATE = -288
WIRE_QUERY_WORK_STATE = (LOGICAL_QUERY_WORK_STATE + CMD_OFFSET) & 0xFFFF  # 23172
LOGICAL_HEARTBEAT = -23452
WIRE_HEARTBEAT = (LOGICAL_HEARTBEAT + CMD_OFFSET) & 0xFFFF  # 8  (named TIME; not used)
LOGICAL_GET_SYSTEM_TIME = 8
WIRE_GET_SYSTEM_TIME = (LOGICAL_GET_SYSTEM_TIME + CMD_OFFSET) & 0xFFFF  # 23468
WIRE_SET_WORK_STATE = (LOGICAL_SET_WORK_STATE + CMD_OFFSET) & 0xFFFF  # 33172
WIRE_SET_WORK_STATE_REPLY = 33173
WIRE_QUERY_WORK_STATE_REPLY = (WIRE_QUERY_WORK_STATE + 1) & 0xFFFF  # 23173; NOT a distinguish case
FIXED_INIT_TARGETS = frozenset({1700, 1702, 1704, 1720})

# App empty-DB cursor rule: dataBaseNo < 1 => 0 (Netty writeInt = big-endian).
APP_EMPTY_DB_CURSOR = 0
OFFICIAL_9820_STATE = 1

# NewBluetoothConfig.EVENTS
EVENTS = frozenset(list(range(1032, 1083, 2)) + [1108, 1110, 1112, 1114])

# Commands this session may INITIATE (not ACKs).
INITIATED_ALLOWED = frozenset({
    "VERIFY_SERVER",
    "CONFIRM_KEY",
    "INIT_9772",
    "DOWNLOAD_9820_STATE1",
    "QUERY_WORK_STATE",
})

# Commands this session may send only as a response to a received frame.
RESPONSE_ALLOWED = frozenset({
    "ACK_1700",
    "ACK_1702",
    "ACK_1704",
    "ACK_1706_MODE_ECHO",
    "ACK_1720",
    "ACK_1030",
    "ACK_1090",
    "ACK_EVENT",
    "REPLY_1093_CURSOR0",
    "ACK_1406",
    "ACK_1412",
    "ACK_1416",
})

FORBIDDEN_LOGICAL = frozenset({
    LOGICAL_CLEAR_DEVICE,
    LOGICAL_SET_WORK_STATE,
    LOGICAL_SET_SYS_SETUP,
    LOGICAL_SET_THERAPY_SETUP,
    LOGICAL_HEARTBEAT,
    LOGICAL_GET_SYSTEM_TIME,
    9742,  # setDefault (restore defaults)
    9736,  # setWearTestState
    9756,  # setHeatState
    9746,  # setConsumables
})
# Wire ids that must never be sent. WIRE_QUERY_WORK_STATE is deliberately absent:
# the client has to send it, and it is guarded by the empty-payload check instead.
FORBIDDEN_WIRE = frozenset(
    ((i + CMD_OFFSET) & 0xFFFF) for i in FORBIDDEN_LOGICAL
) | {WIRE_SET_SYS_SETUP, WIRE_SET_THERAPY_SETUP, WIRE_HEARTBEAT, WIRE_GET_SYSTEM_TIME,
     1012, 1014, 1026}  # OTA ids are wire ids, not logical+offset


def logical_to_wire(i: int) -> int:
    return (i + CMD_OFFSET) & 0xFFFF


def ack_wire(incoming_command: int) -> int:
    """summaryAndEventsReplay / 1700-family: MessageToBytes(cmd-23459) => wire cmd+1."""
    return (incoming_command + 1) & 0xFFFF


def build_aes_frame(session_key: bytes, wire_cmd: int, param1: int, param2: int, payload: bytes) -> bytes:
    body = af.fill_crc_body(af.build_body(wire_cmd, param1, param2, payload))
    return af.wrap_aes(session_key, body)


def build_9772(session_key: bytes) -> bytes:
    return build_aes_frame(session_key, WIRE_9772, 0, 0, b"")


def build_query_work_state(session_key: bytes) -> bytes:
    """Official queryWorkState / onAllTargetsCompleted: MessageToBytes(-288, 0, 0, null, 5)."""
    return build_aes_frame(session_key, WIRE_QUERY_WORK_STATE, 0, 0, b"")


def build_set_work_state_forbidden_example(work_state: int, therapy_mode: int) -> tuple[int, bytes]:
    """Layout of setWorkState (9712) for tests only — never sent live."""
    payload = struct.pack("<II", work_state, therapy_mode)
    return WIRE_SET_WORK_STATE, payload


def should_send_query_work_state(received_cmds: list[int], already_sent: bool) -> bool:
    """Official: onAllTargetsCompleted once when targetSet empty and state!=3.
    ready() after 1416 must not send a second query.
    """
    if already_sent:
        return False
    return FIXED_INIT_TARGETS.issubset(set(received_cmds))


def build_9820_state1(session_key: bytes) -> bytes:
    return build_aes_frame(session_key, WIRE_9820, 0, 0, bytes([OFFICIAL_9820_STATE]))


def build_empty_ack(session_key: bytes, incoming_command: int) -> bytes:
    return build_aes_frame(session_key, ack_wire(incoming_command), 1, 0, b"")


def build_1093_cursor0(session_key: bytes) -> bytes:
    return build_aes_frame(session_key, WIRE_SUMMARY_LAST_NO_REPLY, 1, 0, struct.pack(">I", APP_EMPTY_DB_CURSOR))


def build_1706_mode_echo(session_key: bytes, mode: int) -> bytes:
    if not (0 <= mode <= 255):
        raise ValueError("mode out of unsigned-byte range")
    return build_aes_frame(session_key, WIRE_1707, 1, 0, struct.pack("<I", mode))


WIRE_1406, WIRE_1412, WIRE_1416 = 1406, 1412, 1416
WIRE_1407, WIRE_1413, WIRE_1417 = 1407, 1413, 1417

# Complete BaseNewDataProcessing.distinguish cases (EP5/EP6/G5 only call super).
# ack=None means official sends no command, or sending would be forbidden (OTA/setter).
# Do not N+1 an unlisted command.
DISTINGUISH_CASES = {
    1: {"action": "auth_verify", "ack": None, "note": "VERIFY_SERVER_REPLY; handled in auth path"},
    3: {"action": "auth_confirm", "ack": None, "note": "CONFIRM_KEY_REPLY; official calls newDeviceConnect; we send 9772 once ourselves"},
    1012: {"action": "ota_stop", "ack": None, "note": "upgrade file request; official replies with file bytes; OTA forbidden"},
    1014: {"action": "ota_stop", "ack": None, "note": "upgrade file chunk request; official sends file+flag; OTA forbidden"},
    1026: {"action": "ota_stop", "ack": None, "note": "upgrade counts; official ACK writeShortLE(1); OTA forbidden"},
    1027: {"action": "observe", "ack": None, "note": "upgrade-related empty case; official no send"},
    1030: {"action": "ack_empty", "kind": "ACK_1030", "note": "summaryAndEventsReplay empty"},
    1090: {"action": "ack_empty", "kind": "ACK_1090", "note": "summaryAndEventsReplay empty"},
    1092: {"action": "ack_cursor0", "kind": "REPLY_1093_CURSOR0", "note": "writeInt BE cursor; empty-DB => 0"},
    1406: {"action": "ack_param2_echo", "kind": "ACK_1406", "note": "AlarmState; MessageToBytes(-22053,1,param2,null,5) => wire 1407 empty"},
    1412: {"action": "ack_empty", "kind": "ACK_1412", "note": "MessageToBytes(-22047,1,0,null,5) => wire 1413 empty; then parse uint32 LE to EventBus"},
    1416: {"action": "ack_empty", "kind": "ACK_1416", "note": "MessageToBytes(-22043,1,0,null,5) => wire 1417 empty; then ready() (we do not send -288)"},
    1420: {"action": "observe", "ack": None, "note": "WifiInfo list; official no ACK"},
    1422: {"action": "observe", "ack": None, "note": "36-byte UTF-8 string; official no ACK"},
    1424: {"action": "observe", "ack": None, "note": "SpoInfo list; official no ACK"},
    1426: {"action": "observe", "ack": None, "note": "SpoInfo list; official no ACK"},
    1432: {"action": "observe", "ack": None, "note": "wear/mask test state; official no ACK"},
    1436: {"action": "observe", "ack": None, "note": "wear/mask test state; official no ACK"},
    1460: {"action": "observe", "ack": None, "note": "state/result bytes; official no ACK"},
    1520: {"action": "range_then_9820", "ack": None, "note": "device range notify; no ACK; 9820 state=1 only after range parsed"},
    1700: {"action": "ack_empty", "kind": "ACK_1700", "note": "SysConfig push; empty 1701; not a setter"},
    1702: {"action": "ack_empty", "kind": "ACK_1702", "note": "SysFlag push; empty 1703; not a setter"},
    1704: {"action": "ack_empty", "kind": "ACK_1704", "note": "SysSetup push; empty 1705; not a setter (setter is 10004)"},
    1706: {"action": "ack_mode_echo", "kind": "ACK_1706_MODE_ECHO", "note": "TherapySetup push; 1707 + uint32 LE received mode only (setter is 10006)"},
    1708: {"action": "observe", "ack": None, "note": "device time push; official no ACK; do not write time"},
    1712: {"action": "observe", "ack": None, "note": "usage struct; official no ACK"},
    1720: {"action": "ack_empty", "kind": "ACK_1720", "note": "NewDeviceInfo push; empty 1721"},
    1770: {"action": "observe", "ack": None, "note": "realtime data; official no nativeCommand"},
    33173: {"action": "observe", "ack": None, "note": "setWorkState reply; we do not send 9712"},
    33185: {"action": "observe", "ack": None, "note": "eventbus only"},
    33195: {"action": "observe", "ack": None, "note": "eventbus only"},
    33203: {"action": "observe", "ack": None, "note": "eventbus only"},
    33205: {"action": "observe", "ack": None, "note": "eventbus only"},
    33211: {"action": "observe", "ack": None, "note": "eventbus only"},
    33221: {"action": "observe", "ack": None, "note": "eventbus only"},
    33233: {"action": "init_9772_reply", "ack": None, "note": "9772 reply; no ACK; param1!=1 must not retry"},
    33281: {"action": "observe", "ack": None, "note": "local Realm delete on official client; we send nothing"},
    33465: {"action": "setter_reply_stop", "ack": None, "note": "setSysSetup reply; we send no setter"},
    33467: {"action": "setter_reply_stop", "ack": None, "note": "setTherapySetup reply; official may then send 10004; stop, never follow"},
}

# Official switch labels that must stay classified (prevent missed known ACKs).
DISTINGUISH_CASE_IDS = frozenset(DISTINGUISH_CASES)


def classify_incoming(cmd: int) -> dict:
    if cmd in DISTINGUISH_CASES:
        return dict(DISTINGUISH_CASES[cmd], command=cmd)
    if cmd in EVENTS:
        return {"action": "ack_empty", "kind": "ACK_EVENT", "command": cmd, "note": "default EVENTS replay empty ACK"}
    return {"action": "unknown", "ack": None, "command": cmd, "note": "not in distinguish; do not generic N+1"}


def build_1406_ack(session_key: bytes, param2: int) -> bytes:
    """Official: MessageToBytes(-22053, 1, received param2, null, 5) => wire 1407, empty payload."""
    if not (0 <= int(param2) <= 0xFFFF):
        raise ValueError("param2 out of range")
    return build_aes_frame(session_key, WIRE_1407, 1, int(param2) & 0xFFFF, b"")


def build_1412_ack(session_key: bytes) -> bytes:
    return build_aes_frame(session_key, WIRE_1413, 1, 0, b"")


def build_1416_ack(session_key: bytes) -> bytes:
    return build_aes_frame(session_key, WIRE_1417, 1, 0, b"")


def parse_1520(payload: bytes) -> Optional[tuple[int, int]]:
    if len(payload) < 8:
        return None
    lo, hi = struct.unpack("<II", payload[:8])
    return lo, hi


def parse_1706_mode(payload: bytes) -> Optional[int]:
    """therapySetupInfo(buf, z=false): intLE headMode + 8-byte head, then mode uint8."""
    if len(payload) < 13:
        return None
    return payload[12]


def is_event_command(cmd: int) -> bool:
    return cmd in EVENTS


def split_notify_frames(blob: bytes) -> tuple[list[bytes], bytes]:
    frames: list[bytes] = []
    while len(blob) >= 4:
        if blob[0] != af.BLE_HEAD:
            return frames, blob
        need = 4 + int.from_bytes(blob[2:4], "big")
        if len(blob) < need:
            break
        frames.append(blob[:need])
        blob = blob[need:]
    return frames, blob


# --- NewSummaryInfo (field names only used for parse; values stay private) ---

SUMMARY_FIELD_NAMES = [
    "headFlag", "size", "mainVer", "subVer", "headRev", "recordDate", "recordNo",
    "runTime", "treatTime", "leakTime", "spo2Time", "treatCnt", "firstMode", "lastMode",
    "initP", "epapMax", "epapAvg", "epap95", "epap50", "ipapMax", "ipapAvg", "ipap95", "ipap50",
    "reserveP", "odi", "sni", "chi", "ohi", "uhi", "hi", "hiWithCh", "oai", "cai", "uai", "ai",
    "ahi", "ahiWithCh", "reraIndex", "reserveIndex", "vtMax", "vtAvg", "vt95", "vt50",
    "mvMax", "mvAvg", "mv95", "mv50", "leakMax", "leakAvg", "leak95", "leak50",
    "inspTimeMax", "inspTimeAvg", "inspTime95", "inspTime50",
    "spo2Time95to100", "spo2Time90to94", "spo2Time85to89", "spo2Time80to84",
    "spo2Time75to79", "spo2Time70to74", "spo2Time0to69",
    "spo2Max", "spo2Min", "spo2Avg", "spo295", "spo250",
    "prMax", "prMin", "prAvg", "pr95", "pr50",
    "rrMax", "rrAvg", "rr95", "rr50",
    "sInspRatio", "sExpRatio", "ieMax", "ieAvg", "ie95", "ie50",
    "periodicTime", "mildFlowLimitTime", "moderateLimitTime", "severeLimitTime", "snoreTime",
    "reserve2", "buildTime", "leakTime40L",
    "sleepStageWakeTime", "sleepStageLightTime", "sleepStageDeepTime", "mouthLeakTime",
    "hypoBurden", "tst90", "sleepStageWakeCnt", "reserve", "checksum",
]


def parse_bmc_date_raw(buf8: bytes) -> datetime:
    """NewSummaryInfo / BMCTime-style: year=byte+1900, hour as raw byte, ms uint16 LE."""
    if len(buf8) < 8:
        raise ValueError("short date")
    year = buf8[0] + 1900
    month = buf8[1]
    day = buf8[2]
    hour = buf8[3]
    minute = buf8[4]
    second = buf8[5]
    ms = int.from_bytes(buf8[6:8], "little")
    return datetime(year, month, day, hour, minute, second, ms * 1000)


def parse_new_summary_info(payload: bytes) -> dict:
    """Parse NewSummaryInfo.getnewSummaryInfo layout. Raises on short buffer."""
    if len(payload) < 16:
        raise ValueError("summary payload too short for date/recordNo")
    o = 0

    def u8():
        nonlocal o
        v = payload[o]
        o += 1
        return v

    def u16():
        nonlocal o
        v = int.from_bytes(payload[o:o + 2], "little")
        o += 2
        return v

    def i16():
        nonlocal o
        v = int.from_bytes(payload[o:o + 2], "little", signed=True)
        o += 2
        return v

    def u32():
        nonlocal o
        v = int.from_bytes(payload[o:o + 4], "little")
        o += 4
        return v

    def take(n: int) -> bytes:
        nonlocal o
        b = payload[o:o + n]
        if len(b) < n:
            raise ValueError("truncated summary")
        o += n
        return b

    out = {}
    out["headFlag"] = u16()
    out["size"] = u16()
    out["mainVer"] = u8()
    out["subVer"] = u8()
    out["headRev"] = take(2).decode("utf-8", "replace")
    date_raw = take(8)
    out["recordDate"] = parse_bmc_date_raw(date_raw)
    out["recordDate_raw"] = date_raw
    out["recordNo"] = u32()
    out["runTime"] = u32()
    out["treatTime"] = u32()
    out["leakTime"] = u32()
    out["spo2Time"] = u32()
    out["treatCnt"] = u16()
    out["firstMode"] = u8()
    out["lastMode"] = u8()
    for name in ("initP", "epapMax", "epapAvg", "epap95", "epap50", "ipapMax", "ipapAvg", "ipap95", "ipap50"):
        out[name] = u16()
    out["reserveP"] = take(18).decode("utf-8", "replace")
    for name in ("odi", "sni", "chi", "ohi", "uhi", "hi", "hiWithCh", "oai", "cai", "uai", "ai", "ahi", "ahiWithCh", "reraIndex"):
        out[name] = u16()
    out["reserveIndex"] = take(16).decode("utf-8", "replace")
    for name in ("vtMax", "vtAvg", "vt95", "vt50"):
        out[name] = u16()
    for name in ("mvMax", "mvAvg", "mv95", "mv50"):
        out[name] = u32()
    for name in ("leakMax", "leakAvg", "leak95", "leak50", "inspTimeMax", "inspTimeAvg", "inspTime95", "inspTime50"):
        out[name] = u16()
    for name in ("spo2Time95to100", "spo2Time90to94", "spo2Time85to89", "spo2Time80to84",
                 "spo2Time75to79", "spo2Time70to74", "spo2Time0to69"):
        out[name] = u16()
    for name in ("spo2Max", "spo2Min", "spo2Avg", "spo295", "spo250", "prMax", "prMin", "prAvg", "pr95", "pr50",
                 "rrMax", "rrAvg", "rr95", "rr50"):
        out[name] = u8()
    for name in ("sInspRatio", "sExpRatio", "ieMax", "ieAvg", "ie95", "ie50",
                 "periodicTime", "mildFlowLimitTime", "moderateLimitTime", "severeLimitTime", "snoreTime"):
        out[name] = u16()
    out["reserve2"] = take(2).decode("utf-8", "replace")
    out["buildTime"] = u32()
    out["leakTime40L"] = u32()
    for name in ("sleepStageWakeTime", "sleepStageLightTime", "sleepStageDeepTime", "mouthLeakTime",
                 "hypoBurden", "tst90", "sleepStageWakeCnt"):
        out[name] = u16()
    out["reserve"] = take(20).decode("utf-8", "replace")
    out["checksum"] = int.from_bytes(take(2), "little")  # bounded: truncated tail is rejected
    out["_parsed_bytes"] = o
    return out


def pack_new_summary_info(fields: dict) -> bytes:
    """Build a synthetic NewSummaryInfo payload for offline tests."""
    dt: datetime = fields["recordDate"]
    date_raw = bytes([
        dt.year - 1900, dt.month, dt.day, dt.hour, dt.minute, dt.second,
    ]) + int(dt.microsecond // 1000).to_bytes(2, "little")

    def u16(n):
        return int(n).to_bytes(2, "little")

    def u32(n):
        return int(n).to_bytes(4, "little")

    def u8(n):
        return bytes([int(n) & 0xFF])

    def pad_str(s, n):
        b = (s or "").encode("utf-8")[:n]
        return b + b"\x00" * (n - len(b))

    parts = [
        u16(fields.get("headFlag", 0)), u16(fields.get("size", 256)),
        u8(fields.get("mainVer", 1)), u8(fields.get("subVer", 0)),
        pad_str(fields.get("headRev", "  "), 2), date_raw,
        u32(fields["recordNo"]),
        u32(fields.get("runTime", 0)), u32(fields.get("treatTime", 0)),
        u32(fields.get("leakTime", 0)), u32(fields.get("spo2Time", 0)),
        u16(fields.get("treatCnt", 0)), u8(fields.get("firstMode", 0)), u8(fields.get("lastMode", 0)),
    ]
    for name in ("initP", "epapMax", "epapAvg", "epap95", "epap50", "ipapMax", "ipapAvg", "ipap95", "ipap50"):
        parts.append(u16(fields.get(name, 0)))
    parts.append(pad_str(fields.get("reserveP", ""), 18))
    for name in ("odi", "sni", "chi", "ohi", "uhi", "hi", "hiWithCh", "oai", "cai", "uai", "ai", "ahi", "ahiWithCh", "reraIndex"):
        parts.append(u16(fields.get(name, 0)))
    parts.append(pad_str(fields.get("reserveIndex", ""), 16))
    for name in ("vtMax", "vtAvg", "vt95", "vt50"):
        parts.append(u16(fields.get(name, 0)))
    for name in ("mvMax", "mvAvg", "mv95", "mv50"):
        parts.append(u32(fields.get(name, 0)))
    for name in ("leakMax", "leakAvg", "leak95", "leak50", "inspTimeMax", "inspTimeAvg", "inspTime95", "inspTime50"):
        parts.append(u16(fields.get(name, 0)))
    for name in ("spo2Time95to100", "spo2Time90to94", "spo2Time85to89", "spo2Time80to84",
                 "spo2Time75to79", "spo2Time70to74", "spo2Time0to69"):
        parts.append(u16(fields.get(name, 0)))
    for name in ("spo2Max", "spo2Min", "spo2Avg", "spo295", "spo250", "prMax", "prMin", "prAvg", "pr95", "pr50",
                 "rrMax", "rrAvg", "rr95", "rr50"):
        parts.append(u8(fields.get(name, 0)))
    for name in ("sInspRatio", "sExpRatio", "ieMax", "ieAvg", "ie95", "ie50",
                 "periodicTime", "mildFlowLimitTime", "moderateLimitTime", "severeLimitTime", "snoreTime"):
        parts.append(u16(fields.get(name, 0)))
    parts.append(pad_str(fields.get("reserve2", ""), 2))
    parts.append(u32(fields.get("buildTime", 0)))
    parts.append(u32(fields.get("leakTime40L", 0)))
    for name in ("sleepStageWakeTime", "sleepStageLightTime", "sleepStageDeepTime", "mouthLeakTime",
                 "hypoBurden", "tst90", "sleepStageWakeCnt"):
        parts.append(u16(fields.get(name, 0)))
    parts.append(pad_str(fields.get("reserve", ""), 20))
    parts.append(u16(fields.get("checksum", 0)))
    return b"".join(parts)


def aes_payload_of(session_key: bytes, wire: bytes) -> dict:
    parsed = None
    # parse_wire needs n,d only for RSA; for AES they are unused if alg=5
    return af.parse_wire(None, None, session_key, wire)  # type: ignore


def inspect_aes_send(session_key: bytes, wire: bytes) -> dict:
    """Decrypt our own outbound AES frame (for tests). parse_wire uses key only for alg 5."""
    # Temporary: parse_wire with dummy n,d is ok for alg=5.
    return af.parse_wire(1, 1, session_key, wire)


# Strict kind -> wire binding: a legal kind can never disguise a setter/OTA command.
EXPECTED_WIRE = {
    "VERIFY_SERVER": 0,
    "CONFIRM_KEY": 2,
    "INIT_9772": WIRE_9772,
    "DOWNLOAD_9820_STATE1": WIRE_9820,
    "QUERY_WORK_STATE": WIRE_QUERY_WORK_STATE,
    "ACK_1700": 1701,
    "ACK_1702": 1703,
    "ACK_1704": 1705,
    "ACK_1720": 1721,
    "ACK_1706_MODE_ECHO": WIRE_1707,
    "ACK_1030": 1031,
    "ACK_1090": 1091,
    "ACK_1412": WIRE_1413,
    "ACK_1416": WIRE_1417,
    "ACK_1406": WIRE_1407,
    "REPLY_1093_CURSOR0": WIRE_SUMMARY_LAST_NO_REPLY,
}


def assert_allowed_send(kind: str, wire_cmd: int, payload: bytes) -> None:
    if kind not in INITIATED_ALLOWED and kind not in RESPONSE_ALLOWED:
        raise PermissionError(f"kind not in whitelist: {kind}")
    if wire_cmd in FORBIDDEN_WIRE:
        raise PermissionError(f"forbidden wire command {wire_cmd}")
    expected = EXPECTED_WIRE.get(kind)
    if expected is not None and wire_cmd != expected:
        raise PermissionError(f"{kind} must use wire {expected}, not {wire_cmd}")
    if kind == "ACK_EVENT" and not is_event_command(wire_cmd - 1):
        raise PermissionError("ACK_EVENT must be event wire+1")
    # Setters carry full setup+CRC; our ACKs must never look like them.
    if wire_cmd in (WIRE_SET_SYS_SETUP, WIRE_SET_THERAPY_SETUP):
        raise PermissionError("refusing host setter command")
    if kind == "DOWNLOAD_9820_STATE1":
        if payload != bytes([OFFICIAL_9820_STATE]):
            raise PermissionError("9820 state is not official 1")
        if wire_cmd != WIRE_9820:
            raise PermissionError("9820 wire mismatch")
    if kind == "QUERY_WORK_STATE":
        if payload != b"" or wire_cmd != WIRE_QUERY_WORK_STATE:
            raise PermissionError("queryWorkState must be empty wire 23172")
        if wire_cmd == WIRE_SET_WORK_STATE:
            raise PermissionError("refusing setWorkState")
    if kind == "INIT_9772":
        if payload != b"" or wire_cmd != WIRE_9772:
            raise PermissionError("9772 must be empty wire 33232")
    if kind == "REPLY_1093_CURSOR0":
        if payload != struct.pack(">I", APP_EMPTY_DB_CURSOR) or wire_cmd != WIRE_SUMMARY_LAST_NO_REPLY:
            raise PermissionError("1093 must be BE cursor 0")
    if kind.startswith("ACK_") and kind not in ("ACK_1706_MODE_ECHO", "ACK_1406"):
        if payload != b"":
            raise PermissionError(f"{kind} must be empty ACK")
    if kind == "ACK_1706_MODE_ECHO":
        if wire_cmd != WIRE_1707 or len(payload) != 4:
            raise PermissionError("1706 ACK must be 4-byte LE mode echo only")
    if kind == "ACK_1406":
        if wire_cmd != WIRE_1407 or payload != b"":
            raise PermissionError("1406 ACK must be wire 1407 with empty payload and echoed param2")
    if kind == "ACK_1412":
        if wire_cmd != WIRE_1413 or payload != b"":
            raise PermissionError("1412 ACK must be empty wire 1413")
    if kind == "ACK_1416":
        if wire_cmd != WIRE_1417 or payload != b"":
            raise PermissionError("1416 ACK must be empty wire 1417")
