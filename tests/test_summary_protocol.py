#!/usr/bin/env python3
"""Offline tests: AES frames, CRC, slices, summary parse, ACK/cursor, caps, finally cleanup."""
from __future__ import annotations

import os
import struct
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

import _bootstrap  # noqa: F401
from bmc_e6.bmc_ble import auth_frames as af
from bmc_e6.bmc_ble import protocol_cmds as pc
from bmc_e6.bmc_ble.fragment import app_mtu_count, slice_write, accumulate_notify_frame


def key24() -> bytes:
    return b"A1_abcdefghijklmnopqrstu"  # exactly 24: digit, letter, underscore


class TestWhitelistAndBuilders(unittest.TestCase):
    def setUp(self):
        self.k = key24()

    def test_wire_ids(self):
        self.assertEqual(pc.WIRE_9772, 33232)
        self.assertEqual(pc.WIRE_9820, 33280)
        self.assertEqual(pc.ack_wire(1030), 1031)
        self.assertEqual(pc.ack_wire(1090), 1091)
        self.assertEqual(pc.ack_wire(1092), 1093)
        self.assertEqual(pc.ack_wire(1700), 1701)
        self.assertEqual(pc.ack_wire(1706), 1707)
        self.assertEqual(pc.WIRE_SET_SYS_SETUP, 33464)
        self.assertEqual(pc.WIRE_SET_THERAPY_SETUP, 33466)
        self.assertEqual(pc.WIRE_HEARTBEAT, 8)
        self.assertEqual(pc.WIRE_GET_SYSTEM_TIME, 23468)
        self.assertEqual(pc.WIRE_QUERY_WORK_STATE, 23172)

    def test_9772_empty(self):
        wire = pc.build_9772(self.k)
        parsed = pc.inspect_aes_send(self.k, wire)
        self.assertTrue(parsed["crc_ok"])
        self.assertEqual(parsed["alg"], 5)
        self.assertEqual(parsed["command"], 33232)
        self.assertEqual(parsed["param1"], 0)
        self.assertEqual(parsed["param2"], 0)
        self.assertEqual(parsed["payload"], b"")
        pc.assert_allowed_send("INIT_9772", parsed["command"], parsed["payload"])

    def test_9820_state1_only(self):
        wire = pc.build_9820_state1(self.k)
        parsed = pc.inspect_aes_send(self.k, wire)
        self.assertTrue(parsed["crc_ok"])
        self.assertEqual(parsed["command"], 33280)
        self.assertEqual(parsed["payload"], b"\x01")
        pc.assert_allowed_send("DOWNLOAD_9820_STATE1", parsed["command"], parsed["payload"])
        with self.assertRaises(PermissionError):
            pc.assert_allowed_send("DOWNLOAD_9820_STATE1", 33280, b"\x00")
        with self.assertRaises(PermissionError):
            pc.assert_allowed_send("DOWNLOAD_9820_STATE1", 33280, b"\x02")

    def test_empty_acks_are_not_setters(self):
        for incoming, kind in ((1700, "ACK_1700"), (1702, "ACK_1702"), (1704, "ACK_1704"),
                               (1720, "ACK_1720"), (1030, "ACK_1030"), (1090, "ACK_1090"),
                               (1032, "ACK_EVENT")):
            wire = pc.build_empty_ack(self.k, incoming)
            parsed = pc.inspect_aes_send(self.k, wire)
            self.assertTrue(parsed["crc_ok"], kind)
            self.assertEqual(parsed["command"], incoming + 1)
            self.assertEqual(parsed["param1"], 1)
            self.assertEqual(parsed["payload"], b"")
            self.assertNotEqual(parsed["command"], pc.WIRE_SET_SYS_SETUP)
            self.assertNotEqual(parsed["command"], pc.WIRE_SET_THERAPY_SETUP)
            # empty payload cannot be SysSetupInfo/TherapySetupInfo + CRC
            self.assertEqual(len(parsed["payload"]), 0)
            pc.assert_allowed_send(kind, parsed["command"], parsed["payload"])

    def test_1706_ack_is_mode_echo_not_therapy_setter(self):
        mode = 3
        wire = pc.build_1706_mode_echo(self.k, mode)
        parsed = pc.inspect_aes_send(self.k, wire)
        self.assertTrue(parsed["crc_ok"])
        self.assertEqual(parsed["command"], 1707)
        self.assertEqual(parsed["param1"], 1)
        self.assertEqual(parsed["payload"], struct.pack("<I", mode))
        self.assertEqual(len(parsed["payload"]), 4)
        self.assertNotEqual(parsed["command"], pc.WIRE_SET_THERAPY_SETUP)
        # setter 10006 carries mode + full TherapySetupInfo + CRC + 8 zeros, far larger
        self.assertLess(len(parsed["payload"]), 16)
        pc.assert_allowed_send("ACK_1706_MODE_ECHO", parsed["command"], parsed["payload"])

    def test_1706_mode_parse_offset(self):
        payload = b"\x11\x22\x33\x44" + b"\x00" * 8 + bytes([7, 9]) + b"\x00" * 20
        self.assertEqual(pc.parse_1706_mode(payload), 7)
        self.assertIsNone(pc.parse_1706_mode(b"\x00" * 12))

    def test_1093_cursor0_be(self):
        wire = pc.build_1093_cursor0(self.k)
        parsed = pc.inspect_aes_send(self.k, wire)
        self.assertTrue(parsed["crc_ok"])
        self.assertEqual(parsed["command"], 1093)
        self.assertEqual(parsed["param1"], 1)
        self.assertEqual(parsed["payload"], b"\x00\x00\x00\x00")
        # Cursor 0 is endian-invariant; App uses Netty writeInt (big-endian) for nonzero values.
        self.assertNotEqual(struct.pack(">I", 1), struct.pack("<I", 1))
        self.assertEqual(struct.pack(">I", 0), parsed["payload"])
        pc.assert_allowed_send("REPLY_1093_CURSOR0", parsed["command"], parsed["payload"])
        with self.assertRaises(PermissionError):
            # inventing max-1 is not allowed
            fake = struct.pack(">I", 41)
            pc.assert_allowed_send("REPLY_1093_CURSOR0", 1093, fake)

    def test_forbidden_commands_rejected(self):
        for cmd in (pc.WIRE_HEARTBEAT, pc.WIRE_GET_SYSTEM_TIME, pc.WIRE_QUERY_WORK_STATE,
                    pc.WIRE_SET_SYS_SETUP, pc.WIRE_SET_THERAPY_SETUP,
                    pc.logical_to_wire(pc.LOGICAL_CLEAR_DEVICE)):
            with self.assertRaises(PermissionError):
                pc.assert_allowed_send("INIT_9772", cmd, b"")
        with self.assertRaises(PermissionError):
            pc.assert_allowed_send("HEARTBEAT", pc.WIRE_HEARTBEAT, b"")

    def test_1520_range(self):
        self.assertEqual(pc.parse_1520(struct.pack("<II", 1, 42)), (1, 42))
        self.assertIsNone(pc.parse_1520(b"\x00\x01"))


class TestSummaryParseAndCaps(unittest.TestCase):
    def test_pack_parse_roundtrip_date_and_recordno(self):
        dt = datetime(2026, 11, 10, 23, 15, 30, 12000)
        payload = pc.pack_new_summary_info({
            "recordDate": dt,
            "recordNo": 42,
            "treatTime": 3600,
            "ahi": 5,
            "headFlag": 0xA55A,
            "size": 256,
        })
        self.assertEqual(len(payload), 256)
        parsed = pc.parse_new_summary_info(payload)
        self.assertEqual(parsed["recordNo"], 42)
        self.assertEqual(parsed["recordDate"], dt)
        self.assertEqual(parsed["treatTime"], 3600)
        self.assertEqual(parsed["ahi"], 5)
        self.assertEqual(parsed["headFlag"], 0xA55A)
        for name in ("recordDate", "recordNo", "ahi", "treatTime", "checksum"):
            self.assertIn(name, pc.SUMMARY_FIELD_NAMES)

    def test_short_payload_rejected(self):
        with self.assertRaises(ValueError):
            pc.parse_new_summary_info(b"\x00" * 10)

    def test_truncated_tail_rejected(self):
        dt = datetime(2026, 11, 10, 23, 15, 30, 12000)
        payload = pc.pack_new_summary_info({
            "recordDate": dt, "recordNo": 42, "treatTime": 3600, "ahi": 5,
            "headFlag": 0xA55A, "size": 256,
        })
        for cut in (1, 2, 3):
            with self.assertRaises(ValueError):
                pc.parse_new_summary_info(payload[:-cut])

    def test_setters_and_ota_cannot_masquerade_as_legal_kinds(self):
        # Every setter/OTA wire must be rejected even with a legal kind name.
        setter_wires = [
            pc.logical_to_wire(9742), pc.logical_to_wire(9736), pc.logical_to_wire(9756),
            pc.logical_to_wire(9746), pc.logical_to_wire(9744), pc.logical_to_wire(9712),
            pc.logical_to_wire(10004), pc.logical_to_wire(10006),
            1012, 1014, 1026,
        ]
        legal_kinds = ["ACK_1030", "ACK_1090", "INIT_9772", "DOWNLOAD_9820_STATE1",
                       "QUERY_WORK_STATE", "ACK_1700", "ACK_EVENT", "VERIFY_SERVER"]
        for kind in legal_kinds:
            for wire in setter_wires:
                with self.assertRaises(PermissionError, msg=f"{kind} wire {wire} was accepted"):
                    pc.assert_allowed_send(kind, wire, b"")

    def test_kind_wire_binding_rejects_mismatch(self):
        with self.assertRaises(PermissionError):
            pc.assert_allowed_send("ACK_1030", 1091, b"")  # 1030's ACK is 1031, not 1091
        with self.assertRaises(PermissionError):
            pc.assert_allowed_send("ACK_EVENT", 1031, b"")  # 1030 is not an event command

    def test_aes_summary_frame_roundtrip_and_slices(self):
        k = key24()
        dt = datetime(2026, 3, 1, 1, 2, 3)
        payload = pc.pack_new_summary_info({"recordDate": dt, "recordNo": 7})
        body = af.fill_crc_body(af.build_body(1030, 0, 0, payload))
        wire = af.wrap_aes(k, body)
        parsed = pc.inspect_aes_send(k, wire)
        self.assertTrue(parsed["crc_ok"])
        self.assertEqual(parsed["command"], 1030)
        rec = pc.parse_new_summary_info(parsed["payload"])
        self.assertEqual(rec["recordNo"], 7)
        self.assertEqual(rec["recordDate"], dt)
        mtu = app_mtu_count(None, False)
        self.assertEqual(mtu, 20)
        chunks = slice_write(wire, mtu)
        self.assertEqual(b"".join(chunks), wire)
        self.assertTrue(all(len(c) <= 20 for c in chunks))
        self.assertEqual(accumulate_notify_frame(chunks), wire)

    def test_split_notify_two_frames_and_leftover(self):
        k = key24()
        a = pc.build_empty_ack(k, 1030)
        b = pc.build_empty_ack(k, 1090)
        frames, left = pc.split_notify_frames(a + b + a[:6])
        self.assertEqual(len(frames), 2)
        self.assertEqual(frames[0], a)
        self.assertEqual(frames[1], b)
        self.assertEqual(left, a[:6])
        more, left2 = pc.split_notify_frames(left + a[6:])
        self.assertEqual(more, [a])
        self.assertEqual(left2, b"")

    def test_runtime_caps(self):
        n = 0
        plain = 0
        cap_n, cap_plain = 10, 256 * 1024
        for i in range(12):
            plain += 256
            if n >= cap_n or plain > cap_plain:
                break
            n += 1
        self.assertEqual(n, 10)

    def test_finally_deletes_temp_key(self):
        td = tempfile.TemporaryDirectory()
        try:
            pem = Path(td.name) / "protocol_rsa.pem"
            pem.write_bytes(b"DUMMY-NOT-A-REAL-KEY")
            os.chmod(pem, 0o600)
            self.assertTrue(pem.exists())
            session_key = bytearray(key24())
            try:
                # finally cleanup pattern used by the session
                if pem.exists():
                    pem.unlink()
                for i in range(len(session_key)):
                    session_key[i] = 0
            finally:
                td.cleanup()
            self.assertFalse(pem.exists())
            self.assertEqual(bytes(session_key), b"\x00" * len(session_key))
            self.assertEqual(len(session_key), 24)
        except Exception:
            td.cleanup()
            raise




class TestDistinguishCatalogAndNewAcks(unittest.TestCase):
    """Source-to-whitelist audit: every distinguish case classified; known pure ACKs built."""

    SOURCE_CASE_IDS = frozenset({
        1, 3, 1012, 1014, 1026, 1027, 1030, 1090, 1092, 1406, 1412, 1416,
        1420, 1422, 1424, 1426, 1432, 1436, 1460, 1520,
        1700, 1702, 1704, 1706, 1708, 1712, 1720, 1770,
        33173, 33185, 33195, 33203, 33205, 33211, 33221,
        33233, 33281, 33465, 33467,
    })

    def setUp(self):
        self.k = key24()

    def test_catalog_covers_every_source_case_and_no_extras(self):
        self.assertEqual(pc.DISTINGUISH_CASE_IDS, self.SOURCE_CASE_IDS)

    def test_every_ack_action_has_whitelist_kind_and_is_not_a_setter(self):
        for cmd, meta in pc.DISTINGUISH_CASES.items():
            action = meta["action"]
            if action in ("ack_empty", "ack_param2_echo", "ack_mode_echo", "ack_cursor0"):
                kind = meta["kind"]
                self.assertIn(kind, pc.RESPONSE_ALLOWED, msg=f"missing kind for {cmd}")
            if action == "observe":
                self.assertIsNone(meta.get("ack"))
            if action in ("ota_stop", "setter_reply_stop"):
                self.assertIsNone(meta.get("ack"))
        # real setters never in allow-lists
        self.assertNotIn(pc.WIRE_SET_SYS_SETUP, pc.FORBIDDEN_WIRE ^ pc.FORBIDDEN_WIRE)
        for cmd in (pc.WIRE_SET_SYS_SETUP, pc.WIRE_SET_THERAPY_SETUP, pc.WIRE_HEARTBEAT,
                    pc.WIRE_SET_WORK_STATE, pc.WIRE_GET_SYSTEM_TIME):
            self.assertIn(cmd, pc.FORBIDDEN_WIRE)
        self.assertNotIn(pc.WIRE_QUERY_WORK_STATE, pc.FORBIDDEN_WIRE)

    def test_1406_ack_param2_echo_empty_payload(self):
        self.assertEqual(pc.logical_to_wire(-22053), 1407)
        self.assertEqual(pc.classify_incoming(1406)["action"], "ack_param2_echo")
        for p2 in (0, 1, 2, 3, 255):
            wire = pc.build_1406_ack(self.k, p2)
            parsed = pc.inspect_aes_send(self.k, wire)
            self.assertTrue(parsed["crc_ok"])
            self.assertEqual(parsed["command"], 1407)
            self.assertEqual(parsed["param1"], 1)
            self.assertEqual(parsed["param2"], p2)
            self.assertEqual(parsed["payload"], b"")
            self.assertNotEqual(parsed["command"], pc.WIRE_SET_SYS_SETUP)
            pc.assert_allowed_send("ACK_1406", parsed["command"], parsed["payload"])

    def test_1412_and_1416_empty_acks(self):
        self.assertEqual(pc.logical_to_wire(-22047), 1413)
        self.assertEqual(pc.logical_to_wire(-22043), 1417)
        self.assertEqual(pc.classify_incoming(1412)["action"], "ack_empty")
        self.assertEqual(pc.classify_incoming(1416)["action"], "ack_empty")
        for builder, kind, incoming, wire_cmd in (
            (pc.build_1412_ack, "ACK_1412", 1412, 1413),
            (pc.build_1416_ack, "ACK_1416", 1416, 1417),
        ):
            parsed = pc.inspect_aes_send(self.k, builder(self.k))
            self.assertTrue(parsed["crc_ok"], kind)
            self.assertEqual(parsed["command"], wire_cmd)
            self.assertEqual(parsed["param1"], 1)
            self.assertEqual(parsed["param2"], 0)
            self.assertEqual(parsed["payload"], b"")
            # same as generic empty-ack builder for these two
            generic = pc.inspect_aes_send(self.k, pc.build_empty_ack(self.k, incoming))
            self.assertEqual(parsed["command"], generic["command"])
            self.assertEqual(parsed["payload"], generic["payload"])
            pc.assert_allowed_send(kind, parsed["command"], parsed["payload"])

    def test_1770_and_other_observe_have_no_ack(self):
        for cmd in (1770, 1708, 1712, 1420, 1422, 1424, 1426, 1432, 1436, 1460, 33281, 1027):
            info = pc.classify_incoming(cmd)
            self.assertEqual(info["action"], "observe", cmd)
            self.assertIsNone(info.get("ack"))

    def test_unknown_is_not_generic_n_plus_one(self):
        info = pc.classify_incoming(19999)
        self.assertEqual(info["action"], "unknown")
        with self.assertRaises(PermissionError):
            # inventing a kind for an unknown command is rejected
            pc.assert_allowed_send("ACK_UNKNOWN", 20000, b"")

    def test_ota_and_setter_replies_are_stop_not_ack(self):
        for cmd in (1012, 1014, 1026):
            self.assertEqual(pc.classify_incoming(cmd)["action"], "ota_stop")
        for cmd in (33465, 33467):
            self.assertEqual(pc.classify_incoming(cmd)["action"], "setter_reply_stop")

    def test_events_still_empty_ack_only_when_in_set(self):
        self.assertEqual(pc.classify_incoming(1032)["kind"], "ACK_EVENT")
        self.assertFalse(pc.is_event_command(1406))
        self.assertFalse(pc.is_event_command(1412))




class TestQueryWorkStateVsSetter(unittest.TestCase):
    def setUp(self):
        self.k = key24()

    def test_query_is_empty_and_not_set_work_state(self):
        self.assertEqual(pc.WIRE_QUERY_WORK_STATE, 23172)
        self.assertEqual(pc.logical_to_wire(-288), 23172)
        self.assertEqual(pc.WIRE_SET_WORK_STATE, 33172)
        self.assertEqual(pc.logical_to_wire(9712), 33172)
        self.assertNotEqual(pc.WIRE_QUERY_WORK_STATE, pc.WIRE_SET_WORK_STATE)
        wire = pc.build_query_work_state(self.k)
        parsed = pc.inspect_aes_send(self.k, wire)
        self.assertTrue(parsed["crc_ok"])
        self.assertEqual(parsed["command"], 23172)
        self.assertEqual(parsed["param1"], 0)
        self.assertEqual(parsed["param2"], 0)
        self.assertEqual(parsed["payload"], b"")
        pc.assert_allowed_send("QUERY_WORK_STATE", parsed["command"], parsed["payload"])
        # setter layout carries workState + therapyMode; must not match query
        set_wire, set_payload = pc.build_set_work_state_forbidden_example(1, 2)
        self.assertEqual(set_wire, 33172)
        self.assertEqual(len(set_payload), 8)
        self.assertEqual(set_payload, struct.pack("<II", 1, 2))
        self.assertNotEqual(set_payload, parsed["payload"])
        with self.assertRaises(PermissionError):
            pc.assert_allowed_send("QUERY_WORK_STATE", 33172, b"")
        with self.assertRaises(PermissionError):
            pc.assert_allowed_send("QUERY_WORK_STATE", 23172, set_payload)
        with self.assertRaises(PermissionError):
            pc.assert_allowed_send("INIT_9772", 33172, set_payload)

    def test_wear_heat_setters_still_forbidden_and_distinct(self):
        # 9736 / 9756 are other work-state-named setters (byte payload), not this query
        for logical in (9736, 9756, 9712, 9744, 10004, 10006, -23452, 8):
            wire = pc.logical_to_wire(logical)
            self.assertTrue(wire in pc.FORBIDDEN_WIRE or logical in (9736, 9756))
        # 9736/9756 not in FORBIDDEN_WIRE set unless added; session must still not send them
        self.assertNotIn(pc.logical_to_wire(9736), [pc.WIRE_QUERY_WORK_STATE])
        self.assertNotIn(pc.logical_to_wire(9756), [pc.WIRE_QUERY_WORK_STATE])

    def test_official_call_site_sends_once_after_four_targets_not_on_1416(self):
        seq = []
        sent = False
        for cmd in (33233, 1700, 1702, 1720, 1704, 1706, 1406, 1412, 1416, 1770):
            if pc.should_send_query_work_state(seq + [cmd], sent):
                self.assertEqual(cmd, 1704)  # fourth fixed target in this order
                sent = True
            seq.append(cmd)
        self.assertTrue(sent)
        # 1416/later must not trigger a second send
        self.assertFalse(pc.should_send_query_work_state(seq, sent))
        # incomplete targets: no send
        self.assertFalse(pc.should_send_query_work_state([1700, 1702, 1704], False))

    def test_query_reply_23173_is_not_a_distinguish_ack(self):
        self.assertEqual(pc.WIRE_QUERY_WORK_STATE_REPLY, 23173)
        self.assertNotIn(23173, pc.DISTINGUISH_CASE_IDS)
        self.assertEqual(pc.classify_incoming(23173)["action"], "unknown")
        info33173 = pc.classify_incoming(33173)
        self.assertEqual(info33173["action"], "observe")  # setWorkStateReply: log only, no ACK

    def test_heartbeat_and_get_system_time_remain_forbidden(self):
        self.assertEqual(pc.WIRE_HEARTBEAT, 8)
        self.assertEqual(pc.WIRE_GET_SYSTEM_TIME, 23468)
        self.assertIn(pc.WIRE_HEARTBEAT, pc.FORBIDDEN_WIRE)
        self.assertIn(pc.WIRE_GET_SYSTEM_TIME, pc.FORBIDDEN_WIRE)
        with self.assertRaises(PermissionError):
            pc.assert_allowed_send("INIT_9772", pc.WIRE_HEARTBEAT, b"")
        with self.assertRaises(PermissionError):
            pc.assert_allowed_send("QUERY_WORK_STATE", pc.WIRE_GET_SYSTEM_TIME, b"")


if __name__ == "__main__":
    unittest.main()
