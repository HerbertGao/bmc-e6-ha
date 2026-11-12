#!/usr/bin/env python3
"""Offline tests for resume download: 1093 resume cursor, completion tracking."""
from __future__ import annotations

import struct
import unittest
from datetime import datetime

import _bootstrap  # noqa: F401
from bmc_e6.bmc_ble import auth_frames as af
from bmc_e6.bmc_ble import protocol_cmds as pc
from bmc_e6.bmc_ble import download as rr


class FakeClient:
    def __init__(self):
        self.writes = []

    async def write_gatt_char(self, _uuid, data, response=True):
        self.writes.append(bytes(data))


def parsed(cmd, payload=b"", param1=0, param2=0):
    return {"command": cmd, "payload": payload, "param1": param1, "param2": param2,
            "crc_ok": True, "body_len": 18 + len(payload)}


def make_sess(cursor=0):
    sess = rr.Session({"requests": [], "replies": []})
    sess.aes_key = af.random_aes_key_24()
    sess.resume_cursor = cursor
    sess.sent_9820 = True
    return sess


def summary_payload(record_no):
    return pc.pack_new_summary_info({
        "recordDate": datetime(2026, 10, 21, 12), "recordNo": record_no,
        "treatTime": 3600, "ahi": 5, "headFlag": 0xA55A, "size": 256,
    })


class BuildResumeCursorTests(unittest.TestCase):
    def test_zero_uses_pc_whitelist(self):
        sess = make_sess(0)
        wire, kind = rr.build_1093_resume(sess, 0)
        self.assertEqual(kind, "REPLY_1093_CURSOR0")
        pc.assert_allowed_send(kind, pc.WIRE_SUMMARY_LAST_NO_REPLY, struct.pack(">I", 0))

    def test_resume_cursor_frame(self):
        sess = make_sess(20)
        wire, kind = rr.build_1093_resume(sess, 20)
        self.assertEqual(kind, "REPLY_1093_CURSOR_RESUME")
        assert sess.aes_key is not None
        parsed = pc.inspect_aes_send(sess.aes_key, wire)
        self.assertTrue(parsed["crc_ok"])
        self.assertEqual(parsed["command"], 1093)
        self.assertEqual(parsed["param1"], 1)
        self.assertEqual(parsed["payload"], struct.pack(">I", 20))  # Netty writeInt BE

    def test_out_of_range_rejected(self):
        sess = make_sess()
        for bad in (-1, 0x100000000):
            with self.assertRaises(PermissionError):
                rr.build_1093_resume(sess, bad)


class Resume1092Tests(unittest.IsolatedAsyncioTestCase):
    async def test_1092_answered_with_resume_cursor(self):
        sess, client = make_sess(20), FakeClient()
        reason = await rr.handle_incoming(client, sess, parsed(pc.WIRE_SUMMARY_LAST_NO))
        self.assertIsNone(reason)
        reqs = [r for r in sess.report["requests"] if r["kind"] == "REPLY_1093_CURSOR_RESUME"]
        self.assertEqual(len(reqs), 1)
        self.assertEqual(reqs[0]["cursor"], 20)
        self.assertIn("REPLY_1093_CURSOR_RESUME_cursor=20", sess.acks_sent)

    async def test_1092_zero_cursor_uses_whitelist_kind(self):
        sess, client = make_sess(0), FakeClient()
        reason = await rr.handle_incoming(client, sess, parsed(pc.WIRE_SUMMARY_LAST_NO))
        self.assertIsNone(reason)
        kinds = [r["kind"] for r in sess.report["requests"]]
        self.assertIn("REPLY_1093_CURSOR0", kinds)


class CompletionTrackingTests(unittest.IsolatedAsyncioTestCase):
    async def test_1090_marks_record_complete(self):
        sess, client = make_sess(20), FakeClient()
        await rr.handle_incoming(client, sess, parsed(pc.WIRE_SUMMARY, summary_payload(21), param1=13653))
        await rr.handle_incoming(client, sess, parsed(pc.WIRE_SUMMARY_END, param1=13653))
        # A newer summary without its 1090 stays incomplete.
        await rr.handle_incoming(client, sess, parsed(pc.WIRE_SUMMARY, summary_payload(22), param1=13654))
        self.assertEqual(sess.completed_record_nos, {21})
        self.assertEqual(max(sess.completed_record_nos), 21)  # next round's cursor

    async def test_no_1090_nothing_complete(self):
        sess, client = make_sess(20), FakeClient()
        await rr.handle_incoming(client, sess, parsed(pc.WIRE_SUMMARY, summary_payload(21), param1=13653))
        self.assertEqual(sess.completed_record_nos, set())


if __name__ == "__main__":
    unittest.main()
