#!/usr/bin/env python3
"""Offline tests for the active-download probe (9820 state=1 Dart path).

No BLE scan/connect. handle_incoming is driven with a fake client; frame
construction and gating are asserted from the recorded writes/report.
"""
from __future__ import annotations

import struct
import unittest

import _bootstrap  # noqa: F401
from bmc_e6.bmc_ble import auth_frames as af
from bmc_e6.bmc_ble import protocol_cmds as pc
from bmc_e6.bmc_ble import download as rd


class FakeClient:
    def __init__(self):
        self.writes = []

    async def write_gatt_char(self, _uuid, data, response=True):
        self.writes.append(bytes(data))


def parsed(cmd, payload=b"", param1=0, param2=0):
    return {"command": cmd, "payload": payload, "param1": param1, "param2": param2,
            "crc_ok": True, "body_len": 18 + len(payload)}


def make_sess():
    report = {"requests": [], "replies": []}
    sess = rd.Session(report)
    sess.aes_key = af.random_aes_key_24()
    return sess


def sent_kinds(sess):
    return [r["kind"] for r in sess.report["requests"]]


class ActiveDownloadTests(unittest.IsolatedAsyncioTestCase):
    async def test_1416_triggers_single_active_9820(self):
        sess, client = make_sess(), FakeClient()
        reason = await rd.handle_incoming(client, sess, parsed(1416))
        self.assertIsNone(reason)
        self.assertTrue(sess.sent_9820)
        kinds = sent_kinds(sess)
        self.assertEqual(kinds.count("DOWNLOAD_9820_STATE1"), 1)
        self.assertIn("ACK_1416", kinds)
        self.assertEqual(sess.report["active_download"]["after_incoming"], 1416)
        # 9820 frame request is wire 33280 with a 1-byte payload (state=1).
        req = next(r for r in sess.report["requests"] if r["kind"] == "DOWNLOAD_9820_STATE1")
        self.assertEqual(req["wire_cmd"], pc.WIRE_9820)
        self.assertEqual(req["payload_len"], 1)
        # A second 1416 must not resend 9820.
        reason = await rd.handle_incoming(client, sess, parsed(1416))
        self.assertIsNone(reason)
        self.assertEqual(sent_kinds(sess).count("DOWNLOAD_9820_STATE1"), 1)

    async def test_1520_after_active_9820_does_not_resend(self):
        sess, client = make_sess(), FakeClient()
        sess.sent_9820 = True
        reason = await rd.handle_incoming(client, sess, parsed(1520, struct.pack("<II", 0, 5)))
        self.assertIsNone(reason)
        self.assertTrue(sess.got_1520)
        self.assertEqual((sess.range_min, sess.range_max), (0, 5))
        self.assertNotIn("DOWNLOAD_9820_STATE1", sent_kinds(sess))

    async def test_1092_answered_cursor0_after_active_9820(self):
        sess, client = make_sess(), FakeClient()
        sess.sent_9820 = True  # active path: no 1520 needed for official empty-DB 0
        reason = await rd.handle_incoming(client, sess, parsed(pc.WIRE_SUMMARY_LAST_NO))
        self.assertIsNone(reason)
        self.assertTrue(sess.sent_1093)
        self.assertIn("REPLY_1093_CURSOR0", sent_kinds(sess))

    async def test_1092_without_any_download_still_stops(self):
        sess, client = make_sess(), FakeClient()
        reason = await rd.handle_incoming(client, sess, parsed(pc.WIRE_SUMMARY_LAST_NO))
        self.assertIsNotNone(reason)
        self.assertFalse(sess.sent_1093)
        self.assertNotIn("REPLY_1093_CURSOR0", sent_kinds(sess))

    async def test_1090_accepted_on_active_path(self):
        sess, client = make_sess(), FakeClient()
        sess.sent_9820 = True
        reason = await rd.handle_incoming(client, sess, parsed(pc.WIRE_SUMMARY_END))
        self.assertIsNone(reason)
        self.assertIn("ACK_1090", sent_kinds(sess))


class SafetyTests(unittest.TestCase):
    def test_shared_whitelist_unchanged(self):
        self.assertIn("DOWNLOAD_9820_STATE1", pc.INITIATED_ALLOWED)
        self.assertIn(pc.WIRE_HEARTBEAT, pc.FORBIDDEN_WIRE)
        with self.assertRaises(PermissionError):
            pc.assert_allowed_send("DOWNLOAD_9820_STATE1", pc.WIRE_9820, bytes([2]))


if __name__ == "__main__":
    unittest.main()
