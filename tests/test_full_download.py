#!/usr/bin/env python3
"""Offline tests for the full-download probe: caps, idle stop, payload hashing."""
from __future__ import annotations

import unittest

import _bootstrap  # noqa: F401
from bmc_e6.bmc_ble import auth_frames as af
from bmc_e6.bmc_ble import download as rf


def make_sess():
    sess = rf.Session({"requests": [], "replies": []})
    sess.aes_key = af.random_aes_key_24()
    return sess


class CapTests(unittest.TestCase):
    def test_raised_transfer_caps(self):
        self.assertEqual(rf.GATT_WRITE_LIMIT, 400)
        self.assertEqual(rf.MAX_PLAINTEXT, 1024 * 1024)
        self.assertEqual(rf.MAX_SUMMARIES, 10)
        self.assertEqual(rf.SESSION_LIMIT_S, 60.0)  # session cap unchanged

    def test_cap_messages_use_current_values(self):
        sess = make_sess()
        sess.gatt_writes = rf.GATT_WRITE_LIMIT
        with self.assertRaises(rf.SessionLimits) as cm:
            sess.check_limits(extra_writes=1)
        self.assertIn("400", str(cm.exception))


class IdleStopTests(unittest.TestCase):
    def test_no_1520_no_summaries_keeps_waiting(self):
        sess = make_sess()
        sess.sent_9820 = True
        self.assertIsNone(rf.idle_stop_reason(sess, 5))

    def test_summaries_stop_after_two_idle_rounds(self):
        sess = make_sess()
        sess.sent_9820 = True
        sess.summaries.append({"recordNo": 17})
        self.assertIsNone(rf.idle_stop_reason(sess, 1))
        reason = rf.idle_stop_reason(sess, 2)
        assert reason is not None
        self.assertIn("idle after summaries", reason)

    def test_1520_without_summaries_stops(self):
        sess = make_sess()
        sess.sent_9820 = True
        sess.got_1520 = True
        reason = rf.idle_stop_reason(sess, 2)
        assert reason is not None
        self.assertIn("no summary frames", reason)

    def test_not_sent_9820_never_stops(self):
        sess = make_sess()
        sess.summaries.append({"recordNo": 17})
        self.assertIsNone(rf.idle_stop_reason(sess, 9))


class PayloadHashTests(unittest.TestCase):
    def test_semantic_hashes_payload_without_archiving_it(self):
        sem = rf.semantic({"command": 1068, "param1": 13649, "payload": b"\x01" * 480, "crc_ok": True})
        self.assertEqual(sem["payload_len"], 480)
        self.assertEqual(len(sem["payload_sha8"]), 8)
        self.assertNotIn("payload", sem)  # raw health payload never archived
        other = rf.semantic({"command": 1068, "param1": 13649, "payload": b"\x02" * 480})
        self.assertNotEqual(sem["payload_sha8"], other["payload_sha8"])

    def test_empty_payload_hash_is_none(self):
        self.assertIsNone(rf.semantic({"command": 1092, "payload": b""})["payload_sha8"])


if __name__ == "__main__":
    unittest.main()
