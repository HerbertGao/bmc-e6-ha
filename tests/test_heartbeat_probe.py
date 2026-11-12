#!/usr/bin/env python3
"""Offline tests for heartbeat scheduling and frame shape (bmc_ble.download).

No BLE scan/connect.
"""
from __future__ import annotations

import unittest

import _bootstrap  # noqa: F401
from bmc_e6.bmc_ble import auth_frames as af
from bmc_e6.bmc_ble import protocol_cmds as pc
from bmc_e6.bmc_ble import download as rh


class HeartbeatScheduleTests(unittest.TestCase):
    def test_official_cadence(self):
        # startHeartbeat: first at connect+10s, then every 10s, max 5.
        self.assertEqual(rh.heartbeat_due(1000.0, 0), 1010.0)
        self.assertEqual(rh.heartbeat_due(1000.0, 1), 1020.0)
        self.assertEqual(rh.heartbeat_due(1000.0, 2), 1030.0)
        self.assertEqual(rh.heartbeat_due(1000.0, 3), 1040.0)
        self.assertEqual(rh.heartbeat_due(1000.0, 4), 1050.0)

    def test_budget_spent(self):
        self.assertIsNone(rh.heartbeat_due(1000.0, 5))
        self.assertIsNone(rh.heartbeat_due(1000.0, 99))

    def test_not_connected(self):
        self.assertIsNone(rh.heartbeat_due(None, 0))

    def test_max_five_within_60s_cap(self):
        last = rh.heartbeat_due(0.0, rh.HEARTBEAT_MAX - 1)
        self.assertEqual(last, 50.0)  # fifth beat at T+50s, inside the 60s cap
        self.assertLessEqual(50.0, rh.SESSION_LIMIT_S)


class HeartbeatFrameTests(unittest.TestCase):
    def test_wire8_empty_alg5_roundtrip(self):
        key = af.random_aes_key_24()
        wire = pc.build_aes_frame(key, pc.WIRE_HEARTBEAT, 0, 0, b"")
        self.assertEqual(wire[0], af.BLE_HEAD)
        self.assertEqual(wire[1], 5)  # alg=5 AES, same as other post-auth frames
        parsed = af.parse_wire(1, 1, key, wire)
        self.assertTrue(parsed["crc_ok"])
        self.assertEqual(parsed["command"], 8)
        self.assertEqual(parsed["param1"], 0)
        self.assertEqual(parsed["param2"], 0)
        self.assertEqual(parsed["payload"], b"")

    def test_heartbeat_logical_matches_official_constant(self):
        # MessageToBytes(-23452) -> wire 8; distinct from getSystemTime 23468.
        self.assertEqual(pc.LOGICAL_HEARTBEAT, -23452)
        self.assertEqual(pc.WIRE_HEARTBEAT, 8)
        self.assertNotEqual(pc.WIRE_HEARTBEAT, pc.WIRE_GET_SYSTEM_TIME)


class SafetyRailTests(unittest.TestCase):
    def test_shared_whitelist_not_widened(self):
        # The probe asserts its heartbeat locally; the shared module keeps
        # forbidding wire 8 for every other caller.
        self.assertNotIn("HEARTBEAT", pc.INITIATED_ALLOWED)
        self.assertNotIn("HEARTBEAT", pc.RESPONSE_ALLOWED)
        self.assertIn(pc.WIRE_HEARTBEAT, pc.FORBIDDEN_WIRE)
        with self.assertRaises(PermissionError):
            pc.assert_allowed_send("HEARTBEAT", pc.WIRE_HEARTBEAT, b"")


if __name__ == "__main__":
    unittest.main()
