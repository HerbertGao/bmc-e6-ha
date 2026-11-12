#!/usr/bin/env python3
"""Offline tests for device identification and the client helpers."""
from __future__ import annotations

import unittest

import _bootstrap  # noqa: F401
from bmc_e6.bmc_ble import client
import os
import stat
import tempfile
from pathlib import Path


FE60 = "0000fe60-0000-1000-8000-00805f9b34fb"


class ModelFromNameTests(unittest.TestCase):
    def test_e6(self):
        self.assertEqual(client.model_from_name("BMC_E6123456789"), "E6")

    def test_e5(self):
        self.assertEqual(client.model_from_name("BMC_E5123456789"), "E5")

    def test_unsupported(self):
        for name in ("BMC_G5123", "BMC_X6123", "OTHER_E6123", "", "BMC_"):
            self.assertIsNone(client.model_from_name(name))


class SupportedAdvertisementTests(unittest.TestCase):
    def test_real_e6_broadcast_shape(self):
        # Mirrors the on-air capture: FE60 + manufacturer 682 + BMC_E6 name.
        self.assertTrue(client.is_supported_advertisement("BMC_E6123456789", [FE60], {682: b""}))

    def test_e5_accepted(self):
        self.assertTrue(client.is_supported_advertisement("BMC_E5123456789", [FE60], {682: b""}))

    def test_rejects_wrong_manufacturer(self):
        self.assertFalse(client.is_supported_advertisement("BMC_E6123456789", [FE60], {999: b""}))

    def test_rejects_missing_fe60(self):
        self.assertFalse(client.is_supported_advertisement("BMC_E6123456789", [], {682: b""}))

    def test_rejects_other_names(self):
        for name in ("BMC_G5123", "SomeE6", "", "BMC_"):
            self.assertFalse(client.is_supported_advertisement(name, [FE60], {682: b""}))


class MatchScoreTests(unittest.TestCase):
    class Dev:
        def __init__(self, name, address):
            self.name = name
            self.address = address

    class Adv:
        def __init__(self):
            self.local_name = None
            self.service_uuids = [FE60]
            self.manufacturer_data = {682: b""}
            self.rssi = -80

    def test_exact_name_wins(self):
        score, info = client.match_score(self.Dev("BMC_E6123456789", "AA"), self.Adv(), "BMC_E6123456789")
        self.assertEqual(score, 15)
        self.assertEqual(info["address"], "AA")

    def test_other_bmc_device_scores_lower(self):
        score, _ = client.match_score(self.Dev("BMC_E6000000000", "BB"), self.Adv(), "BMC_E6123456789")
        self.assertEqual(score, 5)  # FE60(3) + manufacturer(2), no exact-name bonus


class WritePrivateTests(unittest.TestCase):
    def test_created_with_0600_from_the_start(self):
        with tempfile.TemporaryDirectory() as td:
            path = client.write_private(Path(td) / "nested" / "out.json", "{}")
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            self.assertEqual(path.read_text(), "{}")

    def test_existing_0644_file_is_also_fixed(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "out.json"
            path.write_text("old")
            os.chmod(path, 0o644)
            client.write_private(path, "new")
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            self.assertEqual(path.read_text(), "new")


class ExitCodeTests(unittest.TestCase):
    def report(self, authenticated, reason, received=None):
        return {
            "auth": {"authenticated": authenticated},
            "stop_reason": reason,
            "counts": {"received_cmds": received or []},
        }

    def test_auth_failure_is_nonzero(self):
        self.assertEqual(client.exit_code(self.report(False, "idle after summaries")), 1)

    def test_bounded_stops_are_success(self):
        for reason in ("idle after summaries", "GATT write cap 400",
                       "summary cap 10 reached", "download reached device max record"):
            self.assertEqual(client.exit_code(self.report(True, reason)), 0)

    def test_budget_stops_need_download_phase_evidence(self):
        for reason in ("time cap approaching with no 1520", "session 60s cap"):
            # Only the initial handshake: the device never served the download.
            self.assertEqual(
                client.exit_code(self.report(True, reason, received=[33233, 1700, 1702])), 1, reason
            )
            # Config push only (1406/1412/1416/1706 arrive before the download):
            # still a stalled round, per every captured session.
            self.assertEqual(
                client.exit_code(self.report(True, reason, received=[1700, 1406, 1412, 1416, 1706])),
                1, reason,
            )
            # Caught up: the device re-pushes its newest record and closes the list.
            for served in ([1700, 1092, 1090], [1700, 1030]):
                self.assertEqual(client.exit_code(self.report(True, reason, received=served)), 0, reason)

    def test_all_other_stops_are_failures(self):
        for reason in ("post-auth CRC failed; stopping", "post-auth decrypt/parse failed: ValueError",
                       "9820 write failed; not resending", "connect failed: BleakError",
                       "exception RuntimeError: boom", "9772 reply param1!=1; not retrying",
                       "1090 without download; not ACKing", "unexpected setter reply 33173; stopping",
                       "1520+9820 sent but no summary frames before idle timeout; stopping",
                       "no 1520 range within budget"):
            self.assertEqual(client.exit_code(self.report(True, reason)), 1, reason)


if __name__ == "__main__":
    unittest.main()


class _Char:
    def __init__(self, uuid: str, value: bytes, props: int = 2) -> None:
        self.uuid = uuid
        self.handle = 1
        self.properties = props
        self._value = value


class _Svc:
    def __init__(self, chars: list) -> None:
        self.characteristics = chars


class _FakeClient:
    def __init__(self, chars: list, fail: bool = False) -> None:
        self.services = [_Svc(chars)]
        self._fail = fail

    async def read_gatt_char(self, ch):
        if self._fail:
            raise RuntimeError("boom")
        return ch._value


class ReadDeviceVersionsTests(unittest.IsolatedAsyncioTestCase):
    async def test_reads_only_the_version_characteristics(self):
        fake = _FakeClient([
            _Char("00002a24-0000-1000-8000-00805f9b34fb", b"L-BTMSB95-G0SC4"),
            _Char("00002a28-0000-1000-8000-00805f9b34fb", b"v3.1.Apr 14 2023\x00"),
            _Char("00002a00-0000-1000-8000-00805f9b34fb", b"BMC_E6123456789"),
        ])
        report: dict = {}
        got = await client.read_device_versions(fake, report)
        self.assertEqual(
            got, {"hw_version": "L-BTMSB95-G0SC4", "sw_version": "v3.1.Apr 14 2023"}
        )
        self.assertNotIn("device_info_error", report)

    async def test_read_failure_never_breaks_the_download(self):
        fake = _FakeClient([_Char("00002a24-0000-1000-8000-00805f9b34fb", b"x")], fail=True)
        report: dict = {}
        got = await client.read_device_versions(fake, report)
        self.assertEqual(got, {})
        self.assertIn("device_info_error", report)
