#!/usr/bin/env python3
"""Offline tests for the mini agent's push/cursor safety rules."""
from __future__ import annotations

import sys
import unittest
import os
import stat
import tempfile
import json
from pathlib import Path
from unittest import mock

import _bootstrap  # noqa: F401

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "mini_agent"))
import agent  # noqa: E402


class PendingPushTests(unittest.TestCase):
    def test_none_cursor_pushes_nothing(self):
        # No 1090 this round: incomplete records must not be pushed or persisted.
        self.assertEqual(agent.pending_push([{"recordNo": 21}], None), [])

    def test_only_completed_records_pushed(self):
        summaries = [{"recordNo": 19}, {"recordNo": 20}, {"recordNo": 21}]
        self.assertEqual(agent.pending_push(summaries, 20), [{"recordNo": 19}, {"recordNo": 20}])

    def test_missing_record_no_ignored(self):
        self.assertEqual(agent.pending_push([{"recordNo": None}, {"recordNo": 5}], 20), [{"recordNo": 5}])

    def test_empty_summaries(self):
        self.assertEqual(agent.pending_push([], 20), [])


class ReadCursorTests(unittest.TestCase):
    def test_corrupt_and_wrong_shapes_fall_back_to_zero(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "cursor.json"
            for content in ("not json", "[]", "null", '"str"', "42", "true", "-1", "1.5", "{}"):
                path.write_text(content)
                self.assertEqual(agent.read_cursor(path), 0, content)
            path.write_text('{"next_cursor": "42"}')
            self.assertEqual(agent.read_cursor(path), 0)  # str cursor rejected
            path.write_text('{"next_cursor": true}')
            self.assertEqual(agent.read_cursor(path), 0)  # bool rejected
            path.write_text('{"next_cursor": 42}')
            self.assertEqual(agent.read_cursor(path), 42)
            path.write_text('{"next_cursor": -3}')
            self.assertEqual(agent.read_cursor(path), 0)
            path.write_text('{"next_cursor": 4294967296}')
            self.assertEqual(agent.read_cursor(path), 0)
    def test_atomic_write_0600_no_tmp_left(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "cursor.json"
            agent.write_cursor_atomic(path, 42)
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            import json
            self.assertEqual(json.loads(path.read_text()), {"next_cursor": 42})
            self.assertFalse((Path(td) / "cursor.json.tmp").exists())
            agent.write_cursor_atomic(path, 43)  # replace works on existing file
            self.assertEqual(json.loads(path.read_text()), {"next_cursor": 43})
            agent.write_cursor_atomic(path, 41)  # late/lower writer cannot regress cursor
            self.assertEqual(json.loads(path.read_text()), {"next_cursor": 43})
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)


class FlockConcurrencyTests(unittest.TestCase):
    def test_concurrent_writers_never_regress(self):
        from concurrent.futures import ThreadPoolExecutor

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "cursor.json"
            cursors = [10, 42, 7, 33, 21, 42, 5]
            with ThreadPoolExecutor(max_workers=4) as pool:
                list(pool.map(lambda c: agent.write_cursor_atomic(path, c), cursors))
            self.assertEqual(json.loads(path.read_text()), {"next_cursor": 42})
            self.assertTrue((Path(td) / "cursor.json.lock").exists())


class RunSuccessTests(unittest.IsolatedAsyncioTestCase):
    def cfg(self, td):
        return {"target_name": "BMC_E6TEST", "pem_path": "/nonexistent/key.pem",
                "ha_webhook_url": "http://example.invalid/hook",
                "cursor_file": str(Path(td) / "cursor.json"),
                "push_secret": "test-secret"}

    def result(self, code, summaries, next_cursor, authenticated):
        return {"code": code, "summaries": summaries, "next_cursor": next_cursor,
                "report": {"auth": {"authenticated": authenticated}, "stop_reason": "idle after summaries"}}

    async def run_with(self, td, result):
        cfg = self.cfg(td)
        with mock.patch.object(agent, "ha_is_healthy", return_value=False), \
                mock.patch.object(agent.client, "E6BleClient") as ble_cls, \
                mock.patch.object(agent, "push_records") as push, \
                mock.patch.object(agent, "write_cursor_atomic") as write:
            ble_cls.return_value.download = mock.AsyncMock(return_value=result)
            code = await agent.run(cfg)
            return code, push, write

    async def test_healthy_ha_skips_ble(self):
        with tempfile.TemporaryDirectory() as td, \
                mock.patch.object(agent, "ha_is_healthy", return_value=True), \
                mock.patch.object(agent.client, "E6BleClient") as ble_cls:
            code = await agent.run(self.cfg(td))
            self.assertEqual(code, 0)
            ble_cls.assert_not_called()

    async def test_empty_summaries_is_not_success(self):
        with tempfile.TemporaryDirectory() as td:
            code, push, write = await self.run_with(td, self.result(0, [], 42, True))
            self.assertEqual(code, 1)
            push.assert_not_called()
            write.assert_not_called()

    async def test_completed_records_pushed_and_cursor_written(self):
        with tempfile.TemporaryDirectory() as td:
            result = self.result(0, [{"recordNo": 42}], 42, True)
            code, push, write = await self.run_with(td, result)
            self.assertEqual(code, 0)
            push.assert_called_once()
            write.assert_called_once()

    async def test_unauthenticated_is_failure(self):
        with tempfile.TemporaryDirectory() as td:
            # code=0, completed record and valid cursor, ONLY auth false: this
            # isolates the authenticated condition from all other success gates.
            result = self.result(0, [{"recordNo": 42}], 42, False)
            code, push, write = await self.run_with(td, result)
            self.assertEqual(code, 1)
            push.assert_not_called()
            write.assert_not_called()

    async def test_incomplete_records_filtered_is_failure(self):
        with tempfile.TemporaryDirectory() as td:
            result = self.result(0, [{"recordNo": 43}], 42, True)
            code, push, write = await self.run_with(td, result)
            self.assertEqual(code, 1)
            push.assert_not_called()
            write.assert_not_called()


if __name__ == "__main__":
    unittest.main()


class HealthCheckAuthTests(unittest.TestCase):
    """The health check must authenticate, or it always sees 403 and never skips."""

    def test_sends_bearer_header(self):
        seen = {}

        class _Resp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return b'{"ok": true, "last_success_age_s": 60}'

        def fake_urlopen(req, timeout=10):
            seen["auth"] = req.get_header("Authorization")
            return _Resp()

        with mock.patch.object(agent.urllib.request, "urlopen", fake_urlopen):
            healthy = agent.ha_is_healthy("http://x/api/webhook/h", "BMC_E6T", "s3cret")
        self.assertTrue(healthy)
        self.assertEqual(seen["auth"], "Bearer s3cret")

    def test_forbidden_and_bad_json_are_not_healthy(self):
        def forbidden(req, timeout=10):
            raise agent.urllib.error.HTTPError("u", 403, "denied", {}, None)

        with mock.patch.object(agent.urllib.request, "urlopen", forbidden):
            self.assertFalse(agent.ha_is_healthy("http://x/h", "BMC_E6T", "s3cret"))

        class _Bad:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return b"not json"

        with mock.patch.object(agent.urllib.request, "urlopen", lambda req, timeout=10: _Bad()):
            self.assertFalse(agent.ha_is_healthy("http://x/h", "BMC_E6T", "s3cret"))
