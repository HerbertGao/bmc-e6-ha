#!/usr/bin/env python3
"""Offline tests for bmc_ble.records merge/validation."""
from __future__ import annotations

import json
import unittest
from datetime import datetime

import _bootstrap  # noqa: F401
from bmc_e6.bmc_ble import records


class MergeTests(unittest.TestCase):
    def test_first_merge_updates_cursor(self):
        merged, added, cursor = records.merge_records({}, [{"recordNo": 7}], "ble")
        self.assertEqual(added, 1)
        self.assertEqual(cursor, 7)
        self.assertEqual(merged[7]["source"], "ble")

    def test_consecutive_merges_dedupe(self):
        merged, added, cursor = records.merge_records({}, [{"recordNo": 7}, {"recordNo": 8}], "ble")
        merged2, added2, cursor2 = records.merge_records(merged, [{"recordNo": 8}, {"recordNo": 9}], "mini_ble")
        self.assertEqual((added, added2), (2, 1))
        self.assertEqual(cursor2, 9)
        self.assertEqual(merged2[8]["source"], "mini_ble")  # re-push refreshes the copy
        self.assertEqual(merged2[9]["source"], "mini_ble")

    def test_repush_refreshes_payload_without_counting_as_added(self):
        merged, _, _ = records.merge_records({}, [{"recordNo": 5, "ahi": 0}], "ble")
        merged2, added, cursor = records.merge_records(merged, [{"recordNo": 5, "ahi": 19}], "ble")
        self.assertEqual(added, 0)
        self.assertEqual(merged2[5]["ahi"], 19)
        self.assertEqual(cursor, 5)

    def test_mixed_types_rejected_before_mutation(self):
        existing = {7: {"recordNo": 7}}
        with self.assertRaises(ValueError):
            records.merge_records(existing, [{"recordNo": 8}, {"recordNo": "9"}], "ble")
        self.assertEqual(existing, {7: {"recordNo": 7}})  # no partial merge

    def test_bool_and_none_rejected(self):
        for bad in (True, None, -1, 1.5):
            with self.assertRaises(ValueError):
                records.validate_record_no(bad)

    def test_above_uint32_rejected(self):
        # Such a value becomes the resume cursor and would kill every later round.
        for bad in (0x1_0000_0000, 2**40):
            with self.assertRaises(ValueError):
                records.validate_record_no(bad)
        self.assertEqual(records.validate_record_no(0xFFFFFFFF), 0xFFFFFFFF)

    def test_empty_batch(self):
        merged, added, cursor = records.merge_records({}, [], "ble")
        self.assertEqual((added, cursor), (0, None))


class RestoreTests(unittest.TestCase):
    def test_json_roundtrip_restores_int_keys(self):
        merged, _, _ = records.merge_records({}, [{"recordNo": 7}, {"recordNo": 9}], "ble")
        store = json.loads(json.dumps({"records": [merged[7], merged[9]]}))
        restored = records.restore_records(store["records"])
        self.assertEqual(sorted(restored), [7, 9])  # int keys, not "7"/"9"
        self.assertEqual(max(restored), 9)

    def test_malformed_entries_dropped_without_raising(self):
        restored = records.restore_records(
            [{"recordNo": 3}, {"recordNo": "4"}, {"recordNo": True}, "junk", {"nope": 1}]
        )
        self.assertEqual(sorted(restored), [3])

    def test_missing_or_wrong_shape_is_empty(self):
        for bad in (None, {}, "text", 5):
            self.assertEqual(records.restore_records(bad), {})


class JsonSafeRecordTests(unittest.TestCase):
    def test_bytes_dropped_and_datetime_isoformatted(self):
        rec = {"recordNo": 41, "recordDate_raw": b"~\n\x10\x0c", "treatTime": 5}
        safe = records.json_safe_record(rec)
        self.assertNotIn("recordDate_raw", safe)
        self.assertEqual(safe["recordNo"], 41)
        json.dumps(safe)  # must not raise: HA storage rejects bytes

    def test_datetime_becomes_string(self):
        safe = records.json_safe_record({"recordDate": datetime(2026, 11, 11, 12, 0)})
        self.assertEqual(safe["recordDate"], "2026-11-11T12:00:00")
        json.dumps(safe)


if __name__ == "__main__":
    unittest.main()
