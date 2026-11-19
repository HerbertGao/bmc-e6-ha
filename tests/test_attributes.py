#!/usr/bin/env python3
"""The summary record must be fully classified: every parsed field is either an
entity value, an attribute, or explicitly listed as neither."""
from __future__ import annotations

import unittest
from datetime import datetime

import _bootstrap  # noqa: F401
from bmc_e6 import attributes
from bmc_e6.bmc_ble import protocol_cmds as pc

PAYLOAD = pc.pack_new_summary_info({"recordDate": datetime(2026, 1, 1, 12, 0, 0), "recordNo": 1})


class CoverageTests(unittest.TestCase):
    def test_every_parsed_field_is_classified(self):
        parsed = pc.parse_new_summary_info(PAYLOAD)
        attr_fields = {field for spec in attributes._ATTRS.values() for (_a, field, _t) in spec}
        missing = set(parsed) - attr_fields - attributes.NOT_ATTRIBUTES
        self.assertEqual(missing, set(), f"parsed but unclassified: {sorted(missing)}")

    def test_no_stale_entries(self):
        # Removing a parser field should also clean up the spec, otherwise the
        # list quietly grows wrong names that never resolve.
        parsed = set(pc.parse_new_summary_info(PAYLOAD))
        attr_fields = {field for spec in attributes._ATTRS.values() for (_a, field, _t) in spec}
        stale = (attr_fields | attributes.NOT_ATTRIBUTES) - parsed
        self.assertEqual(stale, set(), f"named but not produced by the parser: {sorted(stale)}")

    def test_attribute_keys_are_unique_per_group(self):
        for key, spec in attributes._ATTRS.items():
            names = [attr for (attr, _f, _t) in spec]
            self.assertEqual(len(names), len(set(names)), f"duplicate attribute in {key}")


class ConversionTests(unittest.TestCase):
    """Values come from a real captured night (record 49)."""

    REC = {
        "ahi": 20, "ai": 15, "oai": 13, "ohi": 4, "sni": 214,
        "epapAvg": 691, "epap95": 900, "initP": 300,
        "mvMax": 20560, "mv95": 10625, "leakAvg": 71, "leak95": 140, "runTime": 24191,
        "inspTimeAvg": 11,
        "spo2Avg": 94, "spo295": 98, "spo2Time": 4753, "prAvg": 77, "pr95": 89,
        "treatTime": 24191,
        "sleepStageWakeTime": 948, "sleepStageLightTime": 7874, "sleepStageDeepTime": 3272,
        "ieAvg": 448,
    }

    def test_events_per_hour_are_tenths(self):
        self.assertEqual(attributes.extra_attrs("ahi", self.REC)["ai"], 1.5)
        self.assertEqual(attributes.extra_attrs("ahi", self.REC)["sni"], 21.4)

    def test_pressure_is_hundredths(self):
        attrs = attributes.extra_attrs("epap_avg", self.REC)
        self.assertEqual(attrs["epap95"], 9.0)
        self.assertEqual(attrs["initP"], 3.0)

    def test_minute_ventilation_is_thousandths_and_leak_is_tenths(self):
        self.assertEqual(attributes.extra_attrs("mv_avg", self.REC)["mvMax"], 20.56)
        self.assertEqual(attributes.extra_attrs("leak_avg", self.REC)["leak95"], 14.0)

    def test_sleep_stages_are_two_second_units(self):
        attrs = attributes.extra_attrs("treat_time_h", self.REC)
        self.assertEqual(attrs["sleepStageWakeTime"], 32)      # 948 * 2 s = 31.6 min
        self.assertEqual(attrs["sleepStageLightTime"], 262)    # 7874 * 2 s = 4.37 h
        total_min = (948 + 7874 + 3272) * 2 / 60
        self.assertAlmostEqual(total_min, 403.1, places=1)      # matches treatTime 6.72 h
        self.assertEqual(attrs["runTime"], 24191)

    def test_inspiratory_time_is_tenths(self):
        self.assertEqual(attributes.extra_attrs("treat_time_h", self.REC)["inspTimeAvg"], 1.1)

    def test_ie_ratio(self):
        self.assertEqual(attributes.extra_attrs("treat_time_h", self.REC)["ieAvg"], 0.448)

    def test_absent_field_is_omitted(self):
        attrs = attributes.extra_attrs("pr_avg", {"prAvg": 77})
        self.assertEqual(attrs, {})


if __name__ == "__main__":
    unittest.main()
