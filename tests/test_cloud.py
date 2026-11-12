#!/usr/bin/env python3
"""Offline tests for the Remot cloud client (fake aiohttp-like session)."""
from __future__ import annotations

import unittest

import _bootstrap  # noqa: F401
from bmc_e6 import cloud


def secrets():
    return {
        "access_token": "OLD",
        "refresh_token": "REFRESH",
        "serial": "SN123",
        "terminal_id": "TID",
        "base_url": "https://example.invalid",
    }


def day_body(treat=3600, ahi=1.9, score=88):
    return {
        "success": True,
        "data": {
            "baseInfo": {
                "recordDate": "2026-11-10", "serial": "SN123", "ahi": ahi,
                "treatTime": treat, "leakAvg": 9.6, "spo2Avg": None,
                "epapAvg": 6.86, "ipapAvg": 11.59, "epap95": 7.2, "ipap95": 12.1,
                "rrAvg": 16, "vtAvg": 407, "sleepTotalMinute": 400,
                "sleepDeepMinute": 65, "sleepLightMinute": 118, "sleepWakeMinute": 13,
                "mouthLeakTime": 120, "deviceMode": 6,
            },
            "scoreInfo": {"totalScore": score, "summaryTitle": "良好", "summary": "报告摘要"},
        },
    }


class FakeResp:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status = status

    async def json(self):
        return self._payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


class FakeSession:
    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def _route(self, method, url):
        for m, sub, payload, status in self.routes:
            if m == method and sub in url:
                return payload, status
        raise AssertionError(f"no route for {method} {url}")

    def get(self, url, headers=None):
        self.calls.append(("GET", url))
        payload, status = self._route("GET", url)
        return FakeResp(payload, status)

    def post(self, url, data=None, headers=None):
        self.calls.append(("POST", url, data))
        payload, status = self._route("POST", url)
        return FakeResp(payload, status)


class MetricsTests(unittest.TestCase):
    def test_metrics_from_day_full(self):
        m = cloud.metrics_from_day(day_body())
        self.assertEqual(m["record_date"], "2026-11-10")
        self.assertEqual(m["ahi"], 1.9)
        self.assertEqual(m["treat_time_s"], 3600)
        self.assertEqual(m["treat_time_h"], 1.0)
        self.assertEqual(m["leak_avg"], 9.6)
        self.assertEqual(m["epap_avg"], 6.86)
        self.assertEqual(m["score"], 88)
        self.assertEqual(m["score_title"], "良好")
        self.assertEqual(m["score_summary"], "报告摘要")
        self.assertEqual(m["serial_last4"], "N123")

    def test_metrics_empty_returns_none(self):
        self.assertIsNone(cloud.metrics_from_day({"success": False}))
        self.assertIsNone(cloud.metrics_from_day({"success": True, "data": {"baseInfo": {}}}))


class PickReportTests(unittest.IsolatedAsyncioTestCase):
    async def test_prefers_yesterday(self):
        sess = FakeSession([("GET", "/api2/ventilator/report/day", day_body(), 200)])
        client = cloud.RemotCloudClient(sess, secrets())
        m = await client.pick_report()
        self.assertEqual(m["source"], "day")
        self.assertEqual(m["ahi"], 1.9)
        # only one day fetch (yesterday) should have happened
        self.assertEqual(len(sess.calls), 1)

    async def test_fallback_to_card(self):
        sess = FakeSession([
            ("GET", "/api2/ventilator/report/day", {"success": True, "data": {"baseInfo": {}}}, 200),
            ("GET", "/api2/home/card/info", {
                "success": True,
                "data": {"serial": "SN123", "ahi": 2.2, "treatTime": 1800,
                         "scoreInfo": {"totalScore": 80, "summaryTitle": "一般", "summary": "卡片"}},
            }, 200),
        ])
        client = cloud.RemotCloudClient(sess, secrets())
        m = await client.pick_report()
        self.assertEqual(m["source"], "card")
        self.assertEqual(m["ahi"], 2.2)
        self.assertEqual(m["score"], 80)
        self.assertEqual(m["score_summary"], "卡片")

    async def test_day_http_401_raises(self):
        sess = FakeSession([("GET", "/api2/ventilator/report/day", {"success": False}, 401)])
        client = cloud.RemotCloudClient(sess, secrets())
        with self.assertRaises(cloud.CloudAuthError):
            await client.pick_report()

    async def test_failed_card_response_raises_not_card_result(self):
        # success=false or HTTP 500 card must not return a normal source=card result.
        for card in ({"success": False, "code": -1, "msg": "err"}, {"success": True, "data": {}}):
            sess = FakeSession([
                ("GET", "/api2/ventilator/report/day", {"success": True, "data": {"baseInfo": {}}}, 200),
                ("GET", "/api2/home/card/info", card, 200),
            ])
            client = cloud.RemotCloudClient(sess, secrets())
            with self.assertRaises(RuntimeError):
                await client.pick_report()

    async def test_http_500_raises_before_json_parsing(self):
        class Json500Session(FakeSession):
            def get(self, url, headers=None):
                self.calls.append(("GET", url))
                return FakeResp({"success": True, "data": {"baseInfo": {}}}, 500)

        client = cloud.RemotCloudClient(Json500Session([]), secrets())
        with self.assertRaises(RuntimeError):
            await client.pick_report()

    async def test_non_json_401_triggers_refresh_not_parse_error(self):
        # 401 with an HTML/non-JSON body must still refresh (status checked first).
        class NonJsonResp(FakeResp):
            async def json(self):
                raise ValueError("not json")

        class NonJsonSession(FakeSession):
            def get(self, url, headers=None):
                self.calls.append(("GET", url))
                if "/api2/home/card/info" in url:
                    return NonJsonResp({}, 401)
                return super().get(url, headers)

        sess = NonJsonSession([
            ("POST", "/api1/oauth2/token", {"success": True, "data": {"accessToken": "NEW"}}, 200),
        ])
        client = cloud.RemotCloudClient(sess, secrets())
        await client.ensure_auth()
        self.assertEqual(client.secrets["access_token"], "NEW")


class AuthFlowTests(unittest.IsolatedAsyncioTestCase):
    async def test_ensure_auth_refreshes_and_persists(self):
        refreshed = []

        async def on_updated(sec):
            refreshed.append(sec["access_token"])

        sess = FakeSession([
            ("GET", "/api2/home/card/info", {"success": False, "code": -401, "msg": "未认证"}, 200),
            ("POST", "/api1/oauth2/token", {
                "success": True,
                "data": {"accessToken": "NEW", "refreshToken": "NEWREF", "expiresIn": 7200},
            }, 200),
        ])
        client = cloud.RemotCloudClient(sess, secrets(), on_tokens_updated=on_updated)
        await client.ensure_auth()
        self.assertEqual(client.secrets["access_token"], "NEW")
        self.assertEqual(client.secrets["refresh_token"], "NEWREF")
        self.assertEqual(refreshed, ["NEW"])
        self.assertEqual(sess.calls[-1][0], "POST")

    async def test_refresh_failure_raises(self):
        sess = FakeSession([
            ("GET", "/api2/home/card/info", {"success": False, "code": -401}, 200),
            ("POST", "/api1/oauth2/token", {"success": False, "code": -1, "msg": "bad refresh"}, 200),
        ])
        client = cloud.RemotCloudClient(sess, secrets())
        with self.assertRaises(cloud.CloudAuthError):
            await client.ensure_auth()


if __name__ == "__main__":
    unittest.main()
