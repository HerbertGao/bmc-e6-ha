"""Remot cloud backup channel: OAuth2 refresh, day report, score analysis.

Migrated from the proven remot-e6 poller to an async client for Home Assistant.
Secrets are supplied by the caller (HA config entry / local file) and are never
logged. Token refreshes are persisted through the on_tokens_updated callback.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

TZ = timezone(timedelta(hours=8))
USER_AGENT = "ResmartHealth/2 CFNetwork/3896.300.31 Darwin/27.3.0"


class CloudAuthError(PermissionError):
    """401/403 or a business auth failure from the Remot cloud."""


def api_headers(sec: dict, *, auth: bool = True) -> dict:
    h = {
        "terminal-version": sec["terminal_version"],
        "terminal": sec["terminal"],
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Content-Type": "application/json",
        "Accept-Language": "zh-CN,zh-Hans;q=0.9",
    }
    if auth:
        h["Authorization"] = f"Bearer {sec['access_token']}"
    return h


def metrics_from_day(body: dict) -> dict | None:
    """Map a /api2/ventilator/report/day response to flat metrics (None if empty)."""
    if not body.get("success"):
        return None
    data = body.get("data") or {}
    base = data.get("baseInfo") or {}
    score = data.get("scoreInfo") or {}
    if not base.get("recordDate") and base.get("ahi") is None and not base.get("treatTime"):
        return None
    treat = base.get("treatTime") or 0
    return {
        "record_date": base.get("recordDate"),
        "serial_last4": str(base.get("serial") or "")[-4:],
        "ahi": float(base["ahi"]) if base.get("ahi") is not None else None,
        "treat_time_s": int(treat),
        "treat_time_h": round(int(treat) / 3600, 2),
        "leak_avg": base.get("leakAvg"),
        "spo2_avg": base.get("spo2Avg"),
        "epap_avg": base.get("epapAvg"),
        "ipap_avg": base.get("ipapAvg"),
        "epap95": base.get("epap95"),
        "ipap95": base.get("ipap95"),
        "rr_avg": base.get("rrAvg"),
        "vt_avg": base.get("vtAvg"),
        "sleep_total_min": base.get("sleepTotalMinute"),
        "sleep_deep_min": base.get("sleepDeepMinute"),
        "sleep_light_min": base.get("sleepLightMinute"),
        "sleep_wake_min": base.get("sleepWakeMinute"),
        "mouth_leak_s": base.get("mouthLeakTime"),
        "score": score.get("totalScore"),
        "score_title": score.get("summaryTitle"),
        "score_summary": score.get("summary"),
        "device_mode": base.get("deviceMode"),
        "polled_at": datetime.now(TZ).isoformat(),
    }


class RemotCloudClient:
    """Async Remot cloud client. session must be aiohttp-like (get/post async CM)."""

    def __init__(self, session, secrets: dict, on_tokens_updated=None) -> None:
        sec = dict(secrets)
        for k in ("access_token", "refresh_token", "serial", "terminal_id", "base_url"):
            if not sec.get(k):
                raise ValueError(f"missing secret: {k}")
        sec.setdefault("client_id", "app_ios")
        sec.setdefault("terminal", "app_ios")
        sec.setdefault("terminal_version", "1.01.02")
        self._session = session
        self.secrets = sec
        self._on_tokens_updated = on_tokens_updated

    async def _get_json(self, path: str) -> dict:
        url = self.secrets["base_url"] + path
        async with self._session.get(url, headers=api_headers(self.secrets)) as resp:
            if resp.status in (401, 403):  # check status before parsing (may be non-JSON)
                raise CloudAuthError(f"HTTP {resp.status}")
            if resp.status != 200:  # 500 etc. must not be parsed as a normal result
                # Never interpolate the URL: it carries the cloud serial and this
                # text reaches home-assistant.log at WARNING.
                raise RuntimeError(f"HTTP {resp.status}")
            return await resp.json()

    async def refresh(self) -> None:
        body = urlencode({
            "grant_type": "refresh_token",
            "refresh_token": self.secrets["refresh_token"],
            "client_id": self.secrets["client_id"],
            "terminal-id": self.secrets["terminal_id"],
        }).encode()
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "terminal-version": self.secrets["terminal_version"],
            "terminal": self.secrets["terminal"],
            "User-Agent": USER_AGENT,
            "Accept": "*/*",
        }
        async with self._session.post(
            f"{self.secrets['base_url']}/api1/oauth2/token", data=body, headers=headers
        ) as resp:
            if resp.status in (401, 403):  # status before parsing (may be non-JSON)
                raise CloudAuthError(f"refresh HTTP {resp.status}")
            if resp.status != 200:
                raise RuntimeError(f"refresh HTTP {resp.status}")
            j = await resp.json()
        if not j.get("success"):
            raise CloudAuthError(f"refresh failed: {j.get('code')} {j.get('msg')}")
        data = j["data"]
        self.secrets["access_token"] = data["accessToken"]
        if data.get("refreshToken"):
            self.secrets["refresh_token"] = data["refreshToken"]
        self.secrets["token_refreshed_at"] = datetime.now(TZ).isoformat()
        self.secrets["expires_in"] = data.get("expiresIn")
        if self._on_tokens_updated is not None:
            await self._on_tokens_updated(self.secrets)

    async def ensure_auth(self) -> None:
        try:
            card = await self._get_json("/api2/home/card/info?type=3")
            if card.get("success"):
                return
            if card.get("code") in (-401, 401, 403) or "认证" in str(card.get("msg") or ""):
                await self.refresh()
        except CloudAuthError:
            await self.refresh()

    async def _fetch_day(self, day: datetime) -> dict:
        midnight = day.replace(hour=0, minute=0, second=0, microsecond=0)
        ms = int(midnight.timestamp() * 1000)
        path = f"/api2/ventilator/report/day?serial={self.secrets['serial']}&time={ms}"
        body = await self._get_json(path)
        if body.get("success") is False and body.get("code") in (-1, 401, 403):
            raise CloudAuthError(body.get("msg") or "auth failed")
        return body

    async def pick_report(self) -> dict:
        """Prefer yesterday's night; fall back today/older, then the home card."""
        today = datetime.now(TZ)
        for days in (1, 0, 2, 3):
            day = today - timedelta(days=days)
            body = await self._fetch_day(day)
            m = metrics_from_day(body)
            if m and (m.get("treat_time_s") or 0) > 0:
                m["source"] = "day"
                return m
        card = await self._get_json("/api2/home/card/info?type=3")
        if not card.get("success") or not isinstance(card.get("data"), dict) or not card["data"]:
            # A failed card response must not masquerade as a normal card result.
            raise RuntimeError(f"cloud card fallback failed: code={card.get('code')} msg={card.get('msg')}")
        d = card["data"]
        treat = d.get("treatTime") or 0
        score = d.get("scoreInfo") or {}
        return {
            "record_date": None,
            "serial_last4": str(d.get("serial") or "")[-4:],
            "ahi": float(d["ahi"]) if d.get("ahi") is not None else None,
            "treat_time_s": int(treat),
            "treat_time_h": round(int(treat) / 3600, 2),
            "leak_avg": d.get("leakAvg"),
            "spo2_avg": d.get("spo2Avg"),
            "score": score.get("totalScore"),
            "score_title": score.get("summaryTitle"),
            "score_summary": score.get("summary"),
            "source": "card",
            "polled_at": datetime.now(TZ).isoformat(),
        }
