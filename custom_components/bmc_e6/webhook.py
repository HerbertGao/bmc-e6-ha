"""Local webhook for Mini-side BLE backups and health checks."""
from __future__ import annotations

import hmac

from aiohttp import web
from homeassistant.components import webhook
from homeassistant.core import HomeAssistant

from .const import CONF_PUSH_SECRET, DOMAIN

WEBHOOK_ID = f"{DOMAIN}_push"


def _coordinators(hass: HomeAssistant) -> list:
    return list((hass.data.get(DOMAIN) or {}).values())


def _find_coordinator(hass: HomeAssistant, target_name: str | None):
    matches = [c for c in _coordinators(hass) if not target_name or c.target_name == target_name]
    return matches[0] if len(matches) == 1 else None


async def _handle(hass: HomeAssistant, _webhook_id: str, request) -> web.Response:
    body = None
    if request.method == "POST":
        try:
            body = await request.json()
        except (ValueError, TypeError):
            return web.json_response({"ok": False, "error": "invalid_json"}, status=400)
        if not isinstance(body, dict):
            return web.json_response({"ok": False, "error": "object_required"}, status=400)

    # The client names its entry in the body (POST) or the query (GET); the secret
    # has to be resolved from that before any work happens.
    target_name = (body or {}).get("target_name") or request.query.get("target_name")
    secret = _find_secret(hass, target_name)
    if secret is None:
        return web.json_response({"ok": False, "error": "push_not_configured"}, status=403)
    supplied = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    if not hmac.compare_digest(supplied, secret):
        return web.json_response({"ok": False, "error": "unauthorized"}, status=401)

    if request.method == "GET":
        coordinator = _find_coordinator(hass, target_name)
        if coordinator is None:
            return web.json_response({"ok": False, "error": "target_not_found"}, status=404)
        health = coordinator.health_status()
        # Never return target_name: it carries the device serial.
        return web.json_response({k: health.get(k) for k in ("ok", "cursor", "last_success_age_s")})

    records = body.get("records")
    if not isinstance(target_name, str) or not target_name:
        return web.json_response({"ok": False, "error": "target_name_required"}, status=400)
    if not isinstance(records, list):
        return web.json_response({"ok": False, "error": "records_required"}, status=400)

    coordinator = _find_coordinator(hass, target_name)
    if coordinator is None:
        return web.json_response({"ok": False, "error": "target_not_found"}, status=404)
    try:
        added = coordinator.merge_records(records, "mini_ble")
    except (AttributeError, TypeError, ValueError) as ex:
        return web.json_response({"ok": False, "error": f"invalid_records: {ex}"}, status=400)
    try:
        await coordinator.async_persist_state()
    except Exception as ex:  # persistence failure must prevent Mini cursor advancement
        return web.json_response({"ok": False, "error": f"state_persist_failed: {ex}"}, status=503)
    return web.json_response({
        "ok": True,
        "accepted": len(records),
        "added": added,
        "cursor": coordinator.health_status().get("cursor"),
    })


def _find_secret(hass: HomeAssistant, target_name: str | None) -> str | None:
    """Return the configured push secret, or None if not set for exactly one entry."""
    entries = hass.config_entries.async_entries(DOMAIN)
    if target_name:
        entries = [
            e for e in entries
            if e.data.get("target_name") == target_name or e.title == target_name
        ]
    secrets = {
        e.data.get(CONF_PUSH_SECRET) for e in entries
    } - {None, ""}
    return next(iter(secrets)) if len(secrets) == 1 else None


def async_setup(hass: HomeAssistant) -> bool:
    """Register one local webhook shared by all configured BMC entries."""
    webhook.async_register(
        hass,
        DOMAIN,
        "BMC E5/E6 Mini backup",
        WEBHOOK_ID,
        _handle,
        local_only=True,
        allowed_methods={"GET", "POST"},
    )
    return True
