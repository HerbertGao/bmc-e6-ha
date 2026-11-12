"""BMC E5/E6 ventilator integration (local BLE + cloud backup + mini agent).

Home Assistant imports are kept inside setup functions so the shared protocol
package (bmc_e6.bmc_ble) stays importable without HA installed (offline tests).
"""
from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler

from .const import DOMAIN  # const has no HA dependency

PLATFORMS = ["sensor"]


class _PrivateRotatingHandler(RotatingFileHandler):
    """Rotating handler that keeps the log 0600, including after a rollover.

    RotatingFileHandler reopens the base file with builtin open() on rollover,
    which would silently restore the umask mode (usually 0644).
    """

    def _open(self):
        fd = os.open(self.baseFilename, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.fchmod(fd, 0o600)
        return os.fdopen(fd, self.mode, encoding=self.encoding, errors=self.errors)


async def async_setup(hass, config) -> bool:
    from .webhook import async_setup as async_setup_webhook

    return async_setup_webhook(hass)


async def async_setup_entry(hass, entry) -> bool:
    import os
    from contextlib import suppress

    from homeassistant.helpers.aiohttp_client import async_get_clientsession
    from homeassistant.helpers.storage import Store

    from .cloud import RemotCloudClient
    from .const import CONF_CLOUD_TOKENS, CONF_PROTOCOL_PEM, CONF_TARGET_NAME, DOMAIN
    from .coordinator import BmcE6Coordinator

    target_name = entry.data[CONF_TARGET_NAME]
    # Persist the user-supplied PEM to a 0600 file inside HA's config dir.
    # Keyed by entry_id rather than the serial. (The cursor store still uses the
    # configured name as its key — migrating it would orphan existing history.)
    pem_path = hass.config.path(".storage", f"{DOMAIN}_{entry.entry_id}_protocol.pem")
    legacy_pem = hass.config.path(".storage", f"{DOMAIN}_{target_name}_protocol.pem")
    if legacy_pem != pem_path and os.path.exists(legacy_pem):
        with suppress(OSError):
            os.unlink(legacy_pem)
    fd = os.open(pem_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(entry.data[CONF_PROTOCOL_PEM])

    cloud_client = None
    cloud_tokens = entry.data.get(CONF_CLOUD_TOKENS)
    if cloud_tokens:
        async def on_tokens_updated(secrets: dict) -> None:
            data = dict(entry.data)
            data[CONF_CLOUD_TOKENS] = secrets
            hass.config_entries.async_update_entry(entry, data=data)

        cloud_client = RemotCloudClient(
            async_get_clientsession(hass), cloud_tokens, on_tokens_updated=on_tokens_updated
        )
    coordinator = BmcE6Coordinator(
        hass,
        target_name=target_name,
        pem_path=pem_path,
        cloud_client=cloud_client,
        store=Store(hass, 1, f"{DOMAIN}_{target_name}_cursor"),
    )
    # Dedicated log file for this integration's BLE/cloud flow (easy to tail
    # without the noise of the main Home Assistant log). It can hold device
    # identifiers, so it stays 0600 and is capped instead of growing forever.
    log = logging.getLogger(f"custom_components.{DOMAIN}")
    log_path = hass.config.path(f"{DOMAIN}.log")
    if not any(isinstance(h, logging.FileHandler) and h.baseFilename == log_path
               for h in log.handlers):

        def _open_handler() -> logging.Handler:
            handler = _PrivateRotatingHandler(log_path, maxBytes=2 << 20, backupCount=2)
            handler.setFormatter(
                logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
            )
            return handler

        handler = await hass.async_add_executor_job(_open_handler)
        log.addHandler(handler)
    log.setLevel(logging.INFO)
    await coordinator.async_initialize()
    await coordinator.async_config_entry_first_refresh()
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass, entry) -> bool:
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return unloaded
