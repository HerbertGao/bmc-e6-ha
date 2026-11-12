"""DataUpdateCoordinator: daily BLE fetch + cloud backup + mini-agent merge."""
from __future__ import annotations

import asyncio
import logging
import os
import time
from datetime import timedelta

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import DOMAIN
from .bmc_ble.records import json_safe_record, merge_records, restore_records

_LOGGER = logging.getLogger(__name__)

# ESPHome Bluetooth proxy scanners register ~20s after HA starts; the first BLE
# round can otherwise lose routing to the weak local adapter.
PROXY_SETTLE_S = 45

# shortcut: only the newest RECORD_CAP summaries are persisted; raise it when
# multi-year history is needed (one record per day, ~2KB each as JSON).
RECORD_CAP = 730

# Backfill: a capped round returns ~1-2 summaries, so a round that advanced the
# cursor shortens the coordinator interval and HA schedules the next refresh
# itself. Each refresh stays one bounded connection.
BACKFILL_INTERVAL = timedelta(seconds=20)
BLE_INTERVAL = timedelta(hours=1)


class BmcE6Coordinator(DataUpdateCoordinator):
    """Owns the daily incremental download and merges all three data sources.

    Sources: ble (HA-side, primary), cloud (daily score report + fallback),
    mini_ble (pushed by the mini agent webhook). Records dedupe by recordNo.
    """

    def __init__(self, hass: HomeAssistant, target_name: str, pem_path: str, cloud_client=None, store=None) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN}_{target_name}",
            update_interval=BLE_INTERVAL,
        )
        self.target_name = target_name
        self._pem_path = pem_path
        self._cloud = cloud_client
        self._store = store
        # The integration is always BLE-enabled (target_name is required in the
        # config flow); cloud is a backup/report channel. Never infer "cloud only"
        # from an empty record set (first boot / BLE not yet fetched).
        self._ble_enabled = bool(target_name)
        self._cursor = 0  # persisted max completed recordNo (restore from storage)
        self.last_success = None
        self._last_success_epoch: float | None = None
        self._records: dict[int, dict] = {}
        self._ble_advanced = False
        self.hw_version: str | None = None
        self.sw_version: str | None = None

    async def async_initialize(self) -> None:
        if self._store is not None:
            loaded = await self._store.async_load()
            if isinstance(loaded, int) and not isinstance(loaded, bool) and 0 <= loaded <= 0xFFFFFFFF:
                self._cursor = loaded
            elif isinstance(loaded, dict):
                cursor = loaded.get("cursor")
                # Clamp on load too: a previously poisoned store must not keep
                # producing a cursor the wire builder rejects.
                if (isinstance(cursor, int) and not isinstance(cursor, bool)
                        and 0 <= cursor <= 0xFFFFFFFF):
                    self._cursor = cursor
                epoch = loaded.get("last_success_epoch")
                if isinstance(epoch, (int, float)) and not isinstance(epoch, bool):
                    self._last_success_epoch = float(epoch)
                if isinstance(loaded.get("last_success"), str):
                    self.last_success = loaded["last_success"]
                self._records = restore_records(loaded.get("records"))
                for attr in ("hw_version", "sw_version"):
                    if isinstance(loaded.get(attr), str):
                        setattr(self, attr, loaded[attr])

    async def _async_update_data(self) -> dict:
        # BLE primary channel (HA bluetooth routes via local/ESPHome adapters).
        if self._ble_enabled:
            await self._async_ble_channel()
        cloud_metrics = None
        cloud_error = None
        if self._cloud is not None:
            try:
                await self._cloud.ensure_auth()
                cloud_metrics = await self._cloud.pick_report()
            except Exception as ex:  # cloud is a backup channel; never block BLE
                cloud_error = f"{type(ex).__name__}: {ex}"
                _LOGGER.warning("Remot cloud fetch failed: %s", cloud_error)
                if not self._ble_enabled and self.data is None:
                    # Only a truly cloud-only FIRST refresh fails hard; later
                    # failures keep old data plus cloud_error (never fake success).
                    from homeassistant.helpers.update_coordinator import UpdateFailed

                    raise UpdateFailed(f"Remot cloud fetch failed: {cloud_error}") from ex
        return {
            "records": self._records,
            "latest": max(self._records) if self._records else None,
            "cursor": self._cursor,
            "last_success": self.last_success,
            "cloud": cloud_metrics,
            "cloud_error": cloud_error,
        }

    async def _async_ble_channel(self) -> None:
        """One bounded BLE round; continue sooner while older records remain."""
        ok = await self._async_ble_round()
        if not ok:
            await asyncio.sleep(PROXY_SETTLE_S)
            ok = await self._async_ble_round()
        # Advancing the cursor means more history is waiting. Any failure falls
        # back to the hourly rate so a broken link cannot spin.
        backfill = ok and self._ble_advanced
        self.update_interval = BACKFILL_INTERVAL if backfill else BLE_INTERVAL
        if backfill:
            _LOGGER.info("BLE backfill: next round in %ss (cursor=%s)",
                         BACKFILL_INTERVAL.seconds, self._cursor)

    async def _async_ble_round(self) -> bool:
        """One bounded BLE download round. True once the session authenticated."""
        before_cursor = self._cursor
        self._ble_advanced = False
        _LOGGER.info("BLE download start: cursor=%s device=%s", self._cursor,
                     "configured" if self.target_name else "unset")
        try:
            from habluetooth import HaBleakClientWrapper
            from homeassistant.components.bluetooth import async_discovered_service_info, async_get_scanner

            from .bmc_ble.client import E6BleClient

            infos = async_discovered_service_info(self.hass)
            _LOGGER.info("BT discovered %d devices", len(infos))
            scanner = async_get_scanner(self.hass)
            ble = E6BleClient(self.target_name, self._pem_path)
            result = await ble.download(
                self._cursor, scanner=scanner, client_factory=HaBleakClientWrapper,
                # The device-information strings never change; read them once.
                want_device_info=self.hw_version is None or self.sw_version is None,
            )
            report = result["report"]
            versions = report.get("device_versions") or {}
            if versions:
                self.hw_version = versions.get("hw_version") or self.hw_version
                self.sw_version = versions.get("sw_version") or self.sw_version
            if report["auth"].get("authenticated"):
                added = self.merge_records(result["summaries"], "ble")
                if result["next_cursor"] is not None:
                    # Never regress: a re-pushed older record must not undo the
                    # max(merged) bump merge_records just made.
                    self._cursor = max(self._cursor, result["next_cursor"])
                self._ble_advanced = self._cursor > before_cursor
                if result["code"] == 0:
                    self.last_success = result["report"].get("ended")
                    self._last_success_epoch = time.time()
                await self.async_persist_state()
                _LOGGER.info("BLE download done: %d new summaries, %d total, next_cursor=%s stop=%s counts=%s rssi=%s",
                             added, len(result["summaries"]), result["next_cursor"], report.get("stop_reason"),
                             report.get("counts"), report.get("rssi"))
                return True
            connect = report.get("connect") or {}
            _LOGGER.warning("BLE download failed: %s (rssi=%s discovered=%s connect_ok=%s error=%s) auth=%s",
                            report.get("stop_reason"), report.get("rssi"),
                            report.get("discovered"), connect.get("ok"), connect.get("error"),
                            report.get("auth"))
        except Exception as ex:  # BLE failure must not block the cloud channel
            _LOGGER.warning("BLE download error: %s: %s", type(ex).__name__, ex)
        return False

    async def async_persist_state(self) -> None:
        if self._store is None:
            _LOGGER.warning("no state store; cursor/records are not persisted")
            return
        keep = sorted(self._records)[-RECORD_CAP:]
        await self._store.async_save({
            "cursor": self._cursor,
            "last_success": self.last_success,
            "last_success_epoch": self._last_success_epoch,
            "hw_version": self.hw_version,
            "sw_version": self.sw_version,
            "records": [json_safe_record(self._records[no]) for no in keep],
        })
        _LOGGER.info("state persisted: cursor=%s records=%d", self._cursor, len(keep))
        # HA's storage layer swallows serialization failures, so confirm the write.
        try:
            age = time.time() - os.stat(self._store.path).st_mtime
        except OSError as ex:
            _LOGGER.warning("state store stat failed: %s", ex)
            return
        if age > 5:
            _LOGGER.warning("state store write did not land (file is %.0fs old)", age)

    def health_status(self) -> dict:
        age = None
        if self._last_success_epoch is not None:
            age = max(0.0, time.time() - self._last_success_epoch)
        return {
            "ok": age is not None and age < BLE_INTERVAL.total_seconds() * 2,
            "target_name": self.target_name,
            "cursor": self._cursor,
            "last_success": self.last_success,
            "last_success_age_s": age,
        }

    def merge_records(self, records: list[dict], source: str) -> int:
        """Merge records from any source, deduplicating by recordNo. Returns new count.

        Never moves the BLE resume cursor. Only a device session may advance it,
        from that session's own next_cursor: records arriving from a push can be
        ahead of the device cursor by nature, and taking max() over the merged set
        would let one such record skip every record below it.
        """
        merged, added, _cursor = merge_records(self._records, records, source)
        self._records = merged
        if added:
            # Rebuild data so latest reflects the merge before notifying.
            data = dict(self.data or {})
            data.update({
                "records": merged,
                "latest": max(merged) if merged else None,
                "cursor": self._cursor,
            })
            self.async_set_updated_data(data)
        return added
