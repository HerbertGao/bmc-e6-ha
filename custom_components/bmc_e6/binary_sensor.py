"""Binary sensor for the ventilator's water-shortage alarm.

The device reports every alarm slot on wire 1406 (AlarmState): a 18-byte record
per slot with an active bit plus the window it was active. Slot 308 is the
"check water" alarm; the full snapshot is exposed as attributes so the other
slots stay visible without one entity each.
"""
from __future__ import annotations

from datetime import datetime
import time

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .bmc_ble.protocol_cmds import ALARM_ITEM_CHECK_WATER
from .const import DOMAIN
from .coordinator import BmcE6Coordinator


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator: BmcE6Coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([BmcE6WaterShortageSensor(coordinator, entry.entry_id)])


def _device_info(entry_id: str) -> DeviceInfo:
    return DeviceInfo(identifiers={(DOMAIN, entry_id)}, name="瑞迈特", manufacturer="瑞迈特", model=None)


class BmcE6WaterShortageSensor(CoordinatorEntity, BinarySensorEntity):
    """On while the device reports the water-check alarm (slot 308)."""

    _attr_has_entity_name = True
    _attr_translation_key = "water_shortage"
    _attr_device_class = BinarySensorDeviceClass.PROBLEM
    _attr_icon = "mdi:water-alert"

    def __init__(self, coordinator: BmcE6Coordinator, entry_id: str) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{entry_id}_water_shortage"
        self._attr_device_info = _device_info(entry_id)

    def _alarms(self) -> list[dict]:
        return (self.coordinator.data or {}).get("alarms") or []

    def _water(self) -> dict | None:
        for alarm in self._alarms():
            if alarm.get("item_id") == ALARM_ITEM_CHECK_WATER:
                return alarm
        return None

    @property
    def available(self) -> bool:
        return super().available and bool(self._alarms())

    @property
    def is_on(self) -> bool:
        water = self._water()
        return bool(water and water.get("active"))

    @property
    def extra_state_attributes(self) -> dict:
        water = self._water()
        active = [a for a in self._alarms() if a.get("active")]
        taken = (self.coordinator.data or {}).get("alarms_at")
        return {
            # The device only reports alarm slots when a BLE session connects, so
            # the reading can be up to one refresh interval old.
            "snapshot_at": (
                datetime.fromtimestamp(taken).astimezone().isoformat(timespec="seconds")
                if taken else None
            ),
            "snapshot_age_minutes": (
                round((time.time() - taken) / 60) if taken else None
            ),
            # The device keeps the window of the last occurrence even when the
            # alarm is currently inactive, which is why it is worth showing.
            "last_water_start": (water or {}).get("start"),
            "last_water_end": (water or {}).get("end"),
            "active_alarms": [
                {"name": a.get("name"), "item_id": a.get("item_id"), "start": a.get("start")}
                for a in active
            ],
            "all_alarms": [
                {
                    "item_id": a.get("item_id"),
                    "name": a.get("name"),
                    "active": a.get("active"),
                    "start": a.get("start"),
                    "end": a.get("end"),
                }
                for a in self._alarms()
            ],
        }
