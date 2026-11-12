"""Sensors: latest-night metrics + cloud score report for the BMC ventilator."""
from __future__ import annotations

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity, SensorStateClass
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import BmcE6Coordinator
# key, summary field, unit transformer, icon, native unit, device class
_SENSORS = (
    ("ahi", "ahi", lambda v: round(v / 10, 1), "mdi:sleep", "events/h", None),
    ("treat_time_h", "treatTime", lambda v: round(v / 3600, 2), "mdi:timer-outline", "h",
     SensorDeviceClass.DURATION),
    ("leak_avg", "leakAvg", lambda v: round(v / 10, 1), "mdi:weather-windy", "L/min", None),
    ("epap_avg", "epapAvg", lambda v: round(v / 100, 2), "mdi:arrow-down-bold", "cmH2O", None),
    ("ipap_avg", "ipapAvg", lambda v: round(v / 100, 2), "mdi:arrow-up-bold", "cmH2O", None),
    ("vt_avg", "vtAvg", lambda v: v, "mdi:lungs", "mL", None),
    ("mv_avg", "mvAvg", lambda v: round(v / 1000, 2), "mdi:fan", "L/min", None),
    ("rr_avg", "rrAvg", lambda v: v, "mdi:respiratory", "breaths/min", None),
)


def _device_info(entry_id: str, coordinator: BmcE6Coordinator) -> DeviceInfo:
    return DeviceInfo(
        identifiers={(DOMAIN, entry_id)},
        name="瑞迈特",
        manufacturer="瑞迈特",
        # Explicit None clears the model/manufacturer left by earlier versions.
        model=None,
        # Measured from the GATT Device Information service, not hardcoded.
        hw_version=coordinator.hw_version,
        sw_version=coordinator.sw_version,
    )


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator: BmcE6Coordinator = hass.data[DOMAIN][entry.entry_id]
    entities = [BmcE6MetricSensor(coordinator, entry.entry_id, *spec) for spec in _SENSORS]
    entities.append(BmcE6CloudScoreSensor(coordinator, entry.entry_id))
    async_add_entities(entities)


class BmcE6CloudScoreSensor(CoordinatorEntity, SensorEntity):
    """Cloud score/analysis report (score, title, summary) for the latest night."""

    _attr_has_entity_name = True
    _attr_translation_key = "cloud_score"
    _attr_icon = "mdi:star-circle"

    def __init__(self, coordinator, entry_id) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{entry_id}_cloud_score"
        self._attr_device_info = _device_info(entry_id, coordinator)

    @property
    def _cloud(self) -> dict:
        return (self.coordinator.data or {}).get("cloud") or {}

    @property
    def native_value(self):
        return self._cloud.get("score")

    @property
    def available(self) -> bool:
        # UpdateFailed => super().available False; cloud_error => unavailable too.
        return super().available and (self.coordinator.data or {}).get("cloud_error") is None

    @property
    def extra_state_attributes(self) -> dict:
        c = self._cloud
        return {
            "score_title": c.get("score_title"),
            "score_summary": c.get("score_summary"),
            "record_date": c.get("record_date"),
            "ahi": c.get("ahi"),
            "treat_time_h": c.get("treat_time_h"),
            "leak_avg": c.get("leak_avg"),
            "spo2_avg": c.get("spo2_avg"),
            "source": c.get("source"),
            "polled_at": c.get("polled_at"),
        }


class BmcE6MetricSensor(CoordinatorEntity, SensorEntity):
    """One metric of the latest completed night; attributes carry provenance."""

    _attr_has_entity_name = True
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, coordinator, entry_id, key, field, transform, icon, unit, device_class) -> None:
        super().__init__(coordinator)
        self._key = key
        self._field = field
        self._transform = transform
        self._attr_translation_key = key
        self._attr_icon = icon
        self._attr_native_unit_of_measurement = unit
        self._attr_device_class = device_class
        self._attr_unique_id = f"{entry_id}_{key}"
        self._attr_device_info = _device_info(entry_id, coordinator)

    def _latest_record(self) -> dict:
        records = (self.coordinator.data or {}).get("records") or {}
        latest = (self.coordinator.data or {}).get("latest")
        return records.get(latest) or {}

    @property
    def native_value(self):
        rec = self._latest_record()
        value = rec.get(self._field)
        return self._transform(value) if value is not None else None

    @property
    def extra_state_attributes(self) -> dict:
        rec = self._latest_record()
        record_date = rec.get("recordDate")
        return {
            # The device stores a date; the 12:00 time is an encoding artifact.
            "record_date": str(record_date)[:10] if record_date else None,
            "record_no": rec.get("recordNo"),
            "source": rec.get("source"),
            "treat_count": rec.get("treatCnt"),
        }
