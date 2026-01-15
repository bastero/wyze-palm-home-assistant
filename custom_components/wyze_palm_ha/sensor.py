"""Sensor platform for Wyze Palm integration."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import PERCENTAGE, UnitOfTime
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import ATTRIBUTION, DOMAIN
from .coordinator import WyzePalmDataUpdateCoordinator


@dataclass(frozen=True, kw_only=True)
class WyzePalmSensorEntityDescription(SensorEntityDescription):
    """Describes Wyze Palm sensor entity."""

    value_fn: Callable[[dict[str, Any], WyzePalmDataUpdateCoordinator, str], Any]


def get_battery(data: dict[str, Any], coordinator: WyzePalmDataUpdateCoordinator, mac: str) -> int | None:
    """Get battery level."""
    return data.get("battery")


def get_last_unlock_method(data: dict[str, Any], coordinator: WyzePalmDataUpdateCoordinator, mac: str) -> str | None:
    """Get last unlock method."""
    events = data.get("events", [])
    for event in events:
        event_type = getattr(event, "event_type", None)
        if event_type and "unlock" in str(event_type).lower():
            return coordinator._get_unlock_method(event)
    return None


def get_last_unlock_user(data: dict[str, Any], coordinator: WyzePalmDataUpdateCoordinator, mac: str) -> str | None:
    """Get last unlock user."""
    events = data.get("events", [])
    for event in events:
        event_type = getattr(event, "event_type", None)
        if event_type and "unlock" in str(event_type).lower():
            return coordinator._get_event_user(event)
    return None


def get_failed_attempts(data: dict[str, Any], coordinator: WyzePalmDataUpdateCoordinator, mac: str) -> int:
    """Get failed palm attempts count."""
    return coordinator.get_failed_attempts(mac)


def get_auto_lock_time(data: dict[str, Any], coordinator: WyzePalmDataUpdateCoordinator, mac: str) -> int:
    """Get auto-lock time setting."""
    return data.get("auto_lock_time", 0) or 0


SENSOR_DESCRIPTIONS: tuple[WyzePalmSensorEntityDescription, ...] = (
    WyzePalmSensorEntityDescription(
        key="battery",
        translation_key="battery",
        device_class=SensorDeviceClass.BATTERY,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=PERCENTAGE,
        value_fn=get_battery,
    ),
    WyzePalmSensorEntityDescription(
        key="last_unlock_method",
        translation_key="last_unlock_method",
        icon="mdi:key-variant",
        value_fn=get_last_unlock_method,
    ),
    WyzePalmSensorEntityDescription(
        key="last_unlock_user",
        translation_key="last_unlock_user",
        icon="mdi:account",
        value_fn=get_last_unlock_user,
    ),
    WyzePalmSensorEntityDescription(
        key="failed_attempts",
        translation_key="failed_attempts",
        icon="mdi:alert-circle",
        state_class=SensorStateClass.TOTAL_INCREASING,
        value_fn=get_failed_attempts,
    ),
    WyzePalmSensorEntityDescription(
        key="auto_lock_time",
        translation_key="auto_lock_time",
        icon="mdi:timer-lock",
        native_unit_of_measurement=UnitOfTime.SECONDS,
        value_fn=get_auto_lock_time,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Wyze Palm sensors from a config entry."""
    coordinator: WyzePalmDataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id]

    entities = []
    for lock_mac in coordinator.data.get("locks", {}):
        for description in SENSOR_DESCRIPTIONS:
            entities.append(WyzePalmSensor(coordinator, lock_mac, description))

    async_add_entities(entities)


class WyzePalmSensor(CoordinatorEntity[WyzePalmDataUpdateCoordinator], SensorEntity):
    """Representation of a Wyze Palm sensor."""

    _attr_has_entity_name = True
    _attr_attribution = ATTRIBUTION

    entity_description: WyzePalmSensorEntityDescription

    def __init__(
        self,
        coordinator: WyzePalmDataUpdateCoordinator,
        lock_mac: str,
        description: WyzePalmSensorEntityDescription,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator)
        self._lock_mac = lock_mac
        self.entity_description = description
        self._attr_unique_id = f"{lock_mac}_{description.key}"

    @property
    def device_info(self) -> DeviceInfo:
        """Return device information."""
        lock_data = self.coordinator.get_lock_data(self._lock_mac)
        return DeviceInfo(
            identifiers={(DOMAIN, self._lock_mac)},
            name=lock_data.get("nickname", self._lock_mac) if lock_data else self._lock_mac,
            manufacturer="Wyze",
            model=lock_data.get("model", "Palm Lock") if lock_data else "Palm Lock",
        )

    @property
    def available(self) -> bool:
        """Return True if entity is available."""
        lock_data = self.coordinator.get_lock_data(self._lock_mac)
        if lock_data is None:
            return False
        return lock_data.get("online", False) and self.coordinator.last_update_success

    @property
    def native_value(self) -> Any:
        """Return the state of the sensor."""
        lock_data = self.coordinator.get_lock_data(self._lock_mac)
        if lock_data is None:
            return None
        return self.entity_description.value_fn(lock_data, self.coordinator, self._lock_mac)

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        self.async_write_ha_state()
