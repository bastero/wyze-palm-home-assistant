"""Binary sensor platform for Wyze Palm integration."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import ATTRIBUTION, DOMAIN
from .coordinator import WyzePalmDataUpdateCoordinator


@dataclass(frozen=True, kw_only=True)
class WyzePalmBinarySensorEntityDescription(BinarySensorEntityDescription):
    """Describes Wyze Palm binary sensor entity."""

    value_fn: Callable[[dict[str, Any]], bool | None]


def get_door_open(data: dict[str, Any]) -> bool | None:
    """Get door open state."""
    return data.get("door_open")


def get_connected(data: dict[str, Any]) -> bool | None:
    """Get connectivity state."""
    return data.get("online")


BINARY_SENSOR_DESCRIPTIONS: tuple[WyzePalmBinarySensorEntityDescription, ...] = (
    WyzePalmBinarySensorEntityDescription(
        key="door",
        translation_key="door",
        device_class=BinarySensorDeviceClass.DOOR,
        value_fn=get_door_open,
    ),
    WyzePalmBinarySensorEntityDescription(
        key="connected",
        translation_key="connected",
        device_class=BinarySensorDeviceClass.CONNECTIVITY,
        value_fn=get_connected,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Wyze Palm binary sensors from a config entry."""
    coordinator: WyzePalmDataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id]

    entities = []
    for lock_mac in coordinator.data.get("locks", {}):
        for description in BINARY_SENSOR_DESCRIPTIONS:
            entities.append(WyzePalmBinarySensor(coordinator, lock_mac, description))

    async_add_entities(entities)


class WyzePalmBinarySensor(
    CoordinatorEntity[WyzePalmDataUpdateCoordinator], BinarySensorEntity
):
    """Representation of a Wyze Palm binary sensor."""

    _attr_has_entity_name = True
    _attr_attribution = ATTRIBUTION

    entity_description: WyzePalmBinarySensorEntityDescription

    def __init__(
        self,
        coordinator: WyzePalmDataUpdateCoordinator,
        lock_mac: str,
        description: WyzePalmBinarySensorEntityDescription,
    ) -> None:
        """Initialize the binary sensor."""
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
        # Connectivity sensor should always be available if coordinator has data
        if self.entity_description.key == "connected":
            return self.coordinator.last_update_success

        lock_data = self.coordinator.get_lock_data(self._lock_mac)
        if lock_data is None:
            return False
        return lock_data.get("online", False) and self.coordinator.last_update_success

    @property
    def is_on(self) -> bool | None:
        """Return true if the binary sensor is on."""
        lock_data = self.coordinator.get_lock_data(self._lock_mac)
        if lock_data is None:
            return None
        return self.entity_description.value_fn(lock_data)

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        self.async_write_ha_state()
