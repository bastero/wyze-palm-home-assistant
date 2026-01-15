"""Number platform for Wyze Palm integration."""
from __future__ import annotations

from typing import Any

from homeassistant.components.number import NumberEntity, NumberMode
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfTime
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import ATTRIBUTION, DOMAIN
from .coordinator import WyzePalmDataUpdateCoordinator


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Wyze Palm number entities from a config entry."""
    coordinator: WyzePalmDataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id]

    entities = []
    for lock_mac in coordinator.data.get("locks", {}):
        entities.append(WyzePalmAutoLockNumber(coordinator, lock_mac))

    async_add_entities(entities)


class WyzePalmAutoLockNumber(
    CoordinatorEntity[WyzePalmDataUpdateCoordinator], NumberEntity
):
    """Representation of Wyze Palm auto-lock time setting."""

    _attr_has_entity_name = True
    _attr_translation_key = "auto_lock_time_setting"
    _attr_attribution = ATTRIBUTION
    _attr_icon = "mdi:timer-lock-outline"
    _attr_mode = NumberMode.BOX
    _attr_native_min_value = 0
    _attr_native_max_value = 1800
    _attr_native_step = 1
    _attr_native_unit_of_measurement = UnitOfTime.SECONDS

    def __init__(
        self,
        coordinator: WyzePalmDataUpdateCoordinator,
        lock_mac: str,
    ) -> None:
        """Initialize the number entity."""
        super().__init__(coordinator)
        self._lock_mac = lock_mac
        self._attr_unique_id = f"{lock_mac}_auto_lock_setting"

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
    def native_value(self) -> float | None:
        """Return the current auto-lock time."""
        lock_data = self.coordinator.get_lock_data(self._lock_mac)
        if lock_data is None:
            return None
        return lock_data.get("auto_lock_time", 0) or 0

    async def async_set_native_value(self, value: float) -> None:
        """Set the auto-lock time."""
        await self.coordinator.async_set_auto_lock(self._lock_mac, int(value))

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        self.async_write_ha_state()
