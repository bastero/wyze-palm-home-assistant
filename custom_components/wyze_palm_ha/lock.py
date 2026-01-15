"""Lock platform for Wyze Palm integration."""
from __future__ import annotations

from typing import Any

from homeassistant.components.lock import LockEntity, LockEntityFeature
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import (
    ATTR_AUTO_LOCK_ENABLED,
    ATTR_AUTO_LOCK_TIME,
    ATTR_DOOR_OPEN,
    ATTR_LAST_UNLOCK_METHOD,
    ATTR_LAST_UNLOCK_USER,
    ATTRIBUTION,
    DOMAIN,
)
from .coordinator import WyzePalmDataUpdateCoordinator


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Wyze Palm locks from a config entry."""
    coordinator: WyzePalmDataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id]

    entities = []
    for lock_mac, lock_data in coordinator.data.get("locks", {}).items():
        entities.append(WyzePalmLock(coordinator, lock_mac))

    async_add_entities(entities)


class WyzePalmLock(CoordinatorEntity[WyzePalmDataUpdateCoordinator], LockEntity):
    """Representation of a Wyze Palm Lock."""

    _attr_has_entity_name = True
    _attr_name = None
    _attr_attribution = ATTRIBUTION
    _attr_supported_features = LockEntityFeature.OPEN

    def __init__(
        self,
        coordinator: WyzePalmDataUpdateCoordinator,
        lock_mac: str,
    ) -> None:
        """Initialize the lock."""
        super().__init__(coordinator)
        self._lock_mac = lock_mac
        self._attr_unique_id = f"{lock_mac}_lock"

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
    def is_locked(self) -> bool | None:
        """Return true if the lock is locked."""
        lock_data = self.coordinator.get_lock_data(self._lock_mac)
        if lock_data is None:
            return None
        return lock_data.get("is_locked")

    @property
    def is_locking(self) -> bool:
        """Return true if the lock is locking."""
        return False

    @property
    def is_unlocking(self) -> bool:
        """Return true if the lock is unlocking."""
        return False

    @property
    def is_jammed(self) -> bool:
        """Return true if the lock is jammed."""
        return False

    @property
    def available(self) -> bool:
        """Return True if entity is available."""
        lock_data = self.coordinator.get_lock_data(self._lock_mac)
        if lock_data is None:
            return False
        return lock_data.get("online", False) and self.coordinator.last_update_success

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra state attributes."""
        lock_data = self.coordinator.get_lock_data(self._lock_mac)
        if lock_data is None:
            return {}

        attrs = {
            ATTR_DOOR_OPEN: lock_data.get("door_open"),
            ATTR_AUTO_LOCK_TIME: lock_data.get("auto_lock_time", 0),
            ATTR_AUTO_LOCK_ENABLED: (lock_data.get("auto_lock_time", 0) or 0) > 0,
        }

        # Get last unlock info from events
        events = lock_data.get("events", [])
        for event in events:
            event_type = getattr(event, "event_type", None)
            if event_type and "unlock" in str(event_type).lower():
                attrs[ATTR_LAST_UNLOCK_METHOD] = self.coordinator._get_unlock_method(event)
                attrs[ATTR_LAST_UNLOCK_USER] = self.coordinator._get_event_user(event)
                break

        return attrs

    async def async_lock(self, **kwargs: Any) -> None:
        """Lock the lock."""
        await self.coordinator.async_lock(self._lock_mac)

    async def async_unlock(self, **kwargs: Any) -> None:
        """Unlock the lock."""
        await self.coordinator.async_unlock(self._lock_mac)

    async def async_open(self, **kwargs: Any) -> None:
        """Open the lock (same as unlock for this device)."""
        await self.coordinator.async_unlock(self._lock_mac)

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        self.async_write_ha_state()
