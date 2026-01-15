"""Diagnostics support for Wyze Palm integration."""
from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD
from homeassistant.core import HomeAssistant

from .const import CONF_ACCESS_TOKEN, CONF_REFRESH_TOKEN, DOMAIN
from .coordinator import WyzePalmDataUpdateCoordinator

TO_REDACT = {
    CONF_EMAIL,
    CONF_PASSWORD,
    CONF_ACCESS_TOKEN,
    CONF_REFRESH_TOKEN,
    "access_token",
    "refresh_token",
    "email",
    "password",
    "user_id",
    "mac",
}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: ConfigEntry
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""
    coordinator: WyzePalmDataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id]

    # Get lock data without raw objects (not serializable)
    locks_data = {}
    if coordinator.data:
        for lock_mac, lock_data in coordinator.data.get("locks", {}).items():
            locks_data[lock_mac] = {
                "mac": lock_mac,
                "nickname": lock_data.get("nickname"),
                "model": lock_data.get("model"),
                "is_locked": lock_data.get("is_locked"),
                "door_open": lock_data.get("door_open"),
                "battery": lock_data.get("battery"),
                "online": lock_data.get("online"),
                "auto_lock_time": lock_data.get("auto_lock_time"),
                "event_count": len(lock_data.get("events", [])),
            }

    diagnostics_data = {
        "config_entry": {
            "entry_id": entry.entry_id,
            "version": entry.version,
            "domain": entry.domain,
            "title": entry.title,
            "data": async_redact_data(dict(entry.data), TO_REDACT),
            "options": dict(entry.options),
        },
        "coordinator": {
            "last_update_success": coordinator.last_update_success,
            "update_interval": str(coordinator.update_interval),
        },
        "locks": async_redact_data(locks_data, TO_REDACT),
        "failed_attempts": coordinator._failed_attempts,
    }

    return diagnostics_data
