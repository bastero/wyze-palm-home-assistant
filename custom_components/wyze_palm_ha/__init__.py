"""The Wyze Palm integration."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_DEVICE_ID
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.helpers import config_validation as cv

from .const import (
    ATTR_AUTO_LOCK_TIME,
    DOMAIN,
    PLATFORMS,
    SERVICE_SET_AUTO_LOCK,
)
from .coordinator import WyzePalmDataUpdateCoordinator

_LOGGER = logging.getLogger(__name__)

SERVICE_SET_AUTO_LOCK_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_DEVICE_ID): cv.string,
        vol.Required(ATTR_AUTO_LOCK_TIME): vol.All(
            vol.Coerce(int), vol.Range(min=0, max=1800)
        ),
    }
)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Wyze Palm from a config entry."""
    coordinator = WyzePalmDataUpdateCoordinator(hass, entry)

    await coordinator._async_setup()
    await coordinator.async_config_entry_first_refresh()

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = coordinator

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Register services
    await _async_register_services(hass)

    # Listen for options updates
    entry.async_on_unload(entry.add_update_listener(async_options_update_listener))

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id)

    # Unregister services if no more entries
    if not hass.data[DOMAIN]:
        for service in [SERVICE_SET_AUTO_LOCK]:
            if hass.services.has_service(DOMAIN, service):
                hass.services.async_remove(DOMAIN, service)

    return unload_ok


async def async_options_update_listener(
    hass: HomeAssistant, entry: ConfigEntry
) -> None:
    """Handle options update."""
    await hass.config_entries.async_reload(entry.entry_id)


async def _async_register_services(hass: HomeAssistant) -> None:
    """Register integration services."""

    async def async_set_auto_lock(call: ServiceCall) -> None:
        """Handle set_auto_lock service call."""
        device_id = call.data[CONF_DEVICE_ID]
        auto_lock_time = call.data[ATTR_AUTO_LOCK_TIME]

        for entry_id, coordinator in hass.data[DOMAIN].items():
            if isinstance(coordinator, WyzePalmDataUpdateCoordinator):
                lock_data = coordinator.get_lock_data(device_id)
                if lock_data:
                    await coordinator.async_set_auto_lock(device_id, auto_lock_time)
                    return

        _LOGGER.error("Lock device %s not found", device_id)

    if not hass.services.has_service(DOMAIN, SERVICE_SET_AUTO_LOCK):
        hass.services.async_register(
            DOMAIN,
            SERVICE_SET_AUTO_LOCK,
            async_set_auto_lock,
            schema=SERVICE_SET_AUTO_LOCK_SCHEMA,
        )
