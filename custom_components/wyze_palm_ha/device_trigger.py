"""Device triggers for Wyze Palm integration."""
from __future__ import annotations

from typing import Any

import voluptuous as vol

from homeassistant.components.device_automation import DEVICE_TRIGGER_BASE_SCHEMA
from homeassistant.components.homeassistant.triggers import event as event_trigger
from homeassistant.const import CONF_DEVICE_ID, CONF_DOMAIN, CONF_PLATFORM, CONF_TYPE
from homeassistant.core import CALLBACK_TYPE, HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.trigger import TriggerActionType, TriggerInfo
from homeassistant.helpers.typing import ConfigType

from .const import (
    DOMAIN,
    EVENT_FAILED,
    EVENT_LOCK,
    EVENT_UNLOCK,
    TRIGGER_BATTERY_LOW,
    TRIGGER_DOOR_CLOSED,
    TRIGGER_DOOR_OPENED,
    TRIGGER_FAILED_ATTEMPT,
    TRIGGER_LOCKED,
    TRIGGER_UNLOCKED,
    TRIGGER_UNLOCKED_PALM,
    UNLOCK_METHOD_PALM,
)

TRIGGER_TYPES = {
    TRIGGER_UNLOCKED,
    TRIGGER_UNLOCKED_PALM,
    TRIGGER_LOCKED,
    TRIGGER_FAILED_ATTEMPT,
    TRIGGER_DOOR_OPENED,
    TRIGGER_DOOR_CLOSED,
    TRIGGER_BATTERY_LOW,
}

TRIGGER_SCHEMA = DEVICE_TRIGGER_BASE_SCHEMA.extend(
    {
        vol.Required(CONF_TYPE): vol.In(TRIGGER_TYPES),
    }
)


async def async_get_triggers(
    hass: HomeAssistant, device_id: str
) -> list[dict[str, Any]]:
    """Return a list of triggers for a device."""
    device_registry = dr.async_get(hass)
    device = device_registry.async_get(device_id)

    if device is None:
        return []

    # Check if this device belongs to our integration
    if DOMAIN not in [id[0] for id in device.identifiers]:
        return []

    triggers = []
    base_trigger = {
        CONF_PLATFORM: "device",
        CONF_DEVICE_ID: device_id,
        CONF_DOMAIN: DOMAIN,
    }

    for trigger_type in TRIGGER_TYPES:
        triggers.append({**base_trigger, CONF_TYPE: trigger_type})

    return triggers


async def async_attach_trigger(
    hass: HomeAssistant,
    config: ConfigType,
    action: TriggerActionType,
    trigger_info: TriggerInfo,
) -> CALLBACK_TYPE:
    """Attach a trigger."""
    device_registry = dr.async_get(hass)
    device = device_registry.async_get(config[CONF_DEVICE_ID])

    if device is None:
        raise ValueError(f"Device {config[CONF_DEVICE_ID]} not found")

    # Get the lock MAC from device identifiers
    lock_mac = None
    for identifier in device.identifiers:
        if identifier[0] == DOMAIN:
            lock_mac = identifier[1]
            break

    if lock_mac is None:
        raise ValueError(f"Could not find lock MAC for device {config[CONF_DEVICE_ID]}")

    trigger_type = config[CONF_TYPE]

    # Map trigger types to events
    if trigger_type == TRIGGER_UNLOCKED:
        event_config = event_trigger.TRIGGER_SCHEMA(
            {
                event_trigger.CONF_PLATFORM: "event",
                event_trigger.CONF_EVENT_TYPE: EVENT_UNLOCK,
                event_trigger.CONF_EVENT_DATA: {"device_id": lock_mac},
            }
        )
    elif trigger_type == TRIGGER_UNLOCKED_PALM:
        event_config = event_trigger.TRIGGER_SCHEMA(
            {
                event_trigger.CONF_PLATFORM: "event",
                event_trigger.CONF_EVENT_TYPE: EVENT_UNLOCK,
                event_trigger.CONF_EVENT_DATA: {
                    "device_id": lock_mac,
                    "method": UNLOCK_METHOD_PALM,
                },
            }
        )
    elif trigger_type == TRIGGER_LOCKED:
        event_config = event_trigger.TRIGGER_SCHEMA(
            {
                event_trigger.CONF_PLATFORM: "event",
                event_trigger.CONF_EVENT_TYPE: EVENT_LOCK,
                event_trigger.CONF_EVENT_DATA: {"device_id": lock_mac},
            }
        )
    elif trigger_type == TRIGGER_FAILED_ATTEMPT:
        event_config = event_trigger.TRIGGER_SCHEMA(
            {
                event_trigger.CONF_PLATFORM: "event",
                event_trigger.CONF_EVENT_TYPE: EVENT_FAILED,
                event_trigger.CONF_EVENT_DATA: {"device_id": lock_mac},
            }
        )
    elif trigger_type in (TRIGGER_DOOR_OPENED, TRIGGER_DOOR_CLOSED, TRIGGER_BATTERY_LOW):
        # These triggers use state changes, handled via state trigger
        from homeassistant.components.homeassistant.triggers import state as state_trigger

        if trigger_type == TRIGGER_DOOR_OPENED:
            state_config = state_trigger.TRIGGER_SCHEMA(
                {
                    state_trigger.CONF_PLATFORM: "state",
                    state_trigger.CONF_ENTITY_ID: f"binary_sensor.{lock_mac}_door",
                    state_trigger.CONF_TO: "on",
                }
            )
            return await state_trigger.async_attach_trigger(
                hass, state_config, action, trigger_info, platform_type="device"
            )
        elif trigger_type == TRIGGER_DOOR_CLOSED:
            state_config = state_trigger.TRIGGER_SCHEMA(
                {
                    state_trigger.CONF_PLATFORM: "state",
                    state_trigger.CONF_ENTITY_ID: f"binary_sensor.{lock_mac}_door",
                    state_trigger.CONF_TO: "off",
                }
            )
            return await state_trigger.async_attach_trigger(
                hass, state_config, action, trigger_info, platform_type="device"
            )
        elif trigger_type == TRIGGER_BATTERY_LOW:
            from homeassistant.components.homeassistant.triggers import (
                numeric_state as numeric_state_trigger,
            )

            numeric_config = numeric_state_trigger.TRIGGER_SCHEMA(
                {
                    numeric_state_trigger.CONF_PLATFORM: "numeric_state",
                    numeric_state_trigger.CONF_ENTITY_ID: f"sensor.{lock_mac}_battery",
                    numeric_state_trigger.CONF_BELOW: 20,
                }
            )
            return await numeric_state_trigger.async_attach_trigger(
                hass, numeric_config, action, trigger_info, platform_type="device"
            )

    return await event_trigger.async_attach_trigger(
        hass, event_config, action, trigger_info, platform_type="device"
    )


async def async_get_trigger_capabilities(
    hass: HomeAssistant, config: ConfigType
) -> dict[str, vol.Schema]:
    """Return trigger capabilities."""
    return {}
