"""Constants for the Wyze Palm integration."""
from __future__ import annotations

from typing import Final

DOMAIN: Final = "wyze_palm_ha"

# Configuration keys
CONF_ACCESS_TOKEN: Final = "access_token"
CONF_REFRESH_TOKEN: Final = "refresh_token"
CONF_USER_ID: Final = "user_id"

# Options
CONF_SCAN_INTERVAL: Final = "scan_interval"
DEFAULT_SCAN_INTERVAL: Final = 60  # seconds

# Platforms
PLATFORMS: Final = ["lock", "sensor", "binary_sensor", "number"]

# Unlock methods
UNLOCK_METHOD_PALM: Final = "palm"
UNLOCK_METHOD_PIN: Final = "pin"
UNLOCK_METHOD_FINGERPRINT: Final = "fingerprint"
UNLOCK_METHOD_KEY: Final = "key"
UNLOCK_METHOD_APP: Final = "app"
UNLOCK_METHOD_AUTO: Final = "auto"
UNLOCK_METHOD_MANUAL: Final = "manual"
UNLOCK_METHOD_UNKNOWN: Final = "unknown"

# Events
EVENT_UNLOCK: Final = "wyze_palm_unlock"
EVENT_LOCK: Final = "wyze_palm_lock"
EVENT_FAILED: Final = "wyze_palm_failed"

# Device trigger types
TRIGGER_UNLOCKED: Final = "unlocked"
TRIGGER_UNLOCKED_PALM: Final = "unlocked_palm"
TRIGGER_LOCKED: Final = "locked"
TRIGGER_FAILED_ATTEMPT: Final = "failed_attempt"
TRIGGER_DOOR_OPENED: Final = "door_opened"
TRIGGER_DOOR_CLOSED: Final = "door_closed"
TRIGGER_BATTERY_LOW: Final = "battery_low"

# Battery threshold
BATTERY_LOW_THRESHOLD: Final = 20

# Attribution
ATTRIBUTION: Final = "Data provided by Wyze"

# Service names
SERVICE_SET_AUTO_LOCK: Final = "set_auto_lock"

# Attributes
ATTR_DOOR_OPEN: Final = "door_open"
ATTR_LAST_UNLOCK_METHOD: Final = "last_unlock_method"
ATTR_LAST_UNLOCK_USER: Final = "last_unlock_user"
ATTR_AUTO_LOCK_ENABLED: Final = "auto_lock_enabled"
ATTR_AUTO_LOCK_TIME: Final = "auto_lock_time"
