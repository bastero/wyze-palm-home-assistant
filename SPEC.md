# Wyze Palm Home Assistant Integration - Specification

## Overview

The intent is to create an integration that exposes HA entities for the Wyze Palm lock.

## Goals

- Integrate Wyze Palm lock with Home Assistant using native lock platform
- Provide full lock control (lock/unlock) via HA services
- Expose palm recognition events with user attribution
- Track all unlock methods (palm, PIN, fingerprint, key, app)
- Auto-discover all palm-enabled locks on a Wyze account
- Support HA device automation triggers for palm events

## Supported Devices

- Wyze Lock with Palm Recognition (primary focus)
- Wyze Lock Bolt (future consideration - design for extensibility)

## Authentication

### Strategy
- **API Token Approach**: Use pre-authenticated tokens to bypass Wyze 2FA
- **Built-in Auth Flow**: Integration handles login and token extraction internally
- **Background Token Refresh**: Silently refresh tokens before expiry

### Token Management
1. User provides Wyze credentials during config flow
2. Integration authenticates and obtains access/refresh tokens
3. Tokens stored securely in HA config entry
4. Background task refreshes tokens before expiration
5. If re-authentication required, create HA repair issue

## Entities

### Lock Platform (Native)

| Entity | Description |
|--------|-------------|
| `lock.wyze_palm_<device_name>` | Native HA lock entity with lock/unlock/open services |

**Attributes:**
- `door_open`: Boolean indicating door position
- `last_unlock_method`: How the lock was last unlocked
- `last_unlock_user`: Who last unlocked (if palm/PIN)
- `auto_lock_enabled`: Current auto-lock setting
- `auto_lock_time`: Auto-lock delay in seconds

### Binary Sensors

| Entity | Description |
|--------|-------------|
| `binary_sensor.<device>_door` | Door open/closed state (separate entity) |
| `binary_sensor.<device>_connected` | Device connectivity/online status |

### Sensors

| Entity | Description |
|--------|-------------|
| `sensor.<device>_battery` | Battery level with device_class: battery |
| `sensor.<device>_last_unlock_method` | Last method used to unlock (palm/PIN/fingerprint/key/app) |
| `sensor.<device>_last_unlock_user` | Wyze username of last unlock (if applicable) |
| `sensor.<device>_failed_attempts` | Counter of failed palm recognition attempts |
| `sensor.<device>_auto_lock_time` | Current auto-lock delay setting |

### Number Entity

| Entity | Description |
|--------|-------------|
| `number.<device>_auto_lock_time` | Configurable auto-lock delay (0 = disabled) |

## Events

| Event | Payload | Description |
|-------|---------|-------------|
| `wyze_palm_unlock` | `device_id`, `method`, `user`, `timestamp` | Fired on any unlock |
| `wyze_palm_lock` | `device_id`, `method`, `timestamp` | Fired on any lock |
| `wyze_palm_failed` | `device_id`, `timestamp` | Fired on failed palm attempt |

## Device Automation Triggers

The integration registers device triggers for automation UI:
- "Lock was unlocked" (with method filter option)
- "Lock was unlocked by palm" (with user filter option)
- "Lock was locked"
- "Failed palm attempt detected"
- "Door opened"
- "Door closed"
- "Battery low"

## Services

| Service | Description |
|---------|-------------|
| `lock.lock` | Lock the device (standard HA service) |
| `lock.unlock` | Unlock the device (standard HA service) |
| `wyze_palm.set_auto_lock` | Configure auto-lock time (0 to disable) |

**Command Execution**: Immediate execution without confirmation dialogs.

## Configuration

### Config Flow

1. User enters Wyze email and password
2. Integration authenticates via built-in auth flow
3. All palm-enabled locks auto-discovered and added
4. Each lock appears as a device with associated entities

### Options Flow

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `scan_interval` | number | 60 | Polling interval in seconds (user configurable) |

## API Integration

### Library
- **Primary**: `wyze-sdk` - Popular unofficial SDK with broad device support

### Data Coordinator
- Single `DataUpdateCoordinator` per config entry
- User-configurable polling interval (default: 60 seconds)
- Fetches: lock state, door state, battery, recent events

### Error Handling

| Scenario | Behavior |
|----------|----------|
| API unreachable | Mark all entities as `unavailable` |
| Auth token expired | Attempt background refresh, create repair if fails |
| API changed/broken | Graceful degradation - disable broken features, keep working ones |
| Rate limited | Exponential backoff, log warning |

## Data Flow

```
┌─────────────────┐
│  Wyze Cloud API │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   wyze-sdk      │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────┐
│  DataUpdateCoordinator      │
│  (configurable interval)    │
└────────┬────────────────────┘
         │
    ┌────┴────┬──────────┬──────────┐
    ▼         ▼          ▼          ▼
┌───────┐ ┌───────┐ ┌─────────┐ ┌─────────┐
│ Lock  │ │Sensors│ │ Binary  │ │ Events  │
│Entity │ │       │ │ Sensors │ │         │
└───────┘ └───────┘ └─────────┘ └─────────┘
```

## History & Storage

- **No local storage**: Rely on HA recorder for entity history
- **No event caching**: Wyze API provides historical data when needed
- Events fire in real-time and are captured by HA's event system

## Home Assistant Features

### Diagnostics
- Full diagnostics support with redacted sensitive data
- Includes: connection status, device info, entity states, last errors
- Redacts: tokens, email, password, API keys

### Repairs
- Implement repair flows for common issues:
  - Authentication expired
  - API connection failed
  - Device offline
  - Rate limit exceeded

### Minimum Version
- **Home Assistant 2024.1+** required
- Leverages modern config flow APIs and entity features

## Dependencies

```
homeassistant>=2024.1.0
wyze-sdk>=1.0.0
```

## File Structure

```
custom_components/wyze_palm_ha/
├── __init__.py          # Integration setup, coordinator
├── manifest.json        # Integration metadata
├── config_flow.py       # Config and options flow
├── const.py             # Constants
├── coordinator.py       # DataUpdateCoordinator
├── lock.py              # Lock platform
├── sensor.py            # Sensor entities
├── binary_sensor.py     # Binary sensor entities
├── number.py            # Number entities (auto-lock)
├── diagnostics.py       # Diagnostics support
├── strings.json         # UI strings
└── translations/
    └── en.json          # English translations
```

## Security Considerations

- Credentials encrypted in HA config entry storage
- Tokens refreshed in background before expiry
- No sensitive data in logs (use `_LOGGER.debug` with redaction)
- HTTPS for all Wyze API communications
- Diagnostics redact all sensitive fields

## Testing Strategy

- Unit tests for API client wrapper
- Unit tests for coordinator logic
- Integration tests with mocked wyze-sdk responses
- Config flow validation tests
- Entity state tests

## Future Considerations

- Wyze Lock Bolt support (non-palm version)
- HA person entity mapping for palm users
- Push-based updates if Wyze adds webhook support
- Palm registration management from HA
