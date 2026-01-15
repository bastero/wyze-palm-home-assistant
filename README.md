# Wyze Palm Home Assistant Integration

A custom Home Assistant integration for Wyze Palm Lock devices. This integration exposes your Wyze Palm locks as native Home Assistant entities with full lock control, sensors, and automation triggers.

## Features

- **Native Lock Control**: Lock/unlock your Wyze Palm lock directly from Home Assistant
- **Door Sensor**: Monitor door open/closed state
- **Battery Monitoring**: Track battery level with low battery alerts
- **Palm Recognition Events**: Fire automations when palm unlock is detected
- **Unlock Tracking**: Track last unlock method (palm, PIN, fingerprint, key, app) and user
- **Failed Attempt Counter**: Monitor failed palm recognition attempts
- **Auto-Lock Configuration**: Adjust auto-lock timing from Home Assistant
- **Device Automations**: Built-in triggers for the automation UI

## Requirements

- Home Assistant 2024.1.0 or newer
- Wyze account with Palm Lock device(s)
- Network connectivity to Wyze cloud services

## Installation

### HACS (Recommended)

1. Open HACS in Home Assistant
2. Click on "Integrations"
3. Click the three dots menu in the top right
4. Select "Custom repositories"
5. Add the repository URL and select "Integration" as the category
6. Click "Add"
7. Search for "Wyze Palm" and install
8. Restart Home Assistant

### Manual Installation

1. Download or clone this repository
2. Copy the `custom_components/wyze_palm_ha` folder to your Home Assistant `config/custom_components/` directory
3. Restart Home Assistant

```bash
# Example using terminal
cd /config
mkdir -p custom_components
cp -r /path/to/wyze_palm_ha/custom_components/wyze_palm_ha custom_components/
```

## Configuration

### Adding the Integration

1. Go to **Settings** → **Devices & Services**
2. Click **+ Add Integration**
3. Search for "Wyze Palm"
4. Enter your Wyze account credentials:
   - **Email**: Your Wyze account email
   - **Password**: Your Wyze account password
5. Click **Submit**

The integration will automatically discover all Palm locks on your Wyze account.

### Configuration Options

After setup, you can configure options by clicking **Configure** on the integration:

| Option | Default | Description |
|--------|---------|-------------|
| Update interval | 60 seconds | How often to poll Wyze API for updates (30-300 seconds) |

## Entities

Each Wyze Palm lock creates the following entities:

### Lock

| Entity | Type | Description |
|--------|------|-------------|
| `lock.<name>` | Lock | Main lock entity with lock/unlock control |

**Lock Attributes:**
- `door_open`: Boolean - door position
- `last_unlock_method`: String - how lock was last unlocked
- `last_unlock_user`: String - who last unlocked (if applicable)
- `auto_lock_enabled`: Boolean - auto-lock status
- `auto_lock_time`: Integer - auto-lock delay in seconds

### Sensors

| Entity | Type | Description |
|--------|------|-------------|
| `sensor.<name>_battery` | Sensor | Battery level (%) |
| `sensor.<name>_last_unlock_method` | Sensor | Last unlock method used |
| `sensor.<name>_last_unlock_user` | Sensor | Last user who unlocked |
| `sensor.<name>_failed_attempts` | Sensor | Count of failed palm attempts |
| `sensor.<name>_auto_lock_time` | Sensor | Current auto-lock delay setting |

### Binary Sensors

| Entity | Type | Description |
|--------|------|-------------|
| `binary_sensor.<name>_door` | Binary Sensor | Door open/closed state |
| `binary_sensor.<name>_connected` | Binary Sensor | Device online status |

### Number

| Entity | Type | Description |
|--------|------|-------------|
| `number.<name>_auto_lock_setting` | Number | Adjustable auto-lock delay (0-1800 seconds, 0 = disabled) |

## Services

### `wyze_palm.set_auto_lock`

Set the auto-lock delay for a lock.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `device_id` | Yes | MAC address of the lock |
| `auto_lock_time` | Yes | Delay in seconds (0-1800, 0 = disabled) |

**Example:**
```yaml
service: wyze_palm.set_auto_lock
data:
  device_id: "ABCD1234567890"
  auto_lock_time: 30
```

## Events

The integration fires events that can be used in automations:

### `wyze_palm_unlock`

Fired when the lock is unlocked.

```yaml
event_type: wyze_palm_unlock
event_data:
  device_id: "ABCD1234567890"
  method: "palm"  # palm, pin, fingerprint, key, app
  user: "John"    # Wyze username (if applicable)
  timestamp: 1234567890
```

### `wyze_palm_lock`

Fired when the lock is locked.

```yaml
event_type: wyze_palm_lock
event_data:
  device_id: "ABCD1234567890"
  method: "auto"
  timestamp: 1234567890
```

### `wyze_palm_failed`

Fired when palm recognition fails.

```yaml
event_type: wyze_palm_failed
event_data:
  device_id: "ABCD1234567890"
  timestamp: 1234567890
```

## Device Automations

The integration provides device triggers in the automation UI:

- **Lock was unlocked** - Any unlock event
- **Lock was unlocked by palm** - Palm-specific unlock
- **Lock was locked** - Any lock event
- **Failed palm attempt detected** - Failed palm recognition
- **Door was opened** - Door opened
- **Door was closed** - Door closed
- **Battery is low** - Battery below 20%

### Example Automation (UI)

1. Go to **Settings** → **Automations & Scenes**
2. Click **+ Create Automation**
3. Choose **Create new automation**
4. For trigger, select **Device** and choose your Wyze Palm lock
5. Select the trigger type (e.g., "Lock was unlocked by palm")
6. Add your actions

### Example Automation (YAML)

```yaml
automation:
  - alias: "Notify on palm unlock"
    trigger:
      - platform: event
        event_type: wyze_palm_unlock
        event_data:
          method: palm
    action:
      - service: notify.mobile_app
        data:
          title: "Door Unlocked"
          message: "{{ trigger.event.data.user }} unlocked the door with palm"

  - alias: "Alert on failed palm attempts"
    trigger:
      - platform: event
        event_type: wyze_palm_failed
    action:
      - service: notify.mobile_app
        data:
          title: "Security Alert"
          message: "Failed palm recognition attempt detected"

  - alias: "Low battery notification"
    trigger:
      - platform: numeric_state
        entity_id: sensor.front_door_battery
        below: 20
    action:
      - service: notify.mobile_app
        data:
          title: "Low Battery"
          message: "Wyze Palm lock battery is low ({{ states('sensor.front_door_battery') }}%)"
```

## Lovelace Card Examples

### Simple Lock Card

```yaml
type: entities
title: Front Door
entities:
  - entity: lock.front_door
  - entity: binary_sensor.front_door_door
  - entity: sensor.front_door_battery
```

### Detailed Lock Card

```yaml
type: vertical-stack
cards:
  - type: entity
    entity: lock.front_door
    name: Front Door Lock
  - type: glance
    entities:
      - entity: binary_sensor.front_door_door
        name: Door
      - entity: sensor.front_door_battery
        name: Battery
      - entity: binary_sensor.front_door_connected
        name: Status
  - type: entities
    entities:
      - entity: sensor.front_door_last_unlock_method
        name: Last Method
      - entity: sensor.front_door_last_unlock_user
        name: Last User
      - entity: number.front_door_auto_lock_setting
        name: Auto-Lock Delay
```

## Troubleshooting

### Authentication Issues

If you see "Authentication expired" errors:
1. Go to **Settings** → **Devices & Services**
2. Find the Wyze Palm integration
3. Click **Configure** or check for repair notifications
4. Re-enter your password

### Lock Not Responding

1. Check the `binary_sensor.<name>_connected` entity
2. Verify the lock has power and is within WiFi range
3. Try toggling the lock from the Wyze app to verify connectivity
4. Check Home Assistant logs for API errors

### Entities Showing "Unavailable"

This usually indicates:
- Wyze API is temporarily unreachable
- Your authentication has expired
- The lock is offline

Check the integration's diagnostics for detailed error information.

### Debug Logging

Enable debug logging to troubleshoot issues:

```yaml
# configuration.yaml
logger:
  default: info
  logs:
    custom_components.wyze_palm_ha: debug
```

## Privacy & Security

- Credentials are stored encrypted in Home Assistant's config entry storage
- API tokens are refreshed automatically in the background
- Diagnostics redact all sensitive information (email, password, tokens)
- All communication with Wyze uses HTTPS

## Known Limitations

- Wyze API is cloud-based; local control is not available
- 2FA is handled through the initial login flow
- Polling-based updates (no real-time push notifications from Wyze)
- API rate limits may affect update frequency during heavy use

## Contributing

Contributions are welcome! Please submit issues and pull requests on GitHub.

## License

MIT License - see LICENSE file for details.

## Disclaimer

This is an unofficial integration and is not affiliated with, endorsed by, or connected to Wyze Labs, Inc. Use at your own risk.
