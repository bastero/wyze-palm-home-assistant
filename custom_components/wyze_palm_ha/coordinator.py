"""DataUpdateCoordinator for Wyze Palm integration."""
from __future__ import annotations

from datetime import timedelta
import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import (
    CONF_ACCESS_TOKEN,
    CONF_API_KEY,
    CONF_KEY_ID,
    CONF_REFRESH_TOKEN,
    CONF_SCAN_INTERVAL,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    EVENT_FAILED,
    EVENT_LOCK,
    EVENT_UNLOCK,
    UNLOCK_METHOD_APP,
    UNLOCK_METHOD_FINGERPRINT,
    UNLOCK_METHOD_KEY,
    UNLOCK_METHOD_PALM,
    UNLOCK_METHOD_PIN,
    UNLOCK_METHOD_UNKNOWN,
)
from .wyze_api import WyzeApiClient, WyzeApiError, WyzeAuthError

_LOGGER = logging.getLogger(__name__)


class WyzePalmDataUpdateCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Class to manage fetching Wyze Palm lock data."""

    config_entry: ConfigEntry

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
    ) -> None:
        """Initialize the coordinator."""
        self.entry = entry
        self._client: WyzeApiClient | None = None
        self._locks: dict[str, Any] = {}
        self._last_events: dict[str, list[Any]] = {}
        self._failed_attempts: dict[str, int] = {}

        scan_interval = entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)

        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=scan_interval),
        )

    async def _async_setup(self) -> None:
        """Set up the Wyze client."""
        self._client = WyzeApiClient(
            api_key=self.entry.data[CONF_API_KEY],
            key_id=self.entry.data[CONF_KEY_ID],
            access_token=self.entry.data.get(CONF_ACCESS_TOKEN),
            refresh_token=self.entry.data.get(CONF_REFRESH_TOKEN),
        )

        # If no access token, login
        if not self.entry.data.get(CONF_ACCESS_TOKEN):
            await self._async_login()

    async def _async_login(self) -> None:
        """Login to Wyze API."""
        try:
            result = await self._client.login(
                email=self.entry.data[CONF_EMAIL],
                password=self.entry.data[CONF_PASSWORD],
            )

            # Update stored tokens
            self.hass.config_entries.async_update_entry(
                self.entry,
                data={
                    **self.entry.data,
                    CONF_ACCESS_TOKEN: result.get("access_token"),
                    CONF_REFRESH_TOKEN: result.get("refresh_token"),
                },
            )
        except WyzeAuthError as err:
            raise ConfigEntryAuthFailed("Failed to authenticate with Wyze") from err

    async def _async_update_data(self) -> dict[str, Any]:
        """Fetch data from Wyze API."""
        if self._client is None:
            await self._async_setup()

        try:
            data = await self._fetch_locks_data()
            await self._process_events(data)
            return data
        except WyzeAuthError as err:
            # Token expired, try to re-login
            try:
                await self._async_login()
                return await self._fetch_locks_data()
            except WyzeAuthError:
                raise ConfigEntryAuthFailed(
                    "Authentication failed, please re-authenticate"
                ) from err
        except WyzeApiError as err:
            raise UpdateFailed(f"Error communicating with Wyze API: {err}") from err

    async def _fetch_locks_data(self) -> dict[str, Any]:
        """Fetch lock data from Wyze API."""
        locks_data: dict[str, Any] = {"locks": {}}

        try:
            locks = await self._client.get_locks()
        except WyzeApiError as err:
            _LOGGER.error("Failed to fetch locks: %s", err)
            raise

        for lock in locks:
            lock_mac = lock.get("mac", lock.get("device_mac"))
            lock_model = lock.get("product_model", "")

            if not lock_mac:
                continue

            # Get detailed lock info
            try:
                lock_info = await self._client.get_lock_info(lock_mac, lock_model)
            except WyzeApiError as err:
                _LOGGER.warning("Failed to get info for lock %s: %s", lock_mac, err)
                lock_info = {}

            # Get lock events
            events = []
            try:
                events = await self._client.get_lock_events(lock_mac, lock_model, limit=20)
            except WyzeApiError as err:
                _LOGGER.debug("Failed to get events for lock %s: %s", lock_mac, err)

            locks_data["locks"][lock_mac] = {
                "mac": lock_mac,
                "model": lock_model,
                "nickname": lock.get("nickname", lock_mac),
                "is_locked": lock_info.get("is_locked"),
                "door_open": lock_info.get("door_open"),
                "battery": lock_info.get("battery"),
                "online": lock_info.get("online", True),
                "auto_lock_time": lock_info.get("auto_lock_time", 0),
                "events": events,
                "raw_lock": lock,
                "raw_info": lock_info,
            }

        return locks_data

    async def _process_events(self, data: dict[str, Any]) -> None:
        """Process lock events and fire HA events."""
        for lock_mac, lock_data in data.get("locks", {}).items():
            events = lock_data.get("events", [])
            last_processed = self._last_events.get(lock_mac, [])

            for event in events:
                event_id = event.get("event_id") or id(event)
                if event_id in last_processed:
                    continue

                event_type = self._get_event_type(event)
                if event_type == EVENT_UNLOCK:
                    self.hass.bus.async_fire(
                        EVENT_UNLOCK,
                        {
                            "device_id": lock_mac,
                            "method": self._get_unlock_method(event),
                            "user": self._get_event_user(event),
                            "timestamp": event.get("event_ts"),
                        },
                    )
                elif event_type == EVENT_LOCK:
                    self.hass.bus.async_fire(
                        EVENT_LOCK,
                        {
                            "device_id": lock_mac,
                            "method": self._get_unlock_method(event),
                            "timestamp": event.get("event_ts"),
                        },
                    )
                elif event_type == EVENT_FAILED:
                    self._failed_attempts[lock_mac] = (
                        self._failed_attempts.get(lock_mac, 0) + 1
                    )
                    self.hass.bus.async_fire(
                        EVENT_FAILED,
                        {
                            "device_id": lock_mac,
                            "timestamp": event.get("event_ts"),
                        },
                    )

            # Update last processed events
            self._last_events[lock_mac] = [
                e.get("event_id") or id(e) for e in events[:20]
            ]

    def _get_event_type(self, event: dict[str, Any]) -> str | None:
        """Determine the event type."""
        event_type = event.get("event_type") or event.get("type", "")
        event_str = str(event_type).lower()

        if "unlock" in event_str:
            return EVENT_UNLOCK
        if "lock" in event_str:
            return EVENT_LOCK
        if "fail" in event_str:
            return EVENT_FAILED
        return None

    def _get_unlock_method(self, event: dict[str, Any]) -> str:
        """Get the unlock method from event."""
        method = event.get("unlock_method") or event.get("type", "")
        method_str = str(method).lower()

        if "palm" in method_str:
            return UNLOCK_METHOD_PALM
        if "pin" in method_str or "keypad" in method_str:
            return UNLOCK_METHOD_PIN
        if "fingerprint" in method_str:
            return UNLOCK_METHOD_FINGERPRINT
        if "key" in method_str:
            return UNLOCK_METHOD_KEY
        if "app" in method_str or "remote" in method_str:
            return UNLOCK_METHOD_APP
        return UNLOCK_METHOD_UNKNOWN

    def _get_event_user(self, event: dict[str, Any]) -> str | None:
        """Get the user from event."""
        return event.get("user_name") or event.get("user")

    def get_lock_data(self, lock_mac: str) -> dict[str, Any] | None:
        """Get data for a specific lock."""
        if self.data is None:
            return None
        return self.data.get("locks", {}).get(lock_mac)

    def get_failed_attempts(self, lock_mac: str) -> int:
        """Get failed attempt count for a lock."""
        return self._failed_attempts.get(lock_mac, 0)

    async def async_lock(self, lock_mac: str) -> bool:
        """Lock a device."""
        lock_data = self.get_lock_data(lock_mac)
        if not lock_data:
            return False

        result = await self._client.lock(lock_mac, lock_data.get("model", ""))
        if result:
            await self.async_request_refresh()
        return result

    async def async_unlock(self, lock_mac: str) -> bool:
        """Unlock a device."""
        lock_data = self.get_lock_data(lock_mac)
        if not lock_data:
            return False

        result = await self._client.unlock(lock_mac, lock_data.get("model", ""))
        if result:
            await self.async_request_refresh()
        return result

    async def async_set_auto_lock(self, lock_mac: str, seconds: int) -> bool:
        """Set auto-lock time for a device."""
        lock_data = self.get_lock_data(lock_mac)
        if not lock_data:
            return False

        result = await self._client.set_auto_lock_time(
            lock_mac, lock_data.get("model", ""), seconds
        )
        if result:
            await self.async_request_refresh()
        return result

    async def async_shutdown(self) -> None:
        """Shutdown the coordinator."""
        if self._client:
            await self._client.close()
