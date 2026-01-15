"""DataUpdateCoordinator for Wyze Palm integration."""
from __future__ import annotations

import asyncio
from datetime import timedelta
import logging
from typing import Any

from wyze_sdk import Client
from wyze_sdk.errors import WyzeApiError

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import (
    CONF_ACCESS_TOKEN,
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
        self._client: Client | None = None
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
        await self._async_init_client()

    async def _async_init_client(self) -> None:
        """Initialize the Wyze client."""
        try:
            self._client = await self.hass.async_add_executor_job(
                self._create_client
            )
        except WyzeApiError as err:
            _LOGGER.error("Failed to initialize Wyze client: %s", err)
            raise ConfigEntryAuthFailed("Failed to authenticate with Wyze") from err

    def _create_client(self) -> Client:
        """Create Wyze client (runs in executor)."""
        email = self.entry.data.get(CONF_EMAIL)
        password = self.entry.data.get(CONF_PASSWORD)

        # Try using stored tokens first
        access_token = self.entry.data.get(CONF_ACCESS_TOKEN)
        refresh_token = self.entry.data.get(CONF_REFRESH_TOKEN)

        if access_token and refresh_token:
            try:
                return Client(token=access_token)
            except WyzeApiError:
                _LOGGER.debug("Stored token invalid, re-authenticating")

        # Authenticate with credentials
        client = Client()
        response = client.login(email=email, password=password)

        # Store new tokens
        self.hass.config_entries.async_update_entry(
            self.entry,
            data={
                **self.entry.data,
                CONF_ACCESS_TOKEN: response.get("access_token"),
                CONF_REFRESH_TOKEN: response.get("refresh_token"),
            },
        )

        return Client(token=response.get("access_token"))

    async def _async_update_data(self) -> dict[str, Any]:
        """Fetch data from Wyze API."""
        if self._client is None:
            await self._async_init_client()

        try:
            data = await self.hass.async_add_executor_job(self._fetch_locks_data)
            await self._process_events(data)
            return data
        except WyzeApiError as err:
            if "401" in str(err) or "unauthorized" in str(err).lower():
                # Token expired, try to refresh
                try:
                    await self._async_init_client()
                    return await self.hass.async_add_executor_job(self._fetch_locks_data)
                except WyzeApiError as refresh_err:
                    raise ConfigEntryAuthFailed(
                        "Authentication failed, please re-authenticate"
                    ) from refresh_err
            raise UpdateFailed(f"Error communicating with Wyze API: {err}") from err
        except Exception as err:
            raise UpdateFailed(f"Unexpected error: {err}") from err

    def _fetch_locks_data(self) -> dict[str, Any]:
        """Fetch lock data from Wyze API (runs in executor)."""
        locks_data: dict[str, Any] = {"locks": {}}

        try:
            locks = self._client.locks.list()
        except Exception as err:
            _LOGGER.error("Failed to fetch locks: %s", err)
            raise

        for lock in locks:
            lock_mac = lock.mac
            lock_info = self._client.locks.info(device_mac=lock_mac)

            # Get lock events/history
            try:
                events = self._client.locks.get_records(device_mac=lock_mac, limit=20)
            except Exception:
                events = []

            locks_data["locks"][lock_mac] = {
                "mac": lock_mac,
                "nickname": lock.nickname or lock_mac,
                "model": getattr(lock, "product_model", "Unknown"),
                "is_locked": getattr(lock_info, "is_locked", None),
                "door_open": getattr(lock_info, "door_open", None),
                "battery": getattr(lock_info, "battery", None),
                "online": getattr(lock_info, "online", True),
                "auto_lock_time": getattr(lock_info, "auto_lock_time", 0),
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
                event_id = getattr(event, "event_id", None) or str(event)
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
                            "timestamp": getattr(event, "event_ts", None),
                        },
                    )
                elif event_type == EVENT_LOCK:
                    self.hass.bus.async_fire(
                        EVENT_LOCK,
                        {
                            "device_id": lock_mac,
                            "method": self._get_unlock_method(event),
                            "timestamp": getattr(event, "event_ts", None),
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
                            "timestamp": getattr(event, "event_ts", None),
                        },
                    )

            # Update last processed events
            self._last_events[lock_mac] = [
                getattr(e, "event_id", None) or str(e) for e in events[:20]
            ]

    def _get_event_type(self, event: Any) -> str | None:
        """Determine the event type."""
        event_type = getattr(event, "event_type", None)
        if event_type is None:
            return None

        event_str = str(event_type).lower()
        if "unlock" in event_str:
            return EVENT_UNLOCK
        if "lock" in event_str:
            return EVENT_LOCK
        if "fail" in event_str:
            return EVENT_FAILED
        return None

    def _get_unlock_method(self, event: Any) -> str:
        """Get the unlock method from event."""
        method = getattr(event, "unlock_method", None) or getattr(event, "type", None)
        if method is None:
            return UNLOCK_METHOD_UNKNOWN

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

    def _get_event_user(self, event: Any) -> str | None:
        """Get the user from event."""
        return getattr(event, "user_name", None) or getattr(event, "user", None)

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
        try:
            await self.hass.async_add_executor_job(
                self._client.locks.lock, lock_mac
            )
            await self.async_request_refresh()
            return True
        except WyzeApiError as err:
            _LOGGER.error("Failed to lock device %s: %s", lock_mac, err)
            return False

    async def async_unlock(self, lock_mac: str) -> bool:
        """Unlock a device."""
        try:
            await self.hass.async_add_executor_job(
                self._client.locks.unlock, lock_mac
            )
            await self.async_request_refresh()
            return True
        except WyzeApiError as err:
            _LOGGER.error("Failed to unlock device %s: %s", lock_mac, err)
            return False

    async def async_set_auto_lock(self, lock_mac: str, seconds: int) -> bool:
        """Set auto-lock time for a device."""
        try:
            await self.hass.async_add_executor_job(
                self._client.locks.set_auto_lock_time, lock_mac, seconds
            )
            await self.async_request_refresh()
            return True
        except WyzeApiError as err:
            _LOGGER.error("Failed to set auto-lock for %s: %s", lock_mac, err)
            return False
