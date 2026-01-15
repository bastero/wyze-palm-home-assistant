"""Direct Wyze API client without external dependencies."""
from __future__ import annotations

import asyncio
import hashlib
import logging
import time
import uuid
from typing import Any

import aiohttp

_LOGGER = logging.getLogger(__name__)

# Wyze API endpoints
WYZE_API_URL = "https://api.wyzecam.com"
WYZE_AUTH_URL = "https://auth-prod.api.wyze.com"

# API paths
PATH_LOGIN = "/user/login"
PATH_REFRESH_TOKEN = "/app/user/refresh_token"
PATH_GET_OBJECT_LIST = "/app/v2/home_page/get_object_list"
PATH_GET_DEVICE_INFO = "/app/v2/device/get_device_info"
PATH_GET_LOCK_INFO = "/app/v2/device/get_property_list"
PATH_RUN_ACTION = "/app/v2/auto/run_action"
PATH_GET_EVENT_LIST = "/app/v2/device/get_event_list"

# Wyze app constants (for API compatibility)
WYZE_APP_NAME = "com.hualai.WyzeCam"
WYZE_APP_VERSION = "2.50.0"
WYZE_PHONE_ID = str(uuid.uuid4())
WYZE_SC = "a626948714654571f64ce589dced5963"
WYZE_SV = "e1fe392906d54888a9b99b88de4162d7"


class WyzeApiError(Exception):
    """Wyze API error."""

    def __init__(self, message: str, code: int | None = None):
        """Initialize the error."""
        super().__init__(message)
        self.code = code


class WyzeAuthError(WyzeApiError):
    """Wyze authentication error."""


class WyzeApiClient:
    """Wyze API client using direct HTTP calls."""

    def __init__(
        self,
        api_key: str,
        key_id: str,
        access_token: str | None = None,
        refresh_token: str | None = None,
    ) -> None:
        """Initialize the API client."""
        self._api_key = api_key
        self._key_id = key_id
        self._access_token = access_token
        self._refresh_token = refresh_token
        self._session: aiohttp.ClientSession | None = None

    @property
    def access_token(self) -> str | None:
        """Return the access token."""
        return self._access_token

    @property
    def refresh_token(self) -> str | None:
        """Return the refresh token."""
        return self._refresh_token

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create the aiohttp session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def close(self) -> None:
        """Close the session."""
        if self._session and not self._session.closed:
            await self._session.close()

    def _get_headers(self) -> dict[str, str]:
        """Get common headers for API requests."""
        return {
            "Content-Type": "application/json",
            "User-Agent": f"{WYZE_APP_NAME}/{WYZE_APP_VERSION}",
            "apikey": self._api_key,
            "keyid": self._key_id,
        }

    def _get_base_payload(self) -> dict[str, Any]:
        """Get base payload for API requests."""
        return {
            "app_name": WYZE_APP_NAME,
            "app_ver": WYZE_APP_VERSION,
            "app_version": WYZE_APP_VERSION,
            "phone_id": WYZE_PHONE_ID,
            "phone_system_type": "1",
            "sc": WYZE_SC,
            "sv": WYZE_SV,
            "ts": int(time.time() * 1000),
        }

    async def login(self, email: str, password: str) -> dict[str, Any]:
        """Login with email and password to get tokens."""
        session = await self._get_session()

        # Hash the password
        password_hash = hashlib.md5(
            hashlib.md5(password.encode()).hexdigest().encode()
        ).hexdigest()

        payload = {
            **self._get_base_payload(),
            "email": email,
            "password": password_hash,
        }

        try:
            async with session.post(
                f"{WYZE_API_URL}{PATH_LOGIN}",
                json=payload,
                headers=self._get_headers(),
            ) as response:
                data = await response.json()

                if data.get("code") != "1":
                    raise WyzeAuthError(
                        data.get("msg", "Login failed"),
                        code=int(data.get("code", 0)),
                    )

                result = data.get("data", {})
                self._access_token = result.get("access_token")
                self._refresh_token = result.get("refresh_token")

                return {
                    "access_token": self._access_token,
                    "refresh_token": self._refresh_token,
                    "user_id": result.get("user_id"),
                }
        except aiohttp.ClientError as err:
            raise WyzeApiError(f"Connection error: {err}") from err

    async def refresh_tokens(self) -> dict[str, Any]:
        """Refresh the access token."""
        if not self._refresh_token:
            raise WyzeAuthError("No refresh token available")

        session = await self._get_session()

        payload = {
            **self._get_base_payload(),
            "refresh_token": self._refresh_token,
        }

        try:
            async with session.post(
                f"{WYZE_API_URL}{PATH_REFRESH_TOKEN}",
                json=payload,
                headers=self._get_headers(),
            ) as response:
                data = await response.json()

                if data.get("code") != "1":
                    raise WyzeAuthError(
                        data.get("msg", "Token refresh failed"),
                        code=int(data.get("code", 0)),
                    )

                result = data.get("data", {})
                self._access_token = result.get("access_token")
                self._refresh_token = result.get("refresh_token")

                return {
                    "access_token": self._access_token,
                    "refresh_token": self._refresh_token,
                }
        except aiohttp.ClientError as err:
            raise WyzeApiError(f"Connection error: {err}") from err

    async def _api_request(
        self,
        path: str,
        payload: dict[str, Any] | None = None,
        retry_auth: bool = True,
    ) -> dict[str, Any]:
        """Make an authenticated API request."""
        if not self._access_token:
            raise WyzeAuthError("Not authenticated")

        session = await self._get_session()

        request_payload = {
            **self._get_base_payload(),
            "access_token": self._access_token,
            **(payload or {}),
        }

        try:
            async with session.post(
                f"{WYZE_API_URL}{path}",
                json=request_payload,
                headers=self._get_headers(),
            ) as response:
                data = await response.json()

                code = data.get("code")

                # Handle auth errors
                if code in ("2001", "2002", 2001, 2002) and retry_auth:
                    # Token expired, try to refresh
                    try:
                        await self.refresh_tokens()
                        return await self._api_request(path, payload, retry_auth=False)
                    except WyzeAuthError:
                        raise WyzeAuthError("Authentication expired")

                if code != "1" and code != 1:
                    raise WyzeApiError(
                        data.get("msg", "API request failed"),
                        code=int(code) if code else None,
                    )

                return data.get("data", {})
        except aiohttp.ClientError as err:
            raise WyzeApiError(f"Connection error: {err}") from err

    async def get_devices(self) -> list[dict[str, Any]]:
        """Get list of all devices."""
        data = await self._api_request(PATH_GET_OBJECT_LIST)
        return data.get("device_list", [])

    async def get_locks(self) -> list[dict[str, Any]]:
        """Get list of lock devices."""
        devices = await self.get_devices()
        locks = []

        for device in devices:
            product_type = device.get("product_type", "")
            product_model = device.get("product_model", "")

            # Filter for lock devices
            if "lock" in product_type.lower() or "lock" in product_model.lower():
                locks.append(device)

        return locks

    async def get_lock_info(self, device_mac: str, device_model: str) -> dict[str, Any]:
        """Get detailed lock information."""
        payload = {
            "device_mac": device_mac,
            "device_model": device_model,
        }

        try:
            data = await self._api_request(PATH_GET_LOCK_INFO, payload)
            return self._parse_property_list(data)
        except WyzeApiError:
            # Fall back to basic device info
            return await self.get_device_info(device_mac, device_model)

    async def get_device_info(self, device_mac: str, device_model: str) -> dict[str, Any]:
        """Get basic device information."""
        payload = {
            "device_mac": device_mac,
            "device_model": device_model,
        }

        return await self._api_request(PATH_GET_DEVICE_INFO, payload)

    def _parse_property_list(self, data: dict[str, Any]) -> dict[str, Any]:
        """Parse property list response into a usable dict."""
        result = {}
        property_list = data.get("property_list", [])

        for prop in property_list:
            pid = prop.get("pid")
            value = prop.get("value")

            if pid == "P3":  # Lock state
                result["is_locked"] = value == "1"
            elif pid == "P5":  # Door state
                result["door_open"] = value == "1"
            elif pid == "P8":  # Battery
                try:
                    result["battery"] = int(value)
                except (ValueError, TypeError):
                    pass
            elif pid == "P1":  # Online status
                result["online"] = value == "1"
            elif pid == "P1301":  # Auto-lock time
                try:
                    result["auto_lock_time"] = int(value)
                except (ValueError, TypeError):
                    pass

        return result

    async def get_lock_events(
        self, device_mac: str, device_model: str, limit: int = 20
    ) -> list[dict[str, Any]]:
        """Get lock event history."""
        payload = {
            "device_mac": device_mac,
            "device_model": device_model,
            "count": limit,
            "order_by": 2,  # Descending by time
        }

        try:
            data = await self._api_request(PATH_GET_EVENT_LIST, payload)
            return data.get("event_list", [])
        except WyzeApiError as err:
            _LOGGER.debug("Failed to get events: %s", err)
            return []

    async def lock(self, device_mac: str, device_model: str) -> bool:
        """Lock the device."""
        return await self._run_lock_action(device_mac, device_model, "lock")

    async def unlock(self, device_mac: str, device_model: str) -> bool:
        """Unlock the device."""
        return await self._run_lock_action(device_mac, device_model, "unlock")

    async def _run_lock_action(
        self, device_mac: str, device_model: str, action: str
    ) -> bool:
        """Run a lock action."""
        # Action values: remoteLock, remoteUnlock
        action_key = "remoteLock" if action == "lock" else "remoteUnlock"

        payload = {
            "provider_key": device_model,
            "instance_id": device_mac,
            "action_key": action_key,
            "action_params": {},
            "custom_string": "",
        }

        try:
            await self._api_request(PATH_RUN_ACTION, payload)
            return True
        except WyzeApiError as err:
            _LOGGER.error("Failed to %s device: %s", action, err)
            return False

    async def set_auto_lock_time(
        self, device_mac: str, device_model: str, seconds: int
    ) -> bool:
        """Set auto-lock time."""
        payload = {
            "provider_key": device_model,
            "instance_id": device_mac,
            "action_key": "set_auto_lock_time",
            "action_params": {"value": str(seconds)},
            "custom_string": "",
        }

        try:
            await self._api_request(PATH_RUN_ACTION, payload)
            return True
        except WyzeApiError as err:
            _LOGGER.error("Failed to set auto-lock time: %s", err)
            return False
