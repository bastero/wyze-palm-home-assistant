"""Direct Wyze API client without external dependencies."""
from __future__ import annotations

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
PATH_LOGIN = "/api/user/login"
PATH_REFRESH_TOKEN = "/app/user/refresh_token"
PATH_GET_OBJECT_LIST = "/app/v2/home_page/get_object_list"
PATH_GET_DEVICE_INFO = "/app/v2/device/get_device_info"
PATH_GET_LOCK_INFO = "/app/v2/device/get_property_list"
PATH_RUN_ACTION = "/app/v2/auto/run_action"
PATH_GET_EVENT_LIST = "/app/v2/device/get_event_list"
# Lock-specific endpoints
PATH_GET_LOCK_STATUS = "/openapi/lock/v1/status"
PATH_LOCK_CONTROL = "/openapi/lock/v1/control"

# Wyze app constants
WYZE_APP_NAME = "com.hualai.WyzeCam"
WYZE_APP_VERSION = "2.50.0.8347"
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

    def _get_headers(self, include_auth: bool = False) -> dict[str, str]:
        """Get common headers for API requests."""
        headers = {
            "Content-Type": "application/json",
            "User-Agent": f"{WYZE_APP_NAME}/{WYZE_APP_VERSION}",
            "Phone-Id": WYZE_PHONE_ID,
            "apikey": self._api_key,
            "keyid": self._key_id,
        }
        if include_auth and self._access_token:
            headers["Authorization"] = self._access_token
        return headers

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

        # Try multiple password formats - Wyze API is inconsistent
        password_formats = [
            # Triple MD5 hash (some Wyze implementations)
            hashlib.md5(hashlib.md5(hashlib.md5(password.encode()).hexdigest().encode()).hexdigest().encode()).hexdigest(),
            # Double MD5 hash (standard Wyze app method)
            hashlib.md5(hashlib.md5(password.encode()).hexdigest().encode()).hexdigest(),
            # Single MD5 hash
            hashlib.md5(password.encode()).hexdigest(),
        ]

        last_error = None

        for i, password_hash in enumerate(password_formats):
            _LOGGER.debug("Attempting login for email: %s (password format %d)", email, i + 1)

            payload = {
                **self._get_base_payload(),
                "email": email.lower(),
                "password": password_hash,
            }

            try:
                async with session.post(
                    f"{WYZE_AUTH_URL}{PATH_LOGIN}",
                    json=payload,
                    headers=self._get_headers(),
                ) as response:
                    response_text = await response.text()
                    _LOGGER.debug("Login response status: %s", response.status)

                    try:
                        data = await response.json()
                    except Exception:
                        _LOGGER.error("Failed to parse response: %s", response_text[:500])
                        continue

                    _LOGGER.debug("Login response: %s", data)

                    # Check for success
                    if "access_token" in data:
                        self._access_token = data["access_token"]
                        self._refresh_token = data.get("refresh_token")
                        _LOGGER.debug("Login successful with format %d", i + 1)
                        return {
                            "access_token": self._access_token,
                            "refresh_token": self._refresh_token,
                            "user_id": data.get("user_id"),
                        }

                    # Check nested data structure
                    result = data.get("data", {})
                    if result.get("access_token"):
                        self._access_token = result["access_token"]
                        self._refresh_token = result.get("refresh_token")
                        _LOGGER.debug("Login successful with format %d", i + 1)
                        return {
                            "access_token": self._access_token,
                            "refresh_token": self._refresh_token,
                            "user_id": result.get("user_id"),
                        }

                    # Store error for last attempt
                    error_msg = data.get("description") or data.get("msg") or data.get("message") or "Login failed"
                    error_code = data.get("errorCode") or data.get("code")
                    last_error = (error_msg, error_code)
                    _LOGGER.debug("Login attempt %d failed: %s", i + 1, error_msg)

            except aiohttp.ClientError as err:
                _LOGGER.error("Connection error during login: %s", err)
                last_error = (str(err), None)
                continue

        # All attempts failed
        error_msg, error_code = last_error or ("Login failed", None)
        _LOGGER.error("All login attempts failed. Last error: %s", error_msg)
        raise WyzeAuthError(error_msg, code=int(error_code) if error_code and str(error_code).isdigit() else None)

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

                code = str(data.get("code", ""))
                if code not in ("1", "0", ""):
                    raise WyzeAuthError(
                        data.get("msg", "Token refresh failed"),
                        code=int(code) if code.isdigit() else None,
                    )

                result = data.get("data", data)
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
                headers=self._get_headers(include_auth=True),
            ) as response:
                data = await response.json()

                code = str(data.get("code", ""))

                # Handle auth errors
                if code in ("2001", "2002") and retry_auth:
                    try:
                        await self.refresh_tokens()
                        return await self._api_request(path, payload, retry_auth=False)
                    except WyzeAuthError:
                        raise WyzeAuthError("Authentication expired")

                if code not in ("1", "0", ""):
                    raise WyzeApiError(
                        data.get("msg", "API request failed"),
                        code=int(code) if code.isdigit() else None,
                    )

                return data.get("data", {})
        except aiohttp.ClientError as err:
            raise WyzeApiError(f"Connection error: {err}") from err

    async def get_devices(self) -> list[dict[str, Any]]:
        """Get list of all devices."""
        _LOGGER.info("Fetching device list from Wyze API...")
        data = await self._api_request(PATH_GET_OBJECT_LIST)
        device_list = data.get("device_list", [])
        if not device_list:
            _LOGGER.warning("Wyze API returned empty device list. Raw response keys: %s", list(data.keys()) if data else "None")
        return device_list

    async def get_locks(self) -> list[dict[str, Any]]:
        """Get list of lock devices."""
        devices = await self.get_devices()
        locks = []

        # Log all devices for debugging
        device_summary = []
        for device in devices:
            product_type = device.get("product_type", "")
            product_model = device.get("product_model", "")
            nickname = device.get("nickname", "")
            mac = device.get("mac", device.get("device_mac", ""))
            device_summary.append(f"{nickname} (model={product_model}, type={product_type}, mac={mac})")

        _LOGGER.warning("Wyze devices found: %s", device_summary)

        for device in devices:
            product_type = device.get("product_type", "")
            product_model = device.get("product_model", "")
            nickname = device.get("nickname", "")
            mac = device.get("mac", device.get("device_mac", ""))

            # Known Wyze lock product models:
            # - WLCK1: Wyze Lock
            # - WLCKB1: Wyze Lock Bolt
            # - WPLCK1: Wyze Palm Lock (SKU)
            # - DX_PVLOC: Wyze Palm Lock (API model)
            # - YD.LO1: Wyze Lock (Yale variant)
            # - LD_SS1: Wyze Lock
            lock_models = ["wlck", "wplck", "pvloc", "dx_pvloc", "lock", "yd.lo", "ld_ss", "palm"]
            lock_types = ["lock", "smart_lock", "door_lock"]

            is_lock = False

            # Check product model
            model_lower = product_model.lower()
            for lock_model in lock_models:
                if lock_model in model_lower:
                    is_lock = True
                    break

            # Check product type
            if not is_lock:
                type_lower = product_type.lower()
                for lock_type in lock_types:
                    if lock_type in type_lower:
                        is_lock = True
                        break

            if is_lock:
                _LOGGER.warning("Found Wyze lock: %s (MAC: %s, model: %s)", nickname, mac, product_model)
                _LOGGER.warning("Full lock device data: %s", device)
                locks.append(device)

        if not locks:
            _LOGGER.warning("No Wyze lock devices found out of %d total devices", len(devices))

        return locks

    async def get_lock_info(self, device_mac: str, device_model: str) -> dict[str, Any]:
        """Get detailed lock information."""
        # Try lock-specific status endpoint first
        try:
            lock_status = await self._get_lock_status(device_mac)
            if lock_status:
                _LOGGER.warning("Lock status API response for %s: %s", device_mac, lock_status)
                return lock_status
        except WyzeApiError as err:
            _LOGGER.debug("Lock status API failed: %s", err)

        # Fall back to property list
        payload = {
            "device_mac": device_mac,
            "device_model": device_model,
        }

        try:
            data = await self._api_request(PATH_GET_LOCK_INFO, payload)
            _LOGGER.warning("Lock property list for %s: %s", device_mac, data)
            return self._parse_property_list(data)
        except WyzeApiError as err:
            _LOGGER.warning("get_property_list failed for %s: %s, trying get_device_info", device_mac, err)
            return await self.get_device_info(device_mac, device_model)

    async def _get_lock_status(self, device_mac: str) -> dict[str, Any] | None:
        """Get lock status using various lock-specific APIs."""
        session = await self._get_session()

        # Try multiple API endpoints for lock status
        endpoints = [
            "/openapi/lock/v1/status",
            "/plugin/locking/v1/get_lock_status",
            "/app/v2/device/get_device_property_list",
            "/plugin/pvlock/v1/get_status",  # Palm Vein Lock specific
        ]

        for endpoint in endpoints:
            payload = {
                **self._get_base_payload(),
                "access_token": self._access_token,
                "device_id": device_mac,
                "device_mac": device_mac,
                "keys": "P3,P5,P8,P2001,P2002",  # Request specific properties
            }

            try:
                async with session.post(
                    f"{WYZE_API_URL}{endpoint}",
                    json=payload,
                    headers=self._get_headers(include_auth=True),
                ) as response:
                    data = await response.json()

                    # Log successful responses
                    if response.status == 200 and data.get("code") in (None, "1", 1, "0", 0):
                        _LOGGER.warning("Lock API %s response: %s", endpoint, data)

                        # Try to parse any useful data
                        result = self._parse_lock_response(data)
                        if result:
                            return result

            except Exception as err:
                _LOGGER.debug("Lock API %s error: %s", endpoint, err)
                continue

        return None

    def _parse_lock_response(self, data: dict[str, Any]) -> dict[str, Any] | None:
        """Parse various lock API response formats."""
        result = {}

        # Try different response structures
        status_data = data.get("data", data)

        # Direct lock_state field
        if "lock_state" in status_data:
            result["is_locked"] = status_data["lock_state"] in (1, "1", True, "locked")

        # Direct door_state field
        if "door_state" in status_data:
            # For Palm Lock: 1 = closed, 0 = open
            result["door_open"] = status_data["door_state"] in (0, "0", False, "open")

        # Battery
        if "battery" in status_data:
            try:
                result["battery"] = int(status_data["battery"])
            except (ValueError, TypeError):
                pass

        # Property list format
        if "property_list" in status_data:
            prop_result = self._parse_property_list(status_data)
            result.update(prop_result)

        # Online status
        if "online" in status_data:
            result["online"] = status_data["online"] in (1, "1", True)

        return result if result else None

    async def get_device_info(self, device_mac: str, device_model: str) -> dict[str, Any]:
        """Get basic device information."""
        payload = {
            "device_mac": device_mac,
            "device_model": device_model,
        }

        data = await self._api_request(PATH_GET_DEVICE_INFO, payload)
        _LOGGER.warning("Device info raw response for %s: %s", device_mac, data)
        return data

    def _parse_property_list(self, data: dict[str, Any]) -> dict[str, Any]:
        """Parse property list response into a usable dict."""
        result = {}
        property_list = data.get("property_list", [])

        _LOGGER.debug("Parsing property list: %s", property_list)

        for prop in property_list:
            pid = prop.get("pid")
            value = prop.get("value")

            # Skip unknown/unavailable values (-1 typically means not reported)
            if value == "-1":
                _LOGGER.debug("Property %s has unknown value (-1)", pid)
                continue

            if pid == "P3":  # Lock state: 0=unlocked, 1=locked, 2=unknown
                if value == "1":
                    result["is_locked"] = True
                elif value == "0":
                    result["is_locked"] = False
                # else leave it unset (unknown)
            elif pid == "P5":  # Door state: 0=open, 1=closed (Palm Lock)
                result["door_open"] = value == "0"
            elif pid == "P8":  # Battery percentage
                try:
                    battery = int(value)
                    if battery >= 0:  # Only set if valid
                        result["battery"] = battery
                except (ValueError, TypeError):
                    pass
            elif pid == "P1":  # Online status
                result["online"] = value == "1"
            elif pid == "P1301":  # Auto-lock time in seconds
                try:
                    result["auto_lock_time"] = int(value)
                except (ValueError, TypeError):
                    pass
            elif pid == "P2001":  # Palm Lock specific - might be palm status
                _LOGGER.debug("Palm property P2001: %s", value)
            elif pid == "P2002":  # Palm Lock specific
                _LOGGER.debug("Palm property P2002: %s", value)

        _LOGGER.debug("Parsed lock info: %s", result)
        return result

    async def get_lock_events(
        self, device_mac: str, device_model: str, limit: int = 20
    ) -> list[dict[str, Any]]:
        """Get lock event history."""
        # Get events from the last 7 days
        end_time = int(time.time() * 1000)
        begin_time = end_time - (7 * 24 * 60 * 60 * 1000)  # 7 days ago

        payload = {
            "device_mac": device_mac,
            "device_model": device_model,
            "count": limit,
            "order_by": 2,
            "begin_time": begin_time,
            "end_time": end_time,
        }

        try:
            data = await self._api_request(PATH_GET_EVENT_LIST, payload)
            events = data.get("event_list", [])
            if events:
                _LOGGER.warning("Lock events for %s: %s", device_mac, events[:3])  # Log first 3
            else:
                _LOGGER.warning("No events returned for lock %s (response: %s)", device_mac, data)
            return events
        except WyzeApiError as err:
            _LOGGER.warning("Failed to get events for %s: %s", device_mac, err)
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
