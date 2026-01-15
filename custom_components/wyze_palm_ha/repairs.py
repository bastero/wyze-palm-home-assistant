"""Repairs for Wyze Palm integration."""
from __future__ import annotations

from typing import Any

import voluptuous as vol

from homeassistant import data_entry_flow
from homeassistant.components.repairs import ConfirmRepairFlow, RepairsFlow
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD
from homeassistant.core import HomeAssistant
from homeassistant.helpers import issue_registry as ir

from .const import CONF_ACCESS_TOKEN, CONF_REFRESH_TOKEN, DOMAIN

ISSUE_AUTH_EXPIRED = "auth_expired"
ISSUE_API_ERROR = "api_error"
ISSUE_DEVICE_OFFLINE = "device_offline"
ISSUE_RATE_LIMITED = "rate_limited"


async def async_create_fix_flow(
    hass: HomeAssistant,
    issue_id: str,
    data: dict[str, Any] | None,
) -> RepairsFlow:
    """Create flow for fixing an issue."""
    if issue_id.startswith(ISSUE_AUTH_EXPIRED):
        return AuthExpiredRepairFlow(hass, issue_id, data)
    if issue_id.startswith(ISSUE_API_ERROR):
        return ConfirmRepairFlow()
    if issue_id.startswith(ISSUE_DEVICE_OFFLINE):
        return ConfirmRepairFlow()
    if issue_id.startswith(ISSUE_RATE_LIMITED):
        return ConfirmRepairFlow()

    return ConfirmRepairFlow()


class AuthExpiredRepairFlow(RepairsFlow):
    """Handler for authentication expired repair flow."""

    def __init__(
        self,
        hass: HomeAssistant,
        issue_id: str,
        data: dict[str, Any] | None,
    ) -> None:
        """Initialize the repair flow."""
        self._hass = hass
        self._issue_id = issue_id
        self._data = data or {}
        self._entry_id = self._data.get("entry_id")

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> data_entry_flow.FlowResult:
        """Handle the first step of the repair flow."""
        return await self.async_step_confirm()

    async def async_step_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> data_entry_flow.FlowResult:
        """Handle the confirm step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            # Try to re-authenticate
            entry = self._hass.config_entries.async_get_entry(self._entry_id)
            if entry is None:
                return self.async_abort(reason="entry_not_found")

            try:
                tokens = await self._async_validate_credentials(
                    entry.data[CONF_EMAIL],
                    user_input[CONF_PASSWORD],
                )

                # Update entry with new tokens
                self._hass.config_entries.async_update_entry(
                    entry,
                    data={
                        **entry.data,
                        CONF_PASSWORD: user_input[CONF_PASSWORD],
                        CONF_ACCESS_TOKEN: tokens.get("access_token"),
                        CONF_REFRESH_TOKEN: tokens.get("refresh_token"),
                    },
                )

                # Remove the issue
                ir.async_delete_issue(self._hass, DOMAIN, self._issue_id)

                # Reload the entry
                await self._hass.config_entries.async_reload(self._entry_id)

                return self.async_create_entry(data={})

            except Exception:
                errors["base"] = "invalid_auth"

        entry = self._hass.config_entries.async_get_entry(self._entry_id)
        email = entry.data.get(CONF_EMAIL, "unknown") if entry else "unknown"

        return self.async_show_form(
            step_id="confirm",
            data_schema=vol.Schema({vol.Required(CONF_PASSWORD): str}),
            errors=errors,
            description_placeholders={"email": email},
        )

    async def _async_validate_credentials(
        self, email: str, password: str
    ) -> dict[str, Any]:
        """Validate Wyze credentials and return tokens."""

        def _login() -> dict[str, Any]:
            from wyze_sdk import Client

            client = Client()
            response = client.login(email=email, password=password)

            access_token = None
            refresh_token = None

            if hasattr(response, "access_token"):
                access_token = response.access_token
            elif isinstance(response, dict):
                access_token = response.get("access_token")

            if hasattr(response, "refresh_token"):
                refresh_token = response.refresh_token
            elif isinstance(response, dict):
                refresh_token = response.get("refresh_token")

            return {
                "access_token": access_token,
                "refresh_token": refresh_token,
            }

        return await self._hass.async_add_executor_job(_login)


def create_auth_expired_issue(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Create an authentication expired issue."""
    ir.async_create_issue(
        hass,
        DOMAIN,
        f"{ISSUE_AUTH_EXPIRED}_{entry.entry_id}",
        is_fixable=True,
        is_persistent=True,
        severity=ir.IssueSeverity.ERROR,
        translation_key="auth_expired",
        translation_placeholders={"email": entry.data.get(CONF_EMAIL, "unknown")},
        data={"entry_id": entry.entry_id},
    )


def create_api_error_issue(hass: HomeAssistant, entry: ConfigEntry, error: str) -> None:
    """Create an API error issue."""
    ir.async_create_issue(
        hass,
        DOMAIN,
        f"{ISSUE_API_ERROR}_{entry.entry_id}",
        is_fixable=True,
        is_persistent=False,
        severity=ir.IssueSeverity.WARNING,
        translation_key="api_error",
        translation_placeholders={"error": error},
        data={"entry_id": entry.entry_id},
    )


def create_device_offline_issue(
    hass: HomeAssistant, entry: ConfigEntry, device_name: str
) -> None:
    """Create a device offline issue."""
    ir.async_create_issue(
        hass,
        DOMAIN,
        f"{ISSUE_DEVICE_OFFLINE}_{entry.entry_id}_{device_name}",
        is_fixable=True,
        is_persistent=False,
        severity=ir.IssueSeverity.WARNING,
        translation_key="device_offline",
        translation_placeholders={"device_name": device_name},
        data={"entry_id": entry.entry_id, "device_name": device_name},
    )


def create_rate_limited_issue(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Create a rate limited issue."""
    ir.async_create_issue(
        hass,
        DOMAIN,
        f"{ISSUE_RATE_LIMITED}_{entry.entry_id}",
        is_fixable=True,
        is_persistent=False,
        severity=ir.IssueSeverity.WARNING,
        translation_key="rate_limited",
        data={"entry_id": entry.entry_id},
    )
