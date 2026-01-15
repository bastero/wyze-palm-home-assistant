"""Config flow for Wyze Palm integration."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry, ConfigFlow, OptionsFlow
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD
from homeassistant.core import callback
from homeassistant.data_entry_flow import FlowResult

from .const import (
    CONF_ACCESS_TOKEN,
    CONF_REFRESH_TOKEN,
    CONF_SCAN_INTERVAL,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_EMAIL): str,
        vol.Required(CONF_PASSWORD): str,
    }
)


class WyzePalmConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Wyze Palm."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            # Check if already configured
            await self.async_set_unique_id(user_input[CONF_EMAIL].lower())
            self._abort_if_unique_id_configured()

            # Validate credentials
            try:
                tokens = await self._async_validate_credentials(
                    user_input[CONF_EMAIL],
                    user_input[CONF_PASSWORD],
                )
            except Exception as err:
                _LOGGER.error("Failed to authenticate with Wyze: %s", err)
                error_str = str(err).lower()
                if "401" in error_str or "invalid" in error_str or "credential" in error_str:
                    errors["base"] = "invalid_auth"
                elif "connect" in error_str or "timeout" in error_str:
                    errors["base"] = "cannot_connect"
                else:
                    errors["base"] = "unknown"
            else:
                return self.async_create_entry(
                    title=f"Wyze Palm ({user_input[CONF_EMAIL]})",
                    data={
                        CONF_EMAIL: user_input[CONF_EMAIL],
                        CONF_PASSWORD: user_input[CONF_PASSWORD],
                        CONF_ACCESS_TOKEN: tokens.get("access_token"),
                        CONF_REFRESH_TOKEN: tokens.get("refresh_token"),
                    },
                )

        return self.async_show_form(
            step_id="user",
            data_schema=STEP_USER_DATA_SCHEMA,
            errors=errors,
        )

    async def _async_validate_credentials(
        self, email: str, password: str
    ) -> dict[str, Any]:
        """Validate Wyze credentials and return tokens."""

        def _login() -> dict[str, Any]:
            # Import here to avoid issues if package not installed
            from wyze_sdk import Client

            client = Client()
            response = client.login(email=email, password=password)

            # Extract tokens from response
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

        return await self.hass.async_add_executor_job(_login)

    async def async_step_reauth(
        self, entry_data: dict[str, Any]
    ) -> FlowResult:
        """Handle reauthorization."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle reauthorization confirmation."""
        errors: dict[str, str] = {}

        if user_input is not None:
            reauth_entry = self._get_reauth_entry()
            try:
                tokens = await self._async_validate_credentials(
                    reauth_entry.data[CONF_EMAIL],
                    user_input[CONF_PASSWORD],
                )
            except Exception:
                errors["base"] = "invalid_auth"
            else:
                return self.async_update_reload_and_abort(
                    reauth_entry,
                    data={
                        **reauth_entry.data,
                        CONF_PASSWORD: user_input[CONF_PASSWORD],
                        CONF_ACCESS_TOKEN: tokens.get("access_token"),
                        CONF_REFRESH_TOKEN: tokens.get("refresh_token"),
                    },
                )

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema({vol.Required(CONF_PASSWORD): str}),
            errors=errors,
            description_placeholders={
                "email": self._get_reauth_entry().data[CONF_EMAIL]
            },
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        """Get the options flow for this handler."""
        return WyzePalmOptionsFlow(config_entry)


class WyzePalmOptionsFlow(OptionsFlow):
    """Handle options flow for Wyze Palm."""

    def __init__(self, config_entry: ConfigEntry) -> None:
        """Initialize options flow."""
        self.config_entry = config_entry

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Manage the options."""
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Optional(
                        CONF_SCAN_INTERVAL,
                        default=self.config_entry.options.get(
                            CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL
                        ),
                    ): vol.All(vol.Coerce(int), vol.Range(min=30, max=300)),
                }
            ),
        )
