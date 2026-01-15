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
    CONF_API_KEY,
    CONF_KEY_ID,
    CONF_REFRESH_TOKEN,
    CONF_SCAN_INTERVAL,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
)
from .wyze_api import WyzeApiClient, WyzeApiError, WyzeAuthError

_LOGGER = logging.getLogger(__name__)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_API_KEY): str,
        vol.Required(CONF_KEY_ID): str,
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
                tokens = await self._async_validate_credentials(user_input)
            except WyzeAuthError as err:
                _LOGGER.error("Authentication failed: %s", err)
                errors["base"] = "invalid_auth"
            except WyzeApiError as err:
                _LOGGER.error("API error: %s", err)
                errors["base"] = "cannot_connect"
            except Exception as err:
                _LOGGER.exception("Unexpected error: %s", err)
                errors["base"] = "unknown"
            else:
                return self.async_create_entry(
                    title=f"Wyze Palm ({user_input[CONF_EMAIL]})",
                    data={
                        CONF_API_KEY: user_input[CONF_API_KEY],
                        CONF_KEY_ID: user_input[CONF_KEY_ID],
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
            description_placeholders={
                "api_console_url": "https://developer-api-console.wyze.com"
            },
        )

    async def _async_validate_credentials(
        self, user_input: dict[str, Any]
    ) -> dict[str, Any]:
        """Validate Wyze credentials and return tokens."""
        client = WyzeApiClient(
            api_key=user_input[CONF_API_KEY],
            key_id=user_input[CONF_KEY_ID],
        )

        try:
            result = await client.login(
                email=user_input[CONF_EMAIL],
                password=user_input[CONF_PASSWORD],
            )
            return result
        finally:
            await client.close()

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

        reauth_entry = self._get_reauth_entry()

        if user_input is not None:
            try:
                client = WyzeApiClient(
                    api_key=reauth_entry.data[CONF_API_KEY],
                    key_id=reauth_entry.data[CONF_KEY_ID],
                )
                try:
                    tokens = await client.login(
                        email=reauth_entry.data[CONF_EMAIL],
                        password=user_input[CONF_PASSWORD],
                    )
                finally:
                    await client.close()

                return self.async_update_reload_and_abort(
                    reauth_entry,
                    data={
                        **reauth_entry.data,
                        CONF_PASSWORD: user_input[CONF_PASSWORD],
                        CONF_ACCESS_TOKEN: tokens.get("access_token"),
                        CONF_REFRESH_TOKEN: tokens.get("refresh_token"),
                    },
                )
            except WyzeAuthError:
                errors["base"] = "invalid_auth"
            except Exception:
                errors["base"] = "unknown"

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema({vol.Required(CONF_PASSWORD): str}),
            errors=errors,
            description_placeholders={
                "email": reauth_entry.data[CONF_EMAIL]
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
