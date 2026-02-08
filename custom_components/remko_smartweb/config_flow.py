from __future__ import annotations

import voluptuous as vol
from homeassistant import config_entries

from .const import DOMAIN, CONF_EMAIL, CONF_PASSWORD, CONF_DEVICE_NAME, CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL
from .api import RemkoSmartWebClient


class RemkoSmartWebConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input=None):
        errors = {}
        if user_input is not None:
            ok = await self._async_validate(user_input)
            if ok:
                return self.async_create_entry(title=user_input[CONF_DEVICE_NAME], data=user_input)
            errors["base"] = "cannot_connect"

        schema = vol.Schema({
            vol.Required(CONF_EMAIL): str,
            vol.Required(CONF_PASSWORD): str,
            vol.Required(CONF_DEVICE_NAME): str,
        })

        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)

    async def _async_validate(self, data) -> bool:
        def _check():
            client = RemkoSmartWebClient(
                email=data[CONF_EMAIL],
                password=data[CONF_PASSWORD],
                device_name=data[CONF_DEVICE_NAME],
            )
            client.login()
            client.resolve_device()
            return True

        try:
            return await self.hass.async_add_executor_job(_check)
        except Exception:
            return False

    async def async_step_import(self, user_input):
        return await self.async_step_user(user_input)

    @staticmethod
    def async_get_options_flow(config_entry: config_entries.ConfigEntry):
        return RemkoSmartWebOptionsFlow(config_entry)


class RemkoSmartWebOptionsFlow(config_entries.OptionsFlow):
    def __init__(self, config_entry: config_entries.ConfigEntry):
        self.config_entry = config_entry

    async def async_step_init(self, user_input=None):
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        schema = vol.Schema({
            vol.Optional(CONF_SCAN_INTERVAL, default=self.config_entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)): vol.Coerce(int),
        })
        return self.async_show_form(step_id="init", data_schema=schema)
