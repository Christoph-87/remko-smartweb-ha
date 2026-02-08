from __future__ import annotations

import voluptuous as vol
from homeassistant import config_entries

from .const import (
    DOMAIN,
    CONF_EMAIL,
    CONF_PASSWORD,
    CONF_DEVICE_NAME,
    CONF_SCAN_INTERVAL,
    CONF_MIN_TEMP,
    CONF_MAX_TEMP,
    CONF_MODEL,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_MIN_TEMP,
    DEFAULT_MAX_TEMP,
)
from .api import RemkoSmartWebClient


class RemkoSmartWebConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input=None):
        existing = self._get_existing_accounts()
        if existing and user_input is None:
            return await self.async_step_account()

        errors = {}
        if user_input is not None:
            ok, device_names = await self._async_fetch_devices(user_input)
            if ok:
                self._email = user_input[CONF_EMAIL]
                self._password = user_input[CONF_PASSWORD]
                self._device_names = device_names
                if len(device_names) == 1:
                    data = {
                        CONF_EMAIL: self._email,
                        CONF_PASSWORD: self._password,
                        CONF_DEVICE_NAME: device_names[0],
                    }
                    return self.async_create_entry(title=device_names[0], data=data)
                return await self.async_step_device()
            errors["base"] = "cannot_connect"

        schema = vol.Schema({
            vol.Required(CONF_EMAIL): str,
            vol.Required(CONF_PASSWORD): str,
        })

        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)

    async def async_step_account(self, user_input=None):
        errors = {}
        existing = self._get_existing_accounts()
        if not existing:
            return await self.async_step_user()

        if user_input is not None:
            selected = user_input.get("account")
            if selected == "new":
                return await self.async_step_user()
            entry = next((e for e in self._get_entries() if e.entry_id == selected), None)
            if entry:
                self._email = entry.data.get(CONF_EMAIL)
                self._password = entry.data.get(CONF_PASSWORD)
                ok, device_names = await self._async_fetch_devices(
                    {CONF_EMAIL: self._email, CONF_PASSWORD: self._password}
                )
                if ok:
                    self._device_names = device_names
                    if len(device_names) == 1:
                        data = {
                            CONF_EMAIL: self._email,
                            CONF_PASSWORD: self._password,
                            CONF_DEVICE_NAME: device_names[0],
                        }
                        return self.async_create_entry(title=device_names[0], data=data)
                    return await self.async_step_device()
            errors["base"] = "cannot_connect"

        options = dict(existing)
        options["new"] = "Use new credentials"
        schema = vol.Schema({
            vol.Required("account"): vol.In(options),
        })
        return self.async_show_form(step_id="account", data_schema=schema, errors=errors)

    async def async_step_device(self, user_input=None):
        errors = {}
        if user_input is not None:
            data = {
                CONF_EMAIL: self._email,
                CONF_PASSWORD: self._password,
                CONF_DEVICE_NAME: user_input[CONF_DEVICE_NAME],
            }
            ok = await self._async_validate(data)
            if ok:
                return self.async_create_entry(title=data[CONF_DEVICE_NAME], data=data)
            errors["base"] = "cannot_connect"

        device_names = getattr(self, "_device_names", None) or []
        if device_names:
            schema = vol.Schema({
                vol.Required(CONF_DEVICE_NAME): vol.In(device_names),
            })
        else:
            schema = vol.Schema({
                vol.Required(CONF_DEVICE_NAME): str,
            })

        return self.async_show_form(step_id="device", data_schema=schema, errors=errors)

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

    async def _async_fetch_devices(self, data):
        def _fetch():
            client = RemkoSmartWebClient(
                email=data[CONF_EMAIL],
                password=data[CONF_PASSWORD],
                device_name="",
            )
            client.login()
            return client.list_devices()

        try:
            names = await self.hass.async_add_executor_job(_fetch)
            return True, names
        except Exception:
            return False, []

    def _get_entries(self):
        return self.hass.config_entries.async_entries(DOMAIN)

    def _get_existing_accounts(self):
        options = {}
        for entry in self._get_entries():
            email = entry.data.get(CONF_EMAIL, "")
            label = f"{email}" if email else entry.title
            options[entry.entry_id] = label
        return options

    async def async_step_import(self, user_input):
        return await self.async_step_user(user_input)

    @staticmethod
    def async_get_options_flow(config_entry: config_entries.ConfigEntry):
        return RemkoSmartWebOptionsFlow(config_entry)


class RemkoSmartWebOptionsFlow(config_entries.OptionsFlow):
    def __init__(self, config_entry: config_entries.ConfigEntry):
        self._config_entry = config_entry

    async def async_step_init(self, user_input=None):
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        model = self._config_entry.options.get(CONF_MODEL, "other")
        model_defaults = {
            "mxw_204": (17, 30),
            "mxw_264": (17, 30),
            "mxw_354": (17, 30),
            "mxw_524": (17, 30),
            "other": (DEFAULT_MIN_TEMP, DEFAULT_MAX_TEMP),
        }
        d_min, d_max = model_defaults.get(model, (DEFAULT_MIN_TEMP, DEFAULT_MAX_TEMP))

        schema = vol.Schema({
            vol.Optional(CONF_MODEL, default=model): vol.In(
                {
                    "mxw_204": "MXW 204",
                    "mxw_264": "MXW 264",
                    "mxw_354": "MXW 354",
                    "mxw_524": "MXW 524",
                    "other": "Other / Unknown",
                }
            ),
            vol.Optional(
                CONF_SCAN_INTERVAL,
                default=self._config_entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
            ): vol.Coerce(int),
            vol.Optional(
                CONF_MIN_TEMP,
                default=self._config_entry.options.get(CONF_MIN_TEMP, d_min),
            ): vol.Coerce(int),
            vol.Optional(
                CONF_MAX_TEMP,
                default=self._config_entry.options.get(CONF_MAX_TEMP, d_max),
            ): vol.Coerce(int),
        })
        return self.async_show_form(step_id="init", data_schema=schema)
