from __future__ import annotations

import logging

import voluptuous as vol
from homeassistant import config_entries

from .const import (
    DOMAIN,
    CONF_EMAIL,
    CONF_PASSWORD,
    CONF_DEVICE_NAME,
    CONF_DEVICE_PATH,
    CONF_SCAN_INTERVAL,
    CONF_MIN_TEMP,
    CONF_MAX_TEMP,
    CONF_MODEL,
    CONF_DEVICE_KIND,
    DEVICE_KIND_AUTO,
    DEVICE_KIND_CLIMATE,
    DEVICE_KIND_DHW,
    DEVICE_KIND_DIAGNOSTICS,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_MIN_TEMP,
    DEFAULT_MAX_TEMP,
)
from .api import RemkoSmartWebClient
from .profiles import looks_like_dhw_name

_LOGGER = logging.getLogger(__name__)

DEVICE_KIND_OPTIONS = {
    DEVICE_KIND_AUTO: "Auto-detect",
    DEVICE_KIND_CLIMATE: "Air conditioner / climate",
    DEVICE_KIND_DHW: "Domestic hot water",
    DEVICE_KIND_DIAGNOSTICS: "Diagnostics only",
}


class RemkoSmartWebConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input=None):
        existing = self._get_existing_accounts()
        if existing and user_input is None:
            return await self.async_step_account()

        errors = {}
        schema = vol.Schema({
            vol.Required(CONF_EMAIL): str,
            vol.Required(CONF_PASSWORD): str,
        })
        if user_input is not None:
            ok, device_map = await self._async_fetch_devices(user_input)
            if ok:
                self._email = user_input[CONF_EMAIL]
                self._password = user_input[CONF_PASSWORD]
                self._device_map = self._filter_existing_device_map(device_map, self._email)
                self._device_names = sorted(self._device_map, key=str.lower)
                if not self._device_names:
                    errors["base"] = "no_devices"
                    return self.async_show_form(step_id="user", data_schema=schema, errors=errors)
                if len(self._device_names) == 1:
                    return await self._prepare_device_kind_step(self._device_names[0])
                return await self.async_step_device()
            errors["base"] = "cannot_connect"

        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)

    async def async_step_account(self, user_input=None):
        errors = {}
        existing = self._get_existing_accounts()
        if not existing:
            return await self.async_step_user()

        options = dict(existing)
        options["new"] = "Use new credentials"
        schema = vol.Schema({
            vol.Required("account"): vol.In(options),
        })

        if user_input is not None:
            selected = user_input.get("account")
            if selected == "new":
                return await self.async_step_user()
            entry = next((e for e in self._get_entries() if e.entry_id == selected), None)
            if entry:
                self._email = entry.data.get(CONF_EMAIL)
                self._password = entry.data.get(CONF_PASSWORD)
                ok, device_map = await self._async_fetch_devices(
                    {CONF_EMAIL: self._email, CONF_PASSWORD: self._password}
                )
                if ok:
                    self._device_map = self._filter_existing_device_map(device_map, self._email)
                    self._device_names = sorted(self._device_map, key=str.lower)
                    if not self._device_names:
                        errors["base"] = "no_devices"
                        return self.async_show_form(step_id="account", data_schema=schema, errors=errors)
                    if len(self._device_names) == 1:
                        return await self._prepare_device_kind_step(self._device_names[0])
                    return await self.async_step_device()
            errors["base"] = "cannot_connect"
        return self.async_show_form(step_id="account", data_schema=schema, errors=errors)

    async def async_step_device(self, user_input=None):
        errors = {}
        if user_input is not None:
            return await self._prepare_device_kind_step(user_input[CONF_DEVICE_NAME])

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

    async def async_step_device_kind(self, user_input=None):
        errors = {}
        data = getattr(self, "_pending_entry_data", None)
        if not data:
            return await self.async_step_device()

        detected_kind = self._suggest_device_kind(data[CONF_DEVICE_NAME])
        options = self._device_kind_options(detected_kind)
        default_kind = detected_kind if detected_kind != DEVICE_KIND_AUTO else DEVICE_KIND_AUTO
        schema = vol.Schema({
            vol.Required(CONF_DEVICE_KIND, default=default_kind): vol.In(options),
        })

        if user_input is not None:
            entry_options = {CONF_DEVICE_KIND: user_input[CONF_DEVICE_KIND]}
            ok = await self._async_validate(data)
            if ok:
                return self.async_create_entry(
                    title=data[CONF_DEVICE_NAME],
                    data=data,
                    options=entry_options,
                )
            errors["base"] = "cannot_connect"

        return self.async_show_form(step_id="device_kind", data_schema=schema, errors=errors)

    async def _async_validate(self, data) -> bool:
        def _check():
            client = RemkoSmartWebClient(
                email=data[CONF_EMAIL],
                password=data[CONF_PASSWORD],
                device_name=data[CONF_DEVICE_NAME],
                device_path=data.get(CONF_DEVICE_PATH),
            )
            try:
                client.login()
                client.resolve_device()
                return True
            finally:
                client.close()

        try:
            return await self.hass.async_add_executor_job(_check)
        except Exception as err:
            _LOGGER.warning("Credential validation failed: %s", err)
            return False

    async def _async_fetch_devices(self, data):
        def _fetch():
            client = RemkoSmartWebClient(
                email=data[CONF_EMAIL],
                password=data[CONF_PASSWORD],
                device_name="",
            )
            try:
                client.login()
                return client.list_device_map()
            finally:
                client.close()

        try:
            device_map = await self.hass.async_add_executor_job(_fetch)
            return True, device_map
        except Exception as err:
            _LOGGER.warning("Device list fetch failed: %s", err)
            return False, {}

    def _get_entries(self):
        return self.hass.config_entries.async_entries(DOMAIN)

    def _get_existing_accounts(self):
        buckets = {}
        for entry in self._get_entries():
            email = (entry.data.get(CONF_EMAIL) or "").strip()
            password = entry.data.get(CONF_PASSWORD) or ""
            key = (email.lower(), password)
            if key not in buckets:
                buckets[key] = {"entry_id": entry.entry_id, "email": email, "count": 0}
            buckets[key]["count"] += 1

        options = {}
        for item in buckets.values():
            email = item["email"]
            count = item["count"]
            if email:
                label = f"{email} ({count} devices)"
            else:
                label = f"Account ({count} devices)"
            options[item["entry_id"]] = label
        return options

    def _filter_existing_device_map(self, device_map: dict[str, str], email: str | None):
        if not device_map:
            return {}
        email = (email or "").strip().lower()
        existing_names = set()
        existing_paths = set()
        for entry in self._get_entries():
            if email and entry.data.get(CONF_EMAIL, "").strip().lower() != email:
                continue
            name = entry.data.get(CONF_DEVICE_NAME)
            if name:
                existing_names.add(name.strip().lower())
            path = entry.data.get(CONF_DEVICE_PATH)
            if path:
                existing_paths.add(path)
        return {
            name: path
            for name, path in device_map.items()
            if name.strip().lower() not in existing_names and path not in existing_paths
        }

    def _entry_data_for_device(self, device_name: str):
        data = {
            CONF_EMAIL: self._email,
            CONF_PASSWORD: self._password,
            CONF_DEVICE_NAME: device_name,
        }
        device_path = getattr(self, "_device_map", {}).get(device_name)
        if device_path:
            data[CONF_DEVICE_PATH] = device_path
        return data

    async def _prepare_device_kind_step(self, device_name: str):
        self._pending_entry_data = self._entry_data_for_device(device_name)
        return await self.async_step_device_kind()

    def _suggest_device_kind(self, device_name: str) -> str:
        if looks_like_dhw_name(device_name):
            return DEVICE_KIND_DHW
        return DEVICE_KIND_AUTO

    def _device_kind_options(self, detected_kind: str | None = None) -> dict[str, str]:
        options = dict(DEVICE_KIND_OPTIONS)
        if detected_kind and detected_kind != DEVICE_KIND_AUTO:
            label = options.get(detected_kind, detected_kind)
            options[detected_kind] = f"{label} (detected)"
        return options

    async def async_step_import(self, user_input):
        return await self.async_step_user(user_input)

    @staticmethod
    def async_get_options_flow(config_entry: config_entries.ConfigEntry):
        return RemkoSmartWebOptionsFlow(config_entry)


class RemkoSmartWebOptionsFlow(config_entries.OptionsFlow):
    def __init__(self, config_entry: config_entries.ConfigEntry):
        self._config_entry = config_entry
        self._options = dict(config_entry.options)

    async def async_step_init(self, user_input=None):
        if user_input is not None:
            self._options.update(user_input)
            if self._shows_climate_options(user_input[CONF_DEVICE_KIND]):
                return await self.async_step_climate()
            self._options.pop(CONF_MODEL, None)
            self._options.pop(CONF_MIN_TEMP, None)
            self._options.pop(CONF_MAX_TEMP, None)
            return self.async_create_entry(title="", data=self._options)

        device_kind = self._config_entry.options.get(
            CONF_DEVICE_KIND,
            self._suggest_device_kind(self._config_entry.data.get(CONF_DEVICE_NAME, "")),
        )
        schema = vol.Schema({
            vol.Optional(CONF_DEVICE_KIND, default=device_kind): vol.In(
                self._device_kind_options(device_kind)
            ),
            vol.Optional(
                CONF_SCAN_INTERVAL,
                default=self._config_entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
            ): vol.Coerce(int),
        })
        return self.async_show_form(step_id="init", data_schema=schema)

    async def async_step_climate(self, user_input=None):
        if user_input is not None:
            self._options.update(user_input)
            return self.async_create_entry(title="", data=self._options)

        model = self._options.get(CONF_MODEL, "other")
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
                CONF_MIN_TEMP,
                default=self._options.get(CONF_MIN_TEMP, d_min),
            ): vol.Coerce(int),
            vol.Optional(
                CONF_MAX_TEMP,
                default=self._options.get(CONF_MAX_TEMP, d_max),
            ): vol.Coerce(int),
        })
        return self.async_show_form(step_id="climate", data_schema=schema)

    def _suggest_device_kind(self, device_name: str) -> str:
        if looks_like_dhw_name(device_name):
            return DEVICE_KIND_DHW
        return DEVICE_KIND_AUTO

    def _device_kind_options(self, detected_kind: str | None = None) -> dict[str, str]:
        options = dict(DEVICE_KIND_OPTIONS)
        if detected_kind and detected_kind != DEVICE_KIND_AUTO:
            label = options.get(detected_kind, detected_kind)
            options[detected_kind] = f"{label} (detected)"
        return options

    def _shows_climate_options(self, device_kind: str) -> bool:
        return device_kind in (DEVICE_KIND_AUTO, DEVICE_KIND_CLIMATE)
