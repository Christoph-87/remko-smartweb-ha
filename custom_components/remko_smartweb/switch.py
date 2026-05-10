from __future__ import annotations

from homeassistant.components.switch import SwitchEntity
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.core import HomeAssistant
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.event import async_call_later

from .const import DOMAIN

SWITCHES = [
    ("power", "Power"),
    ("eco", "Eco"),
    ("frost_protection", "Frost Protection"),
    ("turbo", "Turbo"),
    ("sleep", "Sleep / Silent Mode"),
    ("bioclean", "Bioclean"),
    ("wpm_heat_cool_mode", "WPM Heat/Cool Mode"),
    ("wpm_manual_defrost", "WPM Manual Defrost"),
]

C0_CLIMATE_SWITCH_KEYS = {
    "power",
    "eco",
    "frost_protection",
    "turbo",
    "sleep",
    "bioclean",
}


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities):
    data = hass.data[DOMAIN][entry.entry_id]
    coordinator = data["coordinator"]
    client = data["client"]
    device_name = data["device_name"]
    profile = data["device_profile"]

    present = set(coordinator.data.keys()) if coordinator.data else set()
    entities = []
    for (key, name) in SWITCHES:
        if _should_add_switch(profile, present, key):
            entities.append(RemkoSmartWebSwitch(coordinator, client, device_name, key, name, profile))
    async_add_entities(entities)


def _should_add_switch(profile, present: set[str], key: str) -> bool:
    if getattr(profile, "supports_value_write", False):
        if key != "power" and key not in present:
            return False
        return bool(profile.build_value_write({key: True}) or profile.build_value_write({key: False}))
    if (
        getattr(profile, "supports_climate_write", False)
        and key in C0_CLIMATE_SWITCH_KEYS
    ):
        return True
    return False


class RemkoSmartWebSwitch(CoordinatorEntity, SwitchEntity):
    def __init__(self, coordinator, client, device_name: str, key: str, name: str, profile):
        super().__init__(coordinator)
        self._client = client
        self._key = key
        self._profile = profile
        self._attr_name = f"{device_name} {name}"
        self._attr_unique_id = f"{device_name.lower().replace(' ', '_')}_{key}_switch"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device_name)},
            name=device_name,
            manufacturer="REMKO",
            model="SmartWeb",
        )

    @property
    def is_on(self) -> bool:
        if self._key == "power":
            return self.coordinator.data.get("power") == "ON"
        return bool(self.coordinator.data.get(self._key))

    async def async_turn_on(self, **kwargs):
        await self._async_set(True)

    async def async_turn_off(self, **kwargs):
        await self._async_set(False)

    async def _async_set(self, state: bool):
        if (
            not getattr(self._profile, "supports_value_write", False)
            and not getattr(self._profile, "supports_climate_write", False)
        ):
            return
        overrides = {self._key: state}
        if self._key == "power":
            overrides = {"power": state}
        # Optimistic UI update to avoid flicker.
        if self.coordinator.data is not None:
            data = dict(self.coordinator.data)
            if self._key == "power":
                data["power"] = "ON" if state else "OFF"
            else:
                data[self._key] = bool(state)
            self.coordinator.data = data
            self.async_write_ha_state()

        async def _do_refresh(_now):
            await self.coordinator.async_request_refresh()

        value_write = self._profile.build_value_write(overrides)
        if value_write:
            await self.hass.async_add_executor_job(self._client.set_value_ids, value_write)
            async_call_later(self.hass, 2.0, _do_refresh)
            return
        if getattr(self._profile, "supports_value_write", False):
            return
        else:
            await self.hass.async_add_executor_job(self._client.set_values, overrides)
        async_call_later(self.hass, 2.0, _do_refresh)
