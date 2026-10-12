from __future__ import annotations

from homeassistant.components.select import SelectEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.event import async_call_later
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities):
    data = hass.data[DOMAIN][entry.entry_id]
    coordinator = data["coordinator"]
    client = data["client"]
    device_name = data["device_name"]
    profile = data["device_profile"]
    entities = [
        RemkoSmartWebSelect(coordinator, client, device_name, profile, description)
        for description in getattr(profile, "select_descriptions", ())
    ]
    async_add_entities(entities)


class RemkoSmartWebSelect(CoordinatorEntity, SelectEntity):
    def __init__(self, coordinator, client, device_name: str, profile, description):
        super().__init__(coordinator)
        key, name, options = description
        self._client = client
        self._profile = profile
        self._key = key
        self._attr_has_entity_name = True
        self._attr_translation_key = key
        self._attr_unique_id = f"{device_name.lower().replace(' ', '_')}_{key}_select"
        self._attr_options = list(options)
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device_name)},
            name=device_name,
            manufacturer="REMKO",
            model="SmartWeb",
        )

    @property
    def current_option(self):
        return self.coordinator.data.get(self._key)

    async def async_select_option(self, option: str) -> None:
        if option not in self._attr_options:
            return
        value_write = self._profile.build_value_write({self._key: option})
        if not value_write:
            return
        if self.coordinator.data is not None:
            data = dict(self.coordinator.data)
            data[self._key] = option
            self.coordinator.data = data
            self.async_write_ha_state()

        await self.hass.async_add_executor_job(self._client.set_value_ids, value_write)

        async def _do_refresh(_now):
            await self.coordinator.async_request_refresh()

        async_call_later(self.hass, 2.0, _do_refresh)
