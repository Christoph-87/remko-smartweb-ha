from __future__ import annotations

from homeassistant.components.number import NumberEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import PERCENTAGE, UnitOfTemperature
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
        RemkoSmartWebNumber(coordinator, client, device_name, profile, description)
        for description in getattr(profile, "number_descriptions", ())
    ]
    async_add_entities(entities)


class RemkoSmartWebNumber(CoordinatorEntity, NumberEntity):
    def __init__(self, coordinator, client, device_name: str, profile, description):
        super().__init__(coordinator)
        key, name, min_value, max_value, step, unit = description
        self._client = client
        self._profile = profile
        self._key = key
        self._attr_name = f"{device_name} {name}"
        self._attr_unique_id = f"{device_name.lower().replace(' ', '_')}_{key}_number"
        self._attr_native_min_value = min_value
        self._attr_native_max_value = max_value
        self._attr_native_step = step
        if unit == "temperature":
            self._attr_native_unit_of_measurement = UnitOfTemperature.CELSIUS
        elif unit == "percentage":
            self._attr_native_unit_of_measurement = PERCENTAGE
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device_name)},
            name=device_name,
            manufacturer="REMKO",
            model="SmartWeb",
        )

    @property
    def native_value(self):
        return self.coordinator.data.get(self._key)

    async def async_set_native_value(self, value: float) -> None:
        value_write = self._profile.build_value_write({self._key: value})
        if not value_write:
            return
        if self.coordinator.data is not None:
            data = dict(self.coordinator.data)
            data[self._key] = value
            self.coordinator.data = data
            self.async_write_ha_state()

        await self.hass.async_add_executor_job(self._client.set_value_ids, value_write)

        async def _do_refresh(_now):
            await self.coordinator.async_request_refresh()

        async_call_later(self.hass, 2.0, _do_refresh)
