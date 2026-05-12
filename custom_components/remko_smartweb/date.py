from __future__ import annotations

from datetime import date

from homeassistant.components.date import DateEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
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
    if not profile.supports_water_heater:
        async_add_entities([])
        return
    async_add_entities([RemkoSmartWebVacationEndDate(coordinator, client, device_name, profile)])


class RemkoSmartWebVacationEndDate(CoordinatorEntity, DateEntity):
    _attr_has_entity_name = True
    _attr_translation_key = "dhw_vacation_end_date"

    def __init__(self, coordinator, client, device_name: str, profile):
        super().__init__(coordinator)
        self._client = client
        self._profile = profile
        self._attr_unique_id = f"{device_name.lower().replace(' ', '_')}_dhw_vacation_end_date"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device_name)},
            name=device_name,
            manufacturer="REMKO",
            model="SmartWeb",
        )

    @property
    def native_value(self) -> date | None:
        value = self.coordinator.data.get("dhw_vacation_end_date")
        if not value:
            return None
        try:
            return date.fromisoformat(str(value))
        except ValueError:
            return None

    @property
    def native_min_value(self) -> date:
        return date.today()

    async def async_set_value(self, value: date) -> None:
        if value < self.native_min_value:
            raise HomeAssistantError("DHW vacation end date must not be in the past")

        values = self._profile.build_value_write({"vacation_end_date": value})
        if not values:
            return

        old_data = dict(self.coordinator.data) if self.coordinator.data is not None else None
        if old_data is not None:
            data = dict(self.coordinator.data)
            data["dhw_vacation_enabled"] = True
            data["dhw_vacation_end_date"] = value.isoformat()
            self.coordinator.data = data
            self.async_write_ha_state()

        async def _do_refresh(_now):
            await self.coordinator.async_request_refresh()

        try:
            await self.hass.async_add_executor_job(self._client.set_value_ids, values)
        except Exception as err:
            if old_data is not None:
                self.coordinator.data = old_data
                self.async_write_ha_state()
            raise HomeAssistantError(
                "REMKO SmartWeb vacation end date write was not confirmed by the device"
            ) from err
        finally:
            async_call_later(self.hass, 2.0, _do_refresh)
