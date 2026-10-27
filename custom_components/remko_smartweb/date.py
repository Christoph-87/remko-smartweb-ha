from __future__ import annotations

from datetime import date

from homeassistant.components.date import DateEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from ._pending import PendingStateMixin
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


class RemkoSmartWebVacationEndDate(PendingStateMixin, CoordinatorEntity, DateEntity):
    _attr_has_entity_name = True
    _attr_translation_key = "dhw_vacation_end_date"

    def __init__(self, coordinator, client, device_name: str, profile):
        super().__init__(coordinator)
        self._client = client
        self._profile = profile
        self._init_pending_state()
        self._attr_unique_id = f"{device_name.lower().replace(' ', '_')}_dhw_vacation_end_date"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device_name)},
            name=device_name,
            manufacturer="REMKO",
            model="SmartWeb",
        )

    @property
    def native_value(self) -> date | None:
        value = self._display_value("dhw_vacation_end_date")
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

        pending_generation = self._start_pending_state(
            {"dhw_vacation_end_date": value.isoformat()}
        )

        try:
            await self.hass.async_add_executor_job(self._client.set_value_ids, values)
        except Exception as err:
            self._rollback_pending_state(pending_generation)
            raise HomeAssistantError(
                "REMKO SmartWeb vacation end date write was not confirmed by the device"
            ) from err
        finally:
            self._schedule_readback_refresh()
