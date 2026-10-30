from __future__ import annotations

from homeassistant.components.number import NumberEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import PERCENTAGE, UnitOfTemperature
from homeassistant.core import HomeAssistant
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
    entities = [
        RemkoSmartWebNumber(coordinator, client, device_name, profile, description)
        for description in getattr(profile, "number_descriptions", ())
    ]
    async_add_entities(entities)


class RemkoSmartWebNumber(PendingStateMixin, CoordinatorEntity, NumberEntity):
    def __init__(self, coordinator, client, device_name: str, profile, description):
        super().__init__(coordinator)
        key, name, min_value, max_value, step, unit = description
        self._client = client
        self._profile = profile
        self._key = key
        self._init_pending_state()
        self._attr_has_entity_name = True
        self._attr_translation_key = key
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
        return self._display_value(self._key)

    @property
    def available(self) -> bool:
        """Expose controls only after the device confirmed their value ID."""
        coordinator_data = self.coordinator.data
        return bool(
            getattr(super(), "available", True)
            and isinstance(coordinator_data, dict)
            and self._key in coordinator_data
        )

    async def async_set_native_value(self, value: float) -> None:
        if not self.available:
            return
        value_write = self._profile.build_value_write({self._key: value})
        if not value_write:
            return
        pending_generation = self._start_pending_state({self._key: value})
        try:
            await self.hass.async_add_executor_job(self._client.set_value_ids, value_write)
        except Exception:
            self._rollback_pending_state(pending_generation)
            raise
        self._schedule_readback_refresh()
