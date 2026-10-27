from __future__ import annotations

from homeassistant.components.select import SelectEntity
from homeassistant.config_entries import ConfigEntry
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
        RemkoSmartWebSelect(coordinator, client, device_name, profile, description)
        for description in getattr(profile, "select_descriptions", ())
    ]
    async_add_entities(entities)


class RemkoSmartWebSelect(PendingStateMixin, CoordinatorEntity, SelectEntity):
    def __init__(self, coordinator, client, device_name: str, profile, description):
        super().__init__(coordinator)
        key, name, options = description
        self._client = client
        self._profile = profile
        self._key = key
        self._init_pending_state()
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
        return self._display_value(self._key)

    @property
    def extra_state_attributes(self) -> dict:
        """Expose confirmed and pending state separately for diagnostics."""
        attributes = super().extra_state_attributes
        attributes["confirmed_option"] = self._confirmed_value(self._key)
        return attributes

    @property
    def available(self) -> bool:
        """Expose only selects with a value confirmed by device readback."""
        coordinator_data = self.coordinator.data
        return bool(
            getattr(super(), "available", True)
            and isinstance(coordinator_data, dict)
            and self._key in coordinator_data
        )

    async def async_select_option(self, option: str) -> None:
        if not self.available or option not in self._attr_options:
            return
        if option == self.current_option:
            return
        value_write = self._profile.build_value_write({self._key: option})
        if not value_write:
            return

        pending_generation = self._start_pending_state({self._key: option})

        try:
            await self.hass.async_add_executor_job(self._client.set_value_ids, value_write)
        except Exception:
            self._rollback_pending_state(pending_generation)
            raise
        self._schedule_readback_refresh()
