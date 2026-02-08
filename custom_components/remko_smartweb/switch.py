from __future__ import annotations

from homeassistant.components.switch import SwitchEntity
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.core import HomeAssistant
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.entity import DeviceInfo

from .const import DOMAIN

SWITCHES = [
    ("power", "Power"),
    ("eco", "Eco"),
    ("turbo", "Turbo"),
    ("sleep", "Sleep"),
    ("bioclean", "Bioclean"),
]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities):
    data = hass.data[DOMAIN][entry.entry_id]
    coordinator = data["coordinator"]
    client = data["client"]
    device_name = data["device_name"]

    # Only add switches that are present in the latest data snapshot.
    present = set(coordinator.data.keys()) if coordinator.data else set()
    entities = []
    for (key, name) in SWITCHES:
        if key == "power" or key in present:
            entities.append(RemkoSmartWebSwitch(coordinator, client, device_name, key, name))
    async_add_entities(entities)


class RemkoSmartWebSwitch(CoordinatorEntity, SwitchEntity):
    def __init__(self, coordinator, client, device_name: str, key: str, name: str):
        super().__init__(coordinator)
        self._client = client
        self._key = key
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
        overrides = {self._key: state}
        if self._key == "power":
            overrides = {"power": state}
        await self.hass.async_add_executor_job(self._client.set_values, overrides)
        await self.coordinator.async_request_refresh()
