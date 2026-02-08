from __future__ import annotations

from homeassistant.components.sensor import SensorEntity, SensorDeviceClass
from homeassistant.const import UnitOfTemperature
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.core import HomeAssistant
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.entity import DeviceInfo

from .const import DOMAIN

SENSORS = [
    ("room", "Room Temperature", "temperature"),
    ("outdoor", "Outdoor Temperature", "temperature"),
    ("setpoint", "Setpoint", "temperature"),
    ("error", "Error Code", None),
]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities):
    data = hass.data[DOMAIN][entry.entry_id]
    coordinator = data["coordinator"]
    device_name = data["device_name"]

    entities = [
        RemkoSmartWebSensor(coordinator, device_name, key, name, kind)
        for (key, name, kind) in SENSORS
    ]
    async_add_entities(entities)


class RemkoSmartWebSensor(CoordinatorEntity, SensorEntity):
    def __init__(self, coordinator, device_name: str, key: str, name: str, kind: str | None):
        super().__init__(coordinator)
        self._key = key
        self._kind = kind
        self._attr_name = f"{device_name} {name}"
        self._attr_unique_id = f"{device_name.lower().replace(' ', '_')}_{key}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device_name)},
            name=device_name,
            manufacturer="REMKO",
            model="SmartWeb",
        )

    @property
    def native_value(self):
        return self.coordinator.data.get(self._key)

    @property
    def native_unit_of_measurement(self):
        if self._kind != "temperature":
            return None
        unit = self.coordinator.data.get("unit", "C")
        return UnitOfTemperature.FAHRENHEIT if unit == "F" else UnitOfTemperature.CELSIUS

    @property
    def device_class(self):
        if self._kind == "temperature":
            return SensorDeviceClass.TEMPERATURE
        return None
