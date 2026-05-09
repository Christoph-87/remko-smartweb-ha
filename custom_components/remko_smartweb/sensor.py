from __future__ import annotations

from homeassistant.components.sensor import SensorEntity, SensorDeviceClass
from homeassistant.const import PERCENTAGE, UnitOfTemperature
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.core import HomeAssistant
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.entity import DeviceInfo

from .const import DOMAIN


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities):
    data = hass.data[DOMAIN][entry.entry_id]
    coordinator = data["coordinator"]
    client = data["client"]
    device_name = data["device_name"]
    profile = data["device_profile"]

    entities = [
        RemkoSmartWebSensor(coordinator, device_name, key, name, kind)
        for (key, name, kind) in profile.sensors_for_data(coordinator.data)
    ]
    entities.extend(
        RemkoSmartWebDiagnosticSensor(device_name, key, name, value)
        for key, name, value in _diagnostic_sensor_values(client)
    )
    async_add_entities(entities)


def _diagnostic_sensor_values(client):
    for name, value in client.diagnostic_metadata().items():
        if value in (None, ""):
            continue
        key = name.lower().replace(" ", "_")
        yield key, name, value


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
            if self._kind == "percentage":
                return PERCENTAGE
            return None
        unit = self.coordinator.data.get("unit", "C")
        return UnitOfTemperature.FAHRENHEIT if unit == "F" else UnitOfTemperature.CELSIUS

    @property
    def device_class(self):
        if self._kind == "temperature":
            return SensorDeviceClass.TEMPERATURE
        if self._kind == "percentage":
            return SensorDeviceClass.HUMIDITY
        return None


class RemkoSmartWebDiagnosticSensor(SensorEntity):
    def __init__(self, device_name: str, key: str, name: str, value: str):
        self._value = value
        self._attr_name = f"{device_name} {name}"
        self._attr_unique_id = f"{device_name.lower().replace(' ', '_')}_{key}"
        self._attr_entity_category = "diagnostic"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device_name)},
            name=device_name,
            manufacturer="REMKO",
            model="SmartWeb",
        )

    @property
    def native_value(self):
        return self._value
