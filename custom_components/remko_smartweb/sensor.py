from __future__ import annotations

from homeassistant.components.sensor import SensorEntity, SensorDeviceClass, SensorStateClass
from homeassistant.const import PERCENTAGE, UnitOfTemperature
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.core import HomeAssistant
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.entity import DeviceInfo, EntityCategory
from homeassistant.helpers import entity_registry as er

from .const import DOMAIN

LEGACY_DIAGNOSTIC_KEYS = (
    "detected_profile",
    "profile_class",
    "profile_protocol",
    "profile_write_support",
    "portal_id",
    "portal_name",
    "portal_type",
    "portal_dev",
    "mqtt_topic",
)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities):
    data = hass.data[DOMAIN][entry.entry_id]
    coordinator = data["coordinator"]
    client = data["client"]
    device_name = data["device_name"]
    profile = data["device_profile"]

    _remove_legacy_diagnostic_entities(hass, device_name)

    entities = [
        RemkoSmartWebSensor(coordinator, device_name, key, name, kind)
        for (key, name, kind) in profile.sensors_for_data(coordinator.data)
    ]
    entities.append(RemkoSmartWebDiagnosticSensor(coordinator, client, device_name))
    async_add_entities(entities)



def _remove_legacy_diagnostic_entities(hass: HomeAssistant, device_name: str) -> None:
    registry = er.async_get(hass)
    slug = device_name.lower().replace(" ", "_")
    for key in LEGACY_DIAGNOSTIC_KEYS:
        entity_id = registry.async_get_entity_id("sensor", DOMAIN, f"{slug}_{key}")
        if entity_id:
            registry.async_remove(entity_id)


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

    @property
    def state_class(self):
        if self._kind in ("temperature", "percentage"):
            return SensorStateClass.MEASUREMENT
        return None

    @property
    def extra_state_attributes(self):
        getter = getattr(self.coordinator, "last_value_update_time", None)
        if not callable(getter):
            return None
        updated_at = getter(self._key)
        if not updated_at:
            return None
        return {"last_successful_value_update": updated_at}


class RemkoSmartWebDiagnosticSensor(CoordinatorEntity, SensorEntity):
    def __init__(self, coordinator, client, device_name: str):
        super().__init__(coordinator)
        self._client = client
        self._attr_name = f"{device_name} Diagnostics"
        self._attr_unique_id = f"{device_name.lower().replace(' ', '_')}_diagnostics"
        self._attr_entity_category = EntityCategory.DIAGNOSTIC
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device_name)},
            name=device_name,
            manufacturer="REMKO",
            model="SmartWeb",
        )

    @property
    def native_value(self):
        value = self._client.diagnostic_metadata().get("Detected Profile")
        if value in (None, ""):
            return None
        return value

    @property
    def extra_state_attributes(self):
        return {
            key.lower().replace(" ", "_"): value
            for key, value in self._client.diagnostic_metadata().items()
            if value not in (None, "")
        }
