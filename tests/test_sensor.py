from __future__ import annotations

import asyncio
import sys
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPONENT_PATH = ROOT / "custom_components" / "remko_smartweb"

custom_components = types.ModuleType("custom_components")
custom_components.__path__ = [str(ROOT / "custom_components")]
sys.modules.setdefault("custom_components", custom_components)

remko_smartweb = types.ModuleType("custom_components.remko_smartweb")
remko_smartweb.__path__ = [str(COMPONENT_PATH)]
sys.modules.setdefault("custom_components.remko_smartweb", remko_smartweb)

homeassistant = types.ModuleType("homeassistant")
ha_components = types.ModuleType("homeassistant.components")
ha_sensor = types.ModuleType("homeassistant.components.sensor")
ha_core = types.ModuleType("homeassistant.core")
ha_config_entries = types.ModuleType("homeassistant.config_entries")
ha_helpers = types.ModuleType("homeassistant.helpers")
ha_entity = types.ModuleType("homeassistant.helpers.entity")
ha_entity_registry = types.ModuleType("homeassistant.helpers.entity_registry")
ha_update_coordinator = types.ModuleType("homeassistant.helpers.update_coordinator")
ha_const = types.ModuleType("homeassistant.const")


class SensorEntity:
    pass


class SensorDeviceClass:
    TEMPERATURE = "temperature"
    HUMIDITY = "humidity"


class SensorStateClass:
    MEASUREMENT = "measurement"


class CoordinatorEntity:
    def __init__(self, coordinator):
        self.coordinator = coordinator
        self.hass = coordinator.hass


class HomeAssistant:
    pass


class ConfigEntry:
    entry_id = "entry-id"


class DeviceInfo(dict):
    pass


class EntityCategory:
    DIAGNOSTIC = "diagnostic"


class UnitOfTemperature:
    CELSIUS = "C"
    FAHRENHEIT = "F"


class EntityRegistry:
    def __init__(self):
        self.entities = {}
        self.removed = []

    def async_get_entity_id(self, domain, platform, unique_id):
        return self.entities.get((domain, platform, unique_id))

    def async_remove(self, entity_id):
        self.removed.append(entity_id)


def async_get_entity_registry(hass):
    if not hasattr(hass, "entity_registry"):
        hass.entity_registry = EntityRegistry()
    return hass.entity_registry


ha_sensor.SensorEntity = SensorEntity
ha_sensor.SensorDeviceClass = SensorDeviceClass
ha_sensor.SensorStateClass = SensorStateClass
ha_core.HomeAssistant = HomeAssistant
ha_config_entries.ConfigEntry = ConfigEntry
ha_entity.DeviceInfo = DeviceInfo
ha_entity.EntityCategory = EntityCategory
ha_entity_registry.async_get = async_get_entity_registry
ha_update_coordinator.CoordinatorEntity = CoordinatorEntity
ha_const.PERCENTAGE = "%"
ha_const.UnitOfTemperature = UnitOfTemperature

sys.modules.setdefault("homeassistant", homeassistant)
sys.modules.setdefault("homeassistant.components", ha_components)
sys.modules.setdefault("homeassistant.components.sensor", ha_sensor)
sys.modules.setdefault("homeassistant.core", ha_core)
sys.modules.setdefault("homeassistant.config_entries", ha_config_entries)
sys.modules.setdefault("homeassistant.helpers", ha_helpers)
sys.modules.setdefault("homeassistant.helpers.entity", ha_entity)
sys.modules.setdefault("homeassistant.helpers.entity_registry", ha_entity_registry)
sys.modules.setdefault("homeassistant.helpers.update_coordinator", ha_update_coordinator)
sys.modules.setdefault("homeassistant.const", ha_const)

sys.modules["homeassistant.components.sensor"].SensorEntity = SensorEntity
sys.modules["homeassistant.components.sensor"].SensorDeviceClass = SensorDeviceClass
sys.modules["homeassistant.components.sensor"].SensorStateClass = SensorStateClass
sys.modules["homeassistant.core"].HomeAssistant = HomeAssistant
sys.modules["homeassistant.config_entries"].ConfigEntry = ConfigEntry
sys.modules["homeassistant.helpers.entity"].DeviceInfo = DeviceInfo
sys.modules["homeassistant.helpers.entity"].EntityCategory = EntityCategory
sys.modules["homeassistant.helpers.entity_registry"].async_get = async_get_entity_registry
sys.modules["homeassistant.helpers.update_coordinator"].CoordinatorEntity = CoordinatorEntity
sys.modules["homeassistant.const"].PERCENTAGE = "%"
sys.modules["homeassistant.const"].UnitOfTemperature = UnitOfTemperature

from custom_components.remko_smartweb.const import DOMAIN
from custom_components.remko_smartweb.sensor import (
    LEGACY_DIAGNOSTIC_KEYS,
    RemkoSmartWebDiagnosticSensor,
    RemkoSmartWebSensor,
    async_setup_entry,
)


class EmptyProfile:
    def sensors_for_data(self, data):
        return []


class MutableDiagnosticClient:
    def __init__(self):
        self.metadata = {
            "Detected Profile": "Diagnostics",
            "Profile Class": "DiagnosticsDeviceProfile",
            "Profile Protocol": "unsupported_or_unknown",
            "Profile Write Support": "no",
        }

    def diagnostic_metadata(self):
        return dict(self.metadata)


class SensorSetupTests(unittest.TestCase):
    def test_regular_sensor_exposes_last_successful_value_update_attribute(self):
        hass = HomeAssistant()

        class Coordinator:
            data = {"room": 21.5, "unit": "C"}

            def __init__(self):
                self.hass = hass

            def last_value_update_time(self, key):
                return "2026-05-11T10:00:00+00:00" if key == "room" else None

        sensor = RemkoSmartWebSensor(
            Coordinator(),
            "SmartWeb",
            "room",
            "Room Temperature",
            "temperature",
        )

        self.assertEqual(sensor.native_value, 21.5)
        self.assertEqual(
            sensor.extra_state_attributes,
            {"last_successful_value_update": "2026-05-11T10:00:00+00:00"},
        )

    def test_setup_adds_single_diagnostic_sensor_with_dynamic_attributes(self):
        hass = HomeAssistant()
        entry = ConfigEntry()
        client = MutableDiagnosticClient()
        coordinator = types.SimpleNamespace(hass=hass, data={})
        hass.entity_registry = EntityRegistry()
        hass.entity_registry.entities[
            ("sensor", DOMAIN, "smartweb_portal_type")
        ] = "sensor.smartweb_portal_type"
        hass.data = {
            DOMAIN: {
                entry.entry_id: {
                    "coordinator": coordinator,
                    "client": client,
                    "device_name": "SmartWeb",
                    "device_profile": EmptyProfile(),
                }
            }
        }
        entities = []

        asyncio.run(async_setup_entry(hass, entry, entities.extend))

        diagnostic_entities = [
            entity for entity in entities if isinstance(entity, RemkoSmartWebDiagnosticSensor)
        ]
        self.assertEqual(len(diagnostic_entities), 1)
        diagnostics = diagnostic_entities[0]
        self.assertEqual(diagnostics.native_value, "Diagnostics")
        self.assertNotIn("portal_type", diagnostics.extra_state_attributes)
        self.assertEqual(hass.entity_registry.removed, ["sensor.smartweb_portal_type"])

        client.metadata["Portal Type"] = "MXW 204 - 524"

        self.assertEqual(diagnostics.extra_state_attributes["portal_type"], "MXW 204 - 524")
        self.assertIn("portal_type", LEGACY_DIAGNOSTIC_KEYS)


if __name__ == "__main__":
    unittest.main()
