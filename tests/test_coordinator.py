from __future__ import annotations

import asyncio
import json
from collections import deque
from datetime import date, timedelta
import sys
import threading
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
ha_date = types.ModuleType("homeassistant.components.date")
ha_water_heater = types.ModuleType("homeassistant.components.water_heater")
ha_core = types.ModuleType("homeassistant.core")
ha_config_entries = types.ModuleType("homeassistant.config_entries")
ha_helpers = types.ModuleType("homeassistant.helpers")
ha_event = types.ModuleType("homeassistant.helpers.event")
ha_entity = types.ModuleType("homeassistant.helpers.entity")
ha_update_coordinator = types.ModuleType("homeassistant.helpers.update_coordinator")
ha_storage = types.ModuleType("homeassistant.helpers.storage")
ha_const = types.ModuleType("homeassistant.const")
ha_exceptions = types.ModuleType("homeassistant.exceptions")


class WaterHeaterEntity:
    def async_write_ha_state(self):
        self.wrote_state = True


class DateEntity:
    def async_write_ha_state(self):
        self.wrote_state = True


class WaterHeaterEntityFeature:
    TARGET_TEMPERATURE = 1
    OPERATION_MODE = 2


class DataUpdateCoordinator:
    def __class_getitem__(cls, item):
        return cls

    def __init__(self, hass, logger, name, update_interval):
        self.hass = hass
        self.logger = logger
        self.name = name
        self.update_interval = update_interval
        self.data = None

    def async_set_updated_data(self, data):
        self.data = data


class CoordinatorEntity:
    def __init__(self, coordinator):
        self.coordinator = coordinator
        self.hass = coordinator.hass

    def async_write_ha_state(self):
        self.wrote_state = True


class UpdateFailed(Exception):
    pass


class HomeAssistantError(Exception):
    pass


class Store:
    def __init__(self, hass, version, key):
        self.hass = hass
        self.version = version
        self.key = key

    async def async_load(self):
        return None

    async def async_save(self, data):
        return None


class HomeAssistant:
    def __init__(self):
        self.scheduled_callbacks = []

    async def async_add_executor_job(self, func, *args):
        return func(*args)


class ConfigEntry:
    pass


class DeviceInfo(dict):
    pass


class UnitOfTemperature:
    CELSIUS = "C"
    FAHRENHEIT = "F"


def async_call_later(hass, delay, callback):
    hass.scheduled_callbacks.append((delay, callback))
    return None


ha_date.DateEntity = DateEntity
ha_water_heater.WaterHeaterEntity = WaterHeaterEntity
ha_water_heater.WaterHeaterEntityFeature = WaterHeaterEntityFeature
ha_core.HomeAssistant = HomeAssistant
ha_config_entries.ConfigEntry = ConfigEntry
ha_entity.DeviceInfo = DeviceInfo
ha_event.async_call_later = async_call_later
ha_update_coordinator.DataUpdateCoordinator = DataUpdateCoordinator
ha_update_coordinator.CoordinatorEntity = CoordinatorEntity
ha_update_coordinator.UpdateFailed = UpdateFailed
ha_storage.Store = Store
ha_const.ATTR_TEMPERATURE = "temperature"
ha_const.UnitOfTemperature = UnitOfTemperature
ha_exceptions.HomeAssistantError = HomeAssistantError

sys.modules.setdefault("homeassistant", homeassistant)
sys.modules.setdefault("homeassistant.components", ha_components)
sys.modules.setdefault("homeassistant.components.date", ha_date)
sys.modules.setdefault("homeassistant.components.water_heater", ha_water_heater)
sys.modules.setdefault("homeassistant.core", ha_core)
sys.modules.setdefault("homeassistant.config_entries", ha_config_entries)
sys.modules.setdefault("homeassistant.helpers", ha_helpers)
sys.modules.setdefault("homeassistant.helpers.event", ha_event)
sys.modules.setdefault("homeassistant.helpers.entity", ha_entity)
sys.modules.setdefault("homeassistant.helpers.update_coordinator", ha_update_coordinator)
sys.modules.setdefault("homeassistant.helpers.storage", ha_storage)
sys.modules.setdefault("homeassistant.const", ha_const)
sys.modules.setdefault("homeassistant.exceptions", ha_exceptions)

paho = types.ModuleType("paho")
paho_mqtt = types.ModuleType("paho.mqtt")
paho_mqtt_client = types.ModuleType("paho.mqtt.client")
sys.modules.setdefault("paho", paho)
sys.modules.setdefault("paho.mqtt", paho_mqtt)
sys.modules.setdefault("paho.mqtt.client", paho_mqtt_client)

requests = types.ModuleType("requests")
requests.Session = object
sys.modules.setdefault("requests", requests)

import custom_components.remko_smartweb.api as api_module
from custom_components.remko_smartweb.date import RemkoSmartWebVacationEndDate
from custom_components.remko_smartweb.api import (
    RemkoSmartWebClient,
    UnsupportedPayload,
    _MqttSession,
    _build_kwt_set_cmd,
    _build_rbw_set_cmd,
    _smartweb_value_matches,
)
from custom_components.remko_smartweb.coordinator import RemkoSmartWebCoordinator
from custom_components.remko_smartweb.profiles.domestic_hot_water import DomesticHotWaterDeviceProfile
from custom_components.remko_smartweb.profiles.kwt import KwtDeviceProfile
from custom_components.remko_smartweb.water_heater import OPERATION_MODES, RemkoSmartWebWaterHeater


class FailingClient:
    def read_status(self):
        raise UnsupportedPayload("Unable to parse status")

    def initial_status_if_supported(self):
        return None


class BootstrapClient(FailingClient):
    def initial_status_if_supported(self):
        return {"unit": "C", "_status_pending": True}


class SequencedClient:
    def __init__(self, responses):
        self.responses = deque(responses)

    def read_status(self):
        response = self.responses.popleft()
        if isinstance(response, Exception):
            raise response
        return response

    def initial_status_if_supported(self):
        return None


class FakeMqtt:
    def __init__(self, response_values=None):
        self.response_values = response_values
        self.published = []
        self.cleared = False

    def clear_values(self):
        self.cleared = True

    def publish(self, topic, payload):
        self.published.append((topic, payload))

    def wait_values(self, timeout=10):
        return self.response_values

    def wait_rx(self, timeout=10):
        return '{"Rx":"631004500100AA"}'

    def last_smt_user(self):
        return None


class WriteFailureClient:
    def __init__(self):
        self.values = None

    def set_value_ids(self, values):
        self.values = values
        raise UnsupportedPayload("SmartWeb value write was not confirmed")


class CoordinatorTests(unittest.TestCase):
    def test_unsupported_payload_keeps_last_data(self):
        coordinator = RemkoSmartWebCoordinator(
            HomeAssistant(),
            FailingClient(),
            entry_id="entry",
            scan_interval=30,
        )
        coordinator.async_set_updated_data({"dhw_setpoint": 55.0, "unit": "C"})

        data = asyncio.run(coordinator._async_update_data())

        self.assertEqual(data, {"dhw_setpoint": 55.0, "unit": "C"})

    def test_unsupported_payload_without_last_data_still_fails_refresh(self):
        coordinator = RemkoSmartWebCoordinator(
            HomeAssistant(),
            FailingClient(),
            entry_id="entry",
            scan_interval=30,
        )

        with self.assertRaises(UpdateFailed):
            asyncio.run(coordinator._async_update_data())

    def test_unsupported_payload_can_start_with_pending_initial_data(self):
        coordinator = RemkoSmartWebCoordinator(
            HomeAssistant(),
            BootstrapClient(),
            entry_id="entry",
            scan_interval=30,
        )

        data = asyncio.run(coordinator._async_update_data())

        self.assertEqual(data, {"unit": "C", "_status_pending": True})

    def test_tracks_last_successful_value_update_per_changed_field(self):
        coordinator = RemkoSmartWebCoordinator(
            HomeAssistant(),
            SequencedClient(
                [
                    {"room": 21.0, "setpoint": 22.0, "unit": "C"},
                    {"room": 21.0, "setpoint": 23.0, "unit": "C"},
                    {"room": None, "setpoint": 23.0, "unit": "C"},
                ]
            ),
            entry_id="entry",
            scan_interval=30,
        )

        first = asyncio.run(coordinator._async_update_data())
        coordinator.async_set_updated_data(first)
        first_room_update = coordinator.last_value_update_time("room")
        first_setpoint_update = coordinator.last_value_update_time("setpoint")

        second = asyncio.run(coordinator._async_update_data())
        coordinator.async_set_updated_data(second)
        second_room_update = coordinator.last_value_update_time("room")
        second_setpoint_update = coordinator.last_value_update_time("setpoint")

        third = asyncio.run(coordinator._async_update_data())
        coordinator.async_set_updated_data(third)

        self.assertIsNotNone(first_room_update)
        self.assertEqual(second_room_update, first_room_update)
        self.assertNotEqual(second_setpoint_update, first_setpoint_update)
        self.assertEqual(third["room"], 21.0)
        self.assertEqual(coordinator.last_value_update_time("room"), first_room_update)
        self.assertEqual(coordinator.last_value_update_time("setpoint"), second_setpoint_update)

    def test_partial_status_keeps_missing_previous_values(self):
        coordinator = RemkoSmartWebCoordinator(
            HomeAssistant(),
            SequencedClient(
                [
                    {"room": 21.0, "setpoint": 22.0, "mode": "heat", "unit": "C"},
                    {"setpoint": 23.0, "room": None, "unit": "C"},
                ]
            ),
            entry_id="entry",
            scan_interval=30,
        )

        first = asyncio.run(coordinator._async_update_data())
        coordinator.async_set_updated_data(first)
        room_update = coordinator.last_value_update_time("room")

        second = asyncio.run(coordinator._async_update_data())
        coordinator.async_set_updated_data(second)

        self.assertEqual(
            second,
            {"room": 21.0, "setpoint": 23.0, "mode": "heat", "unit": "C"},
        )
        self.assertEqual(coordinator.last_value_update_time("room"), room_update)

    def test_mqtt_session_ignores_client2host_value_echo_as_status(self):
        session = _MqttSession.__new__(_MqttSession)
        session._lock = threading.Lock()
        session._cond = threading.Condition(session._lock)
        session._last_rx = None
        session._last_values = None
        session._last_seen_values = None
        session._last_tx_echo = None
        session._last_smt_user = None
        session._recent_messages = deque(maxlen=20)
        session._received_non_tx_count = 0

        session._on_message(
            None,
            None,
            types.SimpleNamespace(
                topic="V04P27/ABC/CLIENT2HOST",
                payload=b'{"values":{"1333":"022B"}}',
            ),
        )
        self.assertIsNone(session._last_values)
        self.assertIsNone(session.last_smt_user())

        session._on_message(
            None,
            None,
            types.SimpleNamespace(
                topic="V04P27/ABC/HOST2CLIENT",
                payload=b'{"SMT_USER":12345,"values":{"1333":"0226"}}',
            ),
        )
        self.assertEqual(session._last_values, {"1333": "0226"})
        self.assertEqual(session.last_smt_user(), 12345)

    def test_mqtt_session_handles_double_encoded_rx_payload(self):
        session = _MqttSession.__new__(_MqttSession)
        session._lock = threading.Lock()
        session._cond = threading.Condition(session._lock)
        session._last_rx = None
        session._last_values = None
        session._last_seen_values = None
        session._last_tx_echo = None
        session._last_smt_user = None
        session._recent_messages = deque(maxlen=20)
        session._received_non_tx_count = 0

        session._on_message(
            None,
            None,
            types.SimpleNamespace(
                topic="V04P27/ABC/RESP",
                payload=b'"{\\"Rx\\":\\"63100450000108aa\\"}"',
            ),
        )

        self.assertEqual(session._last_rx, '{"Rx": "63100450000108aa"}')

    def test_smartweb_value_confirmation_allows_left_padded_hex_values(self):
        self.assertTrue(_smartweb_value_matches("09", "00000000000000000009"))
        self.assertTrue(_smartweb_value_matches("01", "00000000000000000001"))
        self.assertTrue(_smartweb_value_matches("022B", "0000000000000000022B"))
        self.assertFalse(_smartweb_value_matches("022B", "0226"))
        self.assertFalse(_smartweb_value_matches("09", None))

    def test_mqtt_write_values_uses_full_status_query_list(self):
        client = RemkoSmartWebClient.__new__(RemkoSmartWebClient)
        client.sid = "0123456789ABCDEF"
        client.sk = "FEDCBA9876543210"
        client.topic = "V04P27/0123456789ABCDEF"
        client.smt_user = 12345
        client.device_name = "DHW"
        client._mqtt = FakeMqtt({"1333": "022B"})
        client._ensure_mqtt = lambda: None

        response = client._mqtt_write_values({"1333": "022B"}, timeout=1)

        self.assertEqual(response, {"1333": "022B"})
        self.assertTrue(client._mqtt.cleared)
        topic, payload = client._mqtt.published[0]
        self.assertEqual(topic, "V04P27/0123456789ABCDEF/CLIENT2HOST")
        self.assertEqual(payload["values"], {"1333": "022B"})
        self.assertIn(1333, payload["query_list"])
        self.assertGreater(len(payload["query_list"]), 1)
        self.assertEqual(payload["SMT_USER"], 12345)
        self.assertTrue(payload["CLIENT_ID"].startswith("SMT"))
        self.assertIn("0123456789ABCDEF", payload["CLIENT_ID"])

    def test_dhw_value_write_uses_rbw_esp_tx_before_client2host_fallback(self):
        client = RemkoSmartWebClient.__new__(RemkoSmartWebClient)
        client.sid = "0123456789ABCDEF"
        client.sk = "FEDCBA9876543210"
        client.topic = "V04P27/0123456789ABCDEF"
        client.smt_user = 12345
        client.device_name = "DHW"
        client.profile = DomesticHotWaterDeviceProfile()
        client._mqtt = FakeMqtt()
        client._ensure_login = lambda: None
        client._ensure_device = lambda: None
        client._ensure_mqtt = lambda: None
        client.read_status = lambda: {"dhw_setpoint": 55.0, "unit": "C"}

        client.set_value_ids({"1333": "0226"})

        topic, payload = client._mqtt.published[0]
        self.assertEqual(topic, "V04P27/0123456789ABCDEF/ESP")
        self.assertEqual(payload, {"Tx": _build_rbw_set_cmd("1333", "0226"), "CLIENT_ID": "SMTACUARTTEST"})

    def test_kwt_value_write_uses_esp_tx_before_client2host_fallback(self):
        client = RemkoSmartWebClient.__new__(RemkoSmartWebClient)
        client.sid = "0123456789ABCDEF"
        client.sk = "FEDCBA9876543210"
        client.topic = "V04P27/0123456789ABCDEF"
        client.smt_user = 12345
        client.device_name = "KWT"
        client.profile = KwtDeviceProfile()
        client._mqtt = FakeMqtt()
        client._ensure_login = lambda: None
        client._ensure_device = lambda: None
        client._ensure_mqtt = lambda: None
        client.read_status = lambda: {"setpoint": 21.5, "unit": "C"}

        client.set_value_ids({"1190": "2B"})

        topic, payload = client._mqtt.published[0]
        self.assertEqual(topic, "V04P27/0123456789ABCDEF/ESP")
        self.assertEqual(payload, {"Tx": _build_kwt_set_cmd("1190", "2B"), "CLIENT_ID": "SMTACUARTTEST"})

    def test_resolve_device_force_list_skips_stored_device_path(self):
        client = RemkoSmartWebClient.__new__(RemkoSmartWebClient)
        client.device_name = "DHW"
        client.device_path = "/stale-device"
        client._ensure_login = lambda: None
        force_flags = []
        resolved_paths = []

        def _fetch_device_name_map(retries=3, force=False):
            force_flags.append(force)
            return {"/fresh-device": "DHW"}

        def _resolve_device_rel(rel):
            resolved_paths.append(rel)

        client._fetch_device_name_map = _fetch_device_name_map
        client._find_device_rel = RemkoSmartWebClient._find_device_rel.__get__(
            client,
            RemkoSmartWebClient,
        )
        client._resolve_device_rel = _resolve_device_rel

        client.resolve_device(force_list=True)

        self.assertEqual(force_flags, [True])
        self.assertEqual(resolved_paths, ["/fresh-device"])

    def test_set_value_ids_rejects_unconfirmed_readback_value(self):
        client = RemkoSmartWebClient.__new__(RemkoSmartWebClient)
        client.device_name = "DHW"
        client.profile = DomesticHotWaterDeviceProfile()
        client._ensure_login = lambda: None
        client._ensure_device = lambda: None
        client._ensure_mqtt = lambda: None
        client._mqtt_write_rbw_esp_values = lambda values, timeout=10, write_id=None: False
        client._mqtt_write_values = lambda values, timeout=10, write_id=None: {"1333": "0226"}
        client._log_mapping_snapshot = lambda *args, **kwargs: None
        client.read_status = lambda: {"dhw_setpoint": 55.0, "unit": "C"}

        original_sleep = api_module.time.sleep
        api_module.time.sleep = lambda _seconds: None
        try:
            with self.assertRaises(UnsupportedPayload):
                client.set_value_ids({"1333": "022B"})
        finally:
            api_module.time.sleep = original_sleep

    def test_dhw_esp_write_does_not_fallback_on_cached_readback_mismatch(self):
        client = RemkoSmartWebClient.__new__(RemkoSmartWebClient)
        client.device_name = "DHW"
        client.profile = DomesticHotWaterDeviceProfile()
        client._ensure_login = lambda: None
        client._ensure_device = lambda: None
        client._ensure_mqtt = lambda: None
        client._mqtt_write_rbw_esp_values = lambda values, timeout=10, write_id=None: True
        client._mqtt_write_values_called = False

        def _mqtt_write_values(values, timeout=10, write_id=None):
            client._mqtt_write_values_called = True
            return {"1333": "0226"}

        def _read_status():
            client._last_status_source = "cached_last_status"
            return {"dhw_setpoint": 55.0, "unit": "C"}

        client._mqtt_write_values = _mqtt_write_values
        client.read_status = _read_status

        original_sleep = api_module.time.sleep
        api_module.time.sleep = lambda _seconds: None
        try:
            client.set_value_ids({"1333": "0230"})
        finally:
            api_module.time.sleep = original_sleep

        self.assertFalse(client._mqtt_write_values_called)

    def test_water_heater_rolls_back_optimistic_state_on_failed_write(self):
        hass = HomeAssistant()
        coordinator = types.SimpleNamespace(
            hass=hass,
            data={
                "dhw_setpoint": 55.0,
                "setpoint": 55.0,
                "dhw_top_temperature": 55.0,
                "power": "ON",
                "unit": "C",
            },
            async_request_refresh=lambda: None,
        )
        client = WriteFailureClient()
        entity = RemkoSmartWebWaterHeater(
            coordinator,
            client,
            "WIFI Stick - Brauchwasserwaermepumpe",
            DomesticHotWaterDeviceProfile(),
        )

        self.assertEqual(entity._attr_target_temperature_step, 0.5)
        self.assertEqual(entity._attr_translation_key, "domestic_hot_water")

        with self.assertRaises(HomeAssistantError):
            asyncio.run(entity.async_set_temperature(temperature=55.5))

        self.assertEqual(
            coordinator.data,
            {
                "dhw_setpoint": 55.0,
                "setpoint": 55.0,
                "dhw_top_temperature": 55.0,
                "power": "ON",
                "unit": "C",
            },
        )
        self.assertEqual(client.values, {"1333": "022B"})
        self.assertEqual(len(hass.scheduled_callbacks), 1)

    def test_water_heater_vacation_mode_requires_end_date(self):
        hass = HomeAssistant()
        coordinator = types.SimpleNamespace(
            hass=hass,
            data={
                "dhw_setpoint": 55.0,
                "power": "ON",
                "unit": "C",
            },
            async_request_refresh=lambda: None,
        )
        entity = RemkoSmartWebWaterHeater(
            coordinator,
            WriteFailureClient(),
            "WIFI Stick - Brauchwasserwaermepumpe",
            DomesticHotWaterDeviceProfile(),
        )

        with self.assertRaises(HomeAssistantError):
            asyncio.run(entity.async_set_operation_mode("vacation"))

    def test_water_heater_vacation_mode_writes_end_date_before_mode(self):
        hass = HomeAssistant()
        coordinator = types.SimpleNamespace(
            hass=hass,
            data={
                "dhw_vacation_end_date": "2026-05-27",
                "power": "ON",
                "unit": "C",
            },
            async_request_refresh=lambda: None,
        )

        class Client:
            def set_value_ids(self, values):
                self.values = values

        client = Client()
        entity = RemkoSmartWebWaterHeater(
            coordinator,
            client,
            "WIFI Stick - Brauchwasserwaermepumpe",
            DomesticHotWaterDeviceProfile(),
        )

        asyncio.run(entity.async_set_operation_mode("vacation"))

        self.assertEqual(list(client.values), [
            "rbw_register:1129",
            "rbw_register:1130",
            "rbw_register:1131",
            "rbw_register:1132",
            "1194",
            "1192",
        ])
        self.assertEqual(client.values["1192"], "0C")

    def test_vacation_end_date_entity_writes_rbw_registers(self):
        hass = HomeAssistant()
        coordinator = types.SimpleNamespace(
            hass=hass,
            data={"unit": "C"},
            async_request_refresh=lambda: None,
        )

        class Client:
            def set_value_ids(self, values):
                self.values = values

        client = Client()
        entity = RemkoSmartWebVacationEndDate(
            coordinator,
            client,
            "WIFI Stick - Brauchwasserwaermepumpe",
            DomesticHotWaterDeviceProfile(),
        )

        vacation_end_date = date.today() + timedelta(days=15)
        asyncio.run(entity.async_set_value(vacation_end_date))

        self.assertEqual(entity.native_min_value, date.today())
        self.assertEqual(entity.native_value, vacation_end_date)
        self.assertEqual(
            client.values,
            {
                "rbw_register:1129": "0001",
                "rbw_register:1130": f"{vacation_end_date.year % 100:04X}",
                "rbw_register:1131": f"{vacation_end_date.month:04X}",
                "rbw_register:1132": f"{vacation_end_date.day:04X}",
            },
        )
        self.assertEqual(len(hass.scheduled_callbacks), 1)

    def test_vacation_end_date_entity_allows_today_and_rejects_past_dates(self):
        hass = HomeAssistant()
        coordinator = types.SimpleNamespace(
            hass=hass,
            data={"unit": "C"},
            async_request_refresh=lambda: None,
        )

        class Client:
            def set_value_ids(self, values):
                self.values = values

        client = Client()
        entity = RemkoSmartWebVacationEndDate(
            coordinator,
            client,
            "WIFI Stick - Brauchwasserwaermepumpe",
            DomesticHotWaterDeviceProfile(),
        )

        asyncio.run(entity.async_set_value(date.today()))

        self.assertEqual(entity.native_value, date.today())
        self.assertEqual(client.values["rbw_register:1132"], f"{date.today().day:04X}")

        with self.assertRaises(HomeAssistantError):
            asyncio.run(entity.async_set_value(date.today() - timedelta(days=1)))

        self.assertEqual(coordinator.data["dhw_vacation_end_date"], date.today().isoformat())
        self.assertEqual(len(hass.scheduled_callbacks), 1)

    def test_water_heater_vacation_mode_allows_today_end_date(self):
        hass = HomeAssistant()
        coordinator = types.SimpleNamespace(
            hass=hass,
            data={
                "dhw_vacation_end_date": date.today().isoformat(),
                "power": "ON",
                "unit": "C",
            },
            async_request_refresh=lambda: None,
        )

        class Client:
            def set_value_ids(self, values):
                self.values = values

        client = Client()
        entity = RemkoSmartWebWaterHeater(
            coordinator,
            client,
            "WIFI Stick - Brauchwasserwaermepumpe",
            DomesticHotWaterDeviceProfile(),
        )

        asyncio.run(entity.async_set_operation_mode("vacation"))

        self.assertEqual(client.values["1192"], "0C")

    def test_water_heater_vacation_mode_rejects_past_end_date(self):
        hass = HomeAssistant()
        coordinator = types.SimpleNamespace(
            hass=hass,
            data={
                "dhw_vacation_end_date": (date.today() - timedelta(days=1)).isoformat(),
                "power": "ON",
                "unit": "C",
            },
            async_request_refresh=lambda: None,
        )

        class Client:
            def set_value_ids(self, values):
                self.values = values

        client = Client()
        entity = RemkoSmartWebWaterHeater(
            coordinator,
            client,
            "WIFI Stick - Brauchwasserwaermepumpe",
            DomesticHotWaterDeviceProfile(),
        )

        with self.assertRaises(HomeAssistantError):
            asyncio.run(entity.async_set_operation_mode("vacation"))

        self.assertFalse(hasattr(client, "values"))

    def test_water_heater_operation_modes_have_german_translations(self):
        translations = json.loads(
            (COMPONENT_PATH / "translations" / "de.json").read_text(encoding="utf-8")
        )

        mode_translations = translations["entity"]["water_heater"]["domestic_hot_water"]["state"]

        self.assertEqual(set(mode_translations), set(OPERATION_MODES))
        self.assertEqual(mode_translations["speed_heating"], "Schnellheizen")
        self.assertEqual(mode_translations["vacation"], "Urlaub")


if __name__ == "__main__":
    unittest.main()
