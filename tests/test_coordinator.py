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
ha_climate = types.ModuleType("homeassistant.components.climate")
ha_climate_const = types.ModuleType("homeassistant.components.climate.const")
ha_date = types.ModuleType("homeassistant.components.date")
ha_switch = types.ModuleType("homeassistant.components.switch")
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


class ClimateEntity:
    def async_write_ha_state(self):
        self.wrote_state = True


class SwitchEntity:
    def async_write_ha_state(self):
        self.wrote_state = True


class ClimateEntityFeature:
    TARGET_TEMPERATURE = 1
    FAN_MODE = 2
    SWING_MODE = 4
    TURN_ON = 8
    TURN_OFF = 16
    PRESET_MODE = 32


class HVACMode:
    OFF = "off"
    AUTO = "auto"
    COOL = "cool"
    HEAT = "heat"
    DRY = "dry"
    FAN_ONLY = "fan_only"


class HVACAction:
    OFF = "off"
    COOLING = "cooling"
    HEATING = "heating"
    DRYING = "drying"
    FAN = "fan"
    IDLE = "idle"


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
        self.config_entries = types.SimpleNamespace(async_update_entry=self.async_update_entry)
        self.updated_entries = []

    async def async_add_executor_job(self, func, *args):
        return func(*args)

    def async_update_entry(self, entry, **kwargs):
        self.updated_entries.append((entry, kwargs))
        if "options" in kwargs:
            entry.options = kwargs["options"]


class ConfigEntry:
    def __init__(self, options=None):
        self.options = options or {}


class DeviceInfo(dict):
    pass


class UnitOfTemperature:
    CELSIUS = "C"
    FAHRENHEIT = "F"


def async_call_later(hass, delay, callback):
    hass.scheduled_callbacks.append((delay, callback))
    return None


ha_date.DateEntity = DateEntity
ha_climate.ClimateEntity = ClimateEntity
ha_climate_const.HVACMode = HVACMode
ha_climate_const.HVACAction = HVACAction
ha_climate_const.ClimateEntityFeature = ClimateEntityFeature
ha_switch.SwitchEntity = SwitchEntity
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
sys.modules.setdefault("homeassistant.components.climate", ha_climate)
sys.modules.setdefault("homeassistant.components.climate.const", ha_climate_const)
sys.modules.setdefault("homeassistant.components.date", ha_date)
sys.modules.setdefault("homeassistant.components.switch", ha_switch)
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
import custom_components.remko_smartweb.client as client_module
from custom_components.remko_smartweb.date import RemkoSmartWebVacationEndDate
from custom_components.remko_smartweb.api import (
    RemkoSmartWebAccount,
    RemkoSmartWebClient,
    SMARTWEB_USER_AGENT,
    UnsupportedPayload,
    _MqttSession,
    _build_kwt_set_cmd,
    _build_rbw_set_cmd,
    _smartweb_value_matches,
)
from custom_components.remko_smartweb.coordinator import RemkoSmartWebCoordinator
from custom_components.remko_smartweb.climate import RemkoSmartWebClimate
from custom_components.remko_smartweb.switch import RemkoSmartWebSwitch, _should_add_switch
from custom_components.remko_smartweb.profiles.climate import ClimateDeviceProfile
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


class CachedStatusClient:
    def __init__(self, response):
        self.response = response
        self._last_status_source = None

    def read_status(self):
        self._last_status_source = "cached_last_status"
        return self.response

    def initial_status_if_supported(self):
        return None


class FakeMqtt:
    def __init__(self, response_values=None):
        self.response_values = response_values
        self.published = []
        self.cleared = False
        self.local_portal = False
        self.local_host2portal_mode = False

    def clear_values(self):
        self.cleared = True

    def clear_rx(self):
        self.cleared = True

    def publish(self, topic, payload):
        self.published.append((topic, payload))

    def wait_values(self, timeout=10):
        return self.response_values

    def wait_rx(self, timeout=10):
        return '{"Rx":"631004500100AA"}'

    def last_smt_user(self):
        return None

    def queue_set(self, tx):
        raise AssertionError("cloud writes must not wait for CLIENT2HOST")

    def wait_set_executed(self, timeout=10):
        raise AssertionError("cloud writes must not wait for CLIENT2HOST")


class WriteFailureClient:
    def __init__(self):
        self.values = None

    def set_value_ids(self, values):
        self.values = values
        raise UnsupportedPayload("SmartWeb value write was not confirmed")


class FakeResponse:
    def raise_for_status(self):
        return None


class FakeCookies:
    def get_dict(self):
        return {"PHPSESSID": "test-session"}


class FakeRequestsSession:
    def __init__(self):
        self.calls = []
        self.cookies = FakeCookies()
        self.headers = {}

    def post(self, url, **kwargs):
        self.calls.append(("post", url, kwargs))
        return FakeResponse()


class ClimateWriteClient:
    uses_local_mqtt = False

    def __init__(self, set_values_error=None):
        self.value_writes = []
        self.state_writes = []
        self.set_values_error = set_values_error
        self.primed_status = None

    def set_value_ids(self, values):
        self.value_writes.append(values)

    def set_values(self, overrides):
        if self.set_values_error is not None:
            raise self.set_values_error
        self.state_writes.append(overrides)

    def prime_status_cache(self, status):
        self.primed_status = status


class CoordinatorTests(unittest.TestCase):
    def test_smartweb_account_uses_browser_user_agent_for_session_and_login(self):
        account_module = sys.modules["custom_components.remko_smartweb._account"]
        original_session = account_module.requests.Session
        try:
            account_module.requests.Session = FakeRequestsSession
            account = RemkoSmartWebAccount("user@example.com", "secret")
            self.assertEqual(account.session.headers["User-Agent"], SMARTWEB_USER_AGENT)

            account.login()

            _, _, kwargs = account.session.calls[0]
            headers = kwargs["headers"]
            self.assertEqual(headers["User-Agent"], SMARTWEB_USER_AGENT)
            self.assertNotEqual(headers["User-Agent"], "Home Assistant")
            self.assertIn("Mozilla/5.0", headers["User-Agent"])
        finally:
            account_module.requests.Session = original_session

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

    def test_cached_status_does_not_overwrite_current_coordinator_state(self):
        coordinator = RemkoSmartWebCoordinator(
            HomeAssistant(),
            CachedStatusClient({"dhw_mode": "eco", "mode": "eco", "power": "ON", "unit": "C"}),
            entry_id="entry",
            scan_interval=30,
        )
        coordinator.async_set_updated_data(
            {"dhw_mode": "vacation", "mode": "vacation", "power": "ON", "unit": "C"}
        )

        data = asyncio.run(coordinator._async_update_data())

        self.assertEqual(
            data,
            {"dhw_mode": "vacation", "mode": "vacation", "power": "ON", "unit": "C"},
        )

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

    def test_mqtt_session_accepts_portal2client_values_like_frontend(self):
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
                topic="V04P27/ABC/PORTAL2CLIENT",
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

    def test_mqtt_session_dispatches_pending_set_without_immediate_status(self):
        class FakeMqttClient:
            def __init__(self):
                self.published = []

            def publish(self, topic, payload, qos=0, retain=False):
                self.published.append((topic, json.loads(payload), qos, retain))

        session = _MqttSession.__new__(_MqttSession)
        session.topic = "V04P27/ABC"
        session.client = FakeMqttClient()
        session._lock = threading.Lock()
        session._cond = threading.Condition(session._lock)
        session._last_rx = None
        session._last_values = None
        session._last_seen_values = None
        session._last_tx_echo = None
        session._last_smt_user = None
        session._last_c2h_time = None
        session._no_c2h_warned = False
        session._local_portal = True
        session._local_host2portal_mode = False
        session._recent_messages = deque(maxlen=20)
        session._received_non_tx_count = 0
        session._pending_set_tx = "AABBCC"
        session._pending_set_done = threading.Event()

        session._on_message(
            None,
            None,
            types.SimpleNamespace(
                topic="V04P27/ABC/CLIENT2HOST",
                payload=b'{"CLIENT_ID":"client","query_list":[1194]}',
            ),
        )

        self.assertEqual(len(session.client.published), 2)
        self.assertEqual(session.client.published[0][0], "V04P27/ABC/HOST2CLIENT")
        self.assertEqual(session.client.published[1][0], "V04P27/ABC/ESP")
        self.assertEqual(session.client.published[1][1]["Tx"], "AABBCC")
        self.assertTrue(session._pending_set_done.is_set())
        self.assertIsNone(session._pending_set_tx)

    def test_mqtt_session_refreshes_status_when_no_pending_set(self):
        class FakeMqttClient:
            def __init__(self):
                self.published = []

            def publish(self, topic, payload, qos=0, retain=False):
                self.published.append((topic, json.loads(payload), qos, retain))

        session = _MqttSession.__new__(_MqttSession)
        session.topic = "V04P27/ABC"
        session.client = FakeMqttClient()
        session._lock = threading.Lock()
        session._cond = threading.Condition(session._lock)
        session._last_rx = None
        session._last_values = None
        session._last_seen_values = None
        session._last_tx_echo = None
        session._last_smt_user = None
        session._last_c2h_time = None
        session._no_c2h_warned = False
        session._local_portal = True
        session._local_host2portal_mode = False
        session._recent_messages = deque(maxlen=20)
        session._received_non_tx_count = 0
        session._pending_set_tx = None
        session._pending_set_done = threading.Event()

        session._on_message(
            None,
            None,
            types.SimpleNamespace(
                topic="V04P27/ABC/CLIENT2HOST",
                payload=b'{"CLIENT_ID":"client","query_list":[1194]}',
            ),
        )

        self.assertEqual(len(session.client.published), 2)
        self.assertEqual(session.client.published[0][0], "V04P27/ABC/HOST2CLIENT")
        self.assertEqual(session.client.published[1][0], "V04P27/ABC/ESP")
        self.assertNotEqual(session.client.published[1][1]["Tx"], "AABBCC")

    def test_mqtt_session_does_not_answer_cloud_client2host_polls(self):
        class FakeMqttClient:
            def __init__(self):
                self.published = []

            def publish(self, topic, payload, qos=0, retain=False):
                self.published.append((topic, json.loads(payload), qos, retain))

        session = _MqttSession.__new__(_MqttSession)
        session.topic = "V04P27/ABC"
        session.client = FakeMqttClient()
        session._lock = threading.Lock()
        session._cond = threading.Condition(session._lock)
        session._last_rx = None
        session._last_values = None
        session._last_seen_values = None
        session._last_tx_echo = None
        session._last_smt_user = None
        session._last_c2h_time = None
        session._no_c2h_warned = False
        session._local_portal = False
        session._local_host2portal_mode = False
        session._command_topic = None
        session._recent_messages = deque(maxlen=20)
        session._received_non_tx_count = 0
        session._pending_set_tx = None
        session._pending_set_done = threading.Event()

        session._on_message(
            None,
            None,
            types.SimpleNamespace(
                topic="V04P27/ABC/CLIENT2HOST",
                payload=b'{"CLIENT_ID":"browser","query_list":[1194]}',
            ),
        )

        self.assertEqual(session.client.published, [])

    def test_mqtt_session_cloud_subscriptions_include_portal_response_topics(self):
        class FakeMqttClient:
            def __init__(self):
                self.subscriptions = None

            def subscribe(self, subscriptions):
                self.subscriptions = subscriptions

        session = _MqttSession.__new__(_MqttSession)
        session.topic = "V04P27/ABC"
        session._lock = threading.Lock()
        session._connected = threading.Event()
        session._closed = False
        session._local_portal = False
        session._local_host2portal_mode = False
        session._subscribed_topics = []
        session._command_topic = None
        client = FakeMqttClient()

        session._on_connect(client, None, None, 0)

        self.assertEqual(
            [topic for topic, _qos in client.subscriptions],
            [
                "V04P27/ABC/HOST2CLIENT",
                "V04P27/ABC/PORTAL2CLIENT",
                "V04P27/ABC/RESP",
                "V04P27/ABC/ESP",
                "V04P27/ABC/CLIENT2HOST",
            ],
        )

    def test_mqtt_session_local_host2portal_subscriptions_include_client2host(self):
        class FakeMqttClient:
            def __init__(self):
                self.subscriptions = None

            def subscribe(self, subscriptions):
                self.subscriptions = subscriptions

        session = _MqttSession.__new__(_MqttSession)
        session.topic = "V04P27/SMTABC"
        session._lock = threading.Lock()
        session._connected = threading.Event()
        session._closed = False
        session._local_portal = True
        session._local_host2portal_mode = True
        session._subscribed_topics = []
        session._command_topic = None
        client = FakeMqttClient()

        session._on_connect(client, None, None, 0)

        topics = [topic for topic, _qos in client.subscriptions]
        self.assertIn("V04P27/SMTABC/HOST2PORTAL", topics)
        self.assertIn("V04P27/SMTABC/PORTAL2HOST", topics)
        self.assertIn("V04P27/SMTABC/CLIENT2HOST", topics)

    def test_mqtt_session_local_command_topic_subscribes_sid_responses(self):
        class FakeMqttClient:
            def __init__(self):
                self.subscriptions = None

            def subscribe(self, subscriptions):
                self.subscriptions = subscriptions

        session = _MqttSession.__new__(_MqttSession)
        session.topic = "V04P27/SMTABC"
        session._command_topic = "V04P27/SIDABC"
        session._lock = threading.Lock()
        session._connected = threading.Event()
        session._closed = False
        session._local_portal = True
        session._local_host2portal_mode = True
        session._subscribed_topics = []
        client = FakeMqttClient()

        session._on_connect(client, None, None, 0)

        topics = [topic for topic, _qos in client.subscriptions]
        self.assertIn("V04P27/SMTABC/HOST2PORTAL", topics)
        self.assertIn("V04P27/SIDABC/RESP", topics)
        self.assertIn("V04P27/SIDABC/ESP", topics)
        self.assertIn("V04P27/SIDABC/HOST2CLIENT", topics)

    def test_mqtt_session_records_failed_connack_for_diagnostics(self):
        session = _MqttSession.__new__(_MqttSession)
        session.topic = "V04P27/SMTABC"
        session._lock = threading.Lock()
        session._cond = threading.Condition(session._lock)
        session._connected = threading.Event()
        session._closed = False
        session._recent_messages = deque(maxlen=20)
        session._last_tx_echo = None
        session._last_seen_values = None
        session._received_non_tx_count = 0
        session._subscribed_topics = []
        session._local_portal = True
        session._local_host2portal_mode = True
        session._last_c2h_time = 0
        session._pending_set_tx = None

        session._on_connect(None, None, None, 5)

        snapshot = session.diagnostic_snapshot()
        self.assertTrue(session._connected.is_set())
        self.assertTrue(session._closed)
        self.assertEqual(snapshot["last_connack_rc"], 5)
        self.assertFalse(snapshot["mqtt_connected"])

    def test_mqtt_session_local_host2portal_answers_client2host_polls(self):
        class FakeMqttClient:
            def __init__(self):
                self.published = []

            def publish(self, topic, payload, qos=0, retain=False):
                self.published.append((topic, json.loads(payload), qos, retain))

        session = _MqttSession.__new__(_MqttSession)
        session.topic = "V04P27/SMTABC"
        session.client = FakeMqttClient()
        session._lock = threading.Lock()
        session._cond = threading.Condition(session._lock)
        session._last_rx = None
        session._last_values = None
        session._last_seen_values = None
        session._last_tx_echo = None
        session._last_smt_user = None
        session._last_c2h_time = None
        session._no_c2h_warned = False
        session._local_portal = True
        session._local_host2portal_mode = True
        session._command_topic = None
        session._recent_messages = deque(maxlen=20)
        session._received_non_tx_count = 0
        session._pending_set_tx = "AABBCC"
        session._pending_set_done = threading.Event()

        session._on_message(
            None,
            None,
            types.SimpleNamespace(
                topic="V04P27/SMTABC/CLIENT2HOST",
                payload=b'{"CLIENT_ID":"stick","query_list":[1194]}',
            ),
        )

        self.assertEqual(len(session.client.published), 2)
        self.assertEqual(session.client.published[0][0], "V04P27/SMTABC/HOST2CLIENT")
        self.assertEqual(session.client.published[1][0], "V04P27/SMTABC/ESP")
        self.assertEqual(session.client.published[1][1]["Tx"], "AABBCC")
        self.assertTrue(session._pending_set_done.is_set())
        self.assertIsNone(session._pending_set_tx)

    def test_mqtt_session_local_pending_set_uses_command_topic(self):
        class FakeMqttClient:
            def __init__(self):
                self.published = []

            def publish(self, topic, payload, qos=0, retain=False):
                self.published.append((topic, json.loads(payload), qos, retain))

        session = _MqttSession.__new__(_MqttSession)
        session.topic = "V04P27/SMTABC"
        session._command_topic = "V04P27/SIDABC"
        session.client = FakeMqttClient()
        session._lock = threading.Lock()
        session._cond = threading.Condition(session._lock)
        session._last_rx = None
        session._last_values = None
        session._last_seen_values = None
        session._last_tx_echo = None
        session._last_smt_user = None
        session._last_c2h_time = None
        session._no_c2h_warned = False
        session._local_portal = True
        session._local_host2portal_mode = True
        session._recent_messages = deque(maxlen=20)
        session._received_non_tx_count = 0
        session._pending_set_tx = "AABBCC"
        session._pending_set_done = threading.Event()

        session._on_message(
            None,
            None,
            types.SimpleNamespace(
                topic="V04P27/SMTABC/CLIENT2HOST",
                payload=b'{"CLIENT_ID":"stick","query_list":[1194]}',
            ),
        )

        self.assertEqual(session.client.published[1][0], "V04P27/SIDABC/ESP")
        self.assertEqual(session.client.published[1][1]["Tx"], "AABBCC")

    def test_mqtt_session_local_host2portal_answers_with_empty_wsid(self):
        class FakeMqttClient:
            def __init__(self):
                self.published = []

            def publish(self, topic, payload, qos=0, retain=False):
                self.published.append((topic, json.loads(payload), qos, retain))

        session = _MqttSession.__new__(_MqttSession)
        session.topic = "V04P27/SMTABC"
        session._command_topic = "V04P27/SIDABC"
        session.client = FakeMqttClient()
        session._lock = threading.Lock()
        session._cond = threading.Condition(session._lock)
        session._last_rx = None
        session._last_values = None
        session._last_seen_values = None
        session._last_tx_echo = None
        session._last_smt_user = None
        session._last_c2h_time = None
        session._no_c2h_warned = False
        session._local_portal = True
        session._local_host2portal_mode = True
        session._recent_messages = deque(maxlen=20)
        session._received_non_tx_count = 0
        session._pending_set_tx = None
        session._pending_set_done = threading.Event()

        session._on_message(
            None,
            None,
            types.SimpleNamespace(
                topic="V04P27/SMTABC/HOST2PORTAL",
                payload=b'{"SMT_ID":"SIDABC","SMT_MAC":"ABC","SMT_DEV":"256"}',
            ),
        )

        self.assertEqual(
            session.client.published,
            [("V04P27/SMTABC/PORTAL2HOST", {"WSID": ""}, 0, False)],
        )

    def test_smartweb_value_confirmation_allows_left_padded_hex_values(self):
        self.assertTrue(_smartweb_value_matches("09", "00000000000000000009"))
        self.assertTrue(_smartweb_value_matches("01", "00000000000000000001"))
        self.assertTrue(_smartweb_value_matches("022B", "0000000000000000022B"))
        self.assertFalse(_smartweb_value_matches("022B", "0226"))
        self.assertFalse(_smartweb_value_matches("09", None))

    def test_cloud_mqtt_write_values_matches_main_client_id_and_query(self):
        client = RemkoSmartWebClient.__new__(RemkoSmartWebClient)
        client.sid = "0123456789ABCDEF"
        client.sk = "FEDCBA9876543210"
        client.topic = "V04P27/0123456789ABCDEF"
        client.smt_user = 12345
        client.device_name = "DHW"
        client._local_mqtt_host = None
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
        self.assertFalse(payload["CLIENT_ID"].startswith("SMTHA"))
        self.assertTrue(payload["CLIENT_ID"].endswith("0123456789ABCDEF"))

    def test_local_mqtt_write_values_uses_non_stick_client_id(self):
        client = RemkoSmartWebClient.__new__(RemkoSmartWebClient)
        client.sid = "0123456789ABCDEF"
        client.sk = "FEDCBA9876543210"
        client.topic = "V04P27/0123456789ABCDEF"
        client.smt_user = 12345
        client.device_name = "DHW"
        client._local_mqtt_host = "192.168.2.4"
        client._mqtt = FakeMqtt({"1333": "022B"})
        client._ensure_mqtt = lambda: None

        client._mqtt_write_values({"1333": "022B"}, timeout=1)

        _topic, payload = client._mqtt.published[0]
        self.assertTrue(payload["CLIENT_ID"].startswith("SMTHA"))
        self.assertNotIn("0123456789ABCDEF", payload["CLIENT_ID"])

    def test_cloud_mqtt_poll_values_matches_main_client_id(self):
        client = RemkoSmartWebClient.__new__(RemkoSmartWebClient)
        client.sid = "0123456789ABCDEF"
        client.sk = "FEDCBA9876543210"
        client.topic = "V04P27/0123456789ABCDEF"
        client.smt_user = 12345
        client.device_name = "DHW"
        client._local_mqtt_host = None
        client._mqtt = FakeMqtt({"1194": "01"})
        client._ensure_mqtt = lambda: None

        response = client._mqtt_poll_values(timeout=1)

        self.assertEqual(response, {"1194": "01"})
        topic, payload = client._mqtt.published[0]
        self.assertEqual(topic, "V04P27/0123456789ABCDEF/CLIENT2HOST")
        self.assertEqual(payload["LASTWRITE"], 0)
        self.assertTrue(payload["FORCE_RESPONSE"])
        self.assertEqual(payload["SMT_USER"], 12345)
        self.assertTrue(payload["CLIENT_ID"].startswith("SMT"))
        self.assertFalse(payload["CLIENT_ID"].startswith("SMTHA"))
        self.assertTrue(payload["CLIENT_ID"].endswith("0123456789ABCDEF"))

    def test_local_mqtt_poll_values_uses_non_stick_client_id(self):
        client = RemkoSmartWebClient.__new__(RemkoSmartWebClient)
        client.sid = "0123456789ABCDEF"
        client.sk = "FEDCBA9876543210"
        client.topic = "V04P27/0123456789ABCDEF"
        client.smt_user = 12345
        client.device_name = "DHW"
        client._local_mqtt_host = "192.168.2.4"
        client._mqtt = FakeMqtt({"1194": "01"})
        client._ensure_mqtt = lambda: None

        client._mqtt_poll_values(timeout=1)

        _topic, payload = client._mqtt.published[0]
        self.assertTrue(payload["CLIENT_ID"].startswith("SMTHA"))
        self.assertNotIn("0123456789ABCDEF", payload["CLIENT_ID"])

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

    def test_local_mqtt_topic_discovery_keeps_local_topic_and_resolves_command_topic(self):
        client = RemkoSmartWebClient.__new__(RemkoSmartWebClient)
        client.device_name = "MXW"
        client.sid = None
        client.sk = None
        client.topic = None
        client._mqtt = None
        client._local_mqtt_host = "192.168.2.4"
        client._local_mqtt_port = 1883
        client._local_mqtt_user = None
        client._local_mqtt_password = None
        client._local_mqtt_command_topic = None

        def _resolve_device(*args, **kwargs):
            client.sid = "FEDCBA9876543210"
            client.sk = "0123456789ABCDEF"
            client.topic = "V04P27/FEDCBA9876543210"

        client.resolve_device = _resolve_device

        original_discover = client_module.discover_local_topic
        client_module.discover_local_topic = (
            lambda host, port, user, password: "V04P27/0123456789ABCDEF"
        )
        try:
            client._ensure_device()
        finally:
            client_module.discover_local_topic = original_discover

        self.assertEqual(client.topic, "V04P27/0123456789ABCDEF")
        self.assertEqual(client.sid, "FEDCBA9876543210")
        self.assertEqual(client._local_mqtt_command_topic, "V04P27/FEDCBA9876543210")
        self.assertEqual(client._esp_topic(), "V04P27/FEDCBA9876543210/ESP")
        self.assertTrue(client._mqtt_credentials_ready())

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

    def test_climate_value_write_allows_empty_response_as_pending(self):
        client = RemkoSmartWebClient.__new__(RemkoSmartWebClient)
        client.device_name = "MXW"
        client.profile = ClimateDeviceProfile()
        client._ensure_login = lambda: None
        client._ensure_device = lambda: None
        client._ensure_mqtt = lambda: None
        client._mqtt_write_values = lambda values, timeout=10, write_id=None: {}
        client._log_mapping_snapshot = lambda *args, **kwargs: None
        client.read_status = lambda: (_ for _ in ()).throw(AssertionError("readback should be skipped"))

        client.set_value_ids({"1194": "02"})

    def test_climate_value_write_allows_timeout_as_pending(self):
        client = RemkoSmartWebClient.__new__(RemkoSmartWebClient)
        client.device_name = "MXW"
        client.profile = ClimateDeviceProfile()
        client._ensure_login = lambda: None
        client._ensure_device = lambda: None
        client._ensure_mqtt = lambda: None
        client._mqtt_write_values = lambda values, timeout=10, write_id=None: None
        client._log_mapping_snapshot = lambda *args, **kwargs: None
        client.read_status = lambda: (_ for _ in ()).throw(AssertionError("readback should be skipped"))

        client.set_value_ids({"1194": "02"})

    def test_climate_set_temperature_honors_hvac_mode(self):
        hass = HomeAssistant()
        coordinator = types.SimpleNamespace(
            hass=hass,
            data={
                "power": "OFF",
                "mode": "dry",
                "setpoint": 24.0,
                "room": 25.0,
                "unit": "C",
            },
            async_request_refresh=lambda: None,
        )
        client = ClimateWriteClient()
        entity = RemkoSmartWebClimate(
            coordinator,
            client,
            "WIFI Stick - Arbeitszimmer Obergeschoss",
            17,
            30,
            ClimateDeviceProfile(),
        )

        asyncio.run(entity.async_set_temperature(temperature=21.0, hvac_mode=HVACMode.COOL))

        self.assertEqual(
            client.state_writes,
            [{"setpoint": 21.0, "power": True, "mode": "cool"}],
        )
        self.assertEqual(client.value_writes, [])

    def test_cloud_generic_ac_climate_prefers_esp_set_path(self):
        hass = HomeAssistant()
        coordinator = types.SimpleNamespace(
            hass=hass,
            data={
                "power": "OFF",
                "mode": "auto",
                "setpoint": 21.0,
                "room": 24.0,
                "unit": "C",
            },
            async_request_refresh=lambda: None,
        )
        client = ClimateWriteClient()
        entity = RemkoSmartWebClimate(
            coordinator,
            client,
            "WIFI Stick - Arbeitszimmer Obergeschoss",
            17,
            30,
            ClimateDeviceProfile(),
        )

        asyncio.run(entity.async_set_hvac_mode(HVACMode.COOL))

        self.assertEqual(client.state_writes, [{"power": True, "mode": "cool"}])
        self.assertEqual(client.value_writes, [])
        self.assertIs(client.primed_status, coordinator.data)

    def test_cloud_generic_ac_climate_falls_back_to_value_write_without_c0_payload(self):
        hass = HomeAssistant()
        coordinator = types.SimpleNamespace(
            hass=hass,
            data={
                "power": "OFF",
                "mode": "auto",
                "setpoint": 21.0,
                "room": 24.0,
                "unit": "C",
            },
            async_request_refresh=lambda: None,
        )
        client = ClimateWriteClient(set_values_error=UnsupportedPayload("No C0 payload"))
        entity = RemkoSmartWebClimate(
            coordinator,
            client,
            "WIFI Stick - Arbeitszimmer Obergeschoss",
            17,
            30,
            ClimateDeviceProfile(),
        )

        asyncio.run(entity.async_set_hvac_mode(HVACMode.COOL))

        self.assertEqual(client.state_writes, [])
        self.assertEqual(client.value_writes, [{"1194": "01", "1192": "04"}])

    def test_generic_ac_extended_switches_are_available_without_value_write_specs(self):
        profile = ClimateDeviceProfile()
        present = {"power", "mode", "setpoint"}

        self.assertTrue(_should_add_switch(profile, present, "beep"))
        self.assertTrue(_should_add_switch(profile, present, "power"))
        self.assertTrue(_should_add_switch(profile, present, "turbo"))
        self.assertTrue(_should_add_switch(profile, present, "bioclean"))
        self.assertTrue(_should_add_switch(profile, present, "sleep"))
        self.assertTrue(_should_add_switch(profile, present, "eco"))
        self.assertFalse(_should_add_switch(profile, present, "wpm_manual_defrost"))

    def test_beep_switch_is_available_for_non_climate_profiles(self):
        self.assertTrue(_should_add_switch(DomesticHotWaterDeviceProfile(), set(), "beep"))

    def test_beep_switch_updates_client_and_entry_options_without_device_write(self):
        hass = HomeAssistant()
        coordinator = types.SimpleNamespace(hass=hass, data={"power": "OFF"})
        client = ClimateWriteClient()
        client.set_beep_enabled = lambda enabled: setattr(client, "beep_enabled", bool(enabled))
        client.beep_enabled = False
        entry = ConfigEntry(options={"scan_interval": 30, "beep": False})
        entity = RemkoSmartWebSwitch(
            coordinator,
            client,
            "WIFI Stick - Arbeitszimmer Obergeschoss",
            "beep",
            "Beep on Command",
            ClimateDeviceProfile(),
            entry,
        )

        asyncio.run(entity.async_turn_on())

        self.assertTrue(client.beep_enabled)
        self.assertTrue(entity.is_on)
        self.assertEqual(entry.options["beep"], True)
        self.assertEqual(entry.options["scan_interval"], 30)
        self.assertEqual(client.value_writes, [])
        self.assertEqual(client.state_writes, [])
        self.assertTrue(entity.wrote_state)

    def test_generic_ac_power_switch_keeps_value_write_path(self):
        hass = HomeAssistant()
        coordinator = types.SimpleNamespace(
            hass=hass,
            data={"power": "OFF", "mode": "auto", "setpoint": 21.0, "unit": "C"},
        )
        client = ClimateWriteClient()
        entity = RemkoSmartWebSwitch(
            coordinator,
            client,
            "WIFI Stick - Arbeitszimmer Obergeschoss",
            "power",
            "Power",
            ClimateDeviceProfile(),
        )

        asyncio.run(entity.async_turn_on())

        self.assertEqual(client.value_writes, [{"1194": "01"}])
        self.assertEqual(client.state_writes, [])
        self.assertEqual(coordinator.data["power"], "ON")

    def test_generic_ac_extended_switch_falls_back_to_c0_set_values(self):
        hass = HomeAssistant()
        coordinator = types.SimpleNamespace(
            hass=hass,
            data={
                "power": "ON",
                "mode": "cool",
                "setpoint": 21.0,
                "turbo": False,
                "unit": "C",
            },
        )
        client = ClimateWriteClient()
        entity = RemkoSmartWebSwitch(
            coordinator,
            client,
            "WIFI Stick - Arbeitszimmer Obergeschoss",
            "turbo",
            "Turbo",
            ClimateDeviceProfile(),
        )

        asyncio.run(entity.async_turn_on())

        self.assertEqual(client.value_writes, [])
        self.assertEqual(client.state_writes, [{"turbo": True}])
        self.assertTrue(coordinator.data["turbo"])

    def test_local_climate_set_queue_falls_back_to_direct_publish(self):
        class QueuedMqtt:
            local_portal = True
            local_host2portal_mode = False

            def __init__(self):
                self.cleared = False
                self.queued = None
                self.cancelled = False
                self.published = []
                self.wait_timeout = None

            def clear_rx(self):
                self.cleared = True

            def queue_set(self, tx):
                self.queued = tx

            def wait_set_executed(self, timeout):
                self.wait_timeout = timeout
                return False

            def cancel_pending_set(self):
                self.cancelled = True
                self.queued = None

            def publish(self, topic, payload):
                self.published.append((topic, payload))

        client = RemkoSmartWebClient.__new__(RemkoSmartWebClient)
        client.device_name = "MXW"
        client.topic = "V04P27/0123456789ABCDEF"
        client.profile = ClimateDeviceProfile()
        client._beep = False
        client._last_payload = None
        client._last_status = None
        client._local_mqtt_host = "192.168.2.4"
        client._ensure_login = lambda: None
        client._ensure_device = lambda: None
        client._ensure_mqtt = lambda: None
        client._read_status_c0 = lambda retries=1: (_ for _ in ()).throw(UnsupportedPayload("no fresh status"))
        client.read_status = lambda: (_ for _ in ()).throw(AssertionError("readback should be skipped"))
        client._mqtt = QueuedMqtt()

        client.prime_status_cache({"_payload": bytes.fromhex("c001453c7f7f00300000005d5300000000000000000099")})
        client.set_values({"power": False})

        self.assertTrue(client._mqtt.cleared)
        self.assertTrue(client._mqtt.cancelled)
        self.assertEqual(client._mqtt.wait_timeout, 1.5)
        self.assertEqual(len(client._mqtt.published), 1)
        topic, payload = client._mqtt.published[0]
        self.assertEqual(topic, "V04P27/0123456789ABCDEF/ESP")
        self.assertEqual(payload["CLIENT_ID"], "SMTACUARTTEST")

    def test_cloud_climate_set_publishes_esp_immediately(self):
        client = RemkoSmartWebClient.__new__(RemkoSmartWebClient)
        client.device_name = "MXW"
        client.topic = "V04P27/0123456789ABCDEF"
        client.profile = ClimateDeviceProfile()
        client._beep = False
        client._last_payload = None
        client._last_status = None
        client._local_mqtt_host = None
        client._ensure_login = lambda: None
        client._ensure_device = lambda: None
        client._ensure_mqtt = lambda: None
        client._read_status_c0 = lambda retries=1: {
            "_payload": bytes.fromhex("c001453c7f7f00300000005d5300000000000000000099")
        }
        client.read_status = lambda: {"power": "OFF", "mode": "cool", "setpoint": 21.0}
        client._mqtt = FakeMqtt()

        client.set_values({"power": True, "mode": "cool", "setpoint": 21.0})

        self.assertEqual(len(client._mqtt.published), 1)
        topic, payload = client._mqtt.published[0]
        self.assertEqual(topic, "V04P27/0123456789ABCDEF/ESP")
        self.assertEqual(payload["CLIENT_ID"], "SMTACUARTTEST")
        self.assertEqual(
            payload["Tx"],
            "AA24AC000000000003024003453C7F7F003000000000000000000000000000000000004EEB",
        )

    def test_local_host2portal_climate_set_publishes_without_readback(self):
        client = RemkoSmartWebClient.__new__(RemkoSmartWebClient)
        client.device_name = "MXW"
        client.topic = "V04P27/SMTABCDEF123456"
        client._local_mqtt_command_topic = "V04P27/FEDCBA9876543210"
        client.profile = ClimateDeviceProfile()
        client._beep = False
        client._last_payload = bytes.fromhex("c001453c7f7f00300000005d5300000000000000000099")
        client._last_status = None
        client._local_mqtt_host = "192.168.2.4"
        client._ensure_login = lambda: None
        client._ensure_device = lambda: None
        client._ensure_mqtt = lambda: None
        client._read_status_c0 = lambda retries=1: (_ for _ in ()).throw(
            AssertionError("local host2portal writes should use cached payload")
        )
        client.read_status = lambda: (_ for _ in ()).throw(
            AssertionError("local host2portal writes should not wait for readback")
        )
        client._mqtt = FakeMqtt()
        client._mqtt.local_portal = True
        client._mqtt.local_host2portal_mode = True

        client.set_values({"power": True, "mode": "cool", "setpoint": 21.0})

        self.assertEqual(len(client._mqtt.published), 1)
        topic, payload = client._mqtt.published[0]
        self.assertEqual(topic, "V04P27/FEDCBA9876543210/ESP")
        self.assertEqual(payload["CLIENT_ID"], "SMTACUARTTEST")
        self.assertIn("Tx", payload)

    def test_climate_set_values_retries_stale_readback_before_mismatch_warning(self):
        client = RemkoSmartWebClient.__new__(RemkoSmartWebClient)
        client.device_name = "MXW"
        client.topic = "V04P27/0123456789ABCDEF"
        client.profile = ClimateDeviceProfile()
        client._beep = False
        client._last_payload = None
        client._last_status = None
        client._local_mqtt_host = None
        client._ensure_login = lambda: None
        client._ensure_device = lambda: None
        client._ensure_mqtt = lambda: None
        client._read_status_c0 = lambda retries=1: {
            "_payload": bytes.fromhex("c001453c7f7f00300000005d5300000000000000000099")
        }
        readbacks = deque(
            [
                {"power": "OFF", "mode": "cool", "setpoint": 21.0},
                {"power": "OFF", "mode": "cool", "setpoint": 21.0},
                {"power": "ON", "mode": "cool", "setpoint": 21.0},
            ]
        )
        client.read_status = lambda: readbacks.popleft()
        client._mqtt = FakeMqtt()
        warnings = []
        original_warning = client_module._LOGGER.warning
        original_sleep = client_module.time.sleep
        client_module._LOGGER.warning = lambda msg, *args, **kwargs: warnings.append(str(msg))
        client_module.time.sleep = lambda _seconds: None
        try:
            client.set_values({"power": True, "mode": "cool", "setpoint": 21.0})
        finally:
            client_module._LOGGER.warning = original_warning
            client_module.time.sleep = original_sleep

        self.assertEqual(len(client._mqtt.published), 1)
        self.assertEqual(len(readbacks), 0)
        self.assertFalse(any("readback mismatch" in msg for msg in warnings))

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
                "dhw_vacation_end_date": "2027-05-27",
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
        sensor_translations = translations["entity"]["sensor"]
        self.assertEqual(
            sensor_translations["compressor_state"]["state"],
            {"on": "Ein", "off": "Aus"},
        )
        self.assertEqual(
            sensor_translations["electric_heater_state"]["state"],
            {"on": "Ein", "off": "Aus"},
        )

    def test_entity_icons_cover_water_heater_and_climate_modes(self):
        icons = json.loads(
            (COMPONENT_PATH / "icons.json").read_text(encoding="utf-8")
        )

        water_heater_icons = icons["entity"]["water_heater"]["domestic_hot_water"]["state"]
        climate_icons = icons["entity"]["climate"]["climate"]["state_attributes"]

        self.assertEqual(set(water_heater_icons), set(OPERATION_MODES))
        self.assertEqual(water_heater_icons["auto"], "mdi:refresh-auto")
        self.assertEqual(water_heater_icons["vacation"], "mdi:island")
        self.assertEqual(water_heater_icons["hybrid"], "mdi:lightning-bolt")
        self.assertEqual(water_heater_icons["speed_heating"], "mdi:fire")
        self.assertEqual(
            set(climate_icons["fan_mode"]["state"]),
            {"auto", "silent", "low", "medium", "high"},
        )
        self.assertEqual(
            set(climate_icons["swing_mode"]["state"]),
            {"off", "vertical", "horizontal", "both"},
        )
        self.assertEqual(
            set(climate_icons["preset_mode"]["state"]),
            {"none", "eco", "turbo", "sleep", "bioclean", "frost_protection"},
        )


if __name__ == "__main__":
    unittest.main()
