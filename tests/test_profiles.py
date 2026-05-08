from __future__ import annotations

import unittest
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPONENT_PATH = ROOT / "custom_components" / "remko_smartweb"

custom_components = types.ModuleType("custom_components")
custom_components.__path__ = [str(ROOT / "custom_components")]
sys.modules.setdefault("custom_components", custom_components)

remko_smartweb = types.ModuleType("custom_components.remko_smartweb")
remko_smartweb.__path__ = [str(COMPONENT_PATH)]
sys.modules.setdefault("custom_components.remko_smartweb", remko_smartweb)

paho = types.ModuleType("paho")
paho_mqtt = types.ModuleType("paho.mqtt")
paho_mqtt_client = types.ModuleType("paho.mqtt.client")
sys.modules.setdefault("paho", paho)
sys.modules.setdefault("paho.mqtt", paho_mqtt)
sys.modules.setdefault("paho.mqtt.client", paho_mqtt_client)

requests = types.ModuleType("requests")
requests.Session = object
sys.modules.setdefault("requests", requests)

from custom_components.remko_smartweb.api import (
    _extract_global_var,
    _extract_sid_sk_from_text,
    _extract_sid_sk_from_url,
    _extract_smt_user_from_text,
    _extract_smt_user_from_url,
    _value_query_list,
)
from custom_components.remko_smartweb.const import DEVICE_KIND_CLIMATE, DEVICE_KIND_DHW
from custom_components.remko_smartweb.profiles import detect_device_kind, get_device_profile, get_parser_profile
from custom_components.remko_smartweb.profiles.climate import ClimateDeviceProfile
from custom_components.remko_smartweb.profiles.domestic_hot_water import DomesticHotWaterDeviceProfile
from custom_components.remko_smartweb.profiles.kwt import KwtDeviceProfile
from custom_components.remko_smartweb.profiles.lte import LteDeviceProfile
from custom_components.remko_smartweb.profiles.value_mapping import ValueWriteSpec, build_value_write


CLIMATE_C0_RX = (
    "aa000000000000000000c00146667f7f0030000000646400000000000000000000"
)


class ProfileParsingTests(unittest.TestCase):
    def test_value_write_spec_encodes_scaled_and_enum_values(self):
        specs = (
            ValueWriteSpec("temperature", "1000", digits=4, scale=10),
            ValueWriteSpec("power", "1001", enum={True: 1, False: 2}),
        )

        self.assertEqual(
            build_value_write({"temperature": 55.5, "power": False}, specs),
            {"1000": "022B", "1001": "02"},
        )

    def test_value_write_spec_ignores_unknown_enum_values(self):
        specs = (ValueWriteSpec("mode", "1002", enum={"eco": 9}),)

        self.assertIsNone(build_value_write({"mode": "unsupported"}, specs))

    def test_extract_smt_user_from_device_page_text(self):
        self.assertEqual(_extract_smt_user_from_text("global.SMT_USER=12345;"), 12345)
        self.assertEqual(_extract_smt_user_from_text('"SMT_USER": 67890'), 67890)
        self.assertEqual(_extract_smt_user_from_url("https://example.invalid/?us=12345"), 12345)

    def test_extract_global_var_from_device_scripts(self):
        self.assertEqual(_extract_global_var('global.SMT_USER="12345";', "SMT_USER"), "12345")
        self.assertEqual(_extract_global_var('SMT_VERSION="4.31";', "SMT_VERSION"), "4.31")

    def test_extract_mqtt_credentials_from_smartweb_ids(self):
        text = 'global.SMT_ID="0123456789ABCDEF";global.SMT_KEY="FEDCBA9876543210";'
        self.assertEqual(
            _extract_sid_sk_from_text(text),
            ("0123456789ABCDEF", "FEDCBA9876543210"),
        )
        self.assertIsNone(_extract_sid_sk_from_text('global.SMT_ID="NaN";global.SMT_KEY="NaN";'))
        self.assertIsNone(_extract_sid_sk_from_url("https://example.invalid/?SID=&SK="))

    def test_value_query_list_includes_written_ids_with_status_ids(self):
        query_list = _value_query_list({"1333": "022B", "9999": "01"})

        self.assertIn(1333, query_list)
        self.assertIn(9999, query_list)
        self.assertEqual(query_list.count(1333), 1)
        self.assertGreater(len(query_list), 2)

    def test_climate_c0_status_parses_core_fields(self):
        status = ClimateDeviceProfile().parse_c0_status(CLIMATE_C0_RX)

        self.assertIsNotNone(status)
        self.assertEqual(status["power"], "ON")
        self.assertEqual(status["setpoint"], 22)
        self.assertEqual(status["mode"], "cool")
        self.assertEqual(status["fan"], "auto")
        self.assertEqual(status["swing"], "off")
        self.assertEqual(status["room"], 25)
        self.assertEqual(status["outdoor"], 25)
        self.assertEqual(status["unit"], "C")
        self.assertEqual(status["_payload"][0], 0xC0)

    def test_climate_c0_status_rejects_non_c0_frame(self):
        self.assertIsNone(ClimateDeviceProfile().parse_c0_status("63100450000108aa"))

    def test_climate_values_status_parses_legacy_value_ids(self):
        values = {
            "1194": "01",
            "1190": "2C",
            "1191": "04",
            "1192": "04",
            "1193": "01",
            "1228": "01",
            "5530": "5A",
        }

        status = ClimateDeviceProfile().parse_values_status(values)

        self.assertEqual(
            status,
            {
                "power": "ON",
                "setpoint": 22,
                "room": 25,
                "mode": "cool",
                "fan": "medium",
                "swing": "vertical",
                "sleep": True,
                "unit": "C",
            },
        )

    def test_dhw_values_status_parses_tenths_temperature_values(self):
        values = {
            "1152": "01",
            "1333": "022B",
            "1336": "0226",
        }

        status = DomesticHotWaterDeviceProfile().parse_values_status(values)

        self.assertEqual(
            status,
            {
                "dhw_setpoint": 55.5,
                "setpoint": 55.5,
                "mode": "heat",
                "dhw_top_temperature": 55.0,
                "room": 55.0,
                "power": "ON",
                "unit": "C",
            },
        )

    def test_dhw_values_status_prefers_observed_top_and_bottom_temperature_ids(self):
        values = {
            "1194": "01",
            "1192": "06",
            "1333": "0226",
            "1336": "0226",
            "5032": "00D2",
            "5943": "0212",
            "5944": "01EA",
        }

        status = DomesticHotWaterDeviceProfile().parse_values_status(values)

        self.assertEqual(status["dhw_setpoint"], 55.0)
        self.assertEqual(status["dhw_top_temperature"], 53.0)
        self.assertEqual(status["dhw_bottom_temperature"], 49.0)
        self.assertEqual(status["dhw_ambient_temperature"], 21.0)
        self.assertEqual(status["dhw_mode"], "heat")
        self.assertEqual(status["dhw_power_state"], "on")
        self.assertEqual(status["power"], "ON")
        self.assertEqual(status["room"], 53.0)

    def test_dhw_values_status_parses_signed_ambient_temperature(self):
        values = {
            "1194": "02",
            "5032": "FFF6",
        }

        status = DomesticHotWaterDeviceProfile().parse_values_status(values)

        self.assertEqual(status["dhw_ambient_temperature"], -1.0)
        self.assertEqual(status["dhw_power_state"], "off")
        self.assertEqual(status["power"], "OFF")

    def test_dhw_values_status_parses_padded_state_bytes(self):
        values = {
            "1192": "00000000000000000009",
            "1194": "00000000000000000001",
            "1333": "0226",
            "5943": "0226",
        }

        status = DomesticHotWaterDeviceProfile().parse_values_status(values)

        self.assertEqual(status["dhw_mode"], "eco")
        self.assertEqual(status["dhw_power_state"], "on")
        self.assertEqual(status["power"], "ON")

    def test_dhw_values_status_parses_long_padded_state_bytes_from_log(self):
        values = {
            "1192": (
                "0000000000000000000000000000000000000000000000000000000000000000"
                "0000000000000000000000000000000000000000000000000000000000000009"
            ),
            "1194": (
                "0000000000000000000000000000000000000000000000000000000000000000"
                "0000000000000000000000000000000000000000000000000000000000000001"
            ),
            "1333": "0226",
            "5943": "0226",
        }

        status = DomesticHotWaterDeviceProfile().parse_values_status(values)

        self.assertEqual(status["dhw_mode"], "eco")
        self.assertEqual(status["mode"], "eco")
        self.assertEqual(status["dhw_power_state"], "on")
        self.assertEqual(status["power"], "ON")

    def test_dhw_profile_builds_value_writes(self):
        values = DomesticHotWaterDeviceProfile().build_value_write(
            {"setpoint": 55.5, "power": True, "mode": "eco"}
        )

        self.assertEqual(values, {"1333": "022B", "1194": "01", "1192": "09"})

    def test_auto_profile_prefers_dhw_for_dhw_device_name(self):
        values = {
            "1190": "2C",
            "5530": "5A",
            "1333": "022B",
            "1336": "0226",
        }

        status = get_parser_profile("WIFI Stick - Brauchwasserwaermepumpe").parse_values_status(values)

        self.assertEqual(status["dhw_setpoint"], 55.5)
        self.assertEqual(status["dhw_top_temperature"], 55.0)

    def test_auto_profile_uses_dhw_when_rbw_style_values_are_present(self):
        values = {
            "1194": "01",
            "1192": "06",
            "1333": "0226",
            "5943": "0212",
            "5944": "01EA",
        }

        status = get_parser_profile("RBW 302 Pro").parse_values_status(values)

        self.assertEqual(status["dhw_setpoint"], 55.0)
        self.assertEqual(status["dhw_mode"], "heat")

    def test_lte_profile_parses_dehumidifier_values(self):
        values = {
            "1194": "01",
            "1302": "32",
            "5769": "2D",
            "5928": "00FA",
            "5931": "00D2",
            "5195": "0000",
        }

        status = LteDeviceProfile().parse_values_status(values)

        self.assertEqual(status["power"], "ON")
        self.assertEqual(status["target_humidity"], 50)
        self.assertEqual(status["internal_humidity"], 45)
        self.assertEqual(status["internal_temperature"], 25.0)
        self.assertEqual(status["external_temperature"], 21.0)
        self.assertEqual(status["error"], 0)

    def test_kwt_profile_parses_readonly_climate_values(self):
        values = {
            "1194": "01",
            "1190": "2C",
            "1191": "04",
            "1192": "06",
            "1193": "04",
            "5530": "5A",
            "5539": "01",
        }

        status = KwtDeviceProfile().parse_values_status(values)

        self.assertEqual(status["power"], "ON")
        self.assertEqual(status["setpoint"], 22)
        self.assertEqual(status["room"], 25)
        self.assertEqual(status["mode"], "heat")
        self.assertEqual(status["fan"], "medium")
        self.assertEqual(status["swing"], "vertical")
        self.assertEqual(status["filter_state"], 1)

    def test_kwt_profile_builds_value_writes(self):
        values = KwtDeviceProfile().build_value_write(
            {
                "setpoint": 22.5,
                "power": True,
                "mode": "heat",
                "fan": "medium",
                "swing": "vertical",
            }
        )

        self.assertEqual(
            values,
            {
                "1190": "2D",
                "1194": "01",
                "1192": "06",
                "1191": "04",
                "1193": "04",
            },
        )

    def test_get_device_profile_returns_specialized_profiles(self):
        self.assertIsInstance(
            get_device_profile("LTE", {"internal_humidity": 45}),
            LteDeviceProfile,
        )
        self.assertIsInstance(
            get_device_profile("KWT 180 - 300 DC", {"setpoint": 22}),
            KwtDeviceProfile,
        )

    def test_auto_profile_uses_climate_values_for_climate_like_values(self):
        values = {
            "1190": "2C",
            "5530": "5A",
            "1333": "022B",
        }

        status = get_parser_profile("Living room AC").parse_values_status(values)

        self.assertNotIn("dhw_setpoint", status)
        self.assertEqual(status["setpoint"], 22)
        self.assertEqual(status["room"], 25)

    def test_detect_device_kind_from_data_and_name(self):
        self.assertEqual(detect_device_kind("Basement", {"dhw_setpoint": 55.5}), DEVICE_KIND_DHW)
        self.assertEqual(detect_device_kind("Living room", {"fan": "auto"}), DEVICE_KIND_CLIMATE)
        self.assertEqual(detect_device_kind("Brauchwasserwaermepumpe", {}), DEVICE_KIND_DHW)


if __name__ == "__main__":
    unittest.main()
