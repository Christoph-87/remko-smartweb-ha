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

from custom_components.remko_smartweb.const import DEVICE_KIND_CLIMATE, DEVICE_KIND_DHW
from custom_components.remko_smartweb.profiles import detect_device_kind, get_parser_profile
from custom_components.remko_smartweb.profiles.climate import ClimateDeviceProfile
from custom_components.remko_smartweb.profiles.domestic_hot_water import DomesticHotWaterDeviceProfile


CLIMATE_C0_RX = (
    "aa000000000000000000c00146667f7f0030000000646400000000000000000000"
)


class ProfileParsingTests(unittest.TestCase):
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
            "5530": "5A",
        }

        status = ClimateDeviceProfile().parse_values_status(values)

        self.assertEqual(
            status,
            {
                "power": "ON",
                "setpoint": 22,
                "room": 25,
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
