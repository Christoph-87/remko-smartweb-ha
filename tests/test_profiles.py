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
    _build_ac_uart_set_cmds,
    _build_kwt_set_cmd,
    _build_lte_set_cmd,
    _build_modbus_read_cmd,
    _build_mqtt_topic,
    _build_rbw_get_status_cmd,
    _build_rbw_set_cmd,
    _build_wpm_set_cmd,
    _extract_device_metadata_from_text,
    _extract_global_var,
    _extract_sid_sk_from_text,
    _extract_sid_sk_from_url,
    _extract_smt_user_from_text,
    _extract_smt_user_from_url,
    _parse_rbw_register_status,
    _parse_rbw_registers_rx,
    _parse_kwt_register_status,
    _parse_modbus_coils_rx,
    _parse_modbus_holding_rx,
    _parse_wpm_register_status,
    _value_query_list,
)
from custom_components.remko_smartweb.const import DEVICE_KIND_CLIMATE, DEVICE_KIND_DHW, DEVICE_KIND_DIAGNOSTICS
from custom_components.remko_smartweb.profiles import detect_device_kind, get_device_profile, get_parser_profile
from custom_components.remko_smartweb.profiles.climate import ClimateDeviceProfile, ReadOnlyAcUartClimateDeviceProfile
from custom_components.remko_smartweb.profiles.diagnostics import DiagnosticsDeviceProfile
from custom_components.remko_smartweb.profiles.domestic_hot_water import DomesticHotWaterDeviceProfile
from custom_components.remko_smartweb.profiles.kwt import KwtDeviceProfile
from custom_components.remko_smartweb.profiles.lte import LteDeviceProfile
from custom_components.remko_smartweb.profiles.wpm import WpmDeviceProfile
from custom_components.remko_smartweb.profiles.value_mapping import ValueWriteSpec, build_value_write


CLIMATE_C0_RX = (
    "aa000000000000000000c00146667f7f0030000000646400000000000000000000"
)


def _rbw_rx(start: int, quantity: int, values: dict[int, int]) -> str:
    data = [0x63, 0x03, (start & 0xFF00) >> 8, start & 0x00FF, quantity & 0xFF]
    for offset in range(quantity):
        value = values.get(start + offset, 0)
        data.extend([(value & 0xFF00) >> 8, value & 0x00FF])
    return "".join(f"{byte:02X}" for byte in data)


def _modbus_holding_rx(start: int, quantity: int, values: dict[int, int]) -> str:
    payload = []
    for offset in range(quantity):
        value = values.get(start + offset, 0) & 0xFFFF
        payload.extend([(value & 0xFF00) >> 8, value & 0x00FF])
    data = [0x01, 0x03, len(payload), *payload]
    return "".join(f"{byte:02X}" for byte in data) + "0000"


def _modbus_coils_rx(start: int, quantity: int, values: dict[int, int]) -> str:
    payload = [0] * ((quantity + 7) // 8)
    for register, value in values.items():
        offset = register - start
        if 0 <= offset < quantity and value:
            payload[offset // 8] |= 1 << (offset % 8)
    data = [0x01, 0x01, len(payload), *payload]
    return "".join(f"{byte:02X}" for byte in data) + "0000"


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
        self.assertEqual(
            _extract_smt_user_from_text(
                'appframe.location.href="/webportal/Wifi/smt.html?SID=0123456789ABCDEF&SK=FEDCBA9876543210&us=3946&DEV=256"'
            ),
            3946,
        )

    def test_extract_device_metadata_from_portal_url(self):
        html = (
            'appframe.location.href="/webportal/Wifi/sd-card/lighttpd/webpages/smt.html'
            '?SMT_ID=70162fe655ec381ac6312ebf026aac54'
            '&SID=0123456789ABCDEF&SK=FEDCBA9876543210&us=3946&DEV=256'
            '&NAME=Klima_Erdgeschoss&TYPE=MXW%20204%20-%20524";'
        )

        self.assertEqual(
            _extract_device_metadata_from_text(html),
            {
                "device_portal_id": "70162fe655ec381ac6312ebf026aac54",
                "device_dev": "256",
                "device_portal_name": "Klima_Erdgeschoss",
                "device_type": "MXW 204 - 524",
            },
        )

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
        self.assertEqual(_build_mqtt_topic("0123456789abcdef"), "V04P27/0123456789ABCDEF")
        self.assertIsNone(_build_mqtt_topic(""))
        self.assertIsNone(_build_mqtt_topic("NaN"))

    def test_value_query_list_includes_written_ids_with_status_ids(self):
        query_list = _value_query_list({"1333": "022B", "9999": "01"})

        self.assertIn(1333, query_list)
        self.assertIn(9999, query_list)
        self.assertIn(4110, query_list)
        self.assertIn(1352, query_list)
        self.assertEqual(query_list.count(1333), 1)
        self.assertGreater(len(query_list), 2)

    def test_build_rbw_set_cmd_uses_frontend_modbus_conversion(self):
        self.assertEqual(_build_rbw_set_cmd("1333", "0226"), "631004500100AA")
        self.assertEqual(_build_rbw_set_cmd("1333", "022B"), "631004500100AB")
        self.assertEqual(_build_rbw_set_cmd("1194", "01"), "631003F3010001")
        self.assertEqual(_build_rbw_set_cmd("1194", "02"), "631003F3010000")
        self.assertEqual(_build_rbw_set_cmd("1192", "09"), "631003F4010002")
        self.assertIsNone(_build_rbw_set_cmd("1192", "06"))

    def test_build_rbw_get_status_cmd_uses_frontend_read_ranges(self):
        self.assertEqual(_build_rbw_get_status_cmd(1001), "630303E95A")
        self.assertEqual(_build_rbw_get_status_cmd(1091), "630304435A")
        self.assertEqual(_build_rbw_get_status_cmd(2001), "630307D15A")

    def test_rbw_direct_modbus_status_parses_frontend_read_ranges(self):
        registers = {}
        for rx in (
            _rbw_rx(1001, 90, {1011: 1, 1012: 2}),
            _rbw_rx(1091, 90, {1104: 170}),
            _rbw_rx(2001, 90, {2019: 102, 2020: 160, 2021: 166}),
        ):
            registers.update(_parse_rbw_registers_rx(rx))

        status = _parse_rbw_register_status(registers)

        self.assertEqual(status["dhw_power_state"], "on")
        self.assertEqual(status["power"], "ON")
        self.assertEqual(status["dhw_mode"], "eco")
        self.assertEqual(status["mode"], "eco")
        self.assertEqual(status["dhw_setpoint"], 55.0)
        self.assertEqual(status["setpoint"], 55.0)
        self.assertEqual(status["dhw_ambient_temperature"], 21.0)
        self.assertEqual(status["dhw_bottom_temperature"], 50.0)
        self.assertEqual(status["dhw_top_temperature"], 53.0)
        self.assertEqual(status["room"], 53.0)

    def test_build_kwt_set_cmd_uses_frontend_modbus_conversion(self):
        self.assertEqual(_build_kwt_set_cmd("1190", "2B"), "0110271A00010200D7B336")
        self.assertEqual(_build_kwt_set_cmd("1194", "01"), "0110271000010200013202")
        self.assertEqual(_build_kwt_set_cmd("1194", "02"), "011027100001020000F3C2")
        self.assertEqual(_build_kwt_set_cmd("1192", "06"), "01102711000102000133D3")
        self.assertEqual(_build_kwt_set_cmd("1191", "04"), "01102712000102000273E1")
        self.assertEqual(_build_kwt_set_cmd("1193", "04"), "0110272400010200013676")

    def test_build_modbus_read_cmd_uses_frontend_modbus_read_format(self):
        self.assertEqual(_build_modbus_read_cmd(1, 3, 10000, 3), "0103271000030EBA")
        self.assertEqual(_build_modbus_read_cmd(1, 3, 10010, 1), "0103271A0001AF79")
        self.assertEqual(_build_modbus_read_cmd(1, 1, 1, 62), "01010001003EEC1A")

    def test_kwt_direct_modbus_status_converts_to_smartweb_values(self):
        registers = {}
        registers.update(_parse_modbus_holding_rx(_modbus_holding_rx(10000, 3, {10000: 1, 10001: 2, 10002: 2}), 10000))
        registers.update(_parse_modbus_holding_rx(_modbus_holding_rx(10010, 1, {10010: 215}), 10010))
        registers.update(_parse_modbus_holding_rx(_modbus_holding_rx(10020, 1, {10020: 1}), 10020))
        registers.update(_parse_modbus_holding_rx(_modbus_holding_rx(11010, 1, {11010: 255}), 11010))

        values = _parse_kwt_register_status(registers)
        status = KwtDeviceProfile().parse_values_status(values)

        self.assertEqual(values["1194"], "01")
        self.assertEqual(values["1192"], "04")
        self.assertEqual(values["1191"], "04")
        self.assertEqual(values["1190"], "2B")
        self.assertEqual(values["1193"], "04")
        self.assertEqual(values["5530"], "5B")
        self.assertEqual(status["power"], "ON")
        self.assertEqual(status["mode"], "cool")
        self.assertEqual(status["fan"], "medium")
        self.assertEqual(status["setpoint"], 21.5)
        self.assertEqual(status["room"], 25.5)

    def test_wpm_direct_modbus_status_converts_to_smartweb_values(self):
        coils = {}
        holding = {}
        coils.update(_parse_modbus_coils_rx(_modbus_coils_rx(1, 62, {47: 1}), 1, 62))
        coils.update(_parse_modbus_coils_rx(_modbus_coils_rx(71, 171, {73: 1, 82: 1}), 71, 171))
        holding.update(_parse_modbus_holding_rx(_modbus_holding_rx(1, 100, {50: 42}), 1))
        holding.update(_parse_modbus_holding_rx(_modbus_holding_rx(401, 16, {415: 45, 416: 48}), 401))

        values = _parse_wpm_register_status(coils, holding)
        status = WpmDeviceProfile().parse_values_status(values)

        self.assertEqual(values["5734"], "01")
        self.assertEqual(values["4110"], "01")
        self.assertEqual(values["4113"], "01")
        self.assertEqual(values["5774"], "002A")
        self.assertEqual(values["1352"], "002D")
        self.assertEqual(values["2179"], "0030")
        self.assertEqual(status["wpm_unit_on"], 1)
        self.assertEqual(status["wpm_heat_cool_mode"], 1)
        self.assertEqual(status["wpm_manual_defrost"], 1)
        self.assertEqual(status["wpm_target_temperature"], 42)
        self.assertEqual(status["wpm_setpoint_ch"], 45)
        self.assertEqual(status["wpm_setpoint_hp"], 48)

    def test_build_ac_uart_set_cmds_use_frontend_esp_protocols(self):
        current = {
            "power": "ON",
            "setpoint": 22,
            "room": 25,
            "mode": "cool",
            "fan": "medium",
            "swing": "off",
        }

        self.assertEqual(
            _build_ac_uart_set_cmds("free_ac_uart", current, {"setpoint": 23, "fan": "high"}),
            ["FC010117190102000000000000CF"],
        )
        self.assertEqual(
            _build_ac_uart_set_cmds("aux_ac_uart", current, {"power": False, "mode": "heat"}),
            ["BB00068000000F000101776000400080190000000000009D5D"],
        )
        self.assertEqual(
            _build_ac_uart_set_cmds("nwt_ac_uart", current, {"setpoint": 23, "power": True}),
            ["55AA0006000802020004000000172C", "55AA0006000501010001010E"],
        )
        self.assertEqual(_build_ac_uart_set_cmds("free_ac_uart", current, {"mode": "heat"}), [])
        self.assertEqual(_build_ac_uart_set_cmds("nwt_ac_uart", current, {"mode": "heat"}), [])

    def test_build_lte_set_cmd_uses_frontend_protocol(self):
        self.assertEqual(
            _build_lte_set_cmd({"power": "OFF", "target_humidity": 45}, {"1194": "01", "1302": "32"}),
            "FCD001010132FF",
        )
        self.assertIsNone(_build_lte_set_cmd({}, {"1302": "64"}))

    def test_build_wpm_set_cmd_uses_frontend_modbus_conversion(self):
        self.assertEqual(_build_wpm_set_cmd("4110", "01"), "01050049FF005DEC")
        self.assertEqual(_build_wpm_set_cmd("4113", "00"), "0105005800004C19")
        self.assertEqual(_build_wpm_set_cmd("1352", "002D"), "0110019F000102002D6B22")
        self.assertEqual(_build_wpm_set_cmd("2179", "0028"), "011001A00001020028AE2E")
        self.assertIsNone(_build_wpm_set_cmd("9999", "01"))

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
        self.assertFalse(status["display"])
        self.assertFalse(status["frost_protection"])
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
            "1199": "01",
            "1228": "01",
            "1298": "01",
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
                "frost_protection": True,
                "sleep": True,
                "display": True,
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
            "1192": "0000000000000000000A",
            "1194": "00000000000000000001",
            "1333": "0226",
            "5943": "0226",
        }

        status = DomesticHotWaterDeviceProfile().parse_values_status(values)

        self.assertEqual(status["dhw_mode"], "hybrid")
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
        self.assertEqual(
            DomesticHotWaterDeviceProfile().build_value_write({"mode": "hybrid"}),
            {"1192": "0A"},
        )
        self.assertEqual(
            DomesticHotWaterDeviceProfile().build_value_write({"mode": "speed_heating"}),
            {"1192": "0B"},
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

    def test_lte_profile_builds_value_writes(self):
        self.assertEqual(
            LteDeviceProfile().build_value_write({"power": True, "target_humidity": 55}),
            {"1194": "01", "1302": "37"},
        )

    def test_wpm_profile_parses_and_builds_experimental_values(self):
        profile = WpmDeviceProfile()
        status = profile.parse_values_status(
            {
                "4110": "01",
                "1352": "002D",
                "2179": "0028",
                "5774": "001E",
            }
        )

        self.assertEqual(status["wpm_heat_cool_mode"], 1)
        self.assertEqual(status["wpm_setpoint_ch"], 45)
        self.assertEqual(status["wpm_setpoint_hp"], 40)
        self.assertEqual(status["wpm_target_temperature"], 30)
        self.assertEqual(
            profile.build_value_write({"wpm_setpoint_ch": 45, "wpm_heat_cool_mode": 1}),
            {"4110": "01", "1352": "002D"},
        )

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
            get_device_profile("MXW 204 - 524 Klima_Erdgeschoss", {"setpoint": 22}),
            ClimateDeviceProfile,
        )
        self.assertIsInstance(
            get_device_profile("LTE", {"internal_humidity": 45}),
            LteDeviceProfile,
        )
        self.assertIsInstance(
            get_device_profile("KWT 180 - 300 DC", {"setpoint": 22}),
            KwtDeviceProfile,
        )
        self.assertIsInstance(
            get_device_profile("RKL 355 DC", {"setpoint": 22}),
            ReadOnlyAcUartClimateDeviceProfile,
        )
        self.assertIsInstance(
            get_device_profile("BL 264 - 354 DC", {"setpoint": 22}),
            ReadOnlyAcUartClimateDeviceProfile,
        )
        self.assertIsInstance(
            get_device_profile("RKL 495 DC", {"setpoint": 22}),
            ReadOnlyAcUartClimateDeviceProfile,
        )
        self.assertEqual(
            get_device_profile("RKL 355 DC", {"setpoint": 22}).protocol_name,
            "nwt_ac_uart",
        )
        self.assertFalse(
            get_device_profile("BL 264 - 354 DC", {"setpoint": 22}).supports_value_write
        )
        self.assertTrue(
            get_device_profile("RKL 495 DC", {"setpoint": 22}).supports_climate_write
        )
        self.assertIsInstance(
            get_device_profile("Luftentfeuchter", {"internal_humidity": 45}),
            LteDeviceProfile,
        )
        self.assertIsInstance(
            get_device_profile("WPM 400 A Pro", {"setpoint": 22}),
            WpmDeviceProfile,
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
        self.assertEqual(detect_device_kind("SQW 405 Pro", {}), DEVICE_KIND_DIAGNOSTICS)


if __name__ == "__main__":
    unittest.main()
