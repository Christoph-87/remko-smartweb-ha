from __future__ import annotations

from ..const import DEVICE_KIND_DIAGNOSTICS
from .base import SmartWebDeviceProfile
from .value_mapping import ValueWriteSpec, build_value_write


def looks_like_wpm_name(device_name: str | None) -> bool:
    name = (device_name or "").casefold()
    return any(
        token in name
        for token in (
            "wpm",
            "wpk",
            "wkf",
            "wsp",
            "wkm",
            "sqw",
            "waermepumpe",
            "wärmepumpe",
            "modulare_waermepumpe",
            "modulare wärmepumpe",
        )
    )


def _first_word(hexstr: str | None):
    if not hexstr or len(hexstr) < 4:
        return None
    try:
        value = int(hexstr[0:4], 16)
    except Exception:
        return None
    if value > 0x7FFF:
        return value - 0x10000
    return value


def _first_byte(hexstr: str | None):
    if not hexstr:
        return None
    try:
        return int(hexstr[0:2], 16)
    except Exception:
        return None


def _first_present_word(values: dict, *value_ids: str):
    for value_id in value_ids:
        value = _first_word(values.get(value_id))
        if value is not None:
            return value
    return None


def _first_present_tenths(values: dict, *value_ids: str):
    value = _first_present_word(values, *value_ids)
    if value is None:
        return None
    return value / 10


def _first_present_byte(values: dict, *value_ids: str):
    for value_id in value_ids:
        value = _first_byte(values.get(value_id))
        if value is not None:
            return value
    return None


class WpmDeviceProfile(SmartWebDeviceProfile):
    """Experimental diagnostics/write profile for WPM/WPK/WKM/SQW heat pumps."""

    kind = DEVICE_KIND_DIAGNOSTICS
    profile_name = "WPM Heat Pump"
    protocol_name = "wpm_modbus"
    diagnostics_only = True
    supports_value_write = True
    query_value_ids = (
        4110,
        4113,
        5734,
        5774,
        1352,
        2179,
        1082,
        1893,
        1894,
        1951,
        1946,
        1972,
        1974,
        5001,
        5032,
        5033,
        5034,
        5039,
        5055,
        5085,
        5693,
    )
    heat_cool_mode_value_ids = ("4110", "1951")
    sensor_descriptions = (
        ("wpm_heat_cool_mode", "WPM Heat/Cool Mode", None),
        ("wpm_manual_defrost", "WPM Manual Defrost", None),
        ("wpm_outdoor_temperature", "WPM Outdoor Temperature", "temperature"),
        ("wpm_mixed_temperature", "WPM Mixed Temperature", "temperature"),
        ("wpm_water_temperature", "WPM Water Temperature", "temperature"),
        ("wpm_target_temperature", "WPM Target Temperature", "temperature"),
        ("wpm_dhw_target_temperature", "WPM DHW Target Temperature", "temperature"),
        ("wpm_temperature_adjustment", "WPM Temperature Adjustment", "temperature"),
        ("wpm_fixed_temperature", "WPM Fixed Temperature", "temperature"),
        ("wpm_heating_water_target_temperature", "WPM Heating Water Target Temperature", "temperature"),
        ("wpm_setpoint_ch", "WPM CH Setpoint", "temperature"),
        ("wpm_setpoint_hp", "WPM HP Setpoint", "temperature"),
        ("wpm_unit_on", "WPM Unit On", None),
        ("wpm_absence_mode", "WPM Absence Mode", None),
        ("wpm_party_mode", "WPM Party Mode", None),
        ("wpm_heating_circuit_mode", "WPM Heating Circuit Mode", None),
        ("wpm_dhw_heating", "WPM One-Time DHW Heating", None),
    )
    number_descriptions = (
        ("wpm_target_temperature", "WPM Target Temperature", 0, 80, 1, "temperature"),
        ("wpm_dhw_target_temperature", "WPM DHW Target Temperature", 20, 60, 0.5, "temperature"),
        ("wpm_temperature_adjustment", "WPM Temperature Adjustment", -10, 10, 0.5, "temperature"),
        ("wpm_fixed_temperature", "WPM Fixed Temperature", 20, 60, 0.5, "temperature"),
        ("wpm_heating_water_target_temperature", "WPM Heating Water Target Temperature", 20, 60, 0.5, "temperature"),
        ("wpm_setpoint_ch", "WPM CH Setpoint", 0, 80, 1, "temperature"),
        ("wpm_setpoint_hp", "WPM HP Setpoint", 0, 80, 1, "temperature"),
    )

    def parse_values_status(self, values: dict) -> dict | None:
        if not isinstance(values, dict):
            return None
        status = {}
        for key, value in (
            ("wpm_heat_cool_mode", _first_present_byte(values, *self.heat_cool_mode_value_ids)),
            ("wpm_manual_defrost", _first_present_byte(values, "4113")),
            ("wpm_unit_on", _first_present_byte(values, "5734", "5001")),
            ("wpm_absence_mode", _first_present_byte(values, "1893")),
            ("wpm_party_mode", _first_present_byte(values, "1894")),
            ("wpm_heating_circuit_mode", _first_present_byte(values, "1972")),
            ("wpm_dhw_heating", _first_present_byte(values, "5693")),
            # WKF/WPM 4.26 local MQTT commonly exposes 1082/5032/5033/5034/5039/5055
            # instead of the newer SmartWeb IDs used by the cloud profile.
            ("wpm_outdoor_temperature", _first_present_tenths(values, "5032", "5055")),
            ("wpm_mixed_temperature", _first_present_tenths(values, "5055")),
            ("wpm_water_temperature", _first_present_tenths(values, "5039")),
            ("wpm_dhw_target_temperature", _first_present_tenths(values, "1082")),
            ("wpm_temperature_adjustment", _first_present_tenths(values, "1946")),
            ("wpm_fixed_temperature", _first_present_tenths(values, "1974")),
            ("wpm_heating_water_target_temperature", _first_present_tenths(values, "5085")),
            (
                "wpm_target_temperature",
                _first_present_word(values, "5774")
                if values.get("5774") is not None
                else _first_present_tenths(values, "1082", "5033"),
            ),
            (
                "wpm_setpoint_ch",
                _first_present_word(values, "1352")
                if values.get("1352") is not None
                else _first_present_tenths(values, "5033", "1082"),
            ),
            (
                "wpm_setpoint_hp",
                _first_present_word(values, "2179")
                if values.get("2179") is not None
                else _first_present_tenths(values, "5034", "5039"),
            ),
        ):
            if value is not None:
                status[key] = value
        status["unit"] = "C"
        return status if any(key != "unit" for key in status) else None

    def build_value_write(self, overrides: dict) -> dict[str, str] | None:
        return build_value_write(
            overrides,
            (
                ValueWriteSpec("wpm_heat_cool_mode", "4110"),
                ValueWriteSpec("wpm_manual_defrost", "4113"),
                ValueWriteSpec("wpm_absence_mode", "1893"),
                ValueWriteSpec("wpm_party_mode", "1894"),
                ValueWriteSpec("wpm_heating_circuit_mode", "1972"),
                ValueWriteSpec("wpm_dhw_heating", "5693"),
                ValueWriteSpec("wpm_target_temperature", "5774", digits=4),
                ValueWriteSpec("wpm_dhw_target_temperature", "1082", digits=4, scale=10),
                ValueWriteSpec(
                    "wpm_temperature_adjustment",
                    "1946",
                    digits=4,
                    scale=10,
                    signed=True,
                ),
                ValueWriteSpec("wpm_fixed_temperature", "1974", digits=4, scale=10),
                ValueWriteSpec(
                    "wpm_heating_water_target_temperature",
                    "5085",
                    digits=4,
                    scale=10,
                ),
                ValueWriteSpec("wpm_setpoint_ch", "1352", digits=4),
                ValueWriteSpec("wpm_setpoint_hp", "2179", digits=4),
            ),
        )


class WspDeviceProfile(WpmDeviceProfile):
    """Experimental WSP heat pump profile with WSP-specific value IDs."""

    profile_name = "WSP Heat Pump"
    query_value_ids = tuple(
        value_id for value_id in WpmDeviceProfile.query_value_ids if value_id != 1951
    ) + (1088,)
    heat_cool_mode_value_ids = ("1088", "4110", "1951")
