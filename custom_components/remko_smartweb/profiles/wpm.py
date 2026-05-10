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


class WpmDeviceProfile(SmartWebDeviceProfile):
    """Experimental diagnostics/write profile for WPM/WPK/WKM/SQW heat pumps."""

    kind = DEVICE_KIND_DIAGNOSTICS
    profile_name = "WPM Heat Pump"
    protocol_name = "wpm_modbus"
    diagnostics_only = True
    supports_value_write = True
    sensor_descriptions = (
        ("wpm_heat_cool_mode", "WPM Heat/Cool Mode", None),
        ("wpm_manual_defrost", "WPM Manual Defrost", None),
        ("wpm_target_temperature", "WPM Target Temperature", "temperature"),
        ("wpm_setpoint_ch", "WPM CH Setpoint", "temperature"),
        ("wpm_setpoint_hp", "WPM HP Setpoint", "temperature"),
        ("wpm_unit_on", "WPM Unit On", None),
    )
    number_descriptions = (
        ("wpm_target_temperature", "WPM Target Temperature", 0, 80, 1, "temperature"),
        ("wpm_setpoint_ch", "WPM CH Setpoint", 0, 80, 1, "temperature"),
        ("wpm_setpoint_hp", "WPM HP Setpoint", 0, 80, 1, "temperature"),
    )

    def parse_values_status(self, values: dict) -> dict | None:
        if not isinstance(values, dict):
            return None
        status = {}
        for key, value_id in (
            ("wpm_heat_cool_mode", "4110"),
            ("wpm_manual_defrost", "4113"),
            ("wpm_unit_on", "5734"),
        ):
            value = _first_byte(values.get(value_id))
            if value is not None:
                status[key] = value
        for key, value_id in (
            ("wpm_target_temperature", "5774"),
            ("wpm_setpoint_ch", "1352"),
            ("wpm_setpoint_hp", "2179"),
        ):
            value = _first_word(values.get(value_id))
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
                ValueWriteSpec("wpm_target_temperature", "5774", digits=4),
                ValueWriteSpec("wpm_setpoint_ch", "1352", digits=4),
                ValueWriteSpec("wpm_setpoint_hp", "2179", digits=4),
            ),
        )
