from __future__ import annotations

from ..const import DEVICE_KIND_DIAGNOSTICS
from .base import SmartWebDeviceProfile
from .climate import (
    FAN_VALUE_IDS,
    MODE_VALUE_IDS,
    _fan_from_value_id,
    _mode_from_value_id,
)
from .value_mapping import ValueWriteSpec, build_value_write

KWT_SWING_BY_VALUE_ID = {
    0x00: "off",
    0x04: "vertical",
}
KWT_SWING_VALUE_IDS = {mode: value for value, mode in KWT_SWING_BY_VALUE_ID.items()}
KWT_WRITE_SPECS = (
    ValueWriteSpec("setpoint", "1190", scale=2),
    ValueWriteSpec("power", "1194", enum={True: 0x01, False: 0x02}),
    ValueWriteSpec("mode", "1192", enum=MODE_VALUE_IDS),
    ValueWriteSpec("fan", "1191", enum=FAN_VALUE_IDS),
    ValueWriteSpec("swing", "1193", enum=KWT_SWING_VALUE_IDS),
)


def looks_like_kwt_name(device_name: str | None) -> bool:
    return "kwt" in (device_name or "").casefold()


def _first_byte(hexstr: str | None):
    if not hexstr:
        return None
    try:
        return int(hexstr[0:2], 16)
    except Exception:
        return None


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


def _number(hexstr: str | None):
    if not hexstr:
        return None
    if len(hexstr) <= 2:
        return _first_byte(hexstr)
    return _first_word(hexstr)


class KwtDeviceProfile(SmartWebDeviceProfile):
    """Profile for KWT 180-300 DC devices exposed through Smart-Web values."""

    kind = DEVICE_KIND_DIAGNOSTICS
    supports_climate = True
    supports_climate_write = True
    supports_value_write = True
    supports_climate_presets = False
    profile_name = "KWT 180 - 300 DC"
    protocol_name = "kwt_modbus"
    sensor_descriptions = (
        ("room", "Room Temperature", "temperature"),
        ("setpoint", "Setpoint", "temperature"),
        ("mode", "Mode", None),
        ("fan", "Fan", None),
        ("swing", "Swing", None),
        ("filter_state", "Filter State", None),
        ("frost_protection", "Frost Protection", None),
        ("error", "Error Code", None),
        ("firmware", "Firmware", None),
        ("device_id", "Device ID", None),
    )

    def parse_values_status(self, values: dict) -> dict | None:
        if not isinstance(values, dict):
            return None
        if not any(values.get(value_id) is not None for value_id in ("1190", "1191", "1192", "1194", "5530", "5539")):
            return None

        status = {}
        power = _first_byte(values.get("1194"))
        if power is not None:
            status["power"] = "ON" if power == 0x01 else ("OFF" if power == 0x02 else None)
        setpoint = _first_byte(values.get("1190"))
        if setpoint is not None:
            status["setpoint"] = setpoint / 2
        room = _first_byte(values.get("5530"))
        if room is not None:
            status["room"] = (room - 40) / 2
        mode = _mode_from_value_id(_first_byte(values.get("1192")))
        if mode is not None:
            status["mode"] = mode
        fan = _fan_from_value_id(_first_byte(values.get("1191")))
        if fan is not None:
            status["fan"] = fan
        swing = KWT_SWING_BY_VALUE_ID.get(_first_byte(values.get("1193")))
        if swing is not None:
            status["swing"] = swing
        for key, value_id in (
            ("filter_state", "5539"),
            ("frost_protection", "1199"),
            ("error", "5000"),
            ("firmware", "5315"),
            ("device_id", "5534"),
        ):
            value = _number(values.get(value_id))
            if value is not None:
                status[key] = value
        status["unit"] = "C"
        return status if any(key != "unit" for key in status) else None

    def build_value_write(self, overrides: dict) -> dict[str, str] | None:
        return build_value_write(overrides, KWT_WRITE_SPECS)
