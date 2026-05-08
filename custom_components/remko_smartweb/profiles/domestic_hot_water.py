from __future__ import annotations

from ..const import DEVICE_KIND_DHW
from .base import SmartWebDeviceProfile


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
        return int(hexstr[0:4], 16)
    except Exception:
        return None


def _first_signed_word(hexstr: str | None):
    value = _first_word(hexstr)
    if value is None:
        return None
    if value > 0x7FFF:
        return value - 0x10000
    return value


def _temperature_tenths(hexstr: str | None):
    value = _first_signed_word(hexstr)
    if value is None or value == 0:
        return None
    temperature = value / 10
    if -50 <= temperature <= 120:
        return temperature
    return None


def _dhw_mode(hexstr: str | None):
    value = _first_byte(hexstr)
    return {
        0x00: "error",
        0x01: "on",
        0x02: "off",
        0x03: "auto",
        0x06: "heat",
        0x08: "timer",
        0x09: "eco",
        0x0C: "vacation",
    }.get(value)


class DomesticHotWaterDeviceProfile(SmartWebDeviceProfile):
    kind = DEVICE_KIND_DHW
    supports_water_heater = True
    sensor_descriptions = (
        ("dhw_setpoint", "DHW Setpoint", "temperature"),
        ("dhw_top_temperature", "DHW Top Temperature", "temperature"),
        ("dhw_bottom_temperature", "DHW Bottom Temperature", "temperature"),
        ("dhw_ambient_temperature", "DHW Ambient Temperature", "temperature"),
        ("dhw_mode", "DHW Mode", None),
        ("dhw_power_state", "DHW Power State", None),
    )

    def parse_values_status(self, values: dict) -> dict | None:
        if not isinstance(values, dict):
            return None
        b1152 = _first_byte(values.get("1152"))
        b1194 = _first_byte(values.get("1194"))
        dhw_mode = _dhw_mode(values.get("1192"))
        dhw_setpoint = _temperature_tenths(values.get("1333"))
        dhw_top = _temperature_tenths(values.get("5943"))
        dhw_bottom = _temperature_tenths(values.get("5944"))
        dhw_ambient = _temperature_tenths(values.get("5032"))
        dhw_current = dhw_top if dhw_top is not None else _temperature_tenths(values.get("1336"))
        if (
            dhw_setpoint is None
            and dhw_current is None
            and dhw_bottom is None
            and dhw_ambient is None
            and dhw_mode is None
            and b1194 is None
            and b1152 is None
        ):
            return None

        status = {}
        if dhw_setpoint is not None:
            status["dhw_setpoint"] = dhw_setpoint
            status["setpoint"] = dhw_setpoint
            status["mode"] = "heat"
        if dhw_current is not None:
            status["dhw_top_temperature"] = dhw_current
            status["room"] = dhw_current
        if dhw_bottom is not None:
            status["dhw_bottom_temperature"] = dhw_bottom
        if dhw_ambient is not None:
            status["dhw_ambient_temperature"] = dhw_ambient
        if dhw_mode is not None:
            status["dhw_mode"] = dhw_mode
        if b1194 is not None:
            status["dhw_power_state"] = "on" if b1194 == 0x01 else ("off" if b1194 == 0x02 else None)
            status["power"] = "ON" if b1194 == 0x01 else ("OFF" if b1194 == 0x02 else None)
        if status.get("power") is None and (dhw_setpoint is not None or dhw_current is not None):
            status["power"] = "ON" if b1152 in (None, 0x01) else None
        status["unit"] = "C"
        if not any(value is not None for key, value in status.items() if key != "unit"):
            return None
        return status
