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


def _temperature_tenths(hexstr: str | None):
    value = _first_word(hexstr)
    if value is None or value == 0:
        return None
    temperature = value / 10
    if -50 <= temperature <= 120:
        return temperature
    return None


class DomesticHotWaterDeviceProfile(SmartWebDeviceProfile):
    kind = DEVICE_KIND_DHW
    sensor_descriptions = (
        ("dhw_setpoint", "DHW Setpoint", "temperature"),
        ("dhw_top_temperature", "DHW Top Temperature", "temperature"),
        ("dhw_bottom_temperature", "DHW Bottom Temperature", "temperature"),
    )

    def parse_values_status(self, values: dict) -> dict | None:
        if not isinstance(values, dict):
            return None
        b1152 = _first_byte(values.get("1152"))
        dhw_setpoint = _temperature_tenths(values.get("1333"))
        dhw_top = _temperature_tenths(values.get("5943"))
        dhw_bottom = _temperature_tenths(values.get("5944"))
        dhw_current = dhw_top if dhw_top is not None else _temperature_tenths(values.get("1336"))
        if (
            dhw_setpoint is None
            and dhw_current is None
            and dhw_bottom is None
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
        if status.get("power") is None and (dhw_setpoint is not None or dhw_current is not None):
            status["power"] = "ON" if b1152 in (None, 0x01) else None
        status["unit"] = "C"
        if not any(value is not None for key, value in status.items() if key != "unit"):
            return None
        return status
