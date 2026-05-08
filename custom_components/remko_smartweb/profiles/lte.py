from __future__ import annotations

from ..const import DEVICE_KIND_DIAGNOSTICS
from .base import SmartWebDeviceProfile


def looks_like_lte_name(device_name: str | None) -> bool:
    name = (device_name or "").casefold()
    return "lte" in name


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


def _tenths_temperature(hexstr: str | None):
    value = _first_word(hexstr)
    if value is None:
        return None
    temperature = value / 10
    if -50 <= temperature <= 120:
        return temperature
    return None


def _power(hexstr: str | None):
    value = _first_byte(hexstr)
    if value == 0x01:
        return "ON"
    if value == 0x02:
        return "OFF"
    return None


class LteDeviceProfile(SmartWebDeviceProfile):
    """Read-only profile for LTE / dehumidifier-style Smart-Web devices."""

    kind = DEVICE_KIND_DIAGNOSTICS
    sensor_descriptions = (
        ("target_humidity", "Target Humidity", "percentage"),
        ("internal_humidity", "Internal Humidity", "percentage"),
        ("internal_temperature", "Internal Temperature", "temperature"),
        ("external_humidity", "External Humidity", "percentage"),
        ("external_temperature", "External Temperature", "temperature"),
        ("evaporator_temperature", "Evaporator Temperature", "temperature"),
        ("condenser_temperature", "Condenser Temperature", "temperature"),
        ("tank_state", "Tank State", None),
        ("filter_state", "Filter State", None),
        ("defrost_state", "Defrost State", None),
        ("compressor_state", "Compressor State", None),
        ("runtime", "Runtime", None),
        ("energy", "Energy", None),
        ("error", "Error Code", None),
    )

    def parse_values_status(self, values: dict) -> dict | None:
        if not isinstance(values, dict):
            return None
        if not any(values.get(value_id) is not None for value_id in ("1302", "5769", "5928", "5930", "5931")):
            return None

        status = {}
        power = _power(values.get("1194"))
        if power is not None:
            status["power"] = power
        for key, value_id in (
            ("target_humidity", "1302"),
            ("internal_humidity", "5769"),
            ("external_humidity", "5930"),
            ("tank_state", "5927"),
            ("filter_state", "5929"),
            ("defrost_state", "5626"),
            ("compressor_state", "5628"),
            ("runtime", "5982"),
            ("energy", "5933"),
            ("error", "5195"),
        ):
            value = _number(values.get(value_id))
            if value is not None:
                status[key] = value
        for key, value_id in (
            ("internal_temperature", "5928"),
            ("external_temperature", "5931"),
            ("evaporator_temperature", "5490"),
            ("condenser_temperature", "5932"),
        ):
            value = _tenths_temperature(values.get(value_id))
            if value is not None:
                status[key] = value
        status["unit"] = "C"
        return status if any(key != "unit" for key in status) else None
