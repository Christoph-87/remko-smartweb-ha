from __future__ import annotations

from datetime import date

from ..const import DEVICE_KIND_DHW
from .base import SmartWebDeviceProfile
from .value_mapping import ValueWriteSpec, build_value_write

DHW_MODE_VALUE_IDS = {
    "auto": 0x03,
    "eco": 0x09,
    "hybrid": 0x0A,
    "speed_heating": 0x0B,
    "vacation": 0x0C,
}
DHW_WRITE_SPECS = (
    ValueWriteSpec("setpoint", "1333", digits=4, scale=10),
    ValueWriteSpec("power", "1194", enum={True: 0x01, False: 0x02}),
    ValueWriteSpec("mode", "1192", enum=DHW_MODE_VALUE_IDS),
)
VACATION_END_DATE_REGISTER_SPECS = {
    "enabled": "rbw_register:1129",
    "year": "rbw_register:1130",
    "month": "rbw_register:1131",
    "day": "rbw_register:1132",
}


def _state_byte(hexstr: str | None):
    if not hexstr:
        return None
    try:
        bytes_ = [
            int(hexstr[index : index + 2], 16)
            for index in range(0, len(hexstr) - 1, 2)
        ]
    except Exception:
        return None
    if not bytes_:
        return None
    for value in reversed(bytes_):
        if value != 0:
            return value
    return bytes_[0]


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
    value = _state_byte(hexstr)
    return {
        0x00: "error",
        0x01: "on",
        0x02: "off",
        0x03: "auto",
        0x06: "heat",
        0x08: "timer",
        0x09: "eco",
        0x0A: "hybrid",
        0x0B: "speed_heating",
        0x0C: "vacation",
    }.get(value)


class DomesticHotWaterDeviceProfile(SmartWebDeviceProfile):
    kind = DEVICE_KIND_DHW
    supports_water_heater = True
    supports_value_write = True
    profile_name = "RBW 302 Pro"
    protocol_name = "rbw_modbus"
    sensor_descriptions = (
        ("dhw_setpoint", "DHW Setpoint", "temperature"),
        ("dhw_top_temperature", "DHW Top Temperature", "temperature"),
        ("dhw_bottom_temperature", "DHW Bottom Temperature", "temperature"),
        ("dhw_ambient_temperature", "DHW Ambient Temperature", "temperature"),
        ("dhw_mode", "DHW Mode", None),
        ("dhw_power_state", "DHW Power State", None),
        ("compressor_state", "Compressor State", None),
        ("electric_heater_state", "Electric Heater State", None),
        ("compressor_runtime", "Compressor Runtime", "diagnostic_hours"),
        ("electric_heater_runtime", "Electric Heater Runtime", "diagnostic_hours"),
    )

    def parse_values_status(self, values: dict) -> dict | None:
        if not isinstance(values, dict):
            return None
        b1152 = _state_byte(values.get("1152"))
        b1194 = _state_byte(values.get("1194"))
        dhw_mode = _dhw_mode(values.get("1192"))
        dhw_setpoint = _temperature_tenths(values.get("1333"))
        dhw_top = _temperature_tenths(values.get("5943"))
        dhw_bottom = _temperature_tenths(values.get("5944"))
        dhw_ambient = _temperature_tenths(values.get("5032"))
        dhw_current = dhw_top if dhw_top is not None else _temperature_tenths(values.get("1336"))
        compressor_state = _state_byte(values.get("5081"))
        electric_heater_state = _state_byte(values.get("6009"))
        compressor_runtime = _first_word(values.get("5946"))
        electric_heater_runtime = _first_word(values.get("5947"))
        if (
            dhw_setpoint is None
            and dhw_current is None
            and dhw_bottom is None
            and dhw_ambient is None
            and dhw_mode is None
            and b1194 is None
            and b1152 is None
            and compressor_state is None
            and electric_heater_state is None
            and compressor_runtime is None
            and electric_heater_runtime is None
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
            status["mode"] = dhw_mode
        if b1194 is not None:
            status["dhw_power_state"] = "on" if b1194 == 0x01 else ("off" if b1194 == 0x02 else None)
            status["power"] = "ON" if b1194 == 0x01 else ("OFF" if b1194 == 0x02 else None)
        if compressor_state is not None:
            status["compressor_state"] = bool(compressor_state)
        if electric_heater_state is not None:
            status["electric_heater_state"] = bool(electric_heater_state)
        if compressor_runtime is not None:
            status["compressor_runtime"] = compressor_runtime
        if electric_heater_runtime is not None:
            status["electric_heater_runtime"] = electric_heater_runtime
        if status.get("power") is None and (dhw_setpoint is not None or dhw_current is not None):
            status["power"] = "ON" if b1152 in (None, 0x01) else None
        status["unit"] = "C"
        if not any(value is not None for key, value in status.items() if key != "unit"):
            return None
        return status

    def build_value_write(self, overrides: dict) -> dict[str, str] | None:
        values = {}
        vacation_end_date = overrides.get("vacation_end_date")
        if vacation_end_date is not None:
            if isinstance(vacation_end_date, date):
                parsed_date = vacation_end_date
            else:
                parsed_date = date.fromisoformat(str(vacation_end_date))
            values.update(
                {
                    VACATION_END_DATE_REGISTER_SPECS["enabled"]: "0001",
                    VACATION_END_DATE_REGISTER_SPECS["year"]: f"{parsed_date.year % 100:04X}",
                    VACATION_END_DATE_REGISTER_SPECS["month"]: f"{parsed_date.month:04X}",
                    VACATION_END_DATE_REGISTER_SPECS["day"]: f"{parsed_date.day:04X}",
                }
            )
        values.update(build_value_write(overrides, DHW_WRITE_SPECS) or {})
        return values or None
