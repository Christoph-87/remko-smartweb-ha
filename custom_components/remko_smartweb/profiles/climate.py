from __future__ import annotations

from ..const import DEVICE_KIND_CLIMATE
from .base import SmartWebDeviceProfile


def _hex_to_bytes(hexstr: str):
    hexstr = hexstr.strip()
    if len(hexstr) % 2 != 0:
        return None
    try:
        return [int(hexstr[i:i + 2], 16) for i in range(0, len(hexstr), 2)]
    except Exception:
        return None


def _first_byte(hexstr: str | None):
    if not hexstr:
        return None
    try:
        return int(hexstr[0:2], 16)
    except Exception:
        return None


MODE_BY_VALUE_ID = {
    0x03: "auto",
    0x04: "cool",
    0x05: "dry",
    0x06: "heat",
    0x07: "fan",
}
FAN_BY_VALUE_ID = {
    0x02: "auto",
    0x03: "low",
    0x04: "medium",
    0x05: "high",
    0x06: "silent",
    0x0D: "high",
}
SWING_BY_VALUE_ID = {
    0x00: "off",
    0x01: "vertical",
    0x02: "horizontal",
    0x03: "both",
    0x04: "vertical",
}


def _first_reverse(mapping: dict[int, str]) -> dict[str, int]:
    reversed_mapping = {}
    for value, name in mapping.items():
        reversed_mapping.setdefault(name, value)
    return reversed_mapping


MODE_VALUE_IDS = _first_reverse(MODE_BY_VALUE_ID)
FAN_VALUE_IDS = _first_reverse(FAN_BY_VALUE_ID)
SWING_VALUE_IDS = _first_reverse(SWING_BY_VALUE_ID)


def _mode_from_value_id(value: int | None):
    return MODE_BY_VALUE_ID.get(value)


def _fan_from_value_id(value: int | None):
    return FAN_BY_VALUE_ID.get(value)


def _swing_from_value_id(value: int | None):
    return SWING_BY_VALUE_ID.get(value)


class ClimateDeviceProfile(SmartWebDeviceProfile):
    kind = DEVICE_KIND_CLIMATE
    supports_climate = True
    sensor_descriptions = (
        ("room", "Room Temperature", "temperature"),
        ("outdoor", "Outdoor Temperature", "temperature"),
        ("setpoint", "Setpoint", "temperature"),
        ("error", "Error Code", None),
    )

    def parse_c0_status(self, rx_hex: str) -> dict | None:
        data = _hex_to_bytes(rx_hex)
        if not data or len(data) < 20:
            return None
        if data[0] != 0xAA:
            return None
        payload = data[10:-2]
        if not payload or payload[0] != 0xC0:
            return None

        pwr = (payload[1] & 0x01) > 0
        mode_raw = (payload[2] & 0xE0) >> 5
        setpoint = (payload[2] & 0x0F) + 16 + ((payload[2] & 0x10) >> 4) * 0.5
        fan_raw = payload[3] & 0x7F
        vertical = (payload[7] & 0x03) > 0
        horizontal = (payload[7] & 0x0C) > 0
        eco = ((payload[9] & 0x10) >> 4) > 0
        turbo = ((payload[10] & 0x02) >> 1) > 0
        sleep = (payload[10] & 0x01) > 0
        indoor = (payload[11] - 50) / 2
        outdoor = (payload[12] - 50) / 2
        error = payload[16]
        temp_unit_f = ((payload[10] & 0x04) >> 2) > 0

        mode_map = {1: "auto", 2: "cool", 3: "dry", 4: "heat", 5: "fan"}
        mode = mode_map.get(mode_raw, f"mode{mode_raw}")

        if fan_raw < 21:
            fan = "silent"
        elif fan_raw < 41:
            fan = "low"
        elif fan_raw < 61:
            fan = "medium"
        elif fan_raw < 101:
            fan = "high"
        else:
            fan = "auto"

        if vertical and horizontal:
            swing = "both"
        elif vertical:
            swing = "vertical"
        elif horizontal:
            swing = "horizontal"
        else:
            swing = "off"

        unit = "F" if temp_unit_f else "C"
        if temp_unit_f:
            setpoint = round(setpoint * 1.8 + 32, 1)
            indoor = round(indoor * 1.8 + 32, 1)
            outdoor = round(outdoor * 1.8 + 32, 1)

        return {
            "power": "ON" if pwr else "OFF",
            "setpoint": setpoint,
            "room": indoor,
            "mode": mode,
            "fan": fan,
            "swing": swing,
            "eco": eco,
            "turbo": turbo,
            "sleep": sleep,
            "outdoor": outdoor,
            "error": error,
            "unit": unit,
            "_payload": payload,
        }

    def parse_values_status(self, values: dict) -> dict | None:
        if not isinstance(values, dict):
            return None
        b1194 = _first_byte(values.get("1194"))
        b1190 = _first_byte(values.get("1190"))
        b5530 = _first_byte(values.get("5530"))
        b1192 = _first_byte(values.get("1192"))
        b1191 = _first_byte(values.get("1191"))
        b1193 = _first_byte(values.get("1193"))
        has_climate_core = b1190 is not None or b5530 is not None or b1191 is not None or b1193 is not None
        has_dhw_values = any(values.get(value_id) is not None for value_id in ("1333", "5032", "5943", "5944"))
        if has_dhw_values and not has_climate_core:
            return None
        if b1194 is None and not has_climate_core and b1192 is None:
            return None

        status = {}
        if b1194 is not None:
            status["power"] = "ON" if b1194 == 0x01 else ("OFF" if b1194 == 0x02 else None)
        if b1190 is not None:
            status["setpoint"] = b1190 / 2
        if b5530 is not None:
            status["room"] = (b5530 - 40) / 2
        mode = _mode_from_value_id(b1192)
        if mode is not None:
            status["mode"] = mode
        fan = _fan_from_value_id(b1191)
        if fan is not None:
            status["fan"] = fan
        swing = _swing_from_value_id(b1193)
        if swing is not None:
            status["swing"] = swing
        for key, value_id in (
            ("eco", "1046"),
            ("turbo", "1218"),
            ("sleep", "1228"),
            ("bioclean", "1229"),
        ):
            value = _first_byte(values.get(value_id))
            if value is not None:
                status[key] = value == 0x01
        status["unit"] = "C"
        if not any(value is not None for key, value in status.items() if key != "unit"):
            return None
        return status
