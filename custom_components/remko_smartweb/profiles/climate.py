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
        if b1194 is None and b1190 is None and b5530 is None:
            return None

        status = {}
        if b1194 is not None:
            status["power"] = "ON" if b1194 == 0x01 else ("OFF" if b1194 == 0x02 else None)
        if b1190 is not None:
            status["setpoint"] = b1190 / 2
        if b5530 is not None:
            status["room"] = (b5530 - 40) / 2
        status["unit"] = "C"
        if not any(value is not None for key, value in status.items() if key != "unit"):
            return None
        return status
