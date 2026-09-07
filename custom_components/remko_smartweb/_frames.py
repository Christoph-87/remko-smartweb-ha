"""Frame building and protocol parsing (CRC, UART, Modbus, etc.)."""
from __future__ import annotations

import json
import logging
from datetime import date

from ._helpers import _json_loads_maybe_wrapped, _extract_values_from_payload

_LOGGER = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants used by frame logic — imported from api.py at runtime to avoid
# circular imports at module level.  We reference them via a lazy getter so
# that api.py can import _frames.py during its own initialisation.
# ---------------------------------------------------------------------------

def _api():
    """Return the api module (lazy import avoids circular dependency)."""
    from . import api as _api_module
    return _api_module


# ---------------------------------------------------------------------------
# CRC / checksum helpers
# ---------------------------------------------------------------------------

_CRC8_TABLE = [
    0x00, 0x5E, 0xBC, 0xE2, 0x61, 0x3F, 0xDD, 0x83,
    0xC2, 0x9C, 0x7E, 0x20, 0xA3, 0xFD, 0x1F, 0x41,
    0x9D, 0xC3, 0x21, 0x7F, 0xFC, 0xA2, 0x40, 0x1E,
    0x5F, 0x01, 0xE3, 0xBD, 0x3E, 0x60, 0x82, 0xDC,
    0x23, 0x7D, 0x9F, 0xC1, 0x42, 0x1C, 0xFE, 0xA0,
    0xE1, 0xBF, 0x5D, 0x03, 0x80, 0xDE, 0x3C, 0x62,
    0xBE, 0xE0, 0x02, 0x5C, 0xDF, 0x81, 0x63, 0x3D,
    0x7C, 0x22, 0xC0, 0x9E, 0x1D, 0x43, 0xA1, 0xFF,
    0x46, 0x18, 0xFA, 0xA4, 0x27, 0x79, 0x9B, 0xC5,
    0x84, 0xDA, 0x38, 0x66, 0xE5, 0xBB, 0x59, 0x07,
    0xDB, 0x85, 0x67, 0x39, 0xBA, 0xE4, 0x06, 0x58,
    0x19, 0x47, 0xA5, 0xFB, 0x78, 0x26, 0xC4, 0x9A,
    0x65, 0x3B, 0xD9, 0x87, 0x04, 0x5A, 0xB8, 0xE6,
    0xA7, 0xF9, 0x1B, 0x45, 0xC6, 0x98, 0x7A, 0x24,
    0xF8, 0xA6, 0x44, 0x1A, 0x99, 0xC7, 0x25, 0x7B,
    0x3A, 0x64, 0x86, 0xD8, 0x5B, 0x05, 0xE7, 0xB9,
    0x8C, 0xD2, 0x30, 0x6E, 0xED, 0xB3, 0x51, 0x0F,
    0x4E, 0x10, 0xF2, 0xAC, 0x2F, 0x71, 0x93, 0xCD,
    0x11, 0x4F, 0xAD, 0xF3, 0x70, 0x2E, 0xCC, 0x92,
    0xD3, 0x8D, 0x6F, 0x31, 0xB2, 0xEC, 0x0E, 0x50,
    0xAF, 0xF1, 0x13, 0x4D, 0xCE, 0x90, 0x72, 0x2C,
    0x6D, 0x33, 0xD1, 0x8F, 0x0C, 0x52, 0xB0, 0xEE,
    0x32, 0x6C, 0x8E, 0xD0, 0x53, 0x0D, 0xEF, 0xB1,
    0xF0, 0xAE, 0x4C, 0x12, 0x91, 0xCF, 0x2D, 0x73,
    0xCA, 0x94, 0x76, 0x28, 0xAB, 0xF5, 0x17, 0x49,
    0x08, 0x56, 0xB4, 0xEA, 0x69, 0x37, 0xD5, 0x8B,
    0x57, 0x09, 0xEB, 0xB5, 0x36, 0x68, 0x8A, 0xD4,
    0x95, 0xCB, 0x29, 0x77, 0xF4, 0xAA, 0x48, 0x16,
    0xE9, 0xB7, 0x55, 0x0B, 0x88, 0xD6, 0x34, 0x6A,
    0x2B, 0x75, 0x97, 0xC9, 0x4A, 0x14, 0xF6, 0xA8,
    0x74, 0x2A, 0xC8, 0x96, 0x15, 0x4B, 0xA9, 0xF7,
    0xB6, 0xE8, 0x0A, 0x54, 0xD7, 0x89, 0x6B, 0x35,
]


def _crc8(data: list[int]) -> int:
    crc = 0
    for b in data:
        crc = _CRC8_TABLE[crc ^ b]
    return crc


def _checksum(data: list[int]) -> int:
    s = 0
    for i in range(1, len(data)):
        s += data[i]
    return 256 - (s % 256)


# ---------------------------------------------------------------------------
# ESP C0 / SET frames
# ---------------------------------------------------------------------------

def _build_status_cmd() -> str:
    """Build a status request frame (C0) for the ESP topic."""
    cmd = [
        0x41, 0x81, 0x00, 0xFF, 0x03, 0xFF,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x03
    ]
    cmd.append(_crc8(cmd))
    header = [0xAA, 0x00, 0xAC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x03]
    packet = header + cmd
    packet[1] = len(packet)
    packet.append(_checksum(packet))
    return "".join(f"{b:02X}" for b in packet)


def _bool_state(value, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.upper() == "ON"
    if value is None:
        return default
    return bool(value)


def _clamp_int(value, low: int, high: int, default: int) -> int:
    try:
        number = int(round(float(value)))
    except Exception:
        return default
    return max(low, min(high, number))


def _high_level_status(current_status: dict | None, overrides: dict) -> dict:
    status = dict(current_status or {})
    status.update({key: value for key, value in overrides.items() if value is not None})
    return status


def _bool_from_str(val: str | None) -> bool | None:
    if val is None:
        return None
    v = val.strip().lower()
    if v in ("1", "true", "on", "yes"):
        return True
    if v in ("0", "false", "off", "no"):
        return False
    return None


def _build_set_cmd_from_c0(payload: list[int], overrides: dict, beep: bool = False) -> str | None:
    """Build a SET frame by applying overrides on top of a C0 payload."""
    if not payload or payload[0] != 0xC0 or len(payload) < 22:
        return None

    b1 = payload[1] | 0x02
    if beep:
        b1 |= 0x40
    mode_map = {"auto": 1, "cool": 2, "dry": 3, "heat": 4, "fan": 5}
    mode = (payload[2] & 0xE0) >> 5
    if overrides.get("mode"):
        mode = mode_map.get(overrides["mode"], mode)

    sp = (payload[2] & 0x0F) + 16 + ((payload[2] & 0x10) >> 4) * 0.5
    if overrides.get("setpoint") is not None:
        sp = overrides["setpoint"]
    if sp > 60:
        sp = round((sp - 32) / 1.8 * 2) / 2
    b2 = (mode << 5) | (0x10 if sp % 1 else 0x00) | int(sp - 16)

    fan_raw = payload[3] & 0x7F
    # Normalize to canonical UART fan values — the AC unit rejects non-canonical values
    # (e.g. dry mode returns 0x65=101 for "auto", but the only valid auto encoding is 102)
    if fan_raw < 21:
        fan = 20
    elif fan_raw < 41:
        fan = 40
    elif fan_raw < 61:
        fan = 60
    elif fan_raw < 101:
        fan = 80
    else:
        fan = 102
    if fan_raw != fan and not overrides.get("fan"):
        _LOGGER.debug(
            "REMKO SmartWeb SET fan byte normalized: raw=0x%02X → canonical=0x%02X",
            fan_raw, fan,
        )
    if overrides.get("fan"):
        fan = {"silent": 20, "low": 40, "medium": 60, "high": 80, "auto": 102}.get(overrides["fan"], fan)
    b3 = fan

    b4 = 0x7F
    b5 = 0x7F
    b6 = 0x00

    b7 = 0x30 | (payload[7] & 0x0F)
    if overrides.get("swing"):
        s = overrides["swing"]
        if s == "off":
            b7 = 0x30
        elif s == "vertical":
            b7 = 0x30 | 0x03
        elif s == "horizontal":
            b7 = 0x30 | 0x0C
        elif s == "both":
            b7 = 0x30 | 0x0F

    b8 = payload[8]
    turbo = overrides.get("turbo")
    if turbo is not None:
        if turbo:
            b8 |= 0x20
        else:
            b8 &= ~0x20

    b9 = payload[9]
    eco = overrides.get("eco")
    if eco is not None:
        if eco:
            b9 |= 0x80
        else:
            b9 &= ~0x80
    bio = overrides.get("bioclean")
    if bio is not None:
        if bio:
            b9 |= 0x20
        else:
            b9 &= ~0x20

    b10 = payload[10]
    sleep = overrides.get("sleep")
    if sleep is not None:
        if sleep:
            b10 |= 0x01
        else:
            b10 &= ~0x01
    if turbo is not None:
        if turbo:
            b10 |= 0x02
        else:
            b10 &= ~0x02
    pwr = overrides.get("power")
    if pwr is not None:
        if pwr:
            b1 |= 0x01
        else:
            b1 &= ~0x01

    cmd = [0] * 25
    cmd[0] = 0x40
    cmd[1] = b1
    cmd[2] = b2
    cmd[3] = b3
    cmd[4] = b4
    cmd[5] = b5
    cmd[6] = b6
    cmd[7] = b7
    cmd[8] = b8
    cmd[9] = b9
    cmd[10] = b10
    cmd[11] = 0x00
    cmd[12] = 0x00
    cmd[13] = 0x00
    cmd[14] = 0x00
    cmd[15] = 0x00
    cmd[16] = 0x00
    cmd[17] = 0x00
    cmd[18] = 0x00
    cmd[19] = 0x00
    cmd[20] = 0x00
    frost_protection = overrides.get("frost_protection")
    if frost_protection is None:
        cmd[21] = payload[21] & 0x80
    elif frost_protection:
        cmd[21] = 0x80
    else:
        cmd[21] = 0x00
    cmd[22] = 0x00
    cmd[23] = 0x00
    cmd[24] = 0x00

    cmd.append(_crc8(cmd))
    header = [0xAA, 0x00, 0xAC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x02]
    packet = header + cmd
    packet[1] = len(packet)
    packet.append(_checksum(packet))
    return "".join(f"{b:02X}" for b in packet)


# ---------------------------------------------------------------------------
# RBW Modbus
# ---------------------------------------------------------------------------

def _build_rbw_get_status_cmd(register: int, quantity: int = 90) -> str | None:
    """Build the RBW raw Modbus read Tx used by RBW_query_* in the frontend."""
    if not 0 <= register <= 0xFFFF or not 1 <= quantity <= 0xFF:
        return None
    cmd = [
        0x63,
        0x03,
        (register & 0xFF00) >> 8,
        register & 0x00FF,
        quantity & 0xFF,
    ]
    return "".join(f"{b:02X}" for b in cmd)


def _parse_rbw_registers_rx(rx_hex: str | None) -> dict[int, int] | None:
    if not rx_hex:
        return None
    text = str(rx_hex).strip()
    if len(text) < 10 or len(text) % 2:
        return None
    try:
        data = [int(text[index: index + 2], 16) for index in range(0, len(text), 2)]
    except Exception:
        return None
    if len(data) < 5 or data[0] != 0x63 or data[1] != 0x03:
        return None
    start_register = (data[2] << 8) | data[3]
    quantity = data[4]
    values = {}
    for offset in range(quantity):
        value_index = 5 + (offset * 2)
        if value_index + 1 >= len(data):
            break
        values[start_register + offset] = (data[value_index] << 8) | data[value_index + 1]
    return values or None


def _rbw_temp1(value: int | None) -> float | None:
    if value is None or value == 0:
        return None
    temperature = (value - 60) * 0.5
    if -50 <= temperature <= 120:
        return temperature
    return None


def _rbw_vacation_date(year: int | None, month: int | None, day: int | None) -> str | None:
    if year is None or month is None or day is None:
        return None
    if year < 100:
        year += 2000
    try:
        return date(year, month, day).isoformat()
    except ValueError:
        return None


def _parse_rbw_register_status(registers: dict[int, int]) -> dict | None:
    if not registers:
        return None

    # Lazy import to avoid circular dependency
    api = _api()
    RBW_REGISTER_MODE_VALUES = api.RBW_REGISTER_MODE_VALUES

    dhw_setpoint = _rbw_temp1(registers.get(1104))
    dhw_top = _rbw_temp1(registers.get(2021))
    dhw_bottom = _rbw_temp1(registers.get(2020))
    dhw_ambient = _rbw_temp1(registers.get(2019))
    dhw_mode = RBW_REGISTER_MODE_VALUES.get(registers.get(1012))
    power_register = registers.get(1011)
    vacation_enabled = registers.get(1129)
    vacation_year = registers.get(1130)
    vacation_month = registers.get(1131)
    vacation_day = registers.get(1132)
    output_register = registers.get(2050)
    compressor_runtime = registers.get(2061)
    electric_heater_runtime = registers.get(2062)

    status = {}
    if dhw_setpoint is not None:
        status["dhw_setpoint"] = dhw_setpoint
        status["setpoint"] = dhw_setpoint
        status["mode"] = "heat"
    if dhw_top is not None:
        status["dhw_top_temperature"] = dhw_top
        status["room"] = dhw_top
    if dhw_bottom is not None:
        status["dhw_bottom_temperature"] = dhw_bottom
    if dhw_ambient is not None:
        status["dhw_ambient_temperature"] = dhw_ambient
    if dhw_mode is not None:
        status["dhw_mode"] = dhw_mode
        status["mode"] = dhw_mode
    if power_register is not None:
        status["dhw_power_state"] = "on" if power_register == 1 else "off"
        status["power"] = "ON" if power_register == 1 else "OFF"
    if vacation_enabled is not None:
        status["dhw_vacation_enabled"] = bool(vacation_enabled & 0x01)
    vacation_date = _rbw_vacation_date(vacation_year, vacation_month, vacation_day)
    if vacation_date is not None:
        status["dhw_vacation_end_date"] = vacation_date
    if output_register is not None:
        status["compressor_state"] = "on" if output_register & (1 << 8) else "off"
        status["electric_heater_state"] = "on" if output_register & (1 << 9) else "off"
    if compressor_runtime is not None:
        status["compressor_runtime"] = compressor_runtime
    if electric_heater_runtime is not None:
        status["electric_heater_runtime"] = electric_heater_runtime
    if status.get("power") is None and status:
        status["power"] = "ON"
    if status:
        status["unit"] = "C"
        return status
    return None


def _build_rbw_set_register_cmd(register: int, register_value: int) -> str | None:
    if not 0 <= register <= 0xFFFF or not 0 <= register_value <= 0xFFFF:
        return None
    cmd = [
        0x63,
        0x10,
        (register & 0xFF00) >> 8,
        register & 0x00FF,
        0x01,
        (register_value & 0xFF00) >> 8,
        register_value & 0x00FF,
    ]
    return "".join(f"{b:02X}" for b in cmd)


def _build_rbw_set_cmd(value_id: str, value_hex: str) -> str | None:
    """Build the RBW/KWT-style raw Modbus Tx used by the SmartWeb frontend."""
    api = _api()
    RBW_DIRECT_REGISTER_PREFIX = api.RBW_DIRECT_REGISTER_PREFIX
    RBW_VALUE_WRITE_REGISTERS = api.RBW_VALUE_WRITE_REGISTERS
    RBW_MODE_REGISTER_VALUES = api.RBW_MODE_REGISTER_VALUES

    if str(value_id).startswith(RBW_DIRECT_REGISTER_PREFIX):
        try:
            register = int(str(value_id).removeprefix(RBW_DIRECT_REGISTER_PREFIX))
            register_value = int(str(value_hex), 16)
        except Exception:
            return None
        return _build_rbw_set_register_cmd(register, register_value)
    spec = RBW_VALUE_WRITE_REGISTERS.get(str(value_id))
    if spec is None:
        return None
    try:
        id_value = int(str(value_hex), 16)
    except Exception:
        return None
    register, converter = spec
    if converter == "temp1":
        temperature = id_value / 10
        register_value = round((temperature / 0.5) + 60)
    elif converter == "power":
        register_value = 1 if id_value == 0x01 else 0 if id_value == 0x02 else None
    elif converter == "mode":
        register_value = RBW_MODE_REGISTER_VALUES.get(id_value)
    else:
        register_value = None
    if register_value is None or not 0 <= register_value <= 0xFFFF:
        return None
    cmd = [
        0x63,
        0x10,
        (register & 0xFF00) >> 8,
        register & 0x00FF,
        0x01,
        (register_value & 0xFF00) >> 8,
        register_value & 0x00FF,
    ]
    return "".join(f"{b:02X}" for b in cmd)


# ---------------------------------------------------------------------------
# Generic Modbus
# ---------------------------------------------------------------------------

def _modbus_crc16(data: list[int]) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


def _build_modbus_write_register_cmd(addr: int, register: int, value: int) -> str | None:
    if not 0 <= value <= 0xFFFF:
        return None
    cmd = [
        addr & 0xFF,
        0x10,
        (register & 0xFF00) >> 8,
        register & 0x00FF,
        0x00,
        0x01,
        0x02,
        (value & 0xFF00) >> 8,
        value & 0x00FF,
    ]
    crc = _modbus_crc16(cmd)
    cmd.extend([crc & 0x00FF, (crc & 0xFF00) >> 8])
    return "".join(f"{b:02X}" for b in cmd)


def _build_modbus_write_coil_cmd(addr: int, register: int, value: int) -> str | None:
    if value not in (0, 1):
        return None
    register_value = 0xFF00 if value else 0x0000
    cmd = [
        addr & 0xFF,
        0x05,
        (register & 0xFF00) >> 8,
        register & 0x00FF,
        (register_value & 0xFF00) >> 8,
        register_value & 0x00FF,
    ]
    crc = _modbus_crc16(cmd)
    cmd.extend([crc & 0x00FF, (crc & 0xFF00) >> 8])
    return "".join(f"{byte & 0xFF:02X}" for byte in cmd)


def _build_modbus_read_cmd(addr: int, function_code: int, register: int, quantity: int) -> str | None:
    if function_code not in (1, 3):
        return None
    if not 0 <= register <= 0xFFFF or not 1 <= quantity <= 0xFFFF:
        return None
    cmd = [
        addr & 0xFF,
        function_code & 0xFF,
        (register & 0xFF00) >> 8,
        register & 0x00FF,
        (quantity & 0xFF00) >> 8,
        quantity & 0x00FF,
    ]
    crc = _modbus_crc16(cmd)
    cmd.extend([crc & 0x00FF, (crc & 0xFF00) >> 8])
    return "".join(f"{b:02X}" for b in cmd)


def _parse_modbus_holding_rx(rx_hex: str | None, start_register: int) -> dict[int, int] | None:
    if not rx_hex:
        return None
    text = str(rx_hex).strip()
    if len(text) < 10 or len(text) % 2:
        return None
    try:
        data = [int(text[index: index + 2], 16) for index in range(0, len(text), 2)]
    except Exception:
        return None
    if len(data) < 5 or data[1] != 0x03:
        return None
    byte_count = data[2]
    if byte_count <= 0:
        return None
    values = {}
    for offset in range(byte_count // 2):
        value_index = 3 + (offset * 2)
        if value_index + 1 >= len(data) - 2:
            break
        raw = (data[value_index] << 8) | data[value_index + 1]
        if raw > 0x7FFF:
            raw -= 0x10000
        values[start_register + offset] = raw
    return values or None


def _parse_modbus_coils_rx(rx_hex: str | None, start_register: int, quantity: int) -> dict[int, int] | None:
    if not rx_hex:
        return None
    text = str(rx_hex).strip()
    if len(text) < 8 or len(text) % 2:
        return None
    try:
        data = [int(text[index: index + 2], 16) for index in range(0, len(text), 2)]
    except Exception:
        return None
    if len(data) < 5 or data[1] != 0x01:
        return None
    byte_count = data[2]
    values = {}
    for offset in range(quantity):
        byte_index = 3 + (offset // 8)
        if byte_index >= 3 + byte_count or byte_index >= len(data) - 2:
            break
        values[start_register + offset] = 1 if data[byte_index] & (1 << (offset % 8)) else 0
    return values or None


# ---------------------------------------------------------------------------
# Hex encode helpers
# ---------------------------------------------------------------------------

def _hex_byte(value: int | None) -> str | None:
    if value is None:
        return None
    return f"{max(0, min(0xFF, int(value))):02X}"


def _hex_word(value: int | None) -> str | None:
    if value is None:
        return None
    return f"{int(value) & 0xFFFF:04X}"


# ---------------------------------------------------------------------------
# KWT Modbus
# ---------------------------------------------------------------------------

def _parse_kwt_register_status(registers: dict[int, int]) -> dict[str, str] | None:
    if not registers:
        return None
    api = _api()
    KWT_REGISTER_MODE_VALUES = api.KWT_REGISTER_MODE_VALUES
    KWT_REGISTER_FAN_VALUES = api.KWT_REGISTER_FAN_VALUES

    values = {}
    power = registers.get(10000)
    if power is not None:
        values["1194"] = "01" if power == 1 else "02"
    mode = KWT_REGISTER_MODE_VALUES.get(registers.get(10001))
    if mode is not None:
        values["1192"] = f"{mode:02X}"
    fan = KWT_REGISTER_FAN_VALUES.get(registers.get(10002))
    if fan is not None:
        values["1191"] = f"{fan:02X}"
    setpoint = registers.get(10010)
    if setpoint is not None:
        values["1190"] = f"{round((setpoint / 10) * 2):02X}"
    swing = registers.get(10020)
    if swing is not None:
        values["1193"] = "04" if swing else "00"
    room = registers.get(11010)
    if room is not None:
        values["5530"] = f"{round((room / 10) * 2 + 40):02X}"
    for value_id, register in (
        ("5000", 11000),
        ("5315", 198),
        ("5534", 199),
    ):
        encoded = _hex_word(registers.get(register))
        if encoded is not None:
            values[value_id] = encoded
    return values or None


def _build_kwt_set_cmd(value_id: str, value_hex: str) -> str | None:
    """Build the KWT raw Modbus Tx used by the SmartWeb frontend."""
    api = _api()
    KWT_VALUE_WRITE_REGISTERS = api.KWT_VALUE_WRITE_REGISTERS
    KWT_MODE_REGISTER_VALUES = api.KWT_MODE_REGISTER_VALUES
    KWT_FAN_REGISTER_VALUES = api.KWT_FAN_REGISTER_VALUES
    KWT_SWING_REGISTER_VALUES = api.KWT_SWING_REGISTER_VALUES

    spec = KWT_VALUE_WRITE_REGISTERS.get(str(value_id))
    if spec is None:
        return None
    try:
        id_value = int(str(value_hex), 16)
    except Exception:
        return None
    register, converter = spec
    if converter == "temp":
        register_value = id_value * 5
    elif converter == "power":
        register_value = 1 if id_value == 0x01 else 0 if id_value == 0x02 else None
    elif converter == "mode":
        register_value = KWT_MODE_REGISTER_VALUES.get(id_value)
    elif converter == "fan":
        register_value = KWT_FAN_REGISTER_VALUES.get(id_value, 0)
    elif converter == "swing":
        register_value = KWT_SWING_REGISTER_VALUES.get(id_value, 0)
    else:
        register_value = None
    if register_value is None:
        return None
    return _build_modbus_write_register_cmd(1, register, register_value)


# ---------------------------------------------------------------------------
# WPM Modbus
# ---------------------------------------------------------------------------

WPM_VALUE_WRITE_REGISTERS = {
    # SmartWeb value id: (Modbus register, register type)
    # Matches docs/lib.ac.uart.js WPM_convertDataForImport + WPM_setStatus.
    "4110": (73, "COIL"),
    "4113": (88, "COIL"),
    "5774": (50, "HOLDING"),
    "1352": (415, "HOLDING"),
    "2179": (416, "HOLDING"),
}


def _parse_wpm_register_status(coils: dict[int, int], holding: dict[int, int]) -> dict[str, str] | None:
    values = {}
    for value_id, register in (
        ("5734", 47),
        ("4110", 73),
        ("4113", 82),
    ):
        encoded = _hex_byte(coils.get(register))
        if encoded is not None:
            values[value_id] = encoded
    for value_id, register in (
        ("5774", 50),
        ("1352", 415),
        ("2179", 416),
    ):
        encoded = _hex_word(holding.get(register))
        if encoded is not None:
            values[value_id] = encoded
    return values or None


def _build_wpm_set_cmd(value_id: str, value_hex: str) -> str | None:
    spec = WPM_VALUE_WRITE_REGISTERS.get(str(value_id))
    if spec is None:
        return None
    try:
        value = int(str(value_hex), 16)
    except Exception:
        return None
    register, register_type = spec
    if register_type == "COIL":
        return _build_modbus_write_coil_cmd(1, register, value)
    if register_type == "HOLDING":
        return _build_modbus_write_register_cmd(1, register, value)
    return None


# ---------------------------------------------------------------------------
# Free / AUX / NWT AC UART
# ---------------------------------------------------------------------------

def _free_checksum(data: list[int]) -> int:
    return (256 - (sum(data) % 256)) & 0xFF


def _build_free_ac_uart_set_cmd(current_status: dict | None, overrides: dict) -> str | None:
    """Build the RKL 495 / Freecom ESP Tx frame used by Free_setStatus()."""
    status = _high_level_status(current_status, overrides)
    mode_map = {"fan": 0, "cool": 1, "dry": 2}
    fan_map = {"medium": 0, "low": 1, "high": 2, "auto": 3, "silent": 1}
    if "mode" in overrides and overrides.get("mode") not in mode_map:
        return None
    if "fan" in overrides and overrides.get("fan") not in fan_map:
        return None
    mode = mode_map.get(status.get("mode"), 1)
    fan = fan_map.get(status.get("fan"), 3)
    swing = 1 if status.get("swing") in ("vertical", "both") else 0
    cmd = [
        0xFC,
        0x01,
        0x01 if _bool_state(status.get("power"), True) else 0x00,
        _clamp_int(status.get("setpoint"), 16, 30, 24),
        _clamp_int(status.get("room"), 0, 60, 25),
        mode,
        fan,
        swing,
        0x00,
        0x00,
        _clamp_int(status.get("compressor_rpm"), 0, 255, 0),
        _clamp_int(status.get("tank"), 0, 255, 0),
        _clamp_int(status.get("error"), 0, 255, 0),
    ]
    cmd.append(_free_checksum(cmd))
    return "".join(f"{byte & 0xFF:02X}" for byte in cmd)


def _aux_checksum(data: list[int]) -> int:
    cksum = 0
    length = len(data) - 2
    i = 0
    while i < length:
        if i + 2 > length:
            cksum += data[i]
        else:
            cksum += (data[i + 1] << 8) | data[i]
        i += 2
    cksum = (cksum >> 16) + (cksum & 0xFFFF)
    cksum += cksum >> 16
    cksum ^= 0xFFFF
    return ((cksum >> 8) | ((cksum & 0xFF) << 8)) & 0xFFFF


def _build_aux_ac_uart_set_cmd(current_status: dict | None, overrides: dict) -> str | None:
    """Build the BL/AUX ESP Tx frame used by Aux_setStatus()."""
    status = _high_level_status(current_status, overrides)
    setpoint = _clamp_int(status.get("setpoint"), 8, 39, 24)
    aux_set_temp = max(0, min(31, setpoint - 8))
    aux_set_temp_dec = 0
    fan_map = {"high": 1, "medium": 2, "low": 3, "auto": 5, "silent": 3}
    mode_map = {"auto": 0, "cool": 1, "dry": 2, "heat": 4, "fan": 6}
    if "mode" in overrides and overrides.get("mode") not in mode_map:
        return None
    if "fan" in overrides and overrides.get("fan") not in fan_map:
        return None
    fan = fan_map.get(status.get("fan"), 5)
    mode = mode_map.get(status.get("mode"), 0)
    swing = status.get("swing")
    if swing == "vertical":
        swing_up_down, swing_left_right = 0, 3
    elif swing == "horizontal":
        swing_up_down, swing_left_right = 7, 0
    elif swing == "both":
        swing_up_down, swing_left_right = 0, 0
    else:
        swing_up_down, swing_left_right = 7, 3
    power = 1 if _bool_state(status.get("power"), True) else 0
    cmd = [0] * 25
    cmd[0] = 0xBB
    cmd[1] = 0x00
    cmd[2] = 0x06
    cmd[3] = 0x80
    cmd[4] = 0x00
    cmd[5] = 0x00
    cmd[6] = 0x0F
    cmd[7] = 0x00
    cmd[8] = 0x01
    cmd[9] = 0x01
    cmd[10] = (aux_set_temp << 3) | swing_up_down
    cmd[11] = (swing_left_right << 5)
    cmd[12] = 0x00
    cmd[13] = (fan << 5)
    cmd[14] = (int(bool(status.get("sleep"))) << 7) | (int(bool(status.get("turbo"))) << 6)
    cmd[15] = (mode << 5)
    cmd[16] = _clamp_int(status.get("room"), 0, 63, 0)
    cmd[17] = 0x00
    cmd[18] = (
        (power << 5)
        | (int(bool(status.get("eco"))) << 3)
        | (int(bool(status.get("bioclean"))) << 1)
    )
    cmd[19] = 0x00
    cmd[20] = 0x00
    cmd[21] = 0x00
    cmd[22] = aux_set_temp_dec
    fcc = _aux_checksum(cmd)
    cmd[23] = (fcc >> 8) & 0xFF
    cmd[24] = fcc & 0xFF
    return "".join(f"{byte & 0xFF:02X}" for byte in cmd)


def _nwt_checksum(data: list[int]) -> int:
    return sum(data) % 256


def _nwt_frame(dp: int, payload: list[int]) -> str:
    if len(payload) == 1:
        cmd = [0x55, 0xAA, 0x00, 0x06, 0x00, 0x05, dp, 0x01 if dp in (0x01, 0x10, 0x11, 0x12) else 0x04, 0x00, 0x01, payload[0]]
    else:
        cmd = [0x55, 0xAA, 0x00, 0x06, 0x00, 0x08, dp, 0x02, 0x00, 0x04, *payload]
    cmd.append(_nwt_checksum(cmd))
    return "".join(f"{byte & 0xFF:02X}" for byte in cmd)


def _build_nwt_ac_uart_set_cmds(current_status: dict | None, overrides: dict) -> list[str]:
    """Build the RKL 355 / NWT ESP Tx frames used by NWT_setStatus()."""
    cmds: list[str] = []
    fan_map = {"low": 0x00, "medium": 0x01, "high": 0x02, "silent": 0x00}
    mode_map = {"cool": 0x00, "dry": 0x01, "fan": 0x02}
    if "fan" in overrides and overrides.get("fan") not in fan_map:
        return []
    if "mode" in overrides and overrides.get("mode") not in mode_map:
        return []
    if "setpoint" in overrides:
        temp = _clamp_int(overrides.get("setpoint"), 16, 32, 24)
        cmds.append(_nwt_frame(0x02, [0x00, 0x00, 0x00, temp]))
    if "fan" in overrides:
        cmds.append(_nwt_frame(0x05, [fan_map[overrides.get("fan")]]))
    if "mode" in overrides:
        cmds.append(_nwt_frame(0x04, [mode_map[overrides.get("mode")]]))
    if "swing" in overrides:
        swing = 0x01 if overrides.get("swing") in ("vertical", "both") else 0x00
        cmds.append(_nwt_frame(0x11, [swing]))
    if "power" in overrides:
        cmds.append(_nwt_frame(0x01, [0x01 if bool(overrides.get("power")) else 0x00]))
    return cmds


def _build_ac_uart_set_cmds(protocol_name: str, current_status: dict | None, overrides: dict) -> list[str]:
    if protocol_name == "free_ac_uart":
        tx = _build_free_ac_uart_set_cmd(current_status, overrides)
        return [tx] if tx else []
    if protocol_name == "aux_ac_uart":
        tx = _build_aux_ac_uart_set_cmd(current_status, overrides)
        return [tx] if tx else []
    if protocol_name == "nwt_ac_uart":
        return _build_nwt_ac_uart_set_cmds(current_status, overrides)
    return []


# ---------------------------------------------------------------------------
# LTE dehumidifier
# ---------------------------------------------------------------------------

def _build_lte_set_cmd(current_status: dict | None, values: dict[str, str]) -> str | None:
    """Build the LTE ESP Tx frame used by LTE_setStatus()."""
    status = dict(current_status or {})
    power = 0x01 if status.get("power") == "ON" else 0x00
    humidity = _clamp_int(status.get("target_humidity"), 30, 70, 50)
    if "1194" in values:
        try:
            value = int(str(values["1194"]), 16)
        except Exception:
            return None
        if value not in (0x01, 0x02):
            return None
        power = 0x01 if value == 0x01 else 0x00
    if "1302" in values:
        try:
            humidity = int(str(values["1302"]), 16)
        except Exception:
            return None
        if humidity != 0 and not 30 <= humidity <= 70:
            return None
    cmd = [0xFC, 0xD0, 0x01, 0x01, power, humidity]
    cmd.append(_free_checksum(cmd))
    return "".join(f"{byte & 0xFF:02X}" for byte in cmd)
