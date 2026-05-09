from __future__ import annotations

import json
import logging
import random
import re
import ssl
import threading
import time
from collections import deque
from urllib.parse import urljoin, urlparse, parse_qs

import requests
import paho.mqtt.client as mqtt

from .const import DEVICE_KIND_AUTO
from .profiles import get_parser_profile, get_specialized_profile

BASE = "https://smartweb.remko.media"
LOGIN_URL = f"{BASE}/rest/login_do"
WSS_HOST = "smartweb.remko.media"
WSS_PORT = 8083
WSS_PATH = "/mqtt"
VERSION = "V04P27"
LOGIN_TTL_SEC = 10 * 60
DEVICE_LIST_TTL_SEC = 60
ACCOUNT_REQUEST_MIN_INTERVAL_SEC = 0.5
DEBUG_PAYLOAD_LIMIT = 2000
DEBUG_VALUES_LIMIT = 200000
REDACTED = "<redacted>"
VALUE_STATUS_QUERY_LIST = [
    # Common AC / KWT values observed in the REMKO Smart-Web frontend.
    1046,
    1190,
    1191,
    1192,
    1193,
    1194,
    1218,
    1228,
    1229,
    1451,
    3024,
    5000,
    5315,
    5530,
    5532,
    5534,
    5539,
    # Smart-Web / DHW / RBW values.
    1152,
    1176,
    1177,
    1178,
    1333,
    1336,
    1453,
    1454,
    5032,
    5943,
    5944,
    # LTE / dehumidifier-style values.
    1302,
    5195,
    5490,
    5628,
    5769,
    5927,
    5928,
    5929,
    5930,
    5931,
    5932,
    5933,
    5982,
]
RBW_VALUE_WRITE_REGISTERS = {
    # SmartWeb value id: (Modbus register, converter)
    # Matches docs/lib.ac.uart.js RBW_convertDataForImport + RBW_setStatus.
    "1194": (1011, "power"),
    "1192": (1012, "mode"),
    "1333": (1104, "temp1"),
}
RBW_MODE_REGISTER_VALUES = {
    0x03: 0,  # auto / intelligent
    0x09: 2,  # eco / economic
    0x0A: 3,  # hybrid
    0x0B: 4,  # speed heating / high demand
    0x0C: 7,  # vacation
}
KWT_VALUE_WRITE_REGISTERS = {
    # SmartWeb value id: (Modbus register, converter)
    # Matches docs/lib.ac.uart.js KWT_convertDataForImport + KWT_setStatus.
    "1194": (10000, "power"),
    "1192": (10001, "mode"),
    "1191": (10002, "fan"),
    "1190": (10010, "temp"),
    "1193": (10020, "swing"),
}
KWT_MODE_REGISTER_VALUES = {
    0x03: 0,  # auto / auto_changeover
    0x04: 2,  # cool
    0x05: 4,  # dry / dehumidify
    0x06: 1,  # heat
    0x07: 3,  # fan only
}
KWT_FAN_REGISTER_VALUES = {
    0x02: 0,  # auto
    0x03: 1,  # low
    0x04: 2,  # medium
    0x05: 3,  # high
    0x0D: 4,  # boost
}
KWT_SWING_REGISTER_VALUES = {
    0x00: 0,  # off / default
    0x04: 1,  # swing on
}


def _value_query_list(extra_ids=()) -> list[int]:
    values = []
    seen = set()
    for value_id in list(VALUE_STATUS_QUERY_LIST) + [
        int(value_id) for value_id in extra_ids if str(value_id).isdigit()
    ]:
        if value_id in seen:
            continue
        seen.add(value_id)
        values.append(value_id)
    return values


SENSITIVE_DEBUG_KEYS = {
    "access_key",
    "accesskey",
    "client_id",
    "cookie",
    "email",
    "passwort",
    "password",
    "phpsessid",
    "secret",
    "sid",
    "sk",
    "smt_user",
    "token",
}

_LOGGER = logging.getLogger(__name__)
_ACCOUNT_REQUEST_LOCK = threading.Lock()
_ACCOUNT_LAST_REQUEST_AT = 0.0

# ----------------- helpers -----------------

def _pace_account_request() -> None:
    global _ACCOUNT_LAST_REQUEST_AT
    with _ACCOUNT_REQUEST_LOCK:
        wait = ACCOUNT_REQUEST_MIN_INTERVAL_SEC - (time.time() - _ACCOUNT_LAST_REQUEST_AT)
        if wait > 0:
            time.sleep(wait)
        _ACCOUNT_LAST_REQUEST_AT = time.time()


def _normalize_device_name(name: str | None) -> str:
    if not name:
        return ""
    normalized = name.casefold()
    normalized = normalized.replace("–", "-").replace("—", "-")
    normalized = re.sub(r"\s+", " ", normalized)
    return normalized.strip()


def _redact_debug_text(text: str) -> str:
    """Mask likely credentials and session identifiers before logging."""
    replacements = (
        (r"([?&](?:SID|SK)=)[^&\s\"']+", rf"\1{REDACTED}"),
        (r"(V\d{2}P\d{2}/)[0-9A-Fa-f]{16}", rf"\1{REDACTED}"),
        (r"([\"']?(?:SID|SK)[\"']?\s*[:=]\s*[\"']?)[0-9A-Fa-f]{16}([\"']?)", rf"\1{REDACTED}\2"),
        (r"\b(PHPSESSID=)[^;\s\"']+", rf"\1{REDACTED}"),
        (r"([\"']?CLIENT_ID[\"']?\s*[:=]\s*[\"']?)SMT[A-Za-z0-9]+([\"']?)", rf"\1{REDACTED}\2"),
        (r"([\"']?SMT_USER[\"']?\s*[:=]\s*[\"']?)\d+([\"']?)", rf"\1{REDACTED}\2"),
        (r"([\"']?(?:password|passwort|token|secret|access[_-]?key)[\"']?\s*[:=]\s*[\"']?)[^,}\]\s\"']+([\"']?)", rf"\1{REDACTED}\2"),
        (r"([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", REDACTED),
    )
    for pattern, replacement in replacements:
        text = re.sub(pattern, replacement, text, flags=re.I)
    return text


def _redact_debug_data(value):
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            normalized_key = str(key).lower().replace("-", "_")
            if normalized_key in SENSITIVE_DEBUG_KEYS:
                redacted[key] = REDACTED
            else:
                redacted[key] = _redact_debug_data(item)
        return redacted
    if isinstance(value, list):
        return [_redact_debug_data(item) for item in value]
    if isinstance(value, str):
        return _redact_debug_text(value)
    return value


def _debug_value(value, limit: int = DEBUG_PAYLOAD_LIMIT):
    """Return a bounded representation for diagnostic logging."""
    if value is None:
        return None
    try:
        text = json.dumps(_redact_debug_data(value), sort_keys=True)
    except Exception:
        text = _redact_debug_text(str(value))
    text = _redact_debug_text(text)
    if len(text) > limit:
        return f"{text[:limit]}... <truncated {len(text) - limit} chars>"
    return text


def _sorted_debug_values(values: dict | None) -> dict | None:
    if not isinstance(values, dict):
        return None
    try:
        return {
            str(key): str(values[key])
            for key in sorted(values, key=lambda item: int(item) if str(item).isdigit() else str(item))
        }
    except Exception:
        return {str(key): str(value) for key, value in values.items()}


def _debug_values(values: dict | None, limit: int = DEBUG_VALUES_LIMIT):
    """Return a mapping-friendly representation of SmartWeb values."""
    sorted_values = _sorted_debug_values(values)
    if sorted_values is None:
        return None
    return _debug_value({"count": len(sorted_values), "values": sorted_values}, limit=limit)


def _normalize_smartweb_hex_value(value) -> str | None:
    text = str(value or "").strip()
    if not text or re.fullmatch(r"[0-9A-Fa-f]+", text) is None:
        return None
    normalized = text.upper().lstrip("0")
    return normalized or "0"


def _smartweb_value_matches(expected, actual) -> bool:
    if actual is None:
        return False
    if str(expected) == str(actual):
        return True
    expected_hex = _normalize_smartweb_hex_value(expected)
    actual_hex = _normalize_smartweb_hex_value(actual)
    return expected_hex is not None and expected_hex == actual_hex


def _compact_mqtt_diagnostics(diagnostics: dict | None) -> dict | None:
    """Keep MQTT diagnostics readable; full values are logged separately."""
    if not isinstance(diagnostics, dict):
        return diagnostics
    compact = dict(diagnostics)
    messages = []
    for message in compact.get("recent_messages") or []:
        if not isinstance(message, dict):
            messages.append(message)
            continue
        item = dict(message)
        if item.get("kind") == "values":
            item.pop("values", None)
            item["values_omitted"] = True
        messages.append(item)
    compact["recent_messages"] = messages
    if isinstance(compact.get("last_values"), dict):
        compact["last_values"] = {
            "values_count": len(compact["last_values"]),
            "values_omitted": True,
        }
    return compact


def _values_diff(previous: dict | None, current: dict, limit: int = 200) -> dict:
    """Return changed SmartWeb values for easier manual mapping."""
    if not isinstance(previous, dict):
        return {"baseline": True, "changed": {}, "changed_count": 0}
    changes = {}
    all_keys = sorted(
        {str(key) for key in previous.keys()} | {str(key) for key in current.keys()},
        key=lambda item: int(item) if item.isdigit() else item,
    )
    for key in all_keys:
        old = previous.get(key)
        new = current.get(key)
        if old != new:
            changes[key] = {"old": old, "new": new}
    changed_count = len(changes)
    if changed_count > limit:
        changes = dict(list(changes.items())[:limit])
    return {
        "baseline": False,
        "changed": changes,
        "changed_count": changed_count,
        "omitted_count": max(0, changed_count - limit),
    }


def _mqtt_message_summary(topic: str, payload: str) -> dict:
    summary = {
        "topic": _redact_debug_text(topic),
        "payload": payload,
        "kind": "text",
    }
    try:
        obj = json.loads(payload)
    except Exception:
        return summary

    if isinstance(obj, str):
        summary["kind"] = "json_string"
        summary["payload"] = obj
        try:
            obj = json.loads(obj)
        except Exception:
            return summary

    if isinstance(obj, dict):
        keys = sorted(str(key) for key in obj.keys())
        summary["json_keys"] = keys
        if "Rx" in obj:
            summary["kind"] = "rx"
            summary["payload"] = _debug_value(obj)
        elif "Tx" in obj:
            summary["kind"] = "tx_echo"
            summary["payload"] = _debug_value(obj)
        elif "values" in obj:
            summary["kind"] = "values"
            values = obj.get("values")
            if isinstance(values, dict):
                summary.pop("payload", None)
                summary["values_count"] = len(values)
                summary["values"] = _debug_values(values)
        else:
            values = _extract_values_from_payload(payload)
            if isinstance(values, dict):
                summary["kind"] = "values"
                summary.pop("payload", None)
                summary["values_count"] = len(values)
                summary["values"] = _debug_values(values)
            else:
                summary["kind"] = "json"
                summary["payload"] = _debug_value(obj)
    return summary


def _extract_sid_sk_from_url(url: str):
    qs = parse_qs(urlparse(url).query, keep_blank_values=True)
    sid = (qs.get("SID") or [None])[0]
    sk = (qs.get("SK") or [None])[0]
    if _valid_credential_part(sid) and _valid_credential_part(sk):
        return sid.upper(), sk.upper()
    return None


def _valid_credential_part(value: str | None) -> bool:
    if not value:
        return False
    text = value.strip()
    if text.casefold() in ("nan", "none", "null", "undefined"):
        return False
    return re.fullmatch(r"[0-9A-Fa-f]{16}", text) is not None


def _build_mqtt_topic(sid: str | None) -> str | None:
    if not _valid_credential_part(sid):
        return None
    return f"{VERSION}/{sid.strip().upper()}"


def _extract_sid_sk_from_text(text: str):
    m = re.search(r"SID=([0-9A-Fa-f]{16}).*?SK=([0-9A-Fa-f]{16})", text)
    if m:
        return m.group(1).upper(), m.group(2).upper()
    smt_id = _extract_global_var(text, "SMT_ID")
    smt_key = _extract_global_var(text, "SMT_KEY")
    if _valid_credential_part(smt_id) and _valid_credential_part(smt_key):
        return smt_id.upper(), smt_key.upper()
    return None


def _extract_smt_user_from_text(text: str):
    for pat in (
        r"SMT_USER\s*[:=]\s*(\d+)",
        r"\"SMT_USER\"\s*:\s*(\d+)",
        r"smt_user\s*[:=]\s*(\d+)",
        r"\"smt_user\"\s*:\s*(\d+)",
    ):
        m = re.search(pat, text, flags=re.I)
        if m:
            try:
                return int(m.group(1))
            except Exception:
                pass
    return None


def _extract_smt_user_from_url(url: str) -> int | None:
    qs = parse_qs(urlparse(url).query, keep_blank_values=True)
    for key in ("us", "SMT_USER", "smt_user"):
        value = (qs.get(key) or [None])[0]
        if str(value or "").isdigit():
            return int(value)
    return None


def _extract_global_var(text: str, key: str):
    patterns = [
        rf"global\.{key}\s*=\s*['\"]([^'\"]+)['\"]",
        rf"window\.{key}\s*=\s*['\"]([^'\"]+)['\"]",
        rf"\b{key}\b\s*:\s*['\"]([^'\"]+)['\"]",
        rf"\b{key}\b\s*=\s*['\"]([^'\"]+)['\"]",
    ]
    for pat in patterns:
        m = re.search(pat, text)
        if m:
            return m.group(1)
    return None


def _extract_smt_user_from_scripts(session: requests.Session, html: str):
    scripts = re.findall(r'<script[^>]+src="([^"]+)"', html, flags=re.I)
    for src in scripts:
        if not src:
            continue
        src_abs = urljoin(BASE, src)
        try:
            r = session.get(src_abs, timeout=15)
            r.raise_for_status()
        except Exception:
            continue
        text = r.text
        smt = _extract_smt_user_from_text(text)
        if smt is not None:
            return smt
        v = _extract_global_var(text, "SMT_USER")
        if v is not None:
            try:
                return int(v)
            except Exception:
                pass
    return None


def _extract_names_from_rest_list(html: str):
    name_map = {}
    if not html:
        return name_map
    device_link_re = re.compile(
        r'href="/geraet/(?:fernbedienung|benutzer|bearbeiten|loeschen)/([0-9a-f]{32})"',
        flags=re.I,
    )
    for m in device_link_re.finditer(html):
        rel = f"/geraet/fernbedienung/{m.group(1)}"
        if rel in name_map:
            continue
        tail = html[m.end(): m.end() + 1000]
        m2 = re.search(r"<span[^>]*>([^<]{1,200})</span>", tail, flags=re.I)
        if m2:
            name_map[rel] = m2.group(1).strip()
    return name_map


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
    0xB6, 0xE8, 0x0A, 0x54, 0xD7, 0x89, 0x6B, 0x35
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


def _build_rbw_set_cmd(value_id: str, value_hex: str) -> str | None:
    """Build the RBW/KWT-style raw Modbus Tx used by the SmartWeb frontend."""
    spec = RBW_VALUE_WRITE_REGISTERS.get(str(value_id))
    if spec is None:
        return None
    try:
        id_value = int(str(value_hex), 16)
    except Exception:
        return None
    register, converter = spec
    if converter == "temp1":
        # SmartWeb ID 1333 is temperature in tenths, while RBW register R01 uses
        # half-degree steps with an offset of 60: value2data_TEMP1(value).
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


def _build_kwt_set_cmd(value_id: str, value_hex: str) -> str | None:
    """Build the KWT raw Modbus Tx used by the SmartWeb frontend."""
    spec = KWT_VALUE_WRITE_REGISTERS.get(str(value_id))
    if spec is None:
        return None
    try:
        id_value = int(str(value_hex), 16)
    except Exception:
        return None
    register, converter = spec
    if converter == "temp":
        # SmartWeb ID 1190 is half-degree steps; KWT register TEMP_SET is tenths.
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


def _extract_values_from_payload(payload: str):
    try:
        data = json.loads(payload)
    except Exception:
        return None
    if isinstance(data, dict) and "values" in data:
        return data.get("values")
    # Some responses wrap JSON as string
    if isinstance(data, str):
        try:
            data2 = json.loads(data)
            if isinstance(data2, dict) and "values" in data2:
                return data2.get("values")
        except Exception:
            return None
    return None


def _bool_from_str(val: str | None) -> bool | None:
    if val is None:
        return None
    v = val.strip().lower()
    if v in ("1", "true", "on", "yes"):
        return True
    if v in ("0", "false", "off", "no"):
        return False
    return None


def _build_set_cmd_from_c0(payload: list[int], overrides: dict) -> str | None:
    """Build a SET frame by applying overrides on top of a C0 payload."""
    if not payload or payload[0] != 0xC0 or len(payload) < 22:
        return None

    b1 = payload[1] | 0x02
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

    fan = payload[3] & 0x7F
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
    cmd[21] = payload[21] & 0x80
    cmd[22] = 0x00
    cmd[23] = 0x00
    cmd[24] = 0x00

    cmd.append(_crc8(cmd))
    header = [0xAA, 0x00, 0xAC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x02]
    packet = header + cmd
    packet[1] = len(packet)
    packet.append(_checksum(packet))
    return "".join(f"{b:02X}" for b in packet)


class _MqttSession:
    def __init__(self, sid: str, sk: str, topic: str):
        self.sid = sid
        self.sk = sk
        self.topic = topic
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._connected = threading.Event()
        self._closed = False
        self._last_rx = None
        self._last_values = None
        self._last_seen_values = None
        self._last_tx_echo = None
        self._last_smt_user = None
        self._recent_messages = deque(maxlen=20)
        self._received_non_tx_count = 0
        self._subscribed_topics = []

        self.client = mqtt.Client(
            client_id=f"SMT{random.randint(0,9999):04d}{sid}",
            protocol=mqtt.MQTTv311,
            transport="websockets",
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        )
        self.client.username_pw_set(self.sid, self.sk)
        self.client.tls_set(cert_reqs=ssl.CERT_REQUIRED)
        self.client.ws_set_options(path=WSS_PATH)
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
        self.client.on_disconnect = self._on_disconnect

        self.client.connect(WSS_HOST, WSS_PORT, keepalive=60)
        self.client.loop_start()

    def _on_connect(self, client, userdata, flags, reason_code, properties=None):
        rc = reason_code.value if hasattr(reason_code, "value") else reason_code
        if rc != 0:
            _LOGGER.warning("MQTT connect failed rc=%s", rc)
            self._connected.set()
            return
        subscriptions = [
            (f"{self.topic}/HOST2CLIENT", 2),
            (f"{self.topic}/CLIENT2HOST", 2),
            (f"{self.topic}/RESP", 2),
            (f"{self.topic}/ESP", 2),
        ]
        client.subscribe(subscriptions)
        with self._lock:
            self._subscribed_topics = [topic for topic, _qos in subscriptions]
        self._connected.set()

    def _on_disconnect(self, client, userdata, *args):
        self._closed = True
        self._connected.set()

    def _on_message(self, client, userdata, msg):
        try:
            text = msg.payload.decode("utf-8", errors="replace")
        except Exception:
            text = repr(msg.payload)
        summary = _mqtt_message_summary(msg.topic, text)
        with self._cond:
            if summary.get("kind") == "tx_echo":
                self._last_tx_echo = summary
            else:
                self._received_non_tx_count += 1
                self._recent_messages.append(summary)
            # Rx hex for ESP status
            try:
                obj = json.loads(text)
                if isinstance(obj, dict):
                    if obj.get("Rx"):
                        self._last_rx = text
                        self._cond.notify_all()
                    smt_user = obj.get("SMT_USER")
                    if str(smt_user or "").isdigit():
                        self._last_smt_user = int(smt_user)
            except Exception:
                pass
            values = _extract_values_from_payload(text)
            if isinstance(values, dict) and str(msg.topic).endswith("/HOST2CLIENT"):
                self._last_values = values
                self._last_seen_values = values
                self._cond.notify_all()

    def ensure_connected(self, timeout: float = 8.0) -> bool:
        self._connected.wait(timeout=timeout)
        return not self._closed

    def publish(self, topic: str, payload: dict):
        self.client.publish(topic, json.dumps(payload), qos=2, retain=False)

    def clear_values(self) -> None:
        with self._cond:
            self._last_values = None

    def last_smt_user(self) -> int | None:
        with self._cond:
            return self._last_smt_user

    def wait_rx(self, timeout: float = 10.0) -> str | None:
        end = time.time() + timeout
        with self._cond:
            while time.time() < end:
                if self._last_rx is not None:
                    rx = self._last_rx
                    self._last_rx = None
                    return rx
                remaining = end - time.time()
                if remaining <= 0:
                    break
                self._cond.wait(timeout=remaining)
        return None

    def wait_values(self, timeout: float = 10.0) -> dict | None:
        end = time.time() + timeout
        with self._cond:
            while time.time() < end:
                if self._last_values is not None:
                    values = self._last_values
                    self._last_values = None
                    return values
                remaining = end - time.time()
                if remaining <= 0:
                    break
                self._cond.wait(timeout=remaining)
        return None

    def diagnostic_snapshot(self):
        with self._cond:
            return {
                "recent_messages": list(self._recent_messages),
                "last_tx_echo": self._last_tx_echo,
                "last_values": self._last_seen_values,
                "received_non_tx_count": self._received_non_tx_count,
                "subscribed_topics": list(self._subscribed_topics),
            }

    def close(self):
        try:
            self.client.loop_stop()
            self.client.disconnect()
        except Exception:
            pass
        self._closed = True


# ----------------- client -----------------

class SmartWebError(RuntimeError):
    """Base exception for SmartWeb API failures."""


class SmartWebLoginError(SmartWebError):
    """Raised when SmartWeb login fails."""


class DeviceListUnavailable(SmartWebError):
    """Raised when SmartWeb does not return a usable device list."""


class DeviceNotFound(SmartWebError):
    """Raised when a configured device cannot be found in the SmartWeb account."""


class DeviceResolveError(SmartWebError):
    """Raised when a listed device cannot be resolved to MQTT credentials."""


class UnsupportedPayload(SmartWebError):
    """Raised when a reachable device returns an unsupported status payload."""


class RemkoSmartWebAccount:
    """Shared SmartWeb HTTP account state for one credential pair."""

    def __init__(self, email: str, password: str):
        self.email = email
        self.password = password
        self.session = requests.Session()
        self._lock = threading.RLock()
        self._last_login = 0.0
        self._device_name_map = None
        self._device_name_map_at = 0.0
        self.last_device_list_error = None
        self.last_device_list_empty = False

    def ensure_login(self, force: bool = False) -> None:
        """Ensure a logged-in session is available, reusing it within a TTL."""
        with self._lock:
            if not force:
                if (
                    (time.time() - self._last_login) < LOGIN_TTL_SEC
                    and "PHPSESSID" in self.session.cookies.get_dict()
                ):
                    return
            self.login()

    def account_request(self, method: str, url: str, **kwargs):
        _pace_account_request()
        with self._lock:
            request = getattr(self.session, method)
            return request(url, **kwargs)

    def login(self) -> None:
        r = self.account_request(
            "post",
            LOGIN_URL,
            data={"name": self.email, "passwort": self.password},
            headers={"X-Requested-With": "XMLHttpRequest", "Origin": BASE, "Referer": f"{BASE}/"},
            timeout=15,
        )
        r.raise_for_status()
        if "PHPSESSID" not in self.session.cookies.get_dict():
            raise SmartWebLoginError("Login failed: no PHPSESSID")
        self._last_login = time.time()

    def list_devices(self) -> list[str]:
        """Return available device names from /rest/liste."""
        self.ensure_login()
        name_map = self.fetch_device_name_map()
        names = [v for v in name_map.values() if v]
        return sorted(set(names), key=str.lower)

    def list_device_map(self) -> dict[str, str]:
        """Return available device names mapped to internal SmartWeb paths."""
        self.ensure_login()
        name_map = self.fetch_device_name_map()
        return {name: rel for rel, name in name_map.items() if name}

    def fetch_device_name_map(self, retries: int = 3, force: bool = False) -> dict:
        """Fetch /rest/liste with retries, caching successful results per account."""
        with self._lock:
            if (
                not force
                and self._device_name_map is not None
                and (time.time() - self._device_name_map_at) < DEVICE_LIST_TTL_SEC
            ):
                return dict(self._device_name_map)

        last_error = None
        last_name_map = {}
        saw_empty_response = False
        self.last_device_list_error = None
        self.last_device_list_empty = False
        for attempt in range(1, retries + 1):
            if attempt > 1:
                try:
                    self.ensure_login(force=True)
                except Exception as err:
                    last_error = err
                    _LOGGER.debug("SmartWeb re-login before device list retry failed: %s", err)
            try:
                with self._lock:
                    if (
                        not force
                        and self._device_name_map is not None
                        and (time.time() - self._device_name_map_at) < DEVICE_LIST_TTL_SEC
                    ):
                        return dict(self._device_name_map)
                    r_list = self.account_request("get", f"{BASE}/rest/liste", timeout=15)
                    r_list.raise_for_status()
                    last_name_map = _extract_names_from_rest_list(r_list.text)
                    if last_name_map:
                        self._device_name_map = dict(last_name_map)
                        self._device_name_map_at = time.time()
                        self.last_device_list_error = None
                        self.last_device_list_empty = False
                        if attempt > 1:
                            _LOGGER.debug(
                                "SmartWeb device list recovered on attempt %s with devices: %s",
                                attempt,
                                sorted(last_name_map.values(), key=str.lower),
                            )
                        return dict(last_name_map)
                saw_empty_response = True
                _LOGGER.debug(
                    "SmartWeb device list returned no parseable devices on attempt %s "
                    "(response length: %s)",
                    attempt,
                    len(r_list.text or ""),
                )
            except Exception as err:
                last_error = err
                _LOGGER.debug("SmartWeb device list request failed on attempt %s: %s", attempt, err)
            if attempt < retries:
                time.sleep(float(attempt))
        if last_error:
            _LOGGER.debug("SmartWeb device list retries exhausted: %s", last_error)
            self.last_device_list_error = last_error
        self.last_device_list_empty = saw_empty_response and not last_name_map
        return dict(last_name_map)

    def close(self):
        self.session.close()


class RemkoSmartWebClient:
    def __init__(
        self,
        email: str,
        password: str,
        device_name: str,
        device_path: str | None = None,
        device_kind: str = DEVICE_KIND_AUTO,
        account: RemkoSmartWebAccount | None = None,
    ):
        self.email = email
        self.password = password
        self.device_name = device_name
        self.device_path = device_path
        self.device_kind = device_kind
        self.profile = get_parser_profile(device_name, device_kind)
        self._owns_account = account is None
        self.account = account or RemkoSmartWebAccount(email, password)
        self.session = self.account.session

        self.sid = None
        self.sk = None
        self.topic = None
        self.smt_user = None
        self._last_payload = None
        self._last_status = None
        self._last_mapping_values = None
        self._last_device_list_error = None
        self._last_device_list_empty = False
        self._mqtt = None

    def initial_status_if_supported(self) -> dict | None:
        """Return a minimal state when setup can safely proceed before live values arrive."""
        if self.device_kind != DEVICE_KIND_AUTO or get_specialized_profile(self.device_name) is not None:
            return {"unit": "C", "_status_pending": True}
        return None

    def _ensure_login(self, force: bool = False) -> None:
        """Ensure a logged-in session is available, reusing it within a TTL."""
        self.account.ensure_login(force=force)

    def _ensure_device(self) -> None:
        """Ensure SID/SK/topic are resolved from SmartWeb."""
        if _valid_credential_part(self.sid) and _valid_credential_part(self.sk) and self.topic == _build_mqtt_topic(self.sid):
            return
        self.sid = None
        self.sk = None
        self.topic = None
        if self._mqtt is not None:
            self._mqtt.close()
            self._mqtt = None
        self.resolve_device()

    def _ensure_mqtt(self) -> None:
        if not _valid_credential_part(self.sid) or not _valid_credential_part(self.sk) or self.topic != _build_mqtt_topic(self.sid):
            raise DeviceResolveError("Device MQTT credentials are incomplete")
        if self._mqtt is None or not self._mqtt.ensure_connected():
            self._mqtt = _MqttSession(self.sid, self.sk, self.topic)
            if not self._mqtt.ensure_connected():
                raise DeviceResolveError("MQTT connect failed")

    def _account_request(self, method: str, url: str, **kwargs):
        return self.account.account_request(method, url, **kwargs)

    def login(self) -> None:
        self.account.login()

    def list_devices(self) -> list[str]:
        """Return available device names from /rest/liste."""
        return self.account.list_devices()

    def list_device_map(self) -> dict[str, str]:
        """Return available device names mapped to internal SmartWeb paths."""
        return self.account.list_device_map()

    def _fetch_device_name_map(self, retries: int = 3, force: bool = False) -> dict:
        """Fetch /rest/liste with retries for transient SmartWeb list issues."""
        name_map = self.account.fetch_device_name_map(retries=retries, force=force)
        self._last_device_list_error = self.account.last_device_list_error
        self._last_device_list_empty = self.account.last_device_list_empty
        return name_map

    def _find_device_rel(self, name_map: dict) -> str | None:
        if self.device_path and self.device_path in name_map:
            return self.device_path
        target = _normalize_device_name(self.device_name)
        for rel, name in name_map.items():
            if _normalize_device_name(name) == target:
                return rel
        return None

    def _resolve_device_rel(self, rel: str) -> None:
        self.device_path = rel
        url = urljoin(BASE, rel)
        self.smt_user = _extract_smt_user_from_url(url)
        r0 = self._account_request("get", url, allow_redirects=False, timeout=15)
        r0.raise_for_status()
        loc = r0.headers.get("Location")
        if loc:
            redirect_url = urljoin(BASE, loc)
            hit = _extract_sid_sk_from_url(redirect_url)
            if hit:
                self.sid, self.sk = hit
                self.topic = _build_mqtt_topic(self.sid)
                if not self.topic:
                    raise DeviceResolveError("SID/SK or SMT_ID/SMT_KEY not found")
                self.smt_user = self.smt_user or _extract_smt_user_from_url(redirect_url)
                try:
                    r1 = self._account_request("get", url, allow_redirects=True, timeout=15)
                    if r1.ok:
                        self.smt_user = (
                            self.smt_user
                            or _extract_smt_user_from_url(r1.url)
                            or _extract_smt_user_from_text(r1.text)
                            or _extract_smt_user_from_scripts(self.session, r1.text)
                        )
                except Exception as err:
                    _LOGGER.debug("Could not fetch SmartWeb device page for SMT_USER after redirect: %s", err)
                if self.smt_user is None:
                    _LOGGER.warning("SMT_USER not found in device page; CLIENT2HOST polling may be limited")
                _LOGGER.debug(
                    "Resolved SmartWeb MQTT credentials for %r with topic %s",
                    self.device_name,
                    _redact_debug_text(self.topic),
                )
                return

        r1 = self._account_request("get", url, allow_redirects=True, timeout=15)
        r1.raise_for_status()
        hit = _extract_sid_sk_from_url(r1.url) or _extract_sid_sk_from_text(r1.text)
        if not hit:
            scripts = re.findall(r'<script[^>]+src="([^"]+)"', r1.text, flags=re.I)
            for src in scripts:
                if not src:
                    continue
                try:
                    script_response = self._account_request("get", urljoin(BASE, src), timeout=15)
                    script_response.raise_for_status()
                except Exception:
                    continue
                hit = _extract_sid_sk_from_text(script_response.text)
                if hit:
                    break
        if not hit:
            raise DeviceResolveError("SID/SK or SMT_ID/SMT_KEY not found")
        self.sid, self.sk = hit
        self.topic = _build_mqtt_topic(self.sid)
        if not self.topic:
            raise DeviceResolveError("SID/SK or SMT_ID/SMT_KEY not found")
        self.smt_user = (
            self.smt_user
            or _extract_smt_user_from_url(r1.url)
            or _extract_smt_user_from_text(r1.text)
            or _extract_smt_user_from_scripts(self.session, r1.text)
        )
        if self.smt_user is None:
            _LOGGER.warning("SMT_USER not found in device page; CLIENT2HOST polling may be limited")
        _LOGGER.debug(
            "Resolved SmartWeb MQTT credentials for %r with topic %s",
            self.device_name,
            _redact_debug_text(self.topic),
        )

    def resolve_device(self, force_list: bool = False) -> None:
        self._ensure_login()
        if self.device_path and not force_list:
            try:
                self._resolve_device_rel(self.device_path)
                return
            except Exception as err:
                _LOGGER.debug(
                    "Direct SmartWeb device path resolution failed for %r (%s), falling back to /rest/liste",
                    self.device_name,
                    err,
                )

        name_map = self._fetch_device_name_map(force=force_list)
        rel = self._find_device_rel(name_map)
        if not rel:
            available = sorted(v for v in name_map.values() if v)
            if self.device_path and name_map:
                _LOGGER.warning(
                    "Device path %r for %r not found in /rest/liste. Falling back to name lookup failed. "
                    "Available devices: %s",
                    self.device_path,
                    self.device_name,
                    available,
                )
            if available:
                _LOGGER.warning(
                    "Device name %r not found in /rest/liste. Available devices: %s",
                    self.device_name,
                    available,
                )
            else:
                _LOGGER.warning(
                    "Device name %r not found in /rest/liste because SmartWeb returned no parseable devices",
                    self.device_name,
                )
            if self._last_device_list_error is not None:
                raise DeviceListUnavailable(
                    "SmartWeb device list could not be loaded after retries: "
                    f"{self._last_device_list_error}"
                )
            if self._last_device_list_empty:
                raise DeviceListUnavailable(
                    "SmartWeb returned an empty or unparseable device list from /rest/liste"
                )
            if available:
                raise DeviceNotFound(
                    "Configured device name not found in /rest/liste. "
                    f"Available devices: {', '.join(available)}"
                )
            raise DeviceNotFound("Device name not found in /rest/liste")
        self._resolve_device_rel(rel)

    def _refresh_device_from_list(self) -> None:
        """Force a fresh /rest/liste lookup and recreate MQTT state for this device."""
        if self._mqtt is not None:
            self._mqtt.close()
            self._mqtt = None
        self.sid = None
        self.sk = None
        self.topic = None
        self.resolve_device(force_list=True)

    def _mqtt_roundtrip_esp(self, payload: dict, timeout=10) -> str | None:
        """Publish ESP payload and wait for Rx response on persistent MQTT."""
        if not self.sid or not self.sk or not self.topic:
            raise DeviceResolveError("Device not resolved")
        self._ensure_mqtt()
        self._mqtt.publish(f"{self.topic}/ESP", payload)
        return self._mqtt.wait_rx(timeout=timeout)

    def _mqtt_poll_values(self, timeout=10) -> dict | None:
        """Poll values via CLIENT2HOST on persistent MQTT."""
        if not self.sid or not self.sk or not self.topic:
            raise DeviceResolveError("Device not resolved")
        self._ensure_mqtt()
        poll = {
            "FORCE_RESPONSE": True,
            "query_list": _value_query_list(),
            "CLIENT_ID": f"SMT{random.randint(0,9999):04d}{self.sid}",
            "LASTWRITE": 0,
            "ISTOUCH": False,
            "DEVID": "",
        }
        smt_user = self.smt_user if self.smt_user is not None else self._mqtt.last_smt_user()
        if smt_user is not None:
            poll["SMT_USER"] = smt_user
        self._mqtt.publish(f"{self.topic}/CLIENT2HOST", poll)
        return self._mqtt.wait_values(timeout=timeout)

    def _mqtt_write_values(self, values: dict[str, str], timeout=10) -> dict | None:
        """Write Smart-Web value IDs via CLIENT2HOST and wait for a values update."""
        if not self.sid or not self.sk or not self.topic:
            raise DeviceResolveError("Device not resolved")
        self._ensure_mqtt()
        payload = {
            "values": {str(key): str(value) for key, value in values.items()},
            "query_list": _value_query_list(values),
            "FORCE_RESPONSE": True,
            "CLIENT_ID": f"SMT{random.randint(0,9999):04d}{self.sid}",
            "LASTWRITE": int(time.time() * 1000),
            "ISTOUCH": False,
            "DEVID": "",
        }
        smt_user = self.smt_user if self.smt_user is not None else self._mqtt.last_smt_user()
        if smt_user is not None:
            payload["SMT_USER"] = smt_user
        _LOGGER.warning(
            "Experimental REMKO SmartWeb value write for %r. No confirmed write capture is bundled; "
            "please verify in the REMKO app and share the following payload plus the response logs if it fails: %s",
            self.device_name,
            _debug_value(payload),
        )
        self._mqtt.clear_values()
        self._mqtt.publish(f"{self.topic}/CLIENT2HOST", payload)
        response_values = self._mqtt.wait_values(timeout=timeout)
        if isinstance(response_values, dict):
            _LOGGER.warning(
                "Experimental REMKO SmartWeb value write for %r received values response: %s",
                self.device_name,
                _debug_values(response_values),
            )
        else:
            _LOGGER.warning(
                "Experimental REMKO SmartWeb value write for %r did not receive a values response within %s seconds",
                self.device_name,
                timeout,
            )
        return response_values

    def _mqtt_write_rbw_esp_values(self, values: dict[str, str], timeout=10) -> bool:
        """Write RBW/DHW value IDs through the ESP Tx path used by the frontend."""
        if not self.sid or not self.sk or not self.topic:
            raise DeviceResolveError("Device not resolved")
        self._ensure_mqtt()
        unsupported = []
        for key, value in values.items():
            tx = _build_rbw_set_cmd(str(key), str(value))
            if not tx:
                unsupported.append(str(key))
                continue
            _LOGGER.warning(
                "Experimental REMKO RBW/DHW ESP value write for %r: value id %s via Tx %s",
                self.device_name,
                key,
                tx,
            )
            self._mqtt.publish(f"{self.topic}/ESP", {"Tx": tx, "CLIENT_ID": "SMTACUARTTEST"})
            # The frontend waits for RESP and then refreshes the value model.
            self._mqtt.wait_rx(timeout=timeout)
            time.sleep(1.0)
        return not unsupported

    def _mqtt_write_kwt_esp_values(self, values: dict[str, str], timeout=10) -> bool:
        """Write KWT value IDs through the ESP Modbus Tx path used by the frontend."""
        if not self.sid or not self.sk or not self.topic:
            raise DeviceResolveError("Device not resolved")
        self._ensure_mqtt()
        unsupported = []
        for key, value in values.items():
            tx = _build_kwt_set_cmd(str(key), str(value))
            if not tx:
                unsupported.append(str(key))
                continue
            _LOGGER.warning(
                "Experimental REMKO KWT ESP value write for %r: value id %s via Tx %s",
                self.device_name,
                key,
                tx,
            )
            self._mqtt.publish(f"{self.topic}/ESP", {"Tx": tx, "CLIENT_ID": "SMTACUARTTEST"})
            self._mqtt.wait_rx(timeout=timeout)
            time.sleep(1.0)
        return not unsupported

    def _mqtt_diagnostic_snapshot(self):
        if self._mqtt is None:
            return None
        return self._mqtt.diagnostic_snapshot()

    def _log_mapping_snapshot(self, stage: str, values: dict) -> None:
        if not _LOGGER.isEnabledFor(logging.DEBUG):
            return
        current_values = _sorted_debug_values(values)
        changes = _values_diff(
            self._last_mapping_values,
            current_values,
        )
        self._last_mapping_values = dict(current_values)

        if changes["baseline"]:
            _LOGGER.debug(
                "REMKO SmartWeb mapping baseline: %s",
                _debug_value(
                    {
                        "device": self.device_name,
                        "stage": stage,
                        "values_count": len(current_values),
                        "keys": list(current_values.keys()),
                    },
                    limit=DEBUG_VALUES_LIMIT,
                ),
            )
            return

        if changes["changed_count"] == 0:
            return

        mapping_changes = {
            "device": self.device_name,
            "stage": stage,
            "changes_since_previous_snapshot": changes,
        }
        _LOGGER.debug(
            "REMKO SmartWeb mapping changes: %s",
            _debug_value(mapping_changes, limit=DEBUG_VALUES_LIMIT),
        )

    def _log_unsupported_payload(self, stage: str, **diagnostics) -> None:
        if not _LOGGER.isEnabledFor(logging.DEBUG):
            return
        values = diagnostics.get("values")
        if isinstance(values, dict):
            self._log_mapping_snapshot(stage, values)
        mqtt_diagnostics = diagnostics.get("mqtt_diagnostics")
        if isinstance(mqtt_diagnostics, dict) and isinstance(mqtt_diagnostics.get("last_values"), dict):
            self._log_mapping_snapshot(f"{stage}_mqtt_last_values", mqtt_diagnostics["last_values"])
        safe_diagnostics = {
            key: _debug_values(value) if key == "values" and isinstance(value, dict)
            else _debug_value(_compact_mqtt_diagnostics(value) if key == "mqtt_diagnostics" else value)
            for key, value in diagnostics.items()
            if value is not None
        }
        _LOGGER.debug(
            "Unsupported or unparsed REMKO SmartWeb payload for device %r at %s: %s",
            self.device_name,
            stage,
            safe_diagnostics,
        )

    def read_status(self) -> dict:
        self._ensure_login()
        self._ensure_device()
        self._ensure_mqtt()
        tx = _build_status_cmd()
        payload = {"Tx": tx, "CLIENT_ID": "SMTACUARTTEST"}
        resp = self._mqtt_roundtrip_esp(payload, timeout=10)

        def _parse(resp_text: str | None) -> dict | None:
            if not resp_text:
                return None
            try:
                obj = json.loads(resp_text)
                rx_hex = obj.get("Rx")
                if rx_hex:
                    parsed = self.profile.parse_c0_status(rx_hex)
                    if parsed:
                        return parsed
            except Exception:
                return None
            return None

        parsed = _parse(resp)
        if parsed:
            self._last_payload = parsed.get("_payload")
            self._last_status = parsed
            return parsed
        self._log_unsupported_payload(
            "esp_status",
            esp_response=resp,
            mqtt_diagnostics=self._mqtt_diagnostic_snapshot(),
        )

        # fallback: poll values via CLIENT2HOST
        values = self._mqtt_poll_values(timeout=10)
        if isinstance(values, dict):
            self._log_mapping_snapshot("client2host_values", values)
        parsed_values = self.profile.parse_values_status(values) if values else None
        if parsed_values:
            if self._last_status:
                merged = dict(self._last_status)
                merged.update({k: v for k, v in parsed_values.items() if v is not None})
                self._last_status = merged
                return merged
            self._last_status = parsed_values
            return parsed_values
        self._log_unsupported_payload(
            "client2host_values",
            values=values,
            mqtt_diagnostics=self._mqtt_diagnostic_snapshot(),
        )

        try:
            _LOGGER.debug(
                "Status values for %r stayed empty/unparseable; refreshing device lookup from /rest/liste",
                self.device_name,
            )
            self._refresh_device_from_list()
        except Exception as err:
            _LOGGER.debug("Forced SmartWeb device list refresh failed for %r: %s", self.device_name, err)

        # retry once after forcing a re-login
        self._ensure_login(force=True)
        self._ensure_device()
        resp = self._mqtt_roundtrip_esp(payload, timeout=10)
        parsed = _parse(resp)
        if parsed:
            self._last_payload = parsed.get("_payload")
            self._last_status = parsed
            return parsed
        self._log_unsupported_payload(
            "esp_status_retry",
            esp_response=resp,
            mqtt_diagnostics=self._mqtt_diagnostic_snapshot(),
        )

        if self._last_status:
            return self._last_status
        if self.profile.diagnostics_only:
            self._last_status = {"_diagnostics_only": True}
            return self._last_status
        raise UnsupportedPayload("Unable to parse status")

    def _read_status_c0(self, retries: int = 2) -> dict:
        """Read status via ESP (C0 Rx only)."""
        self._ensure_login()
        self._ensure_device()
        self._ensure_mqtt()
        tx = _build_status_cmd()
        payload = {"Tx": tx, "CLIENT_ID": "SMTACUARTTEST"}

        def _parse(resp_text: str | None) -> dict | None:
            if not resp_text:
                return None
            try:
                obj = json.loads(resp_text)
                rx_hex = obj.get("Rx")
                if rx_hex:
                    parsed = self.profile.parse_c0_status(rx_hex)
                    if parsed:
                        return parsed
            except Exception:
                return None
            return None

        last_err = None
        for _ in range(max(1, retries)):
            resp = self._mqtt_roundtrip_esp(payload, timeout=10)
            parsed = _parse(resp)
            if parsed:
                self._last_payload = parsed.get("_payload")
                self._last_status = parsed
                return parsed
            self._log_unsupported_payload(
                "esp_status_c0",
                esp_response=resp,
                mqtt_diagnostics=self._mqtt_diagnostic_snapshot(),
            )
            last_err = "Unable to parse status"
            time.sleep(0.5)
        raise UnsupportedPayload(last_err)

    def set_values(self, overrides: dict) -> None:
        """Read current state, build a SET frame, then publish to /ESP."""
        self._ensure_login()
        self._ensure_device()
        self._ensure_mqtt()
        payload = None
        last_err = None
        for _ in range(2):
            try:
                status = self._read_status_c0(retries=1)
                payload = status.get("_payload")
                last_err = None
                break
            except Exception as err:
                last_err = err
                time.sleep(0.5)
        if not payload:
            raise UnsupportedPayload(f"No C0 payload (status read failed: {last_err})")
        tx = _build_set_cmd_from_c0(payload, overrides)
        if not tx:
            raise UnsupportedPayload("Failed to build SET frame")
        self._mqtt.publish(f"{self.topic}/ESP", {"Tx": tx, "CLIENT_ID": "SMTACUARTTEST"})
        # Try to read back status after SET to keep state in sync (best effort).
        time.sleep(1.0)
        try:
            self.read_status()
        except Exception as err:
            _LOGGER.warning("Readback after SET failed: %s", err)

    def set_value_ids(self, values: dict[str, str]) -> None:
        """Write Smart-Web value IDs directly via CLIENT2HOST.

        This is used for devices whose frontend operates on Smart-Web values instead of C0 ESP
        frames, such as RBW/DHW devices.
        """
        self._ensure_login()
        self._ensure_device()
        self._ensure_mqtt()
        profile_name = type(self.profile).__name__
        if profile_name == "DomesticHotWaterDeviceProfile":
            if self._mqtt_write_rbw_esp_values(values, timeout=10):
                time.sleep(1.0)
                try:
                    readback = self.read_status()
                    mismatches = {
                        str(key): {"expected": str(value), "actual": readback.get("dhw_setpoint")}
                        for key, value in values.items()
                        if str(key) == "1333"
                        and readback.get("dhw_setpoint") is not None
                        and abs((int(str(value), 16) / 10) - float(readback["dhw_setpoint"])) > 0.05
                    }
                    _LOGGER.warning(
                        "Experimental REMKO RBW/DHW ESP value write for %r readback status: %s",
                        self.device_name,
                        _debug_value(readback),
                    )
                    if not mismatches:
                        return
                    _LOGGER.warning(
                        "Experimental REMKO RBW/DHW ESP value write for %r was not confirmed by readback: %s",
                        self.device_name,
                        _debug_value(mismatches),
                    )
                except Exception as err:
                    _LOGGER.warning("Readback after RBW/DHW ESP value write failed: %s", err)
        elif profile_name == "KwtDeviceProfile":
            if self._mqtt_write_kwt_esp_values(values, timeout=10):
                time.sleep(1.0)
                try:
                    readback = self.read_status()
                    parsed_mismatches = self._value_write_readback_mismatches(values, readback)
                    _LOGGER.warning(
                        "Experimental REMKO KWT ESP value write for %r readback status: %s",
                        self.device_name,
                        _debug_value(readback),
                    )
                    if not parsed_mismatches:
                        return
                    _LOGGER.warning(
                        "Experimental REMKO KWT ESP value write for %r was not confirmed by readback: %s",
                        self.device_name,
                        _debug_value(parsed_mismatches),
                    )
                except Exception as err:
                    _LOGGER.warning("Readback after KWT ESP value write failed: %s", err)

        response_values = self._mqtt_write_values(values, timeout=10)
        if isinstance(response_values, dict):
            self._log_mapping_snapshot("client2host_write_values", response_values)
            mismatches = {
                str(key): {"expected": str(value), "actual": response_values.get(str(key))}
                for key, value in values.items()
                if not _smartweb_value_matches(value, response_values.get(str(key)))
            }
            parsed_values = self.profile.parse_values_status(response_values)
            if parsed_values:
                self._last_status = parsed_values
                _LOGGER.warning(
                    "Experimental REMKO SmartWeb value write for %r parsed response status: %s",
                    self.device_name,
                    _debug_value(parsed_values),
                )
            if not mismatches:
                return
            _LOGGER.warning(
                "Experimental REMKO SmartWeb value write for %r was not confirmed by HOST2CLIENT values: %s",
                self.device_name,
                _debug_value(mismatches),
            )
        time.sleep(1.0)
        try:
            readback = self.read_status()
            _LOGGER.warning(
                "Experimental REMKO SmartWeb value write for %r readback status: %s",
                self.device_name,
                _debug_value(readback),
            )
        except Exception as err:
            _LOGGER.warning("Readback after SmartWeb value write failed: %s", err)
        raise UnsupportedPayload("SmartWeb value write was not confirmed")

    def _value_write_readback_mismatches(self, values: dict[str, str], readback: dict) -> dict:
        mismatches = {}
        for key, value in values.items():
            key = str(key)
            try:
                id_value = int(str(value), 16)
            except Exception:
                continue
            if key == "1190":
                actual = readback.get("setpoint")
                if actual is not None and abs((id_value / 2) - float(actual)) > 0.05:
                    mismatches[key] = {"expected": id_value / 2, "actual": actual}
            elif key == "1194":
                actual = readback.get("power")
                expected = "ON" if id_value == 0x01 else "OFF" if id_value == 0x02 else None
                if expected is not None and actual is not None and actual != expected:
                    mismatches[key] = {"expected": expected, "actual": actual}
            elif key == "1192":
                actual = readback.get("mode")
                expected = {
                    0x03: "auto",
                    0x04: "cool",
                    0x05: "dry",
                    0x06: "heat",
                    0x07: "fan",
                }.get(id_value)
                if expected is not None and actual is not None and actual != expected:
                    mismatches[key] = {"expected": expected, "actual": actual}
            elif key == "1191":
                actual = readback.get("fan")
                expected = {
                    0x02: "auto",
                    0x03: "low",
                    0x04: "medium",
                    0x05: "high",
                    0x06: "silent",
                    0x0D: "high",
                }.get(id_value)
                if expected is not None and actual is not None and actual != expected:
                    mismatches[key] = {"expected": expected, "actual": actual}
            elif key == "1193":
                actual = readback.get("swing")
                expected = {
                    0x00: "off",
                    0x04: "vertical",
                }.get(id_value)
                if expected is not None and actual is not None and actual != expected:
                    mismatches[key] = {"expected": expected, "actual": actual}
        return mismatches

    def close(self):
        if self._mqtt is not None:
            self._mqtt.close()
            self._mqtt = None
        if self._owns_account:
            self.account.close()
