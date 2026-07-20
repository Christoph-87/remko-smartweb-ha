from __future__ import annotations

import json
import logging
import random
import re
import ssl
import threading
import time
from collections import deque
from datetime import date
from urllib.parse import parse_qs, unquote, urljoin, urlparse

import requests
import paho.mqtt.client as mqtt

from .const import DEVICE_KIND_AUTO
from .profiles import (
    DomesticHotWaterDeviceProfile,
    KwtDeviceProfile,
    LteDeviceProfile,
    WpmDeviceProfile,
    get_parser_profile,
    get_specialized_profile,
)

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
REDACTED = "[redacted]"
VALUE_STATUS_QUERY_LIST = [
    # Common AC / KWT values observed in the REMKO Smart-Web frontend.
    1046,
    1190,
    1191,
    1192,
    1193,
    1194,
    1195,
    1196,
    1197,
    1198,
    1199,
    1200,
    1218,
    1210,
    1211,
    1228,
    1229,
    1298,
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
    5081,
    6009,
    5943,
    5944,
    5946,
    5947,
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
    # WPM / WPK / WKM / SQW heat-pump values with explicit frontend mappings.
    4110,
    4113,
    5734,
    5774,
    1352,
    2179,
]
RBW_VALUE_WRITE_REGISTERS = {
    # SmartWeb value id: (Modbus register, converter)
    # Matches docs/lib.ac.uart.js RBW_convertDataForImport + RBW_setStatus.
    "1194": (1011, "power"),
    "1192": (1012, "mode"),
    "1333": (1104, "temp1"),
}
RBW_DIRECT_REGISTER_PREFIX = "rbw_register:"
RBW_MODE_REGISTER_VALUES = {
    0x03: 0,  # auto / intelligent
    0x09: 2,  # eco / economic
    0x0A: 3,  # hybrid
    0x0B: 4,  # speed heating / high demand
    0x0C: 7,  # vacation
}
RBW_REGISTER_MODE_VALUES = {
    0: "auto",
    2: "eco",
    3: "hybrid",
    4: "speed_heating",
    7: "vacation",
}
RBW_READ_RANGES = (
    (1001, 90),
    (1091, 90),
    (2001, 90),
)
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
KWT_REGISTER_MODE_VALUES = {
    0: 0x03,  # auto
    1: 0x06,  # heat
    2: 0x04,  # cool
    3: 0x07,  # fan only
    4: 0x05,  # dry
}
KWT_REGISTER_FAN_VALUES = {
    0: 0x02,  # auto
    1: 0x03,  # low
    2: 0x04,  # medium
    3: 0x05,  # high
    4: 0x0D,  # boost
}
KWT_READ_RANGES = (
    (10000, 3),
    (10010, 1),
    (10015, 2),
    (10020, 1),
    (13000, 1),
    (11000, 1),
    (11001, 1),
    (11004, 1),
    (11010, 1),
    (200, 1),
    (198, 1),
    (199, 1),
)
WPM_READ_RANGES = (
    (1, 1, 62),
    (1, 71, 171),
    (3, 1, 100),
    (3, 401, 16),
)


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


def _value_response_summary(values: dict | None, expected: dict | None = None) -> dict:
    summary = {"values_count": len(values) if isinstance(values, dict) else 0}
    if isinstance(values, dict) and expected:
        summary["written_values"] = {
            str(key): values.get(str(key))
            for key in expected
        }
    return summary


def _parsed_status_summary(status: dict | None) -> dict:
    if not isinstance(status, dict):
        return {"parsed": False}
    visible_keys = sorted(str(key) for key in status if not str(key).startswith("_"))
    summary = {
        "parsed": True,
        "parsed_keys": visible_keys,
    }
    for key in ("setpoint", "dhw_setpoint", "room", "dhw_top_temperature", "mode", "dhw_mode", "power"):
        if key in status:
            summary[key] = status.get(key)
    return summary


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


def _json_loads_maybe_wrapped(payload: str):
    try:
        data = json.loads(payload)
    except Exception:
        return None
    if isinstance(data, str):
        try:
            return json.loads(data)
        except Exception:
            return data
    return data


def _extract_sid_sk_from_url(url: str):
    qs = parse_qs(urlparse(url).query, keep_blank_values=True)
    sid = (qs.get("SID") or [None])[0]
    sk = (qs.get("SK") or [None])[0]
    if _valid_credential_part(sid) and _valid_credential_part(sk):
        return sid.upper(), sk.upper()
    return None


def _extract_smartweb_portal_params_from_text(text: str) -> dict[str, str]:
    if not text:
        return {}
    normalized = text.replace("&amp;", "&")
    matches = re.findall(r"""['"]([^'"]*smt\.html\?[^'"]+)['"]""", normalized, flags=re.I)
    for match in matches:
        parsed = urlparse(unquote(match))
        qs = parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            continue
        params = {}
        for key in ("SMT_ID", "SID", "SK", "us", "SMT_USER", "smt_user", "DEV", "NAME", "TYPE"):
            value = (qs.get(key) or [None])[0]
            if value not in (None, ""):
                params[key] = value
        if params:
            return params
    return {}


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
    portal_params = _extract_smartweb_portal_params_from_text(text)
    for key in ("us", "SMT_USER", "smt_user"):
        value = portal_params.get(key)
        if str(value or "").isdigit():
            return int(value)
    for pat in (
        r"SMT_USER\s*[:=]\s*(\d+)",
        r"\"SMT_USER\"\s*:\s*(\d+)",
        r"smt_user\s*[:=]\s*(\d+)",
        r"\"smt_user\"\s*:\s*(\d+)",
        r"[?&]us=(\d+)(?:[&#\"']|$)",
        r"[?&]SMT_USER=(\d+)(?:[&#\"']|$)",
        r"[?&]smt_user=(\d+)(?:[&#\"']|$)",
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


def _extract_device_metadata_from_text(text: str) -> dict[str, str]:
    params = _extract_smartweb_portal_params_from_text(text)
    metadata = {}
    for source_key, target_key in (
        ("SMT_ID", "device_portal_id"),
        ("DEV", "device_dev"),
        ("NAME", "device_portal_name"),
        ("TYPE", "device_type"),
    ):
        value = params.get(source_key)
        if value:
            metadata[target_key] = value
    return metadata


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
        data = [int(text[index : index + 2], 16) for index in range(0, len(text), 2)]
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


def _parse_rbw_register_status(registers: dict[int, int]) -> dict | None:
    if not registers:
        return None
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


def _rbw_vacation_date(year: int | None, month: int | None, day: int | None) -> str | None:
    if year is None or month is None or day is None:
        return None
    if year < 100:
        year += 2000
    try:
        return date(year, month, day).isoformat()
    except ValueError:
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
        data = [int(text[index : index + 2], 16) for index in range(0, len(text), 2)]
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
        data = [int(text[index : index + 2], 16) for index in range(0, len(text), 2)]
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


def _hex_byte(value: int | None) -> str | None:
    if value is None:
        return None
    return f"{max(0, min(0xFF, int(value))):02X}"


def _hex_word(value: int | None) -> str | None:
    if value is None:
        return None
    return f"{int(value) & 0xFFFF:04X}"


def _parse_kwt_register_status(registers: dict[int, int]) -> dict[str, str] | None:
    if not registers:
        return None
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


def _clamp_int(value, low: int, high: int, default: int) -> int:
    try:
        number = int(round(float(value)))
    except Exception:
        return default
    return max(low, min(high, number))


def _bool_state(value, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.upper() == "ON"
    if value is None:
        return default
    return bool(value)


def _high_level_status(current_status: dict | None, overrides: dict) -> dict:
    status = dict(current_status or {})
    status.update({key: value for key, value in overrides.items() if value is not None})
    return status


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


WPM_VALUE_WRITE_REGISTERS = {
    # SmartWeb value id: (Modbus register, register type)
    # Matches docs/lib.ac.uart.js WPM_convertDataForImport + WPM_setStatus.
    "4110": (73, "COIL"),
    "4113": (88, "COIL"),
    "5774": (50, "HOLDING"),
    "1352": (415, "HOLDING"),
    "2179": (416, "HOLDING"),
}


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


def _extract_values_from_payload(payload: str):
    data = _json_loads_maybe_wrapped(payload)
    if isinstance(data, dict) and "values" in data:
        return data.get("values")
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
                obj = _json_loads_maybe_wrapped(text)
                if isinstance(obj, dict):
                    if obj.get("Rx"):
                        self._last_rx = json.dumps(obj)
                        self._cond.notify_all()
                    smt_user = obj.get("SMT_USER")
                    if str(smt_user or "").isdigit():
                        self._last_smt_user = int(smt_user)
                values = _extract_values_from_payload(text)
                if isinstance(values, dict) and str(msg.topic).endswith("/HOST2CLIENT"):
                    self._last_values = values
                    self._last_seen_values = values
                    self._cond.notify_all()
        except Exception:
            _LOGGER.exception("Unexpected error in MQTT message handler (topic=%s)", msg.topic)

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
            headers={"User-Agent": "Home Assistant", "X-Requested-With": "XMLHttpRequest", "Origin": BASE, "Referer": f"{BASE}/"},
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
        self.device_portal_id = None
        self.device_dev = None
        self.device_portal_name = None
        self.device_type = None
        self._last_payload = None
        self._last_status = None
        self._last_status_source = None
        self._last_mapping_values = None
        self._last_device_list_error = None
        self._last_device_list_empty = False
        self._last_support_snapshot_signature = None
        self._mqtt = None
        self._write_lock = threading.RLock()

    def initial_status_if_supported(self) -> dict | None:
        """Return a minimal state when setup can safely proceed before live values arrive."""
        if (
            self.device_kind != DEVICE_KIND_AUTO
            or get_specialized_profile(self._profile_hint_name()) is not None
        ):
            return {"unit": "C", "_status_pending": True}
        return None

    def _profile_hint_name(self) -> str:
        return " ".join(
            value
            for value in (self.device_type, self.device_portal_name, self.device_name)
            if value
        )

    def _apply_device_metadata(self, metadata: dict[str, str]) -> None:
        if not metadata:
            return
        self.device_dev = metadata.get("device_dev") or self.device_dev
        self.device_portal_id = metadata.get("device_portal_id") or self.device_portal_id
        self.device_portal_name = metadata.get("device_portal_name") or self.device_portal_name
        self.device_type = metadata.get("device_type") or self.device_type
        if self.device_kind == DEVICE_KIND_AUTO:
            profile = get_specialized_profile(self._profile_hint_name())
            if profile is not None:
                self.profile = profile

    def diagnostic_metadata(self) -> dict[str, str]:
        profile = self.profile
        metadata = {
            "Detected Profile": getattr(profile, "profile_name", type(profile).__name__),
            "Profile Class": type(profile).__name__,
            "Profile Protocol": getattr(profile, "protocol_name", ""),
            "Profile Write Support": "yes" if (
                getattr(profile, "supports_climate_write", False)
                or getattr(profile, "supports_value_write", False)
            ) else "no",
        }
        if self.device_portal_id:
            metadata["Portal ID"] = self.device_portal_id
        if self.device_portal_name:
            metadata["Portal Name"] = self.device_portal_name
        if self.device_type:
            metadata["Portal Type"] = self.device_type
        if self.device_dev:
            metadata["Portal DEV"] = self.device_dev
        if self.topic:
            metadata["MQTT Topic"] = _redact_debug_text(self.topic)
        return metadata

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
                        self._apply_device_metadata(_extract_device_metadata_from_text(r1.text))
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
        self._apply_device_metadata(_extract_device_metadata_from_text(r1.text))
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

    def _mqtt_write_values(self, values: dict[str, str], timeout=10, write_id: str | None = None) -> dict | None:
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
        write_id = write_id or f"{random.getrandbits(24):06x}"
        _LOGGER.warning(
            "REMKO SmartWeb write start: %s",
            _debug_value(
                {
                    "write_id": write_id,
                    "device": self.device_name,
                    "path": "client2host",
                    "profile": getattr(getattr(self, "profile", None), "profile_name", "unknown"),
                    "value_ids": sorted(str(key) for key in values),
                    "smt_user_present": "SMT_USER" in payload,
                    "topic_present": bool(self.topic),
                }
            ),
        )
        _LOGGER.debug(
            "REMKO SmartWeb write payload: %s",
            _debug_value({"write_id": write_id, "payload": payload}, limit=DEBUG_VALUES_LIMIT),
        )
        self._mqtt.clear_values()
        self._mqtt.publish(f"{self.topic}/CLIENT2HOST", payload)
        response_values = self._mqtt.wait_values(timeout=timeout)
        if isinstance(response_values, dict):
            _LOGGER.warning(
                "REMKO SmartWeb write response: %s",
                _debug_value(
                    {
                        "write_id": write_id,
                        "device": self.device_name,
                        "path": "client2host",
                        **_value_response_summary(response_values, values),
                    }
                ),
            )
            _LOGGER.debug(
                "REMKO SmartWeb write response values: %s",
                _debug_value({"write_id": write_id, "values": response_values}, limit=DEBUG_VALUES_LIMIT),
            )
        else:
            _LOGGER.warning(
                "REMKO SmartWeb write response timeout: %s",
                _debug_value(
                    {
                        "write_id": write_id,
                        "device": self.device_name,
                        "path": "client2host",
                        "timeout_sec": timeout,
                    }
                ),
            )
        return response_values

    def _mqtt_write_rbw_esp_values(self, values: dict[str, str], timeout=10, write_id: str | None = None) -> bool:
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
                "REMKO SmartWeb write start: %s",
                _debug_value(
                    {
                        "write_id": write_id,
                        "device": self.device_name,
                        "path": "rbw_esp",
                        "value_id": str(key),
                        "expected_hex": str(value),
                        "tx": tx,
                    }
                ),
            )
            self._mqtt.publish(f"{self.topic}/ESP", {"Tx": tx, "CLIENT_ID": "SMTACUARTTEST"})
            # The frontend waits for RESP and then refreshes the value model.
            self._mqtt.wait_rx(timeout=timeout)
            time.sleep(1.0)
        return not unsupported

    def _mqtt_write_kwt_esp_values(self, values: dict[str, str], timeout=10, write_id: str | None = None) -> bool:
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
                "REMKO SmartWeb write start: %s",
                _debug_value(
                    {
                        "write_id": write_id,
                        "device": self.device_name,
                        "path": "kwt_esp",
                        "value_id": str(key),
                        "expected_hex": str(value),
                        "tx": tx,
                    }
                ),
            )
            self._mqtt.publish(f"{self.topic}/ESP", {"Tx": tx, "CLIENT_ID": "SMTACUARTTEST"})
            self._mqtt.wait_rx(timeout=timeout)
            time.sleep(1.0)
        return not unsupported

    def _mqtt_write_ac_uart_frames(self, tx_frames: list[str], protocol_name: str, write_id: str, timeout=10) -> bool:
        """Write experimental AC UART Tx frames through the ESP path used by the frontend."""
        if not self.sid or not self.sk or not self.topic:
            raise DeviceResolveError("Device not resolved")
        self._ensure_mqtt()
        for index, tx in enumerate(tx_frames, start=1):
            _LOGGER.warning(
                "REMKO SmartWeb write start: %s",
                _debug_value(
                    {
                        "write_id": write_id,
                        "device": self.device_name,
                        "path": protocol_name,
                        "frame": index,
                        "frame_count": len(tx_frames),
                        "tx": tx,
                    }
                ),
            )
            self._mqtt.publish(f"{self.topic}/ESP", {"Tx": tx, "CLIENT_ID": "SMTACUARTTEST"})
            self._mqtt.wait_rx(timeout=timeout)
            time.sleep(0.5)
        return True

    def _mqtt_write_lte_esp_values(self, values: dict[str, str], timeout=10, write_id: str | None = None) -> bool:
        current_status = self._last_status if isinstance(self._last_status, dict) else None
        tx = _build_lte_set_cmd(current_status, values)
        if not tx:
            return False
        write_id = write_id or f"{random.getrandbits(24):06x}"
        _LOGGER.warning(
            "REMKO SmartWeb experimental LTE write start: %s",
            _debug_value(
                {
                    "write_id": write_id,
                    "device": self.device_name,
                    "path": "lte_ac_uart",
                    "value_ids": sorted(str(key) for key in values),
                    "tx": tx,
                }
            ),
        )
        self._mqtt.publish(f"{self.topic}/ESP", {"Tx": tx, "CLIENT_ID": "SMTACUARTTEST"})
        self._mqtt.wait_rx(timeout=timeout)
        return True

    def _mqtt_write_wpm_esp_values(self, values: dict[str, str], timeout=10, write_id: str | None = None) -> bool:
        write_id = write_id or f"{random.getrandbits(24):06x}"
        unsupported = []
        for key, value in values.items():
            tx = _build_wpm_set_cmd(str(key), str(value))
            if not tx:
                unsupported.append(str(key))
                continue
            _LOGGER.warning(
                "REMKO SmartWeb experimental WPM write start: %s",
                _debug_value(
                    {
                        "write_id": write_id,
                        "device": self.device_name,
                        "path": "wpm_modbus",
                        "value_id": str(key),
                        "expected_hex": str(value),
                        "tx": tx,
                    }
                ),
            )
            self._mqtt.publish(f"{self.topic}/ESP", {"Tx": tx, "CLIENT_ID": "SMTACUARTTEST"})
            self._mqtt.wait_rx(timeout=timeout)
            time.sleep(0.5)
        return not unsupported

    def _mqtt_diagnostic_snapshot(self):
        if self._mqtt is None:
            return None
        return self._mqtt.diagnostic_snapshot()

    def _log_poll_summary(
        self,
        source: str,
        *,
        parsed: dict | None = None,
        values: dict | None = None,
        duration: float | None = None,
    ) -> None:
        if not _LOGGER.isEnabledFor(logging.DEBUG):
            return
        summary = {
            "device": self.device_name,
            "source": source,
            "profile": getattr(self.profile, "profile_name", type(self.profile).__name__),
            "profile_class": type(self.profile).__name__,
            "protocol": getattr(self.profile, "protocol_name", ""),
            "topic_present": bool(self.topic),
            "smt_user_present": self.smt_user is not None,
            "values_count": len(values) if isinstance(values, dict) else None,
        }
        if duration is not None:
            summary["duration_sec"] = round(duration, 3)
        summary.update(_parsed_status_summary(parsed))
        _LOGGER.debug("REMKO SmartWeb poll summary: %s", _debug_value(summary))

    def _log_support_snapshot_once(
        self,
        reason: str,
        *,
        stage: str,
        values: dict | None = None,
        error: str | None = None,
    ) -> None:
        mqtt_diagnostics = self._mqtt_diagnostic_snapshot()
        signature = (
            reason,
            stage,
            type(self.profile).__name__,
            bool(self.topic),
            self.smt_user is not None,
            len(values) if isinstance(values, dict) else None,
            error,
        )
        if signature == self._last_support_snapshot_signature:
            return
        self._last_support_snapshot_signature = signature
        metadata = self.diagnostic_metadata()
        snapshot = {
            "device": self.device_name,
            "reason": reason,
            "stage": stage,
            "profile": metadata.get("Detected Profile"),
            "profile_class": metadata.get("Profile Class"),
            "protocol": metadata.get("Profile Protocol"),
            "portal_type": metadata.get("Portal Type"),
            "portal_dev": metadata.get("Portal DEV"),
            "mqtt_topic_present": bool(self.topic),
            "smt_user_present": self.smt_user is not None,
            "values_count": len(values) if isinstance(values, dict) else None,
            "last_values_count": (
                len(mqtt_diagnostics["last_values"])
                if isinstance(mqtt_diagnostics, dict)
                and isinstance(mqtt_diagnostics.get("last_values"), dict)
                else None
            ),
            "last_error": error,
        }
        _LOGGER.warning("REMKO SmartWeb support snapshot: %s", _debug_value(snapshot))

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

    def _read_status_rbw_modbus(self, started: float) -> dict | None:
        """Read RBW 302 Pro status through the frontend's direct ESP Modbus path."""
        registers: dict[int, int] = {}
        responses = {}
        for register, quantity in RBW_READ_RANGES:
            tx = _build_rbw_get_status_cmd(register, quantity)
            if tx is None:
                continue
            payload = {"Tx": tx, "CLIENT_ID": "SMTACUARTTEST"}
            resp = self._mqtt_roundtrip_esp(payload, timeout=10)
            responses[str(register)] = resp
            obj = _json_loads_maybe_wrapped(resp) if resp else None
            rx_hex = obj.get("Rx") if isinstance(obj, dict) else None
            parsed_registers = _parse_rbw_registers_rx(rx_hex)
            if parsed_registers:
                registers.update(parsed_registers)
                continue
            self._log_unsupported_payload(
                f"rbw_esp_{register}",
                esp_response=resp,
                mqtt_diagnostics=self._mqtt_diagnostic_snapshot(),
            )

        parsed = _parse_rbw_register_status(registers)
        if registers:
            self._log_mapping_snapshot("rbw_esp_registers", registers)
        if not parsed:
            self._log_unsupported_payload(
                "rbw_esp_status",
                esp_responses=responses,
                mqtt_diagnostics=self._mqtt_diagnostic_snapshot(),
            )
            return None
        self._last_status = parsed
        self._last_status_source = "rbw_esp"
        self._log_poll_summary("rbw_esp", parsed=parsed, duration=time.monotonic() - started)
        return parsed

    def _read_status_kwt_modbus(self, started: float) -> dict | None:
        """Read KWT status through the frontend's direct ESP Modbus path."""
        registers: dict[int, int] = {}
        responses = {}
        for register, quantity in KWT_READ_RANGES:
            tx = _build_modbus_read_cmd(1, 3, register, quantity)
            if tx is None:
                continue
            payload = {"Tx": tx, "CLIENT_ID": "SMTACUARTTEST"}
            resp = self._mqtt_roundtrip_esp(payload, timeout=10)
            responses[str(register)] = resp
            obj = _json_loads_maybe_wrapped(resp) if resp else None
            rx_hex = obj.get("Rx") if isinstance(obj, dict) else None
            parsed_registers = _parse_modbus_holding_rx(rx_hex, register)
            if parsed_registers:
                registers.update(parsed_registers)
                continue
            self._log_unsupported_payload(
                f"kwt_esp_{register}",
                esp_response=resp,
                mqtt_diagnostics=self._mqtt_diagnostic_snapshot(),
            )

        values = _parse_kwt_register_status(registers)
        parsed = self.profile.parse_values_status(values) if values else None
        if not parsed:
            self._log_unsupported_payload(
                "kwt_esp_status",
                esp_responses=responses,
                mqtt_diagnostics=self._mqtt_diagnostic_snapshot(),
            )
            return None
        self._last_status = parsed
        self._last_status_source = "kwt_esp"
        self._log_poll_summary("kwt_esp", parsed=parsed, values=values, duration=time.monotonic() - started)
        return parsed

    def _read_status_wpm_modbus(self, started: float) -> dict | None:
        """Read WPM status through the frontend's direct ESP Modbus path."""
        coils: dict[int, int] = {}
        holding: dict[int, int] = {}
        responses = {}
        for function_code, register, quantity in WPM_READ_RANGES:
            tx = _build_modbus_read_cmd(1, function_code, register, quantity)
            if tx is None:
                continue
            payload = {"Tx": tx, "CLIENT_ID": "SMTACUARTTEST"}
            resp = self._mqtt_roundtrip_esp(payload, timeout=10)
            responses[f"{function_code}:{register}"] = resp
            obj = _json_loads_maybe_wrapped(resp) if resp else None
            rx_hex = obj.get("Rx") if isinstance(obj, dict) else None
            parsed_values = (
                _parse_modbus_coils_rx(rx_hex, register, quantity)
                if function_code == 1
                else _parse_modbus_holding_rx(rx_hex, register)
            )
            if parsed_values:
                if function_code == 1:
                    coils.update(parsed_values)
                else:
                    holding.update(parsed_values)
                continue
            self._log_unsupported_payload(
                f"wpm_esp_{function_code}_{register}",
                esp_response=resp,
                mqtt_diagnostics=self._mqtt_diagnostic_snapshot(),
            )

        values = _parse_wpm_register_status(coils, holding)
        parsed = self.profile.parse_values_status(values) if values else None
        if not parsed:
            self._log_unsupported_payload(
                "wpm_esp_status",
                esp_responses=responses,
                mqtt_diagnostics=self._mqtt_diagnostic_snapshot(),
            )
            return None
        self._last_status = parsed
        self._last_status_source = "wpm_esp"
        self._log_poll_summary("wpm_esp", parsed=parsed, values=values, duration=time.monotonic() - started)
        return parsed

    def read_status(self) -> dict:
        started = time.monotonic()
        self._ensure_login()
        self._ensure_device()
        self._ensure_mqtt()
        protocol_name = getattr(self.profile, "protocol_name", "")
        if protocol_name == "rbw_modbus":
            parsed_rbw = self._read_status_rbw_modbus(started)
            if parsed_rbw:
                return parsed_rbw
        elif protocol_name == "kwt_modbus":
            parsed_kwt = self._read_status_kwt_modbus(started)
            if parsed_kwt:
                return parsed_kwt
        elif protocol_name == "wpm_modbus":
            parsed_wpm = self._read_status_wpm_modbus(started)
            if parsed_wpm:
                return parsed_wpm

        tx = _build_status_cmd()
        payload = {"Tx": tx, "CLIENT_ID": "SMTACUARTTEST"}
        resp = self._mqtt_roundtrip_esp(payload, timeout=10)

        def _parse(resp_text: str | None) -> dict | None:
            if not resp_text:
                return None
            obj = _json_loads_maybe_wrapped(resp_text)
            if isinstance(obj, dict):
                rx_hex = obj.get("Rx")
                if rx_hex:
                    parsed = self.profile.parse_c0_status(rx_hex)
                    if parsed:
                        return parsed
            return None

        parsed = _parse(resp)
        if parsed:
            self._last_payload = parsed.get("_payload")
            self._last_status = parsed
            self._last_status_source = "esp_rx"
            self._log_poll_summary("esp_rx", parsed=parsed, duration=time.monotonic() - started)
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
                self._last_status_source = "client2host_values"
                self._log_poll_summary(
                    "client2host_values",
                    parsed=merged,
                    values=values,
                    duration=time.monotonic() - started,
                )
                return merged
            self._last_status = parsed_values
            self._last_status_source = "client2host_values"
            self._log_poll_summary(
                "client2host_values",
                parsed=parsed_values,
                values=values,
                duration=time.monotonic() - started,
            )
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
            self._last_status_source = "esp_rx_retry"
            self._log_poll_summary("esp_rx_retry", parsed=parsed, duration=time.monotonic() - started)
            return parsed
        self._log_unsupported_payload(
            "esp_status_retry",
            esp_response=resp,
            mqtt_diagnostics=self._mqtt_diagnostic_snapshot(),
        )

        if self._last_status:
            self._last_status_source = "cached_last_status"
            self._log_support_snapshot_once(
                "status_unparseable_using_last_status",
                stage="read_status",
                values=values,
                error="Unable to parse status",
            )
            self._log_poll_summary(
                "cached_last_status",
                parsed=self._last_status,
                values=values,
                duration=time.monotonic() - started,
            )
            return self._last_status
        if self.profile.diagnostics_only:
            self._last_status = {"_diagnostics_only": True}
            self._last_status_source = "diagnostics_only"
            self._log_poll_summary(
                "diagnostics_only",
                parsed=self._last_status,
                values=values,
                duration=time.monotonic() - started,
            )
            return self._last_status
        self._log_support_snapshot_once(
            "status_unparseable",
            stage="read_status",
            values=values,
            error="Unable to parse status",
        )
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
            obj = _json_loads_maybe_wrapped(resp_text)
            if isinstance(obj, dict):
                rx_hex = obj.get("Rx")
                if rx_hex:
                    parsed = self.profile.parse_c0_status(rx_hex)
                    if parsed:
                        return parsed
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
        protocol_name = getattr(self.profile, "protocol_name", "")
        if protocol_name in ("free_ac_uart", "aux_ac_uart", "nwt_ac_uart"):
            write_id = f"{random.getrandbits(24):06x}"
            current_status = self._last_status if isinstance(self._last_status, dict) else None
            if current_status is None or current_status.get("_status_pending"):
                values = self._mqtt_poll_values(timeout=10)
                current_status = self.profile.parse_values_status(values) if values else None
            tx_frames = _build_ac_uart_set_cmds(protocol_name, current_status, overrides)
            if not tx_frames:
                raise UnsupportedPayload(f"No experimental AC UART Tx frame for {protocol_name} overrides")
            _LOGGER.warning(
                "REMKO SmartWeb experimental AC UART write: %s",
                _debug_value(
                    {
                        "write_id": write_id,
                        "device": self.device_name,
                        "path": protocol_name,
                        "overrides": overrides,
                        "current_status_keys": sorted(current_status.keys()) if isinstance(current_status, dict) else [],
                        "frame_count": len(tx_frames),
                    }
                ),
            )
            self._mqtt_write_ac_uart_frames(tx_frames, protocol_name, write_id, timeout=10)
            time.sleep(1.0)
            try:
                readback = self.read_status()
                _LOGGER.warning(
                    "REMKO SmartWeb experimental AC UART write readback: %s",
                    _debug_value(
                        {
                            "write_id": write_id,
                            "device": self.device_name,
                            "path": protocol_name,
                            "readback_source": getattr(self, "_last_status_source", None),
                            **_parsed_status_summary(readback),
                        }
                    ),
                )
            except Exception as err:
                _LOGGER.warning(
                    "REMKO SmartWeb experimental AC UART write readback failed: %s",
                    _debug_value(
                        {
                            "write_id": write_id,
                            "device": self.device_name,
                            "path": protocol_name,
                            "error": str(err),
                        }
                    ),
                )
            return
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
        if not payload and self._last_payload:
            _LOGGER.warning(
                "REMKO SmartWeb write using cached C0 payload for %r (live read failed: %s)",
                self.device_name,
                last_err,
            )
            payload = self._last_payload
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
        write_lock = getattr(self, "_write_lock", None)
        if write_lock is None:
            write_lock = self._write_lock = threading.RLock()
        with write_lock:
            return self._set_value_ids_unlocked(values)

    def _set_value_ids_unlocked(self, values: dict[str, str]) -> None:
        """Write Smart-Web value IDs directly via CLIENT2HOST.

        This is used for devices whose frontend operates on Smart-Web values instead of C0 ESP
        frames, such as RBW/DHW devices.
        """
        self._ensure_login()
        self._ensure_device()
        self._ensure_mqtt()
        write_id = f"{random.getrandbits(24):06x}"
        if isinstance(self.profile, DomesticHotWaterDeviceProfile):
            if self._mqtt_write_rbw_esp_values(values, timeout=10, write_id=write_id):
                time.sleep(1.0)
                try:
                    readback = self.read_status()
                    readback_source = getattr(self, "_last_status_source", None)
                    mismatches = {
                        str(key): {"expected": str(value), "actual": readback.get("dhw_setpoint")}
                        for key, value in values.items()
                        if str(key) == "1333"
                        and readback.get("dhw_setpoint") is not None
                        and abs((int(str(value), 16) / 10) - float(readback["dhw_setpoint"])) > 0.05
                    }
                    _LOGGER.warning(
                        "REMKO SmartWeb write readback: %s",
                        _debug_value(
                            {
                                "write_id": write_id,
                                "device": self.device_name,
                                "path": "rbw_esp",
                                "confirmed": None if readback_source == "cached_last_status" else not bool(mismatches),
                                "readback_source": readback_source,
                                **_parsed_status_summary(readback),
                            }
                        ),
                    )
                    if not mismatches:
                        return
                    if readback_source == "cached_last_status":
                        _LOGGER.warning(
                            "REMKO SmartWeb write confirmation pending: %s",
                            _debug_value(
                                {
                                    "write_id": write_id,
                                    "device": self.device_name,
                                    "path": "rbw_esp",
                                    "reason": "fresh_readback_unavailable",
                                    "mismatches_ignored": mismatches,
                                }
                            ),
                        )
                        return
                    _LOGGER.warning(
                        "REMKO SmartWeb write fallback: %s",
                        _debug_value(
                            {
                                "write_id": write_id,
                                "device": self.device_name,
                                "from_path": "rbw_esp",
                                "to_path": "client2host",
                                "reason": "readback_mismatch",
                                "mismatches": mismatches,
                            }
                        ),
                    )
                except Exception as err:
                    _LOGGER.warning(
                        "REMKO SmartWeb write fallback: %s",
                        _debug_value(
                            {
                                "write_id": write_id,
                                "device": self.device_name,
                                "from_path": "rbw_esp",
                                "to_path": "client2host",
                                "reason": "readback_failed",
                                "error": str(err),
                            }
                        ),
                    )
        elif isinstance(self.profile, KwtDeviceProfile):
            if self._mqtt_write_kwt_esp_values(values, timeout=10, write_id=write_id):
                time.sleep(1.0)
                try:
                    readback = self.read_status()
                    parsed_mismatches = self._value_write_readback_mismatches(values, readback)
                    _LOGGER.warning(
                        "REMKO SmartWeb write readback: %s",
                        _debug_value(
                            {
                                "write_id": write_id,
                                "device": self.device_name,
                                "path": "kwt_esp",
                                "confirmed": not bool(parsed_mismatches),
                                **_parsed_status_summary(readback),
                            }
                        ),
                    )
                    if not parsed_mismatches:
                        return
                    _LOGGER.warning(
                        "REMKO SmartWeb write fallback: %s",
                        _debug_value(
                            {
                                "write_id": write_id,
                                "device": self.device_name,
                                "from_path": "kwt_esp",
                                "to_path": "client2host",
                                "reason": "readback_mismatch",
                                "mismatches": parsed_mismatches,
                            }
                        ),
                    )
                except Exception as err:
                    _LOGGER.warning(
                        "REMKO SmartWeb write fallback: %s",
                        _debug_value(
                            {
                                "write_id": write_id,
                                "device": self.device_name,
                                "from_path": "kwt_esp",
                                "to_path": "client2host",
                                "reason": "readback_failed",
                                "error": str(err),
                            }
                        ),
                    )
        elif isinstance(self.profile, LteDeviceProfile):
            if self._mqtt_write_lte_esp_values(values, timeout=10, write_id=write_id):
                time.sleep(1.0)
                try:
                    readback = self.read_status()
                    _LOGGER.warning(
                        "REMKO SmartWeb experimental LTE write readback: %s",
                        _debug_value(
                            {
                                "write_id": write_id,
                                "device": self.device_name,
                                "path": "lte_ac_uart",
                                "readback_source": getattr(self, "_last_status_source", None),
                                **_parsed_status_summary(readback),
                            }
                        ),
                    )
                except Exception as err:
                    _LOGGER.warning(
                        "REMKO SmartWeb experimental LTE write readback failed: %s",
                        _debug_value(
                            {
                                "write_id": write_id,
                                "device": self.device_name,
                                "path": "lte_ac_uart",
                                "error": str(err),
                            }
                        ),
                    )
                return
        elif isinstance(self.profile, WpmDeviceProfile):
            if self._mqtt_write_wpm_esp_values(values, timeout=10, write_id=write_id):
                time.sleep(1.0)
                try:
                    readback = self.read_status()
                    _LOGGER.warning(
                        "REMKO SmartWeb experimental WPM write readback: %s",
                        _debug_value(
                            {
                                "write_id": write_id,
                                "device": self.device_name,
                                "path": "wpm_modbus",
                                "readback_source": getattr(self, "_last_status_source", None),
                                **_parsed_status_summary(readback),
                            }
                        ),
                    )
                except Exception as err:
                    _LOGGER.warning(
                        "REMKO SmartWeb experimental WPM write readback failed: %s",
                        _debug_value(
                            {
                                "write_id": write_id,
                                "device": self.device_name,
                                "path": "wpm_modbus",
                                "error": str(err),
                            }
                        ),
                    )
                return

        response_values = self._mqtt_write_values(values, timeout=10, write_id=write_id)
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
                    "REMKO SmartWeb write parsed response: %s",
                    _debug_value(
                        {
                            "write_id": write_id,
                            "device": self.device_name,
                            "path": "client2host",
                            **_parsed_status_summary(parsed_values),
                        }
                    ),
                )
            if not mismatches:
                return
            _LOGGER.warning(
                "REMKO SmartWeb write response mismatch: %s",
                _debug_value(
                    {
                        "write_id": write_id,
                        "device": self.device_name,
                        "path": "client2host",
                        "mismatches": mismatches,
                    }
                ),
            )
        time.sleep(1.0)
        try:
            readback = self.read_status()
            _LOGGER.warning(
                "REMKO SmartWeb write readback: %s",
                _debug_value(
                    {
                        "write_id": write_id,
                        "device": self.device_name,
                        "path": "client2host",
                        "confirmed": False,
                        **_parsed_status_summary(readback),
                    }
                ),
            )
        except Exception as err:
            _LOGGER.warning(
                "REMKO SmartWeb write readback failed: %s",
                _debug_value(
                    {
                        "write_id": write_id,
                        "device": self.device_name,
                        "path": "client2host",
                        "error": str(err),
                    }
                ),
            )
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
