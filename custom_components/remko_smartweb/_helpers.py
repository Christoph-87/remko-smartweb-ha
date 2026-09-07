"""Utility / debug / parse helpers and HTTP extraction functions."""
from __future__ import annotations

import json
import logging
import re
import threading
import time
from urllib.parse import parse_qs, unquote, urljoin, urlparse

import requests

_LOGGER = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants used only / primarily in helpers (exported back to api.py)
# ---------------------------------------------------------------------------

REDACTED = "[redacted]"
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

# Default limits — api.py defines authoritative copies; these are fallbacks so
# that _helpers.py is importable without importing api.py (breaks circular dep).
DEBUG_PAYLOAD_LIMIT = 2000
DEBUG_VALUES_LIMIT = 200000

# SmartWeb base URL and version — needed for _extract_smt_user_from_scripts.
# These duplicates match the constants in api.py.
_BASE = "https://smartweb.remko.media"
_VERSION = "V04P27"
_ACCOUNT_REQUEST_MIN_INTERVAL_SEC = 0.5

# ---------------------------------------------------------------------------
# Rate-limiter
# ---------------------------------------------------------------------------

_ACCOUNT_REQUEST_LOCK = threading.Lock()
_ACCOUNT_LAST_REQUEST_AT = 0.0


def _pace_account_request() -> None:
    global _ACCOUNT_LAST_REQUEST_AT
    with _ACCOUNT_REQUEST_LOCK:
        wait = _ACCOUNT_REQUEST_MIN_INTERVAL_SEC - (time.time() - _ACCOUNT_LAST_REQUEST_AT)
        if wait > 0:
            time.sleep(wait)
        _ACCOUNT_LAST_REQUEST_AT = time.time()


# ---------------------------------------------------------------------------
# Name / text normalisation
# ---------------------------------------------------------------------------

def _normalize_device_name(name: str | None) -> str:
    if not name:
        return ""
    normalized = name.casefold()
    normalized = normalized.replace("–", "-").replace("—", "-")
    normalized = re.sub(r"\s+", " ", normalized)
    return normalized.strip()


# ---------------------------------------------------------------------------
# Debug / redaction helpers
# ---------------------------------------------------------------------------

def _redact_debug_text(text: str) -> str:
    """Mask likely credentials and session identifiers before logging."""
    replacements = (
        (r"([?&](?:SID|SK)=)[^&\s\"']+", rf"\1{REDACTED}"),
        (r"(V\d{{2}}P\d{{2}}/)[0-9A-Fa-f]{{16}}", rf"\1{REDACTED}"),
        (r"([\"']?(?:SID|SK)[\"']?\s*[:=]\s*[\"']?)[0-9A-Fa-f]{{16}}([\"']?)", rf"\1{REDACTED}\2"),
        (r"\b(PHPSESSID=)[^;\s\"']+", rf"\1{REDACTED}"),
        (r"([\"']?CLIENT_ID[\"']?\s*[:=]\s*[\"']?)SMT[A-Za-z0-9]+([\"']?)", rf"\1{REDACTED}\2"),
        (r"([\"']?SMT_USER[\"']?\s*[:=]\s*[\"']?)\d+([\"']?)", rf"\1{REDACTED}\2"),
        (r"([\"']?(?:password|passwort|token|secret|access[_-]?key)[\"']?\s*[:=]\s*[\"']?)[^,}}\]\s\"']+([\"']?)", rf"\1{REDACTED}\2"),
        (r"([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{{2,}})", REDACTED),
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


def _extract_values_from_payload(payload: str):
    data = _json_loads_maybe_wrapped(payload)
    if isinstance(data, dict) and "values" in data:
        return data.get("values")
    return None


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


# ---------------------------------------------------------------------------
# Credential / URL extraction
# ---------------------------------------------------------------------------

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
    return f"{_VERSION}/{sid.strip().upper()}"


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


def _extract_smt_user_from_scripts(session: requests.Session, html: str):
    scripts = re.findall(r'<script[^>]+src="([^"]+)"', html, flags=re.I)
    for src in scripts:
        if not src:
            continue
        src_abs = urljoin(_BASE, src)
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
