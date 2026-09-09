"""
REMKO SmartWeb API — constants, value query list, and public re-exports.

This module is the single public surface for the package.  All implementation
lives in the sub-modules imported at the bottom.
"""
from __future__ import annotations

import time  # noqa: F401 — kept for backward compatibility (tests patch api.time.sleep)

from .const import DEVICE_KIND_AUTO, DEVICE_KIND_CLIMATE  # noqa: F401 (re-export)

# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

BASE = "https://smartweb.remko.media"
LOGIN_URL = f"{BASE}/rest/login_do"
WSS_HOST = "smartweb.remko.media"
WSS_PORT = 8083
WSS_PATH = "/mqtt"
VERSION = "V04P27"
# SmartWeb may block Python/HA-style HTTP clients after login. Use the same
# browser-like identity for the full HTTP session, not just the login request.
SMARTWEB_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36"
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


# ---------------------------------------------------------------------------
# Sub-module re-exports  (keep public API surface unchanged)
# ---------------------------------------------------------------------------

from ._helpers import (  # noqa: E402, F401
    REDACTED as _REDACTED_HELPERS,  # internal alias — canonical comes from above
    _build_mqtt_topic,
    _compact_mqtt_diagnostics,
    _debug_value,
    _debug_values,
    _extract_device_metadata_from_text,
    _extract_global_var,
    _extract_names_from_rest_list,
    _extract_sid_sk_from_text,
    _extract_sid_sk_from_url,
    _extract_smt_user_from_scripts,
    _extract_smt_user_from_text,
    _extract_smt_user_from_url,
    _json_loads_maybe_wrapped,
    _mqtt_message_summary,
    _normalize_device_name,
    _normalize_smartweb_hex_value,
    _pace_account_request,
    _parsed_status_summary,
    _redact_debug_data,
    _redact_debug_text,
    _smartweb_value_matches,
    _sorted_debug_values,
    _valid_credential_part,
    _value_response_summary,
    _values_diff,
    _extract_values_from_payload,
    _extract_smartweb_portal_params_from_text,
    _extract_smt_user_from_url,
)

from ._frames import (  # noqa: E402, F401
    WPM_VALUE_WRITE_REGISTERS,
    _build_ac_uart_set_cmds,
    _build_aux_ac_uart_set_cmd,
    _build_free_ac_uart_set_cmd,
    _build_kwt_set_cmd,
    _build_lte_set_cmd,
    _build_modbus_read_cmd,
    _build_modbus_write_coil_cmd,
    _build_modbus_write_register_cmd,
    _build_nwt_ac_uart_set_cmds,
    _build_rbw_get_status_cmd,
    _build_rbw_set_cmd,
    _build_rbw_set_register_cmd,
    _build_set_cmd_from_c0,
    _build_status_cmd,
    _build_wpm_set_cmd,
    _bool_from_str,
    _bool_state,
    _checksum,
    _clamp_int,
    _crc8,
    _free_checksum,
    _hex_byte,
    _hex_word,
    _high_level_status,
    _modbus_crc16,
    _parse_kwt_register_status,
    _parse_modbus_coils_rx,
    _parse_modbus_holding_rx,
    _parse_rbw_register_status,
    _parse_rbw_registers_rx,
    _parse_wpm_register_status,
    _rbw_temp1,
    _rbw_vacation_date,
    _CRC8_TABLE,
)

from ._mqtt import (  # noqa: E402, F401
    _BrokerConfig,
    _CloudBrokerConfig,
    _LocalBrokerConfig,
    _MqttSession,
    _detect_local_portal_ip,
)

from ._account import (  # noqa: E402, F401
    DeviceListUnavailable,
    DeviceNotFound,
    DeviceResolveError,
    RemkoSmartWebAccount,
    SmartWebError,
    SmartWebLoginError,
    UnsupportedPayload,
)

from .client import RemkoSmartWebClient  # noqa: E402, F401
