"""RemkoSmartWebClient — the main public client class."""
from __future__ import annotations

import logging
import random
import re
import threading
import time
from urllib.parse import urljoin

from ._helpers import (
    _build_mqtt_topic,
    _compact_mqtt_diagnostics,
    _debug_value,
    _debug_values,
    _extract_device_metadata_from_text,
    _extract_sid_sk_from_text,
    _extract_sid_sk_from_url,
    _extract_smt_user_from_scripts,
    _extract_smt_user_from_text,
    _extract_smt_user_from_url,
    _normalize_device_name,
    _parsed_status_summary,
    _redact_debug_text,
    _smartweb_value_matches,
    _sorted_debug_values,
    _valid_credential_part,
    _value_response_summary,
    _values_diff,
)
from ._frames import (
    _build_ac_uart_set_cmds,
    _build_kwt_set_cmd,
    _build_lte_set_cmd,
    _build_modbus_read_cmd,
    _build_rbw_get_status_cmd,
    _build_rbw_set_cmd,
    _build_set_cmd_from_c0,
    _build_status_cmd,
    _build_wpm_set_cmd,
    _json_loads_maybe_wrapped,
    _parse_kwt_register_status,
    _parse_modbus_coils_rx,
    _parse_modbus_holding_rx,
    _parse_rbw_register_status,
    _parse_rbw_registers_rx,
    _parse_wpm_register_status,
)
from ._mqtt import (
    _BrokerConfig,
    _CloudBrokerConfig,
    _LocalBrokerConfig,
    _MqttSession,
    discover_local_topic,
)
from ._account import (
    DeviceListUnavailable,
    DeviceNotFound,
    DeviceResolveError,
    RemkoSmartWebAccount,
    SmartWebError,
    SmartWebLoginError,
    UnsupportedPayload,
)
from .const import DEVICE_KIND_AUTO, DEVICE_KIND_CLIMATE
from .profiles import (
    DomesticHotWaterDeviceProfile,
    KwtDeviceProfile,
    LteDeviceProfile,
    WpmDeviceProfile,
    get_parser_profile,
    get_specialized_profile,
)

_LOGGER = logging.getLogger(__name__)


class RemkoSmartWebClient:
    def __init__(
        self,
        email: str,
        password: str,
        device_name: str,
        device_path: str | None = None,
        device_kind: str = DEVICE_KIND_AUTO,
        beep: bool = False,
        account: RemkoSmartWebAccount | None = None,
        local_mqtt_host: str | None = None,
        local_mqtt_port: int = 1883,
        local_mqtt_user: str | None = None,
        local_mqtt_password: str | None = None,
        local_mqtt_topic: str | None = None,
    ):
        self.email = email
        self.password = password
        self.device_name = device_name
        self.device_path = device_path
        self.device_kind = device_kind
        self._beep = beep
        self.profile = get_parser_profile(device_name, device_kind)
        self._owns_account = account is None
        self.account = account or RemkoSmartWebAccount(email, password)
        self.session = self.account.session

        self.sid = None
        self.sk = None
        self.topic = local_mqtt_topic
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
        self._mqtt: _MqttSession | None = None
        self._write_lock = threading.RLock()
        self._local_mqtt_host = local_mqtt_host
        self._local_mqtt_port = local_mqtt_port
        self._local_mqtt_user = local_mqtt_user
        self._local_mqtt_password = local_mqtt_password
        self._local_mqtt_command_topic = None

    @property
    def uses_local_mqtt(self) -> bool:
        return bool(self._local_mqtt_host)

    def _mqtt_credentials_ready(self) -> bool:
        if not self.topic:
            return False
        if getattr(self, "_local_mqtt_host", None):
            return True
        return bool(_valid_credential_part(self.sid) and _valid_credential_part(self.sk))

    def _ensure_local_topic(self) -> bool:
        if not self._local_mqtt_host:
            return False
        if self.topic:
            return True
        topic = discover_local_topic(
            self._local_mqtt_host,
            self._local_mqtt_port,
            self._local_mqtt_user,
            self._local_mqtt_password,
        )
        if not topic:
            return False
        self.topic = topic
        parts = topic.split("/")
        if len(parts) >= 2:
            self.sid = parts[1]
        _LOGGER.info(
            "Resolved REMKO SmartWeb local MQTT topic for %r: %s",
            self.device_name,
            _redact_debug_text(topic),
        )
        return True

    def _ensure_local_command_topic(self) -> None:
        """Resolve the SID-based ESP command topic while keeping the local topic.

        Local sticks announce themselves below V04P27/SMT<mac>/HOST2PORTAL, but
        broker logs show they subscribe to ESP frames below the normal SID topic.
        """
        if not self._local_mqtt_host or self._local_mqtt_command_topic:
            return
        local_topic = self.topic
        try:
            self.resolve_device(force_list=False)
            command_topic = _build_mqtt_topic(self.sid)
            if command_topic:
                self._local_mqtt_command_topic = command_topic
                _LOGGER.info(
                    "Resolved REMKO SmartWeb local command topic for %r: %s",
                    self.device_name,
                    _redact_debug_text(command_topic),
                )
        except Exception as err:
            _LOGGER.debug(
                "Could not resolve REMKO SmartWeb local command topic for %r: %s",
                self.device_name,
                err,
            )
        finally:
            self.topic = local_topic

    def _esp_topic(self) -> str:
        base_topic = (
            getattr(self, "_local_mqtt_command_topic", None)
            if getattr(self, "_local_mqtt_host", None)
            else None
        )
        return f"{base_topic or self.topic}/ESP"

    def _publish_esp(self, payload: dict) -> None:
        topic = self._esp_topic()
        _LOGGER.debug(
            "REMKO SmartWeb ESP publish: device=%r topic=%s payload_keys=%s",
            self.device_name,
            _redact_debug_text(topic),
            sorted(payload.keys()),
        )
        self._mqtt.publish(topic, payload)

    def prime_status_cache(self, status: dict | None) -> None:
        """Seed the write cache from coordinator data before a local SET call."""
        if not isinstance(status, dict):
            return
        self._last_status = status
        payload = status.get("_payload")
        if payload:
            self._last_payload = payload

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
        if self.device_kind in (DEVICE_KIND_AUTO, DEVICE_KIND_CLIMATE):
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
        if self._local_mqtt_host:
            metadata["Connection Mode"] = "local"
            metadata["Local Broker"] = f"{self._local_mqtt_host}:{self._local_mqtt_port}"
        elif self._mqtt is not None and self._mqtt.local_portal:
            metadata["Connection Mode"] = "local (auto-detected)"
        else:
            metadata["Connection Mode"] = "cloud"
        return metadata

    def _ensure_login(self, force: bool = False) -> None:
        """Ensure a logged-in session is available, reusing it within a TTL."""
        self.account.ensure_login(force=force)

    def _ensure_device(self) -> None:
        """Ensure SID/SK/topic are resolved from SmartWeb."""
        if self._local_mqtt_host:
            if not self.topic and not self._ensure_local_topic():
                raise DeviceResolveError("Local MQTT topic not found")
            self._ensure_local_command_topic()
            return
        if self._mqtt_credentials_ready():
            return
        self.sid = None
        self.sk = None
        self.topic = None
        if self._mqtt is not None:
            self._mqtt.close()
            self._mqtt = None
        self.resolve_device()

    def _ensure_mqtt(self) -> None:
        if not self._mqtt_credentials_ready():
            raise DeviceResolveError("Device MQTT credentials are incomplete")
        if self._mqtt is None or not self._mqtt.ensure_connected():
            if self._local_mqtt_host:
                broker: _BrokerConfig = _LocalBrokerConfig(
                    self._local_mqtt_host,
                    self._local_mqtt_port,
                    self._local_mqtt_user,
                    self._local_mqtt_password,
                )
            else:
                broker = _CloudBrokerConfig(self.sid, self.sk)
            self._mqtt = _MqttSession(
                topic=self.topic,
                broker=broker,
                command_topic=self._local_mqtt_command_topic if self._local_mqtt_host else None,
            )
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
        from . import api as _api_module
        BASE = _api_module.BASE

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
        """Force a fresh /rest/liste lookup; MQTT is preserved if SID unchanged."""
        old_sid = self.sid
        old_sk = self.sk
        old_topic = self.topic
        saved_mqtt = self._mqtt
        self._mqtt = None
        self.sid = None
        self.sk = None
        self.topic = None
        try:
            self.resolve_device(force_list=True)
        except Exception:
            self.sid = old_sid
            self.sk = old_sk
            self.topic = old_topic
            self._mqtt = saved_mqtt
            raise
        # Reuse existing MQTT session if SID unchanged and still connected,
        # so that autonomously cached RESP messages (e.g. from WiFi sticks that
        # push RESP every ~90 s) are preserved across re-login cycles.
        if saved_mqtt is not None:
            if self.sid == old_sid and saved_mqtt.ensure_connected():
                self._mqtt = saved_mqtt
            else:
                saved_mqtt.close()

    def _mqtt_roundtrip_esp(self, payload: dict, timeout=10) -> str | None:
        """Publish ESP payload and wait for Rx response on persistent MQTT."""
        if not self._mqtt_credentials_ready():
            raise DeviceResolveError("Device not resolved")
        self._ensure_mqtt()
        self._publish_esp(payload)
        return self._mqtt.wait_rx(timeout=timeout)

    def _mqtt_poll_values(self, timeout=10) -> dict | None:
        """Poll values via CLIENT2HOST on persistent MQTT."""
        from . import api as _api_module

        if not self._mqtt_credentials_ready():
            raise DeviceResolveError("Device not resolved")
        self._ensure_mqtt()
        poll = {
            "FORCE_RESPONSE": True,
            "query_list": _api_module._value_query_list(),
            "CLIENT_ID": f"SMTHA{random.randint(0,9999):04d}",
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
        from . import api as _api_module

        if not self._mqtt_credentials_ready():
            raise DeviceResolveError("Device not resolved")
        self._ensure_mqtt()
        payload = {
            "values": {str(key): str(value) for key, value in values.items()},
            "query_list": _api_module._value_query_list(values),
            "FORCE_RESPONSE": True,
            "CLIENT_ID": f"SMTHA{random.randint(0,9999):04d}",
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
        from ._helpers import DEBUG_VALUES_LIMIT
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
        if not self._mqtt_credentials_ready():
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
            self._publish_esp({"Tx": tx, "CLIENT_ID": "SMTACUARTTEST"})
            # The frontend waits for RESP and then refreshes the value model.
            self._mqtt.wait_rx(timeout=timeout)
            time.sleep(1.0)
        return not unsupported

    def _mqtt_write_kwt_esp_values(self, values: dict[str, str], timeout=10, write_id: str | None = None) -> bool:
        """Write KWT value IDs through the ESP Modbus Tx path used by the frontend."""
        if not self._mqtt_credentials_ready():
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
            self._publish_esp({"Tx": tx, "CLIENT_ID": "SMTACUARTTEST"})
            self._mqtt.wait_rx(timeout=timeout)
            time.sleep(1.0)
        return not unsupported

    def _mqtt_write_ac_uart_frames(self, tx_frames: list[str], protocol_name: str, write_id: str, timeout=10) -> bool:
        """Write experimental AC UART Tx frames through the ESP path used by the frontend."""
        if not self._mqtt_credentials_ready():
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
            self._publish_esp({"Tx": tx, "CLIENT_ID": "SMTACUARTTEST"})
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
        self._publish_esp({"Tx": tx, "CLIENT_ID": "SMTACUARTTEST"})
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
            self._publish_esp({"Tx": tx, "CLIENT_ID": "SMTACUARTTEST"})
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
        if self._mqtt is not None:
            self._mqtt.check_local_portal_health(self.device_name)

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
        from ._helpers import DEBUG_VALUES_LIMIT
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
        from . import api as _api_module
        registers: dict[int, int] = {}
        responses = {}
        for register, quantity in _api_module.RBW_READ_RANGES:
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
        from . import api as _api_module
        registers: dict[int, int] = {}
        responses = {}
        for register, quantity in _api_module.KWT_READ_RANGES:
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
        from . import api as _api_module
        coils: dict[int, int] = {}
        holding: dict[int, int] = {}
        responses = {}
        for function_code, register, quantity in _api_module.WPM_READ_RANGES:
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

        if self._local_mqtt_host and self._last_status:
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

        if not self._local_mqtt_host:
            try:
                _LOGGER.debug(
                    "Status values for %r stayed empty/unparseable; refreshing device lookup from /rest/liste",
                    self.device_name,
                )
                self._refresh_device_from_list()
            except Exception as err:
                _LOGGER.debug("Forced SmartWeb device list refresh failed for %r: %s", self.device_name, err)

        # retry once after forcing a re-login
        if not self._local_mqtt_host:
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
        if self._mqtt.local_host2portal_mode:
            if self._last_payload:
                _LOGGER.info(
                    "REMKO SmartWeb local SET using cached C0 payload for %r",
                    self.device_name,
                )
                payload = self._last_payload
            elif isinstance(self._last_status, dict) and self._last_status.get("_payload"):
                _LOGGER.info(
                    "REMKO SmartWeb local SET using cached status payload for %r",
                    self.device_name,
                )
                payload = self._last_status["_payload"]
        if not payload:
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
        if not payload and isinstance(self._last_status, dict) and self._last_status.get("_payload"):
            _LOGGER.warning(
                "REMKO SmartWeb write using cached status payload for %r (live read failed: %s)",
                self.device_name,
                last_err,
            )
            payload = self._last_status["_payload"]
        if not payload:
            raise UnsupportedPayload(f"No C0 payload (status read failed: {last_err})")
        tx = _build_set_cmd_from_c0(payload, overrides, beep=self._beep)
        if not tx:
            raise UnsupportedPayload("Failed to build SET frame")
        _LOGGER.debug(
            "REMKO SmartWeb SET frame: device=%r overrides=%s c0_payload=%s tx=%s",
            self.device_name, overrides, bytes(payload).hex(), tx,
        )
        self._mqtt.clear_rx()  # Force readback to wait for fresh RESP; not stale pre-SET cache
        # Only legacy local portal bridges need an active CLIENT2HOST window
        # before an ESP SET.  In normal cloud mode the frontend publishes the
        # SET directly; waiting for an unrelated CLIENT2HOST would otherwise
        # turn cloud writes into no-ops when no browser portal is open.
        defer_until_client2host = (
            self._mqtt.local_portal
            and not self._mqtt.local_host2portal_mode
        )
        if defer_until_client2host:
            self._mqtt.queue_set(tx)
            executed = self._mqtt.wait_set_executed(timeout=1.5)
            if not executed:
                _LOGGER.warning(
                    "REMKO SmartWeb SET queued for %r; no CLIENT2HOST received within %.1f s",
                    self.device_name,
                    1.5,
                )
                return
        else:
            self._publish_esp({"Tx": tx, "CLIENT_ID": "SMTACUARTTEST"})
            if self._mqtt.local_host2portal_mode:
                _LOGGER.info(
                    "REMKO SmartWeb local SET sent for %r; readback confirmation pending",
                    self.device_name,
                )
                return
        # Try to read back status after SET to keep state in sync (best effort).
        # Some SmartWeb devices briefly report the previous state immediately
        # after accepting an ESP SET frame, so retry before logging a mismatch.
        try:
            readback = None
            last_readback_err = None
            for attempt in range(3):
                time.sleep(1.0)
                try:
                    readback = self.read_status()
                except Exception as err:
                    last_readback_err = err
                    continue
                if not isinstance(readback, dict):
                    continue
                pwr_intended = ("ON" if overrides["power"] else "OFF") if "power" in overrides else None
                mode_intended = overrides.get("mode")
                sp_intended = overrides.get("setpoint")
                pwr_ok = pwr_intended is None or readback.get("power") == pwr_intended
                mode_ok = mode_intended is None or readback.get("mode") == mode_intended
                sp_ok = sp_intended is None or abs((readback.get("setpoint") or 0) - sp_intended) < 0.6
                if pwr_ok and mode_ok and sp_ok:
                    break
                if attempt < 2:
                    continue
                break
            if isinstance(readback, dict):
                pwr_intended = ("ON" if overrides["power"] else "OFF") if "power" in overrides else None
                mode_intended = overrides.get("mode")
                sp_intended = overrides.get("setpoint")
                pwr_ok = pwr_intended is None or readback.get("power") == pwr_intended
                mode_ok = mode_intended is None or readback.get("mode") == mode_intended
                sp_ok = sp_intended is None or abs((readback.get("setpoint") or 0) - sp_intended) < 0.6
                if pwr_ok and mode_ok and sp_ok:
                    _LOGGER.debug(
                        "REMKO SmartWeb SET readback OK: device=%r power=%s mode=%s setpoint=%s",
                        self.device_name,
                        readback.get("power"), readback.get("mode"), readback.get("setpoint"),
                    )
                else:
                    _LOGGER.info(
                        "REMKO SmartWeb SET readback pending for %r — device still reports the previous state:"
                        " intended=%s actual_power=%s actual_mode=%s actual_setpoint=%s",
                        self.device_name,
                        {k: overrides[k] for k in ("power", "mode", "setpoint") if k in overrides},
                        readback.get("power"), readback.get("mode"), readback.get("setpoint"),
                    )
            elif last_readback_err is not None:
                raise last_readback_err
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
        if (
            not response_values
            and getattr(self.profile, "kind", None) == DEVICE_KIND_CLIMATE
        ):
            _LOGGER.warning(
                "REMKO SmartWeb climate value write confirmation pending: %s",
                _debug_value(
                    {
                        "write_id": write_id,
                        "device": self.device_name,
                        "path": "client2host",
                        "reason": (
                            "empty_write_response"
                            if isinstance(response_values, dict)
                            else "write_response_timeout"
                        ),
                        "written_values": sorted(values),
                    }
                ),
            )
            return
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
