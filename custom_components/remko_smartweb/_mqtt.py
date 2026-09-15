"""MQTT broker strategy classes and _MqttSession."""
from __future__ import annotations

import abc
from dataclasses import dataclass
import json
import logging
import random
import socket
import ssl
import threading
import time
from collections import deque

import paho.mqtt.client as mqtt

from .const import (
    LOCAL_MQTT_MODE_AUTO,
    LOCAL_MQTT_MODE_DEVICE_MQTT,
    LOCAL_MQTT_MODE_PORTAL_BROKER,
)
from ._helpers import (
    _extract_values_from_payload,
    _json_loads_maybe_wrapped,
    _mqtt_message_summary,
)
from ._frames import _build_status_cmd

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class LocalMqttProbeResult:
    """Read-only local MQTT probe result for onboarding and diagnostics."""

    host: str
    port: int
    mode_requested: str
    tcp_connected: bool = False
    mqtt_connected: bool = False
    connack_rc: int | None = None
    detected_mode: str | None = None
    topic: str | None = None
    subscriptions: tuple[str, ...] = ()
    sample_topics: tuple[str, ...] = ()
    error: str | None = None

    @property
    def status(self) -> str:
        if self.error == "tcp_connect_failed":
            return "tcp_failed"
        if not self.tcp_connected:
            return "tcp_failed"
        if self.connack_rc not in (None, 0):
            return "mqtt_auth_or_acl_failed"
        if not self.mqtt_connected:
            return "mqtt_failed"
        if self.detected_mode == LOCAL_MQTT_MODE_DEVICE_MQTT:
            return "direct_device_mqtt_detected"
        if self.detected_mode == LOCAL_MQTT_MODE_PORTAL_BROKER:
            return "portal_broker_detected"
        return "mqtt_reachable_no_remko_topics"

    def as_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "mode_requested": self.mode_requested,
            "status": self.status,
            "tcp_connected": self.tcp_connected,
            "mqtt_connected": self.mqtt_connected,
            "connack_rc": self.connack_rc,
            "detected_mode": self.detected_mode,
            "topic": self.topic,
            "subscriptions": list(self.subscriptions),
            "sample_topics": list(self.sample_topics),
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Helper: detect whether WSS_HOST resolves locally
# ---------------------------------------------------------------------------

def _detect_local_portal_ip() -> bool:
    """Return True if WSS_HOST resolves to a private/loopback address.

    When WiFi sticks are DNS-redirected to a local MQTT broker, the same
    hostname resolves to a private IP for the HA host as well.  This enables
    HOST2CLIENT responses and the pending-SET queue automatically.
    """
    import ipaddress
    import socket

    from . import api as _api_module
    WSS_HOST = _api_module.WSS_HOST

    try:
        ip = socket.gethostbyname(WSS_HOST)
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Strategy Pattern — broker configuration
# ---------------------------------------------------------------------------

class _BrokerConfig(abc.ABC):
    """Abstract base for MQTT broker connection strategies."""

    @abc.abstractmethod
    def is_local(self) -> bool:
        """Return True if this broker is a local (plain-TCP) broker."""
        ...

    @abc.abstractmethod
    def apply(self, client: mqtt.Client, topic: str) -> tuple[str, int]:
        """Configure *client* and return (host, port) to connect to."""
        ...


class _CloudBrokerConfig(_BrokerConfig):
    """Connect via WebSocket TLS to the Remko cloud broker using SID/SK credentials."""

    def __init__(self, sid: str, sk: str) -> None:
        self._sid = sid
        self._sk = sk
        self._local: bool | None = None  # lazily detected

    def is_local(self) -> bool:
        if self._local is None:
            self._local = _detect_local_portal_ip()
        return self._local

    def apply(self, client: mqtt.Client, topic: str) -> tuple[str, int]:
        from . import api as _api_module
        WSS_HOST = _api_module.WSS_HOST
        WSS_PORT = _api_module.WSS_PORT
        WSS_PATH = _api_module.WSS_PATH

        client.username_pw_set(self._sid, self._sk)
        client.tls_set(cert_reqs=ssl.CERT_NONE)
        client.ws_set_options(path=WSS_PATH)
        if self.is_local():
            _LOGGER.info(
                "REMKO SmartWeb %s: local portal mode detected "
                "(%s resolves to a private IP) — "
                "HOST2CLIENT responder and pending-SET queue active",
                topic, WSS_HOST,
            )
        return WSS_HOST, WSS_PORT


class _LocalBrokerConfig(_BrokerConfig):
    """Connect via plain TCP to a local MQTT broker (e.g. Mosquitto)."""

    def __init__(
        self,
        host: str,
        port: int,
        user: str | None,
        password: str | None,
    ) -> None:
        self._host = host
        self._port = port
        self._user = user
        self._password = password

    def is_local(self) -> bool:
        return True

    def apply(self, client: mqtt.Client, topic: str) -> tuple[str, int]:
        if self._user:
            client.username_pw_set(self._user, self._password)
        _LOGGER.info(
            "REMKO SmartWeb %s: using explicit local MQTT broker %s:%d",
            topic, self._host, self._port,
        )
        return self._host, self._port


def discover_local_topic(
    host: str,
    port: int,
    user: str | None,
    password: str | None,
    mode: str = LOCAL_MQTT_MODE_AUTO,
    timeout: float = 20.0,
) -> tuple[str, str] | None:
    """Discover the REMKO topic from a local MQTT broker.

    Local portal-broker setups announce below V04P27/<stick>/HOST2PORTAL.
    Direct/bridge SmartControl MQTT setups expose HOST2CLIENT/CLIENT2HOST
    topics, often below a literal SMTID segment.  Return (base_topic, mode).
    """
    probe = probe_local_mqtt(host, port, user, password, mode=mode, timeout=timeout)
    if probe.topic and probe.detected_mode:
        return probe.topic, probe.detected_mode
    return None


def _local_probe_subscriptions(mode: str) -> list[tuple[str, int]]:
    subscriptions: list[tuple[str, int]] = []
    if mode in (LOCAL_MQTT_MODE_AUTO, LOCAL_MQTT_MODE_PORTAL_BROKER):
        subscriptions.extend(
            [
                ("V04P27/+/HOST2PORTAL", 2),
                ("V04P27/+/CLIENT2HOST", 2),
            ]
        )
    if mode in (LOCAL_MQTT_MODE_AUTO, LOCAL_MQTT_MODE_DEVICE_MQTT):
        subscriptions.extend(
            [
                ("V04P27/+/HOST2CLIENT", 2),
                ("V04P27/+/CLIENT2HOST", 2),
                ("V04P28/+/HOST2CLIENT", 2),
                ("V04P28/+/CLIENT2HOST", 2),
                ("+/SMTID/HOST2CLIENT", 2),
                ("+/SMTID/CLIENT2HOST", 2),
            ]
        )
    return subscriptions


def _classify_local_mqtt_topic(topic: str, mode: str) -> tuple[str, str] | None:
    parts = topic.split("/")
    if len(parts) < 3:
        return None
    direction = parts[-1]
    base_topic = "/".join(parts[:-1])
    if (
        mode in (LOCAL_MQTT_MODE_AUTO, LOCAL_MQTT_MODE_PORTAL_BROKER)
        and len(parts) == 3
        and parts[0] == "V04P27"
        and direction == "HOST2PORTAL"
    ):
        return base_topic, LOCAL_MQTT_MODE_PORTAL_BROKER
    if (
        mode in (LOCAL_MQTT_MODE_AUTO, LOCAL_MQTT_MODE_DEVICE_MQTT)
        and direction in {"HOST2CLIENT", "CLIENT2HOST"}
        and (
            parts[0] in {"V04P27", "V04P28"}
            or (len(parts) >= 3 and parts[-2] == "SMTID")
        )
    ):
        return base_topic, LOCAL_MQTT_MODE_DEVICE_MQTT
    return None


def probe_local_mqtt(
    host: str,
    port: int,
    user: str | None,
    password: str | None,
    mode: str = LOCAL_MQTT_MODE_AUTO,
    timeout: float = 8.0,
    tcp_timeout: float = 2.0,
) -> LocalMqttProbeResult:
    """Probe a user-selected local MQTT target without sending device commands."""
    subscriptions = tuple(topic for topic, _qos in _local_probe_subscriptions(mode))
    try:
        with socket.create_connection((host, int(port)), timeout=tcp_timeout):
            pass
    except Exception as err:
        return LocalMqttProbeResult(
            host=host,
            port=int(port),
            mode_requested=mode,
            subscriptions=subscriptions,
            error="tcp_connect_failed",
            sample_topics=(type(err).__name__,),
        )

    found: list[tuple[str, str]] = []
    sample_topics: list[str] = []
    connack_rc: list[int | None] = [None]
    done = threading.Event()
    client = mqtt.Client(
        client_id=f"SMT_PROBE_{random.randint(0, 9999):04d}",
        protocol=mqtt.MQTTv311,
        transport="tcp",
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
    )
    if user:
        client.username_pw_set(user, password)

    def _on_connect(client, userdata, flags, reason_code, properties=None):
        rc = reason_code.value if hasattr(reason_code, "value") else reason_code
        connack_rc[0] = int(rc) if isinstance(rc, int) or str(rc).isdigit() else None
        if rc == 0:
            client.subscribe(_local_probe_subscriptions(mode))
            return
        _LOGGER.warning("REMKO SmartWeb local MQTT discovery connect failed rc=%s", rc)
        done.set()

    def _on_message(client, userdata, msg):
        topic = str(msg.topic)
        if len(sample_topics) < 5:
            sample_topics.append(topic)
        classified = _classify_local_mqtt_topic(topic, mode)
        if classified:
            found.append(classified)
            done.set()

    client.on_connect = _on_connect
    client.on_message = _on_message
    try:
        client.connect(host, int(port), keepalive=30)
        client.loop_start()
        done.wait(timeout=timeout)
    except Exception as err:
        _LOGGER.warning("REMKO SmartWeb local MQTT probe failed: %s", err)
        return LocalMqttProbeResult(
            host=host,
            port=int(port),
            mode_requested=mode,
            tcp_connected=True,
            connack_rc=connack_rc[0],
            subscriptions=subscriptions,
            sample_topics=tuple(sample_topics),
            error=type(err).__name__,
        )
    finally:
        try:
            client.loop_stop()
            client.disconnect()
        except Exception:
            pass
    topic, detected_mode = found[0] if found else (None, None)
    return LocalMqttProbeResult(
        host=host,
        port=int(port),
        mode_requested=mode,
        tcp_connected=True,
        mqtt_connected=connack_rc[0] == 0,
        connack_rc=connack_rc[0],
        detected_mode=detected_mode,
        topic=topic,
        subscriptions=subscriptions,
        sample_topics=tuple(sample_topics),
    )


# ---------------------------------------------------------------------------
# MQTT session
# ---------------------------------------------------------------------------

class _MqttSession:
    def __init__(
        self,
        topic: str,
        broker: _BrokerConfig,
        command_topic: str | None = None,
        local_mqtt_mode: str = LOCAL_MQTT_MODE_AUTO,
    ) -> None:
        self.topic = topic
        self._command_topic = command_topic
        self._local_mqtt_mode = local_mqtt_mode
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._connected = threading.Event()
        self._closed = False
        self._last_rx = None
        self._last_values = None
        self._last_seen_values = None
        self._last_tx_echo = None
        self._last_tx_echo_time: float | None = None
        self._last_esp_publish_time: float | None = None
        self._last_esp_publish_topic: str | None = None
        self._last_rx_time: float | None = None
        self._last_rx_topic: str | None = None
        self._last_values_time: float | None = None
        self._last_values_topic: str | None = None
        self._last_host2portal_time: float | None = None
        self._last_portal2host_time: float | None = None
        self._last_smt_user = None
        self._recent_messages: deque = deque(maxlen=20)
        self._received_non_tx_count = 0
        self._subscribed_topics: list[str] = []
        self._outgoing_client_ids: deque = deque(maxlen=20)
        # Local-portal state
        self._local_portal: bool = broker.is_local()
        topic_device = topic.split("/", 2)[1].upper() if "/" in topic else ""
        self._local_host2portal_mode: bool = (
            self._local_portal
            and local_mqtt_mode != LOCAL_MQTT_MODE_DEVICE_MQTT
            and topic_device.startswith("SMT")
        )
        self._pending_set_tx: str | None = None
        self._pending_set_done = threading.Event()
        self._last_c2h_time: float = 0.0
        self._no_c2h_warned: bool = False
        self._last_connack_rc: int | None = None

        # Derive client_id from sid when available
        _sid = getattr(broker, "_sid", None) or "0000"
        client_id = f"SMT{random.randint(0, 9999):04d}{_sid}"

        transport = "tcp" if broker.is_local() else "websockets"
        self.client = mqtt.Client(
            client_id=client_id,
            protocol=mqtt.MQTTv311,
            transport=transport,
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        )

        conn_host, conn_port = broker.apply(self.client, topic)

        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
        self.client.on_disconnect = self._on_disconnect

        self.client.connect(conn_host, conn_port, keepalive=60)
        self.client.loop_start()

    def _on_connect(self, client, userdata, flags, reason_code, properties=None):
        rc = reason_code.value if hasattr(reason_code, "value") else reason_code
        self._last_connack_rc = int(rc) if str(rc).isdigit() else None
        if rc != 0:
            _LOGGER.warning("MQTT connect failed rc=%s", rc)
            self._closed = True
            self._connected.set()
            return
        subscriptions = [
            (f"{self.topic}/HOST2CLIENT", 2),
            (f"{self.topic}/PORTAL2CLIENT", 2),
            (f"{self.topic}/RESP", 2),
            (f"{self.topic}/ESP", 2),
        ]
        command_topic = getattr(self, "_command_topic", None)
        if command_topic and command_topic != self.topic:
            subscriptions.extend(
                [
                    (f"{command_topic}/HOST2CLIENT", 2),
                    (f"{command_topic}/PORTAL2CLIENT", 2),
                    (f"{command_topic}/RESP", 2),
                    (f"{command_topic}/ESP", 2),
                    (f"{command_topic}/CLIENT2HOST", 2),
                ]
            )
        if (
            self._local_portal
            and getattr(self, "_local_mqtt_mode", LOCAL_MQTT_MODE_AUTO)
            != LOCAL_MQTT_MODE_DEVICE_MQTT
        ):
            subscriptions.extend(
                [
                    (f"{self.topic}/HOST2PORTAL", 2),
                    (f"{self.topic}/PORTAL2HOST", 2),
                ]
            )
        subscriptions.append((f"{self.topic}/CLIENT2HOST", 2))
        client.subscribe(subscriptions)
        with self._lock:
            self._subscribed_topics = [topic for topic, _qos in subscriptions]
        self._connected.set()

    def _on_disconnect(self, client, userdata, *args):
        self._closed = True
        self._connected.set()

    def _record_esp_publish(self, topic: str) -> None:
        with self._lock:
            self._last_esp_publish_time = time.time()
            self._last_esp_publish_topic = str(topic)

    def _on_message(self, client, userdata, msg):
        try:
            try:
                text = msg.payload.decode("utf-8", errors="replace")
            except Exception:
                text = repr(msg.payload)
            _c2h_needs_reply = False
            _h2p_needs_reply = False
            summary = _mqtt_message_summary(msg.topic, text)
            with self._cond:
                now = time.time()
                if summary.get("kind") == "tx_echo":
                    self._last_tx_echo = summary
                    self._last_tx_echo_time = now
                else:
                    self._received_non_tx_count += 1
                    self._recent_messages.append(summary)
                topic_text = str(msg.topic)
                if topic_text.endswith("/HOST2PORTAL"):
                    self._last_host2portal_time = now
                if topic_text.endswith("/PORTAL2HOST"):
                    self._last_portal2host_time = now
                # Rx hex for ESP status
                obj = _json_loads_maybe_wrapped(text)
                is_own_client2host = False
                if isinstance(obj, dict):
                    client_id = str(obj.get("CLIENT_ID") or "")
                    is_own_client2host = (
                        str(msg.topic).endswith("/CLIENT2HOST")
                        and client_id
                        and client_id in getattr(self, "_outgoing_client_ids", ())
                    )
                    if obj.get("Rx"):
                        self._last_rx = json.dumps(obj)
                        self._last_rx_time = now
                        self._last_rx_topic = topic_text
                        self._cond.notify_all()
                    smt_user = obj.get("SMT_USER")
                    if str(smt_user or "").isdigit():
                        self._last_smt_user = int(smt_user)
                values = _extract_values_from_payload(text)
                if isinstance(values, dict) and str(msg.topic).endswith(("/HOST2CLIENT", "/PORTAL2CLIENT")):
                    self._last_values = values
                    self._last_seen_values = values
                    self._last_values_time = now
                    self._last_values_topic = topic_text
                    self._cond.notify_all()
                local_portal_responder = getattr(
                    self,
                    "_local_mqtt_mode",
                    LOCAL_MQTT_MODE_AUTO,
                ) != LOCAL_MQTT_MODE_DEVICE_MQTT and getattr(
                    self,
                    "_local_portal",
                    False,
                )
                _c2h_needs_reply = (
                    isinstance(obj, dict)
                    and str(msg.topic).endswith("/CLIENT2HOST")
                    and local_portal_responder
                    and not is_own_client2host
                    and "query_list" in obj
                )
                if _c2h_needs_reply:
                    self._last_c2h_time = time.time()
                    self._no_c2h_warned = False
                _h2p_needs_reply = (
                    isinstance(obj, dict)
                    and str(msg.topic).endswith("/HOST2PORTAL")
                    and local_portal_responder
                    and "SMT_ID" in obj
                )
            if _c2h_needs_reply:
                reply_topic = msg.topic.replace("/CLIENT2HOST", "/HOST2CLIENT")
                reply = json.dumps(
                    {"CLIENT_ID": obj.get("CLIENT_ID", ""), "values": {}}
                )
                try:
                    self.client.publish(reply_topic, reply, qos=0, retain=False)
                    # Dispatch pending SET, or refresh status when this is just a poll.
                    # Avoid sending SET and STATUS in the same active window; some sticks
                    # ignore the SET when another ESP command follows immediately.
                    pending_tx = self._pending_set_tx
                    if pending_tx is not None:
                        self._pending_set_tx = None
                        esp_base = getattr(self, "_command_topic", None) or self.topic
                        esp_topic = f"{esp_base}/ESP"
                        self._record_esp_publish(esp_topic)
                        self.client.publish(
                            esp_topic,
                            json.dumps({"Tx": pending_tx,
                                        "CLIENT_ID": "SMTACUARTTEST"}),
                            qos=2, retain=False,
                        )
                        self._pending_set_done.set()
                        _LOGGER.debug(
                            "REMKO SmartWeb local portal: dispatched pending SET "
                            "for %s after CLIENT2HOST",
                            self.topic,
                        )
                    else:
                        esp_topic = f"{self.topic}/ESP"
                        self._record_esp_publish(esp_topic)
                        self.client.publish(
                            esp_topic,
                            json.dumps({"Tx": _build_status_cmd(),
                                        "CLIENT_ID": "SMTACUARTTEST"}),
                            qos=2, retain=False,
                        )
                except Exception:
                    pass
            if _h2p_needs_reply:
                reply_topic = msg.topic.replace("/HOST2PORTAL", "/PORTAL2HOST")
                try:
                    self.client.publish(
                        reply_topic,
                        json.dumps({"WSID": ""}),
                        qos=0,
                        retain=False,
                    )
                    _LOGGER.debug(
                        "REMKO SmartWeb local portal: answered HOST2PORTAL "
                        "heartbeat on %s",
                        reply_topic,
                    )
                except Exception:
                    pass
        except Exception:
            _LOGGER.exception("Unexpected error in MQTT message handler (topic=%s)", msg.topic)

    def ensure_connected(self, timeout: float = 8.0) -> bool:
        self._connected.wait(timeout=timeout)
        return not self._closed

    def publish(self, topic: str, payload: dict):
        if str(topic).endswith("/CLIENT2HOST") and isinstance(payload, dict):
            client_id = str(payload.get("CLIENT_ID") or "")
            if client_id:
                with self._lock:
                    if not hasattr(self, "_outgoing_client_ids"):
                        self._outgoing_client_ids = deque(maxlen=20)
                    self._outgoing_client_ids.append(client_id)
        if str(topic).endswith("/ESP"):
            self._record_esp_publish(str(topic))
        self.client.publish(topic, json.dumps(payload), qos=2, retain=False)

    def clear_values(self) -> None:
        with self._cond:
            self._last_values = None

    def last_smt_user(self) -> int | None:
        with self._cond:
            return self._last_smt_user

    def clear_rx(self) -> None:
        """Clear the cached Rx so the next wait_rx waits for a genuinely new RESP."""
        with self._cond:
            self._last_rx = None

    # ── local-portal helpers ──────────────────────────────────────────────

    @property
    def local_portal(self) -> bool:
        """True when connected to a local broker (explicit config or DNS detection)."""
        return self._local_portal

    @property
    def local_host2portal_mode(self) -> bool:
        """True for local sticks that announce HOST2PORTAL instead of CLIENT2HOST."""
        return self._local_host2portal_mode

    def queue_set(self, tx: str) -> None:
        """Store a SET frame for dispatch after the next portal poll trigger."""
        self._pending_set_done.clear()
        self._pending_set_tx = tx

    def cancel_pending_set(self) -> None:
        """Discard any queued SET and unblock callers waiting on it."""
        self._pending_set_tx = None
        self._pending_set_done.set()

    def wait_set_executed(self, timeout: float = 1.5) -> bool:
        """Wait briefly for a queued SET dispatch; callers should fall back."""
        return self._pending_set_done.wait(timeout=timeout)

    def check_local_portal_health(self, device_name: str) -> None:
        """Emit a one-shot warning when local-mode prerequisites appear unmet."""
        if not self._local_host2portal_mode:
            return
        age_s = (time.time() - self._last_c2h_time) if self._last_c2h_time else None
        stale = age_s is None or age_s > 300
        if stale and not self._no_c2h_warned:
            self._no_c2h_warned = True
            if age_s is None:
                _LOGGER.warning(
                    "REMKO SmartWeb local portal %r: no portal poll trigger received yet — "
                    "verify that the WiFi stick's DNS points to this broker",
                    device_name,
                )
            else:
                _LOGGER.warning(
                    "REMKO SmartWeb local portal %r: no portal poll trigger for %.0f min — "
                    "WiFi stick may have lost connectivity or DNS redirect expired",
                    device_name, age_s / 60,
                )

    def wait_rx(self, timeout: float = 10.0) -> str | None:
        end = time.time() + timeout
        with self._cond:
            while time.time() < end:
                if self._last_rx is not None:
                    # Do NOT clear _last_rx — WiFi sticks push RESP autonomously
                    # every ~90 s; keeping it lets every poll succeed until a
                    # fresher RESP arrives.  Callers that need a true fresh read
                    # (e.g. for SET verification) should call clear_rx() first.
                    return self._last_rx
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
            now = time.time()
            def _age(timestamp: float | None) -> float | None:
                return round(now - timestamp, 1) if timestamp is not None else None

            age_s = (time.time() - self._last_c2h_time) if self._last_c2h_time else None
            last_resp_after_last_esp = (
                getattr(self, "_last_rx_time", None) is not None
                and getattr(self, "_last_esp_publish_time", None) is not None
                and self._last_rx_time >= self._last_esp_publish_time
            )
            return {
                "recent_messages": list(self._recent_messages),
                "last_tx_echo": self._last_tx_echo,
                "last_tx_echo_age_s": _age(getattr(self, "_last_tx_echo_time", None)),
                "last_esp_publish_age_s": _age(getattr(self, "_last_esp_publish_time", None)),
                "last_esp_publish_topic": getattr(self, "_last_esp_publish_topic", None),
                "last_resp_age_s": _age(getattr(self, "_last_rx_time", None)),
                "last_resp_topic": getattr(self, "_last_rx_topic", None),
                "last_resp_after_last_esp": last_resp_after_last_esp,
                "last_values_age_s": _age(getattr(self, "_last_values_time", None)),
                "last_values_topic": getattr(self, "_last_values_topic", None),
                "last_host2portal_age_s": _age(getattr(self, "_last_host2portal_time", None)),
                "last_portal2host_age_s": _age(getattr(self, "_last_portal2host_time", None)),
                "last_values": self._last_seen_values,
                "received_non_tx_count": self._received_non_tx_count,
                "subscribed_topics": list(self._subscribed_topics),
                "local_portal": self._local_portal,
                "local_host2portal_mode": self._local_host2portal_mode,
                "last_connack_rc": self._last_connack_rc,
                "mqtt_connected": self._last_connack_rc == 0 and not self._closed,
                "last_c2h_age_s": round(age_s, 1) if age_s is not None else None,
                "pending_set": self._pending_set_tx is not None,
            }

    def close(self):
        self.cancel_pending_set()  # Unblock any thread in wait_set_executed
        try:
            self.client.loop_stop()
            self.client.disconnect()
        except Exception:
            pass
        self._closed = True


class _CloudLocalMqttBridge:
    """Forward REMKO cloud MQTT commands to a local MQTT stick/broker.

    Redirected WiFi-stick setups move the stick away from the REMKO cloud
    broker, so the REMKO app can no longer reach it directly.  This bridge
    keeps a separate cloud MQTT client subscribed to the normal SID command
    topic and mirrors command/status frames to the local broker.
    """

    def __init__(
        self,
        *,
        cloud_topic: str,
        cloud_broker: _BrokerConfig,
        local_topic: str,
        local_command_topic: str,
        local_broker: _BrokerConfig,
    ) -> None:
        self.cloud_topic = cloud_topic
        self.local_topic = local_topic
        self.local_command_topic = local_command_topic
        self._lock = threading.Lock()
        self._connected = threading.Event()
        self._closed = False
        self._last_cloud_to_local_time: float | None = None
        self._last_local_to_cloud_time: float | None = None
        self._last_cloud_to_local_topic: str | None = None
        self._last_local_to_cloud_topic: str | None = None
        self._forward_counts = {"cloud_to_local": 0, "local_to_cloud": 0}
        self._last_cloud_connack_rc: int | None = None
        self._last_cloud_stick_connack_rc: int | None = None
        self._last_local_connack_rc: int | None = None
        self._last_cloud_portal2host_time: float | None = None
        self._last_cloud_portal2host_topic: str | None = None

        _sid = getattr(cloud_broker, "_sid", None) or "0000"
        cloud_stick_client_id = _stick_client_id_from_topic(local_topic)
        self.cloud_client = mqtt.Client(
            client_id=f"SMTBR{random.randint(0, 9999):04d}{_sid}",
            protocol=mqtt.MQTTv311,
            transport="websockets",
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        )
        self.cloud_stick_client = mqtt.Client(
            client_id=cloud_stick_client_id or f"SMTBRSTICK{random.randint(0, 9999):04d}",
            protocol=mqtt.MQTTv311,
            transport="tcp",
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        )
        self.local_client = mqtt.Client(
            client_id=f"SMTHABR{random.randint(0, 9999):04d}",
            protocol=mqtt.MQTTv311,
            transport="tcp",
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        )

        cloud_host, cloud_port = cloud_broker.apply(self.cloud_client, cloud_topic)
        from . import api as _api_module

        cloud_stick_host = _api_module.WSS_HOST
        cloud_stick_port = 8883
        self.cloud_stick_client.tls_set(cert_reqs=ssl.CERT_NONE)
        self.cloud_stick_client.tls_insecure_set(True)
        local_host, local_port = local_broker.apply(self.local_client, local_topic)

        self.cloud_client.on_connect = self._on_cloud_connect
        self.cloud_client.on_message = self._on_cloud_message
        self.cloud_client.on_disconnect = self._on_disconnect
        self.cloud_stick_client.on_connect = self._on_cloud_stick_connect
        self.cloud_stick_client.on_message = self._on_cloud_stick_message
        self.cloud_stick_client.on_disconnect = self._on_disconnect
        self.local_client.on_connect = self._on_local_connect
        self.local_client.on_message = self._on_local_message
        self.local_client.on_disconnect = self._on_disconnect

        self.cloud_client.connect(cloud_host, cloud_port, keepalive=60)
        self.cloud_stick_client.connect(cloud_stick_host, cloud_stick_port, keepalive=60)
        self.local_client.connect(local_host, local_port, keepalive=60)
        self.cloud_client.loop_start()
        self.cloud_stick_client.loop_start()
        self.local_client.loop_start()

    def _on_disconnect(self, client, userdata, *args):
        with self._lock:
            self._closed = True
        self._connected.set()

    def _on_cloud_connect(self, client, userdata, flags, reason_code, properties=None):
        rc = reason_code.value if hasattr(reason_code, "value") else reason_code
        try:
            self._last_cloud_connack_rc = int(rc)
        except Exception:
            self._last_cloud_connack_rc = None
        if rc != 0:
            _LOGGER.warning("REMKO SmartWeb cloud bridge cloud MQTT connect failed rc=%s", rc)
            self._connected.set()
            return
        client.subscribe(
            [
                (f"{self.cloud_topic}/ESP", 2),
                (f"{self.cloud_topic}/CLIENT2HOST", 2),
            ]
        )
        self._connected.set()

    def _on_cloud_stick_connect(self, client, userdata, flags, reason_code, properties=None):
        rc = reason_code.value if hasattr(reason_code, "value") else reason_code
        try:
            self._last_cloud_stick_connack_rc = int(rc)
        except Exception:
            self._last_cloud_stick_connack_rc = None
        if rc != 0:
            _LOGGER.warning("REMKO SmartWeb cloud bridge stick MQTT connect failed rc=%s", rc)
            self._connected.set()
            return
        client.subscribe([(f"{self.local_topic}/PORTAL2HOST", 2)])
        self._connected.set()

    def _on_local_connect(self, client, userdata, flags, reason_code, properties=None):
        rc = reason_code.value if hasattr(reason_code, "value") else reason_code
        try:
            self._last_local_connack_rc = int(rc)
        except Exception:
            self._last_local_connack_rc = None
        if rc != 0:
            _LOGGER.warning("REMKO SmartWeb cloud bridge local MQTT connect failed rc=%s", rc)
            self._connected.set()
            return
        client.subscribe(
            [
                (f"{self.local_command_topic}/RESP", 2),
                (f"{self.local_command_topic}/HOST2CLIENT", 2),
                (f"{self.local_command_topic}/PORTAL2CLIENT", 2),
                (f"{self.local_topic}/HOST2PORTAL", 2),
                (f"{self.local_topic}/HOST2CLIENT", 2),
                (f"{self.local_topic}/PORTAL2CLIENT", 2),
            ]
        )
        self._connected.set()

    def _forward(self, target_client, target_topic: str, payload: bytes, direction: str, source_topic: str):
        target_client.publish(target_topic, payload, qos=2, retain=False)
        with self._lock:
            now = time.time()
            self._forward_counts[direction] = self._forward_counts.get(direction, 0) + 1
            if direction == "cloud_to_local":
                self._last_cloud_to_local_time = now
                self._last_cloud_to_local_topic = f"{source_topic} -> {target_topic}"
            else:
                self._last_local_to_cloud_time = now
                self._last_local_to_cloud_topic = f"{source_topic} -> {target_topic}"

    def _on_cloud_message(self, client, userdata, msg):
        topic = str(msg.topic)
        if topic.endswith("/ESP"):
            target = f"{self.local_command_topic}/ESP"
        elif topic.endswith("/CLIENT2HOST"):
            target = f"{self.local_command_topic}/CLIENT2HOST"
        else:
            return
        _LOGGER.debug(
            "REMKO SmartWeb cloud bridge forwarding cloud %s to local %s",
            _redact_topic(topic),
            _redact_topic(target),
        )
        self._forward(self.local_client, target, msg.payload, "cloud_to_local", topic)

    def _on_cloud_stick_message(self, client, userdata, msg):
        topic = str(msg.topic)
        if not topic.endswith("/PORTAL2HOST"):
            return
        with self._lock:
            self._last_cloud_portal2host_time = time.time()
            self._last_cloud_portal2host_topic = topic
        _LOGGER.debug(
            "REMKO SmartWeb cloud bridge forwarding cloud %s to local %s",
            _redact_topic(topic),
            _redact_topic(topic),
        )
        self._forward(self.local_client, topic, msg.payload, "cloud_to_local", topic)

    def _on_local_message(self, client, userdata, msg):
        topic = str(msg.topic)
        target_client = self.cloud_client
        if topic.endswith("/RESP"):
            target = f"{self.cloud_topic}/RESP"
        elif topic.endswith("/HOST2CLIENT"):
            target = f"{self.cloud_topic}/HOST2CLIENT"
        elif topic.endswith("/HOST2PORTAL"):
            target = f"{self.local_topic}/HOST2PORTAL"
            target_client = self.cloud_stick_client
        elif topic.endswith("/PORTAL2CLIENT"):
            target = f"{self.cloud_topic}/PORTAL2CLIENT"
        else:
            return
        _LOGGER.debug(
            "REMKO SmartWeb cloud bridge forwarding local %s to cloud %s",
            _redact_topic(topic),
            _redact_topic(target),
        )
        self._forward(target_client, target, msg.payload, "local_to_cloud", topic)

    def ensure_connected(self, timeout: float = 8.0) -> bool:
        self._connected.wait(timeout=timeout)
        with self._lock:
            return (
                not self._closed
                and self._last_cloud_connack_rc == 0
                and self._last_cloud_stick_connack_rc == 0
                and self._last_local_connack_rc == 0
            )

    def diagnostic_snapshot(self) -> dict:
        with self._lock:
            now = time.time()

            def _age(timestamp: float | None) -> float | None:
                return round(now - timestamp, 1) if timestamp is not None else None

            return {
                "enabled": True,
                "connected": (
                    not self._closed
                    and self._last_cloud_connack_rc == 0
                    and self._last_cloud_stick_connack_rc == 0
                    and self._last_local_connack_rc == 0
                ),
                "cloud_connack_rc": self._last_cloud_connack_rc,
                "cloud_stick_connack_rc": self._last_cloud_stick_connack_rc,
                "local_connack_rc": self._last_local_connack_rc,
                "cloud_to_local_count": self._forward_counts.get("cloud_to_local", 0),
                "local_to_cloud_count": self._forward_counts.get("local_to_cloud", 0),
                "last_cloud_to_local_age_s": _age(self._last_cloud_to_local_time),
                "last_cloud_to_local_topic": _redact_topic(self._last_cloud_to_local_topic),
                "last_local_to_cloud_age_s": _age(self._last_local_to_cloud_time),
                "last_local_to_cloud_topic": _redact_topic(self._last_local_to_cloud_topic),
                "last_cloud_portal2host_age_s": _age(self._last_cloud_portal2host_time),
                "last_cloud_portal2host_topic": _redact_topic(self._last_cloud_portal2host_topic),
            }

    def close(self):
        with self._lock:
            self._closed = True
        for client in (self.cloud_client, self.cloud_stick_client, self.local_client):
            try:
                client.loop_stop()
                client.disconnect()
            except Exception:
                pass


def _stick_client_id_from_topic(topic: str | None) -> str | None:
    if not topic:
        return None
    parts = str(topic).split("/")
    if len(parts) >= 2 and parts[1].upper().startswith("SMT"):
        return parts[1]
    return None


def _redact_topic(topic: str | None) -> str | None:
    if not topic:
        return topic
    parts = str(topic).split("/")
    redacted = []
    for part in parts:
        if part.startswith("SMT") and len(part) > 8:
            redacted.append(part[:6] + "...")
        elif len(part) >= 16 and all(ch in "0123456789abcdefABCDEF" for ch in part):
            redacted.append(part[:6] + "...")
        else:
            redacted.append(part)
    return "/".join(redacted)
