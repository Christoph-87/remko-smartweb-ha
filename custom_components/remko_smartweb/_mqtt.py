"""MQTT broker strategy classes and _MqttSession."""
from __future__ import annotations

import abc
import json
import logging
import random
import ssl
import threading
import time
from collections import deque

import paho.mqtt.client as mqtt

from ._helpers import (
    _extract_values_from_payload,
    _json_loads_maybe_wrapped,
    _mqtt_message_summary,
)
from ._frames import _build_status_cmd

_LOGGER = logging.getLogger(__name__)


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
    timeout: float = 20.0,
) -> str | None:
    """Discover the REMKO topic from a local MQTT broker.

    A local portal setup may not have current SID/SK credentials from the cloud.
    The stick still announces itself below V04P27/<stick>/...; older setups
    emit CLIENT2HOST while newer/local portal firmware has been observed to
    emit HOST2PORTAL.  Either direction is enough to derive the local
    announcement topic.  ESP commands may still use the SID-based command topic
    resolved from SmartWeb metadata.
    """
    found: list[str] = []
    done = threading.Event()
    client = mqtt.Client(
        client_id=f"SMT_DISCOVERY_{random.randint(0, 9999):04d}",
        protocol=mqtt.MQTTv311,
        transport="tcp",
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
    )
    if user:
        client.username_pw_set(user, password)

    def _on_connect(client, userdata, flags, reason_code, properties=None):
        rc = reason_code.value if hasattr(reason_code, "value") else reason_code
        if rc == 0:
            client.subscribe(
                [
                    ("V04P27/+/CLIENT2HOST", 2),
                    ("V04P27/+/HOST2PORTAL", 2),
                ]
            )
            return
        _LOGGER.warning("REMKO SmartWeb local MQTT discovery connect failed rc=%s", rc)
        done.set()

    def _on_message(client, userdata, msg):
        parts = str(msg.topic).split("/")
        if (
            len(parts) == 3
            and parts[0] == "V04P27"
            and parts[2] in {"CLIENT2HOST", "HOST2PORTAL"}
        ):
            found.append("/".join(parts[:2]))
            done.set()

    client.on_connect = _on_connect
    client.on_message = _on_message
    try:
        client.connect(host, port, keepalive=30)
        client.loop_start()
        done.wait(timeout=timeout)
    except Exception as err:
        _LOGGER.warning("REMKO SmartWeb local MQTT topic discovery failed: %s", err)
    finally:
        try:
            client.loop_stop()
            client.disconnect()
        except Exception:
            pass
    return found[0] if found else None


# ---------------------------------------------------------------------------
# MQTT session
# ---------------------------------------------------------------------------

class _MqttSession:
    def __init__(
        self,
        topic: str,
        broker: _BrokerConfig,
        command_topic: str | None = None,
    ) -> None:
        self.topic = topic
        self._command_topic = command_topic
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._connected = threading.Event()
        self._closed = False
        self._last_rx = None
        self._last_values = None
        self._last_seen_values = None
        self._last_tx_echo = None
        self._last_smt_user = None
        self._recent_messages: deque = deque(maxlen=20)
        self._received_non_tx_count = 0
        self._subscribed_topics: list[str] = []
        self._outgoing_client_ids: deque = deque(maxlen=20)
        # Local-portal state
        self._local_portal: bool = broker.is_local()
        topic_device = topic.split("/", 2)[1].upper() if "/" in topic else ""
        self._local_host2portal_mode: bool = self._local_portal and topic_device.startswith("SMT")
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
        if self._local_portal:
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
                if summary.get("kind") == "tx_echo":
                    self._last_tx_echo = summary
                else:
                    self._received_non_tx_count += 1
                    self._recent_messages.append(summary)
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
                        self._cond.notify_all()
                    smt_user = obj.get("SMT_USER")
                    if str(smt_user or "").isdigit():
                        self._last_smt_user = int(smt_user)
                values = _extract_values_from_payload(text)
                if isinstance(values, dict) and str(msg.topic).endswith(("/HOST2CLIENT", "/PORTAL2CLIENT")):
                    self._last_values = values
                    self._last_seen_values = values
                    self._cond.notify_all()
                _c2h_needs_reply = (
                    isinstance(obj, dict)
                    and str(msg.topic).endswith("/CLIENT2HOST")
                    and getattr(self, "_local_portal", False)
                    and not is_own_client2host
                    and "query_list" in obj
                )
                if _c2h_needs_reply:
                    self._last_c2h_time = time.time()
                    self._no_c2h_warned = False
                _h2p_needs_reply = (
                    isinstance(obj, dict)
                    and str(msg.topic).endswith("/HOST2PORTAL")
                    and getattr(self, "_local_portal", False)
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
                        self.client.publish(
                            f"{esp_base}/ESP",
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
                        self.client.publish(
                            f"{self.topic}/ESP",
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
        if not self._local_portal:
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
            age_s = (time.time() - self._last_c2h_time) if self._last_c2h_time else None
            return {
                "recent_messages": list(self._recent_messages),
                "last_tx_echo": self._last_tx_echo,
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
