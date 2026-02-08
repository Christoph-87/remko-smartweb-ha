from __future__ import annotations

import json
import logging
import random
import re
import ssl
import threading
import time
from urllib.parse import urljoin, urlparse, parse_qs

import requests
import paho.mqtt.client as mqtt

BASE = "https://smartweb.remko.media"
LOGIN_URL = f"{BASE}/rest/login_do"
WSS_HOST = "smartweb.remko.media"
WSS_PORT = 8083
WSS_PATH = "/mqtt"
VERSION = "V04P27"
LOGIN_TTL_SEC = 10 * 60

_LOGGER = logging.getLogger(__name__)

# ----------------- helpers -----------------

def _extract_sid_sk_from_url(url: str):
    qs = parse_qs(urlparse(url).query)
    sid = (qs.get("SID") or [None])[0]
    sk = (qs.get("SK") or [None])[0]
    if sid and sk:
        return sid.upper(), sk.upper()
    return None


def _extract_sid_sk_from_text(text: str):
    m = re.search(r"SID=([0-9A-Fa-f]{16}).*?SK=([0-9A-Fa-f]{16})", text)
    if m:
        return m.group(1).upper(), m.group(2).upper()
    return None


def _extract_smt_user_from_text(text: str):
    for pat in (
        r"SMT_USER\\s*[:=]\\s*(\\d+)",
        r"\"SMT_USER\"\\s*:\\s*(\\d+)",
        r"smt_user\\s*[:=]\\s*(\\d+)",
        r"\"smt_user\"\\s*:\\s*(\\d+)",
    ):
        m = re.search(pat, text, flags=re.I)
        if m:
            try:
                return int(m.group(1))
            except Exception:
                pass
    return None


def _extract_global_var(text: str, key: str):
    patterns = [
        rf"global\\.{key}\\s*=\\s*['\\\"]([^'\\\"]+)['\\\"]",
        rf"window\\.{key}\\s*=\\s*['\\\"]([^'\\\"]+)['\\\"]",
        rf"\\b{key}\\b\\s*:\\s*['\\\"]([^'\\\"]+)['\\\"]",
        rf"\\b{key}\\b\\s*=\\s*['\\\"]([^'\\\"]+)['\\\"]",
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
    for m in re.finditer(r'href="(/geraet/fernbedienung/[0-9a-f]{32})"', html, flags=re.I):
        rel = m.group(1)
        if rel in name_map:
            continue
        tail = html[m.end(): m.end() + 600]
        m2 = re.search(r"<span[^>]*>([^<]{1,200})</span>", tail, flags=re.I)
        if m2:
            name_map[rel] = m2.group(1).strip()
    return name_map


def _hex_to_bytes(hexstr: str):
    hexstr = hexstr.strip()
    if len(hexstr) % 2 != 0:
        return None
    try:
        return [int(hexstr[i:i+2], 16) for i in range(0, len(hexstr), 2)]
    except Exception:
        return None


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


def _parse_c0_from_rx(rx_hex: str):
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


def _first_byte(hexstr: str | None):
    if not hexstr:
        return None
    try:
        return int(hexstr[0:2], 16)
    except Exception:
        return None


def _parse_values_status(values: dict) -> dict | None:
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
        self._last_payload = None

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
        client.subscribe([
            (f"{self.topic}/HOST2CLIENT", 2),
            (f"{self.topic}/RESP", 2),
            (f"{self.topic}/ESP", 2),
        ])
        self._connected.set()

    def _on_disconnect(self, client, userdata, *args):
        self._closed = True
        self._connected.set()

    def _on_message(self, client, userdata, msg):
        try:
            text = msg.payload.decode("utf-8", errors="replace")
        except Exception:
            text = repr(msg.payload)
        with self._cond:
            self._last_payload = text
            # Rx hex for ESP status
            try:
                obj = json.loads(text)
                if isinstance(obj, dict) and obj.get("Rx"):
                    self._last_rx = text
                    self._cond.notify_all()
            except Exception:
                pass
            values = _extract_values_from_payload(text)
            if isinstance(values, dict):
                self._last_values = values
                self._cond.notify_all()

    def ensure_connected(self, timeout: float = 8.0) -> bool:
        self._connected.wait(timeout=timeout)
        return not self._closed

    def publish(self, topic: str, payload: dict):
        self.client.publish(topic, json.dumps(payload), qos=2, retain=False)

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

    def close(self):
        try:
            self.client.loop_stop()
            self.client.disconnect()
        except Exception:
            pass
        self._closed = True


# ----------------- client -----------------

class RemkoSmartWebClient:
    def __init__(self, email: str, password: str, device_name: str):
        self.email = email
        self.password = password
        self.device_name = device_name
        self.session = requests.Session()

        self.sid = None
        self.sk = None
        self.topic = None
        self.smt_user = None
        self._last_login = 0.0
        self._last_payload = None
        self._last_status = None
        self._mqtt = None

    def _ensure_login(self, force: bool = False) -> None:
        """Ensure a logged-in session is available, reusing it within a TTL."""
        if not force:
            if (time.time() - self._last_login) < LOGIN_TTL_SEC and "PHPSESSID" in self.session.cookies.get_dict():
                return
        self.login()

    def _ensure_device(self) -> None:
        """Ensure SID/SK/topic are resolved from SmartWeb."""
        if self.sid and self.sk and self.topic:
            return
        self.resolve_device()

    def _ensure_mqtt(self) -> None:
        if self._mqtt is None or not self._mqtt.ensure_connected():
            self._mqtt = _MqttSession(self.sid, self.sk, self.topic)
            if not self._mqtt.ensure_connected():
                raise RuntimeError("MQTT connect failed")

    def login(self) -> None:
        r = self.session.post(
            LOGIN_URL,
            data={"name": self.email, "passwort": self.password},
            headers={"X-Requested-With": "XMLHttpRequest", "Origin": BASE, "Referer": f"{BASE}/"},
            timeout=15,
        )
        r.raise_for_status()
        if "PHPSESSID" not in self.session.cookies.get_dict():
            raise RuntimeError("Login failed: no PHPSESSID")
        self._last_login = time.time()

    def list_devices(self) -> list[str]:
        """Return available device names from /rest/liste."""
        self._ensure_login()
        r_list = self.session.get(f"{BASE}/rest/liste", timeout=15)
        r_list.raise_for_status()
        name_map = _extract_names_from_rest_list(r_list.text)
        names = [v for v in name_map.values() if v]
        return sorted(set(names), key=str.lower)

    def resolve_device(self) -> None:
        self._ensure_login()
        # fetch list
        r_list = self.session.get(f"{BASE}/rest/liste", timeout=15)
        r_list.raise_for_status()
        name_map = _extract_names_from_rest_list(r_list.text)

        # pick device by name
        rel = None
        for k, v in name_map.items():
            if v.lower() == self.device_name.lower():
                rel = k
                break
        if not rel:
            raise RuntimeError("Device name not found in /rest/liste")

        url = urljoin(BASE, rel)
        r0 = self.session.get(url, allow_redirects=False, timeout=15)
        loc = r0.headers.get("Location")
        if loc:
            hit = _extract_sid_sk_from_url(urljoin(BASE, loc))
            if hit:
                self.sid, self.sk = hit
                self.topic = f"{VERSION}/{self.sid}"
                return

        r1 = self.session.get(url, allow_redirects=True, timeout=15)
        hit = _extract_sid_sk_from_url(r1.url) or _extract_sid_sk_from_text(r1.text)
        if not hit:
            raise RuntimeError("SID/SK not found")
        self.sid, self.sk = hit
        self.topic = f"{VERSION}/{self.sid}"
        self.smt_user = _extract_smt_user_from_text(r1.text) or _extract_smt_user_from_scripts(self.session, r1.text)
        if self.smt_user is None:
            _LOGGER.warning("SMT_USER not found in device page; CLIENT2HOST polling may be limited")

    def _mqtt_roundtrip_esp(self, payload: dict, timeout=10) -> str | None:
        """Publish ESP payload and wait for Rx response on persistent MQTT."""
        if not self.sid or not self.sk or not self.topic:
            raise RuntimeError("Device not resolved")
        self._ensure_mqtt()
        self._mqtt.publish(f"{self.topic}/ESP", payload)
        return self._mqtt.wait_rx(timeout=timeout)

    def _mqtt_poll_values(self, timeout=10) -> dict | None:
        """Poll values via CLIENT2HOST on persistent MQTT."""
        if not self.sid or not self.sk or not self.topic:
            raise RuntimeError("Device not resolved")
        self._ensure_mqtt()
        poll = {
            "FORCE_RESPONSE": True,
            "query_list": [1190, 1194, 5530],
            "CLIENT_ID": f"SMT{random.randint(0,9999):04d}{self.sid}",
            "LASTWRITE": 0,
            "ISTOUCH": False,
            "DEVID": "",
        }
        if self.smt_user is not None:
            poll["SMT_USER"] = self.smt_user
        self._mqtt.publish(f"{self.topic}/CLIENT2HOST", poll)
        return self._mqtt.wait_values(timeout=timeout)

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
                    parsed = _parse_c0_from_rx(rx_hex)
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

        # fallback: poll values via CLIENT2HOST
        values = self._mqtt_poll_values(timeout=10)
        parsed_values = _parse_values_status(values) if values else None
        if parsed_values:
            if self._last_status:
                merged = dict(self._last_status)
                merged.update({k: v for k, v in parsed_values.items() if v is not None})
                self._last_status = merged
                return merged
            self._last_status = parsed_values
            return parsed_values

        # retry once after forcing a re-login
        self._ensure_login(force=True)
        self._ensure_device()
        resp = self._mqtt_roundtrip_esp(payload, timeout=10)
        parsed = _parse(resp)
        if parsed:
            self._last_payload = parsed.get("_payload")
            self._last_status = parsed
            return parsed

        if self._last_status:
            return self._last_status
        raise RuntimeError("Unable to parse status")

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
                    parsed = _parse_c0_from_rx(rx_hex)
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
            last_err = "Unable to parse status"
            time.sleep(0.5)
        raise RuntimeError(last_err)

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
            raise RuntimeError(f"No C0 payload (status read failed: {last_err})")
        tx = _build_set_cmd_from_c0(payload, overrides)
        if not tx:
            raise RuntimeError("Failed to build SET frame")
        self._mqtt.publish(f"{self.topic}/ESP", {"Tx": tx, "CLIENT_ID": "SMTACUARTTEST"})
        # Try to read back status after SET to keep state in sync (best effort).
        time.sleep(1.0)
        try:
            self.read_status()
        except Exception as err:
            _LOGGER.warning("Readback after SET failed: %s", err)

    def close(self):
        if self._mqtt is not None:
            self._mqtt.close()
            self._mqtt = None
