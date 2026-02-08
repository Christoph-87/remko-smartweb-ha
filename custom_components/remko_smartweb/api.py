from __future__ import annotations

import json
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
        self._last_login = 0.0
        self._last_payload = None
        self._last_status = None

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

    def _mqtt_roundtrip(self, publish_topic: str, payload: dict, wait_resp=True, timeout=10) -> str | None:
        """Publish MQTT payload and optionally wait for an Rx response."""
        if not self.sid or not self.sk or not self.topic:
            raise RuntimeError("Device not resolved")

        rx = {"payload": None}
        ev = threading.Event()

        def _rc_value(rc):
            return rc.value if hasattr(rc, "value") else rc

        def on_connect(client, userdata, flags, reason_code, properties=None):
            if _rc_value(reason_code) != 0:
                ev.set()
                return
            client.subscribe([(f"{self.topic}/RESP", 2), (f"{self.topic}/ESP", 2)])
            client.publish(publish_topic, json.dumps(payload), qos=2, retain=False)
            if not wait_resp:
                ev.set()

        def on_message(client, userdata, msg):
            try:
                text = msg.payload.decode("utf-8", errors="replace")
            except Exception:
                text = repr(msg.payload)

            if not wait_resp:
                rx["payload"] = text
                ev.set()
                return

            try:
                obj = json.loads(text)
                if obj.get("Rx"):
                    rx["payload"] = text
                    ev.set()
            except Exception:
                # ignore non-JSON or messages without Rx
                return

        client = mqtt.Client(
            client_id=f"SMT{random.randint(0,9999):04d}{self.sid}",
            protocol=mqtt.MQTTv311,
            transport="websockets",
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        )
        client.username_pw_set(self.sid, self.sk)
        client.tls_set(cert_reqs=ssl.CERT_REQUIRED)
        client.ws_set_options(path=WSS_PATH)
        client.on_connect = on_connect
        client.on_message = on_message

        client.connect(WSS_HOST, WSS_PORT, keepalive=60)
        client.loop_start()
        ev.wait(timeout=timeout)
        client.loop_stop()
        client.disconnect()

        return rx["payload"]

    def read_status(self) -> dict:
        self._ensure_login()
        self._ensure_device()
        tx = _build_status_cmd()
        payload = {"Tx": tx, "CLIENT_ID": "SMTACUARTTEST"}
        resp = self._mqtt_roundtrip(f"{self.topic}/ESP", payload, wait_resp=True, timeout=10)

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

        # retry once after forcing a re-login
        self._ensure_login(force=True)
        self._ensure_device()
        resp = self._mqtt_roundtrip(f"{self.topic}/ESP", payload, wait_resp=True, timeout=10)
        parsed = _parse(resp)
        if parsed:
            self._last_payload = parsed.get("_payload")
            self._last_status = parsed
            return parsed
        raise RuntimeError("Unable to parse status")

    def set_values(self, overrides: dict) -> None:
        """Read current state, build a SET frame, then publish to /ESP."""
        self._ensure_login()
        self._ensure_device()
        payload = None
        try:
            status = self.read_status()
            payload = status.get("_payload")
        except Exception:
            payload = self._last_payload
        if not payload:
            raise RuntimeError("No C0 payload")
        tx = _build_set_cmd_from_c0(payload, overrides)
        if not tx:
            raise RuntimeError("Failed to build SET frame")
        self._mqtt_roundtrip(
            f"{self.topic}/ESP",
            {"Tx": tx, "CLIENT_ID": "SMTACUARTTEST"},
            wait_resp=False,
            timeout=5,
        )
