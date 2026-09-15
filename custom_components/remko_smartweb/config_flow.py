from __future__ import annotations

import random
import logging
import socket
import struct
from pathlib import Path

import voluptuous as vol
from homeassistant import config_entries

from .const import (
    DOMAIN,
    CONF_EMAIL,
    CONF_PASSWORD,
    CONF_DEVICE_NAME,
    CONF_DEVICE_PATH,
    CONF_SCAN_INTERVAL,
    CONF_MIN_TEMP,
    CONF_MAX_TEMP,
    CONF_MODEL,
    CONF_DEVICE_KIND,
    CONF_BEEP,
    CONF_LOCAL_MQTT_HOST,
    CONF_LOCAL_MQTT_PORT,
    CONF_LOCAL_MQTT_USER,
    CONF_LOCAL_MQTT_PASSWORD,
    CONF_LOCAL_MQTT_MODE,
    CONF_LOCAL_MQTT_LAST_PROBE,
    CONF_LOCAL_MQTT_CLOUD_BRIDGE,
    CONF_LOCAL_MQTT_CANDIDATE,
    DEFAULT_LOCAL_MQTT_PORT,
    LOCAL_MQTT_MODE_AUTO,
    LOCAL_MQTT_MODE_DEVICE_MQTT,
    LOCAL_MQTT_MODE_PORTAL_BROKER,
    DEVICE_KIND_AUTO,
    DEVICE_KIND_CLIMATE,
    DEVICE_KIND_DHW,
    DEVICE_KIND_DIAGNOSTICS,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_MIN_TEMP,
    DEFAULT_MAX_TEMP,
)
from .api import RemkoSmartWebClient, probe_local_mqtt
from .profiles import looks_like_dhw_name

_LOGGER = logging.getLogger(__name__)

_MANUAL_LOCAL_MQTT_HOST = "__manual__"

DEVICE_KIND_OPTIONS = {
    DEVICE_KIND_AUTO: "Auto-detect",
    DEVICE_KIND_CLIMATE: "Air conditioner / climate",
    DEVICE_KIND_DHW: "Domestic hot water",
    DEVICE_KIND_DIAGNOSTICS: "Diagnostics only",
}

LOCAL_MQTT_MODE_OPTIONS = {
    LOCAL_MQTT_MODE_AUTO: "Automatic probe",
    LOCAL_MQTT_MODE_PORTAL_BROKER: "Redirected WiFi stick / local portal broker",
    LOCAL_MQTT_MODE_DEVICE_MQTT: "Direct device MQTT / SmartControl bridge",
}


def _candidate_label(ip: str, sources: set[str]) -> str:
    suffix = ", ".join(sorted(sources))
    return f"{ip} ({suffix})" if suffix else ip


def _resolver_search_domains() -> list[str]:
    domains: list[str] = []
    try:
        text = Path("/etc/resolv.conf").read_text(encoding="utf-8", errors="replace")
    except Exception:
        return domains
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        if parts[0] == "search":
            domains.extend(part for part in parts[1:] if part)
        elif parts[0] == "domain" and len(parts) > 1:
            domains.append(parts[1])
    seen = set()
    return [domain for domain in domains if not (domain in seen or seen.add(domain))]


def _default_gateway_ip() -> str | None:
    try:
        text = Path("/proc/net/route").read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 3 or parts[1] != "00000000":
            continue
        try:
            raw = bytes.fromhex(parts[2])[::-1]
        except ValueError:
            continue
        return socket.inet_ntoa(raw)
    return None


def _dns_query_a(server: str, name: str, timeout: float = 1.2) -> set[str]:
    def _qname(hostname: str) -> bytes:
        return b"".join(
            bytes([len(part)]) + part.encode("idna")
            for part in hostname.rstrip(".").split(".")
            if part
        ) + b"\0"

    try:
        query_id = random.randrange(65536)
        packet = (
            struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
            + _qname(name)
            + struct.pack("!HH", 1, 1)
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(packet, (server, 53))
            data, _addr = sock.recvfrom(2048)
        finally:
            sock.close()
    except Exception:
        return set()

    if len(data) < 12:
        return set()
    _rid, _flags, qd_count, an_count, _ns_count, _ar_count = struct.unpack(
        "!HHHHHH", data[:12]
    )
    offset = 12
    for _ in range(qd_count):
        while offset < len(data) and data[offset] != 0:
            label_len = data[offset]
            if label_len & 0xC0 == 0xC0:
                offset += 2
                break
            offset += 1 + label_len
        else:
            return set()
        offset += 5

    results: set[str] = set()
    for _ in range(an_count):
        if offset >= len(data):
            break
        if data[offset] & 0xC0 == 0xC0:
            offset += 2
        else:
            while offset < len(data) and data[offset] != 0:
                offset += 1 + data[offset]
            offset += 1
        if offset + 10 > len(data):
            break
        answer_type, _answer_class, _ttl, rd_len = struct.unpack(
            "!HHIH", data[offset: offset + 10]
        )
        offset += 10
        rdata = data[offset: offset + rd_len]
        offset += rd_len
        if answer_type == 1 and rd_len == 4:
            results.add(socket.inet_ntoa(rdata))
    return results


def discover_local_mqtt_host_candidates() -> dict[str, str]:
    """Return best-effort local REMKO stick IP candidates from hostname hints."""
    hostnames = {"espressif", "espressif.local"}
    for domain in _resolver_search_domains():
        hostnames.add(f"espressif.{domain.strip('.')}")

    candidates: dict[str, set[str]] = {}
    for hostname in hostnames:
        try:
            infos = socket.getaddrinfo(hostname, None, family=socket.AF_INET)
        except Exception:
            infos = []
        for info in infos:
            ip = info[4][0]
            candidates.setdefault(ip, set()).add(f"{hostname} via resolver")

    gateway = _default_gateway_ip()
    if gateway:
        for hostname in hostnames:
            for ip in _dns_query_a(gateway, hostname):
                candidates.setdefault(ip, set()).add(f"{hostname} via gateway DNS")

    return {ip: _candidate_label(ip, sources) for ip, sources in sorted(candidates.items())}


class RemkoSmartWebConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input=None):
        existing = self._get_existing_accounts()
        if existing and user_input is None:
            return await self.async_step_account()

        errors = {}
        schema = vol.Schema({
            vol.Required(CONF_EMAIL): str,
            vol.Required(CONF_PASSWORD): str,
        })
        if user_input is not None:
            ok, device_map = await self._async_fetch_devices(user_input)
            if ok:
                self._email = user_input[CONF_EMAIL]
                self._password = user_input[CONF_PASSWORD]
                self._device_map = self._filter_existing_device_map(device_map, self._email)
                self._device_names = sorted(self._device_map, key=str.lower)
                if not self._device_names:
                    errors["base"] = "no_devices"
                    return self.async_show_form(step_id="user", data_schema=schema, errors=errors)
                if len(self._device_names) == 1:
                    return await self._prepare_device_kind_step(self._device_names[0])
                return await self.async_step_device()
            errors["base"] = "cannot_connect"

        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)

    async def async_step_account(self, user_input=None):
        errors = {}
        existing = self._get_existing_accounts()
        if not existing:
            return await self.async_step_user()

        options = dict(existing)
        options["new"] = "Use new credentials"
        schema = vol.Schema({
            vol.Required("account"): vol.In(options),
        })

        if user_input is not None:
            selected = user_input.get("account")
            if selected == "new":
                return await self.async_step_user()
            entry = next((e for e in self._get_entries() if e.entry_id == selected), None)
            if entry:
                self._email = entry.data.get(CONF_EMAIL)
                self._password = entry.data.get(CONF_PASSWORD)
                ok, device_map = await self._async_fetch_devices(
                    {CONF_EMAIL: self._email, CONF_PASSWORD: self._password}
                )
                if ok:
                    self._device_map = self._filter_existing_device_map(device_map, self._email)
                    self._device_names = sorted(self._device_map, key=str.lower)
                    if not self._device_names:
                        errors["base"] = "no_devices"
                        return self.async_show_form(step_id="account", data_schema=schema, errors=errors)
                    if len(self._device_names) == 1:
                        return await self._prepare_device_kind_step(self._device_names[0])
                    return await self.async_step_device()
            errors["base"] = "cannot_connect"
        return self.async_show_form(step_id="account", data_schema=schema, errors=errors)

    async def async_step_device(self, user_input=None):
        errors = {}
        if user_input is not None:
            return await self._prepare_device_kind_step(user_input[CONF_DEVICE_NAME])

        device_names = getattr(self, "_device_names", None) or []
        if device_names:
            schema = vol.Schema({
                vol.Required(CONF_DEVICE_NAME): vol.In(device_names),
            })
        else:
            schema = vol.Schema({
                vol.Required(CONF_DEVICE_NAME): str,
            })

        return self.async_show_form(step_id="device", data_schema=schema, errors=errors)

    async def async_step_device_kind(self, user_input=None):
        errors = {}
        data = getattr(self, "_pending_entry_data", None)
        if not data:
            return await self.async_step_device()

        detected_kind = self._suggest_device_kind(data[CONF_DEVICE_NAME])
        options = self._device_kind_options(detected_kind)
        default_kind = detected_kind if detected_kind != DEVICE_KIND_AUTO else DEVICE_KIND_AUTO
        schema = vol.Schema({
            vol.Required(CONF_DEVICE_KIND, default=default_kind): vol.In(options),
        })

        if user_input is not None:
            entry_options = {CONF_DEVICE_KIND: user_input[CONF_DEVICE_KIND]}
            ok = await self._async_validate(data)
            if ok:
                return self.async_create_entry(
                    title=data[CONF_DEVICE_NAME],
                    data=data,
                    options=entry_options,
                )
            errors["base"] = "cannot_connect"

        return self.async_show_form(step_id="device_kind", data_schema=schema, errors=errors)

    async def _async_validate(self, data) -> bool:
        def _check():
            client = RemkoSmartWebClient(
                email=data[CONF_EMAIL],
                password=data[CONF_PASSWORD],
                device_name=data[CONF_DEVICE_NAME],
                device_path=data.get(CONF_DEVICE_PATH),
            )
            try:
                client.login()
                client.resolve_device()
                return True
            finally:
                client.close()

        try:
            return await self.hass.async_add_executor_job(_check)
        except Exception as err:
            _LOGGER.warning("Credential validation failed: %s", err)
            return False

    async def _async_fetch_devices(self, data):
        def _fetch():
            client = RemkoSmartWebClient(
                email=data[CONF_EMAIL],
                password=data[CONF_PASSWORD],
                device_name="",
            )
            try:
                client.login()
                return client.list_device_map()
            finally:
                client.close()

        try:
            device_map = await self.hass.async_add_executor_job(_fetch)
            return True, device_map
        except Exception as err:
            _LOGGER.warning("Device list fetch failed: %s", err)
            return False, {}

    def _get_entries(self):
        return self.hass.config_entries.async_entries(DOMAIN)

    def _get_existing_accounts(self):
        buckets = {}
        for entry in self._get_entries():
            email = (entry.data.get(CONF_EMAIL) or "").strip()
            password = entry.data.get(CONF_PASSWORD) or ""
            key = (email.lower(), password)
            if key not in buckets:
                buckets[key] = {"entry_id": entry.entry_id, "email": email, "count": 0}
            buckets[key]["count"] += 1

        options = {}
        for item in buckets.values():
            email = item["email"]
            count = item["count"]
            if email:
                label = f"{email} ({count} devices)"
            else:
                label = f"Account ({count} devices)"
            options[item["entry_id"]] = label
        return options

    def _filter_existing_device_map(self, device_map: dict[str, str], email: str | None):
        if not device_map:
            return {}
        email = (email or "").strip().lower()
        existing_names = set()
        existing_paths = set()
        for entry in self._get_entries():
            if email and entry.data.get(CONF_EMAIL, "").strip().lower() != email:
                continue
            name = entry.data.get(CONF_DEVICE_NAME)
            if name:
                existing_names.add(name.strip().lower())
            path = entry.data.get(CONF_DEVICE_PATH)
            if path:
                existing_paths.add(path)
        return {
            name: path
            for name, path in device_map.items()
            if name.strip().lower() not in existing_names and path not in existing_paths
        }

    def _entry_data_for_device(self, device_name: str):
        data = {
            CONF_EMAIL: self._email,
            CONF_PASSWORD: self._password,
            CONF_DEVICE_NAME: device_name,
        }
        device_path = getattr(self, "_device_map", {}).get(device_name)
        if device_path:
            data[CONF_DEVICE_PATH] = device_path
        return data

    async def _prepare_device_kind_step(self, device_name: str):
        self._pending_entry_data = self._entry_data_for_device(device_name)
        return await self.async_step_device_kind()

    async def async_step_local_broker(self, user_input=None):
        """Optional step: configure and probe local MQTT for this device."""
        errors = {}
        if user_input is not None:
            host = (user_input.get(CONF_LOCAL_MQTT_HOST) or "").strip()
            if host:
                port = int(user_input.get(CONF_LOCAL_MQTT_PORT) or DEFAULT_LOCAL_MQTT_PORT)
                mode = user_input.get(CONF_LOCAL_MQTT_MODE, LOCAL_MQTT_MODE_AUTO)
                user_val = (user_input.get(CONF_LOCAL_MQTT_USER) or "").strip()
                password = user_input.get(CONF_LOCAL_MQTT_PASSWORD) or ""
                probe = await self._async_probe_local_mqtt(
                    host,
                    port,
                    user_val or None,
                    password if user_val else None,
                    mode,
                )
                if probe["status"] == "tcp_failed":
                    errors["base"] = "local_mqtt_tcp_failed"
                    return self._show_local_broker_form(user_input, errors)
                if probe["status"] == "mqtt_auth_or_acl_failed":
                    errors["base"] = "local_mqtt_auth_failed"
                    return self._show_local_broker_form(user_input, errors)

                self._options[CONF_LOCAL_MQTT_MODE] = user_input.get(
                    CONF_LOCAL_MQTT_MODE,
                    LOCAL_MQTT_MODE_AUTO,
                )
                self._options[CONF_LOCAL_MQTT_HOST] = host
                self._options[CONF_LOCAL_MQTT_PORT] = port
                self._options[CONF_LOCAL_MQTT_LAST_PROBE] = probe
                self._options[CONF_LOCAL_MQTT_CLOUD_BRIDGE] = bool(
                    user_input.get(CONF_LOCAL_MQTT_CLOUD_BRIDGE, False)
                )
                if user_val:
                    self._options[CONF_LOCAL_MQTT_USER] = user_val
                    self._options[CONF_LOCAL_MQTT_PASSWORD] = (
                        user_input.get(CONF_LOCAL_MQTT_PASSWORD) or ""
                    )
                else:
                    self._options.pop(CONF_LOCAL_MQTT_USER, None)
                    self._options.pop(CONF_LOCAL_MQTT_PASSWORD, None)
            else:
                # User cleared the host → remove all local broker settings
                for k in (CONF_LOCAL_MQTT_HOST, CONF_LOCAL_MQTT_PORT,
                          CONF_LOCAL_MQTT_USER, CONF_LOCAL_MQTT_PASSWORD,
                          CONF_LOCAL_MQTT_MODE, CONF_LOCAL_MQTT_LAST_PROBE,
                          CONF_LOCAL_MQTT_CLOUD_BRIDGE):
                    self._options.pop(k, None)
            return self.async_create_entry(title="", data=self._options)

        return self._show_local_broker_form()

    def _show_local_broker_form(self, user_input=None, errors=None):
        schema = vol.Schema({
            vol.Optional(
                CONF_LOCAL_MQTT_MODE,
                default=(user_input or self._options).get(
                    CONF_LOCAL_MQTT_MODE,
                    LOCAL_MQTT_MODE_AUTO,
                ),
            ): vol.In(LOCAL_MQTT_MODE_OPTIONS),
            vol.Optional(
                CONF_LOCAL_MQTT_HOST,
                default=(user_input or self._options).get(CONF_LOCAL_MQTT_HOST, ""),
            ): str,
            vol.Optional(
                CONF_LOCAL_MQTT_PORT,
                default=(user_input or self._options).get(
                    CONF_LOCAL_MQTT_PORT,
                    DEFAULT_LOCAL_MQTT_PORT,
                ),
            ): vol.Coerce(int),
            vol.Optional(
                CONF_LOCAL_MQTT_USER,
                default=(user_input or self._options).get(CONF_LOCAL_MQTT_USER, ""),
            ): str,
            vol.Optional(
                CONF_LOCAL_MQTT_PASSWORD,
                default=(user_input or self._options).get(CONF_LOCAL_MQTT_PASSWORD, ""),
            ): str,
            vol.Optional(
                CONF_LOCAL_MQTT_CLOUD_BRIDGE,
                default=(user_input or self._options).get(CONF_LOCAL_MQTT_CLOUD_BRIDGE, False),
            ): bool,
        })
        return self.async_show_form(
            step_id="local_broker",
            data_schema=schema,
            errors=errors or {},
            description_placeholders={
                "broker_hint": "e.g. 192.168.2.4 or leave empty for REMKO cloud"
            },
        )

    async def _async_probe_local_mqtt(self, host, port, user, password, mode):
        def _probe():
            return probe_local_mqtt(
                host,
                port,
                user,
                password,
                mode=mode,
                timeout=4.0,
                tcp_timeout=2.0,
            ).as_dict()

        return await self.hass.async_add_executor_job(_probe)

    def _suggest_device_kind(self, device_name: str) -> str:
        if looks_like_dhw_name(device_name):
            return DEVICE_KIND_DHW
        return DEVICE_KIND_AUTO

    def _device_kind_options(self, detected_kind: str | None = None) -> dict[str, str]:
        options = dict(DEVICE_KIND_OPTIONS)
        if detected_kind and detected_kind != DEVICE_KIND_AUTO:
            label = options.get(detected_kind, detected_kind)
            options[detected_kind] = f"{label} (detected)"
        return options

    async def async_step_import(self, user_input):
        return await self.async_step_user(user_input)

    @staticmethod
    def async_get_options_flow(config_entry: config_entries.ConfigEntry):
        return RemkoSmartWebOptionsFlow(config_entry)


class RemkoSmartWebOptionsFlow(config_entries.OptionsFlow):
    def __init__(self, config_entry: config_entries.ConfigEntry):
        self._config_entry = config_entry
        self._options = dict(config_entry.options)

    async def async_step_init(self, user_input=None):
        if user_input is not None:
            self._options.update(user_input)
            if self._shows_climate_options(user_input[CONF_DEVICE_KIND]):
                return await self.async_step_climate()
            self._options.pop(CONF_MODEL, None)
            self._options.pop(CONF_MIN_TEMP, None)
            self._options.pop(CONF_MAX_TEMP, None)
            return await self.async_step_local_candidate()

        device_kind = self._config_entry.options.get(
            CONF_DEVICE_KIND,
            self._suggest_device_kind(self._config_entry.data.get(CONF_DEVICE_NAME, "")),
        )
        schema = vol.Schema({
            vol.Optional(CONF_DEVICE_KIND, default=device_kind): vol.In(
                self._device_kind_options(device_kind)
            ),
            vol.Optional(
                CONF_SCAN_INTERVAL,
                default=self._config_entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
            ): vol.Coerce(int),
        })
        return self.async_show_form(step_id="init", data_schema=schema)

    async def async_step_climate(self, user_input=None):
        if user_input is not None:
            self._options.update(user_input)
            return await self.async_step_local_candidate()

        model = self._options.get(CONF_MODEL, "other")
        model_defaults = {
            "mxw_204": (17, 30),
            "mxw_264": (17, 30),
            "mxw_354": (17, 30),
            "mxw_524": (17, 30),
            "other": (DEFAULT_MIN_TEMP, DEFAULT_MAX_TEMP),
        }
        d_min, d_max = model_defaults.get(model, (DEFAULT_MIN_TEMP, DEFAULT_MAX_TEMP))

        schema = vol.Schema({
            vol.Optional(CONF_MODEL, default=model): vol.In(
                {
                    "mxw_204": "MXW 204",
                    "mxw_264": "MXW 264",
                    "mxw_354": "MXW 354",
                    "mxw_524": "MXW 524",
                    "other": "Other / Unknown",
                }
            ),
            vol.Optional(
                CONF_MIN_TEMP,
                default=self._options.get(CONF_MIN_TEMP, d_min),
            ): vol.Coerce(int),
            vol.Optional(
                CONF_MAX_TEMP,
                default=self._options.get(CONF_MAX_TEMP, d_max),
            ): vol.Coerce(int),
            vol.Optional(
                CONF_BEEP,
                default=self._options.get(CONF_BEEP, False),
            ): bool,
        })
        return self.async_show_form(step_id="climate", data_schema=schema)

    async def async_step_local_candidate(self, user_input=None):
        """Offer best-effort local stick IP candidates before manual MQTT setup."""
        if user_input is not None:
            selected = user_input.get(CONF_LOCAL_MQTT_CANDIDATE, _MANUAL_LOCAL_MQTT_HOST)
            self._pending_local_mqtt_host = (
                "" if selected == _MANUAL_LOCAL_MQTT_HOST else selected
            )
            self._options[CONF_LOCAL_MQTT_CANDIDATE] = selected
            return await self.async_step_local_broker()

        candidates = await self.hass.async_add_executor_job(
            discover_local_mqtt_host_candidates
        )
        used_hosts = self._local_mqtt_hosts_used_by_other_entries()
        candidates = {
            host: label
            for host, label in candidates.items()
            if host not in used_hosts
        }
        self._local_mqtt_host_candidates = candidates

        options = dict(candidates)
        current_host = self._options.get(CONF_LOCAL_MQTT_HOST)
        if current_host and current_host not in options:
            options[current_host] = f"{current_host} (current)"
        options[_MANUAL_LOCAL_MQTT_HOST] = "Enter IP or broker host manually"

        default = current_host if current_host in options else None
        if default is None and candidates:
            default = next(iter(candidates))
        if default is None:
            default = _MANUAL_LOCAL_MQTT_HOST

        schema = vol.Schema({
            vol.Required(CONF_LOCAL_MQTT_CANDIDATE, default=default): vol.In(options),
        })
        return self.async_show_form(
            step_id="local_candidate",
            data_schema=schema,
            description_placeholders={
                "candidate_count": str(len(candidates)),
            },
        )

    def _local_mqtt_hosts_used_by_other_entries(self) -> set[str]:
        hosts: set[str] = set()
        current_entry_id = getattr(self._config_entry, "entry_id", None)
        for entry in self.hass.config_entries.async_entries(DOMAIN):
            if getattr(entry, "entry_id", None) == current_entry_id:
                continue
            host = (entry.options or {}).get(CONF_LOCAL_MQTT_HOST)
            if host:
                hosts.add(str(host).strip())
        return hosts

    async def async_step_local_broker(self, user_input=None):
        """Optional step: configure and probe local MQTT for this device."""
        errors = {}
        if user_input is not None:
            host = (user_input.get(CONF_LOCAL_MQTT_HOST) or "").strip()
            if host:
                port = int(user_input.get(CONF_LOCAL_MQTT_PORT) or DEFAULT_LOCAL_MQTT_PORT)
                mode = user_input.get(CONF_LOCAL_MQTT_MODE, LOCAL_MQTT_MODE_AUTO)
                user_val = (user_input.get(CONF_LOCAL_MQTT_USER) or "").strip()
                password = user_input.get(CONF_LOCAL_MQTT_PASSWORD)
                if password in (None, "") and user_val:
                    password = self._options.get(CONF_LOCAL_MQTT_PASSWORD, "")
                password = password or ""
                probe = await self._async_probe_local_mqtt(
                    host,
                    port,
                    user_val or None,
                    password if user_val else None,
                    mode,
                )
                if probe["status"] == "tcp_failed":
                    errors["base"] = "local_mqtt_tcp_failed"
                    return self._show_local_broker_form(user_input, errors)
                if probe["status"] == "mqtt_auth_or_acl_failed":
                    errors["base"] = "local_mqtt_auth_failed"
                    return self._show_local_broker_form(user_input, errors)

                self._options[CONF_LOCAL_MQTT_MODE] = mode
                self._options[CONF_LOCAL_MQTT_HOST] = host
                self._options[CONF_LOCAL_MQTT_PORT] = port
                self._options[CONF_LOCAL_MQTT_LAST_PROBE] = probe
                if getattr(self, "_pending_local_mqtt_host", "") == host:
                    self._options[CONF_LOCAL_MQTT_CANDIDATE] = host
                self._options[CONF_LOCAL_MQTT_CLOUD_BRIDGE] = bool(
                    user_input.get(CONF_LOCAL_MQTT_CLOUD_BRIDGE, False)
                )
                if user_val:
                    self._options[CONF_LOCAL_MQTT_USER] = user_val
                    self._options[CONF_LOCAL_MQTT_PASSWORD] = password
                else:
                    self._options.pop(CONF_LOCAL_MQTT_USER, None)
                    self._options.pop(CONF_LOCAL_MQTT_PASSWORD, None)
            else:
                for k in (
                    CONF_LOCAL_MQTT_HOST,
                    CONF_LOCAL_MQTT_PORT,
                    CONF_LOCAL_MQTT_USER,
                    CONF_LOCAL_MQTT_PASSWORD,
                    CONF_LOCAL_MQTT_MODE,
                    CONF_LOCAL_MQTT_LAST_PROBE,
                    CONF_LOCAL_MQTT_CLOUD_BRIDGE,
                    CONF_LOCAL_MQTT_CANDIDATE,
                ):
                    self._options.pop(k, None)
            return self.async_create_entry(title="", data=self._options)

        return self._show_local_broker_form()

    def _show_local_broker_form(self, user_input=None, errors=None):
        schema = vol.Schema({
            vol.Optional(
                CONF_LOCAL_MQTT_MODE,
                default=(user_input or self._options).get(
                    CONF_LOCAL_MQTT_MODE,
                    LOCAL_MQTT_MODE_AUTO,
                ),
            ): vol.In(LOCAL_MQTT_MODE_OPTIONS),
            vol.Optional(
                CONF_LOCAL_MQTT_HOST,
                default=(user_input or self._options).get(
                    CONF_LOCAL_MQTT_HOST,
                    getattr(self, "_pending_local_mqtt_host", ""),
                ),
            ): str,
            vol.Optional(
                CONF_LOCAL_MQTT_PORT,
                default=(user_input or self._options).get(
                    CONF_LOCAL_MQTT_PORT,
                    DEFAULT_LOCAL_MQTT_PORT,
                ),
            ): vol.Coerce(int),
            vol.Optional(
                CONF_LOCAL_MQTT_USER,
                default=(user_input or self._options).get(CONF_LOCAL_MQTT_USER, ""),
            ): str,
            vol.Optional(
                CONF_LOCAL_MQTT_PASSWORD,
                default="",
            ): str,
            vol.Optional(
                CONF_LOCAL_MQTT_CLOUD_BRIDGE,
                default=(user_input or self._options).get(CONF_LOCAL_MQTT_CLOUD_BRIDGE, False),
            ): bool,
        })
        return self.async_show_form(
            step_id="local_broker",
            data_schema=schema,
            errors=errors or {},
            description_placeholders={
                "broker_hint": "e.g. 192.168.2.4 or leave empty for REMKO cloud"
            },
        )

    async def _async_probe_local_mqtt(self, host, port, user, password, mode):
        def _probe():
            return probe_local_mqtt(
                host,
                port,
                user,
                password,
                mode=mode,
                timeout=4.0,
                tcp_timeout=2.0,
            ).as_dict()

        return await self.hass.async_add_executor_job(_probe)

    def _suggest_device_kind(self, device_name: str) -> str:
        if looks_like_dhw_name(device_name):
            return DEVICE_KIND_DHW
        return DEVICE_KIND_AUTO

    def _device_kind_options(self, detected_kind: str | None = None) -> dict[str, str]:
        options = dict(DEVICE_KIND_OPTIONS)
        if detected_kind and detected_kind != DEVICE_KIND_AUTO:
            label = options.get(detected_kind, detected_kind)
            options[detected_kind] = f"{label} (detected)"
        return options

    def _shows_climate_options(self, device_kind: str) -> bool:
        return device_kind in (DEVICE_KIND_AUTO, DEVICE_KIND_CLIMATE)
