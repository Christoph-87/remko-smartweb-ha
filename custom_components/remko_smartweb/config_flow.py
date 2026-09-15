from __future__ import annotations

import random
import logging
import socket
import struct
from pathlib import Path

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.helpers.selector import (
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
)
from homeassistant.helpers.storage import Store

from .const import (
    DOMAIN,
    CONF_EMAIL,
    CONF_PASSWORD,
    CONF_DEVICE_NAME,
    CONF_DEVICE_PATH,
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
    CONF_LOCAL_MQTT_STICK_HOST,
    DEFAULT_LOCAL_MQTT_PORT,
    LOCAL_MQTT_MODE_AUTO,
    LOCAL_MQTT_MODE_CLOUD,
    LOCAL_MQTT_MODE_DEVICE_MQTT,
    LOCAL_MQTT_MODE_PORTAL_BROKER,
    DEVICE_KIND_AUTO,
    DEVICE_KIND_CLIMATE,
    DEVICE_KIND_DHW,
    DEVICE_KIND_DIAGNOSTICS,
    DEFAULT_MIN_TEMP,
    DEFAULT_MAX_TEMP,
)
from .api import RemkoSmartWebClient, probe_local_mqtt
from .profiles import looks_like_dhw_name

_LOGGER = logging.getLogger(__name__)

_MANUAL_LOCAL_MQTT_HOST = "__manual__"
GLOBAL_BROKER_STORE_VERSION = 1
GLOBAL_BROKER_STORE_KEY = f"{DOMAIN}_global_local_mqtt_broker"

DEVICE_KIND_OPTIONS = (
    DEVICE_KIND_AUTO,
    DEVICE_KIND_CLIMATE,
    DEVICE_KIND_DHW,
    DEVICE_KIND_DIAGNOSTICS,
)

LOCAL_MQTT_MODE_OPTIONS = (
    LOCAL_MQTT_MODE_CLOUD,
    LOCAL_MQTT_MODE_PORTAL_BROKER,
    LOCAL_MQTT_MODE_DEVICE_MQTT,
)

CLIMATE_MODEL_OPTIONS = (
    "mxw_204",
    "mxw_264",
    "mxw_354",
    "mxw_524",
    "other",
)


def _select_selector(
    options: list[str] | tuple[str, ...],
    translation_key: str,
) -> SelectSelector:
    return SelectSelector(
        SelectSelectorConfig(
            options=list(options),
            translation_key=translation_key,
            mode=SelectSelectorMode.DROPDOWN,
        )
    )


def _global_broker_store(hass) -> Store:
    return Store(hass, GLOBAL_BROKER_STORE_VERSION, GLOBAL_BROKER_STORE_KEY)


async def _async_load_global_broker(hass) -> dict:
    data = await _global_broker_store(hass).async_load()
    return dict(data or {})


async def _async_save_global_broker(hass, data: dict) -> None:
    if data:
        await _global_broker_store(hass).async_save(data)
    else:
        await _global_broker_store(hass).async_save({})


def _local_mqtt_mode_form_default(values: dict) -> str:
    mode = values.get(CONF_LOCAL_MQTT_MODE, LOCAL_MQTT_MODE_CLOUD)
    return LOCAL_MQTT_MODE_CLOUD if mode == LOCAL_MQTT_MODE_AUTO else mode


def _candidate_label(ip: str, sources: set[str]) -> str:
    return ip


def _compact_mac(value: str | None) -> str | None:
    if not value:
        return None
    compact = "".join(ch for ch in value.upper() if ch in "0123456789ABCDEF")
    return compact if len(compact) == 12 else None


def _arp_ip_for_mac(mac: str | None) -> str | None:
    compact_mac = _compact_mac(mac)
    if not compact_mac:
        return None
    try:
        arp = Path("/proc/net/arp").read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None
    for line in arp.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 4 and _compact_mac(parts[3]) == compact_mac:
            return parts[0]
    return None


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

    def _skip_name(data: bytes, offset: int) -> int | None:
        while offset < len(data):
            label_len = data[offset]
            if label_len == 0:
                return offset + 1
            if label_len & 0xC0 == 0xC0:
                return offset + 2
            offset += 1 + label_len
        return None

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
        offset = _skip_name(data, offset)
        if offset is None or offset + 4 > len(data):
            return set()
        offset += 4

    results: set[str] = set()
    for _ in range(an_count):
        offset = _skip_name(data, offset)
        if offset is None:
            break
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
            candidates.setdefault(ip, set()).add(hostname)

    gateway = _default_gateway_ip()
    if gateway:
        for hostname in hostnames:
            for ip in _dns_query_a(gateway, hostname):
                candidates.setdefault(ip, set()).add(hostname)

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

        options = [
            {"value": entry_id, "label": label}
            for entry_id, label in existing.items()
        ]
        options.append({"value": "new", "label": "new"})
        schema = vol.Schema({
            vol.Required("account"): SelectSelector(
                SelectSelectorConfig(
                    options=options,
                    translation_key="account",
                    mode=SelectSelectorMode.DROPDOWN,
                )
            ),
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
        default_kind = detected_kind if detected_kind != DEVICE_KIND_AUTO else DEVICE_KIND_AUTO
        schema = vol.Schema({
            vol.Required(
                CONF_DEVICE_KIND,
                default=default_kind,
            ): _select_selector(
                self._device_kind_options(detected_kind),
                CONF_DEVICE_KIND,
            ),
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
                default=_local_mqtt_mode_form_default(user_input or self._options),
            ): _select_selector(LOCAL_MQTT_MODE_OPTIONS, CONF_LOCAL_MQTT_MODE),
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
        return dict(DEVICE_KIND_OPTIONS)

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
            vol.Optional(
                CONF_DEVICE_KIND,
                default=device_kind,
            ): _select_selector(
                self._device_kind_options(device_kind),
                CONF_DEVICE_KIND,
            ),
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
            vol.Optional(CONF_MODEL, default=model): _select_selector(
                CLIMATE_MODEL_OPTIONS,
                CONF_MODEL,
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
            self._pending_local_mqtt_stick_host = (
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
        current_host = self._options.get(CONF_LOCAL_MQTT_STICK_HOST)
        if not candidates and not current_host:
            self._pending_local_mqtt_stick_host = ""
            return await self.async_step_local_broker()
        if current_host and current_host not in options:
            options[current_host] = current_host

        default = current_host if current_host in options else None
        if default is None and candidates:
            default = next(iter(candidates))

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
            entry_options = entry.options or {}
            host = entry_options.get(CONF_LOCAL_MQTT_HOST)
            if host:
                mode = entry_options.get(CONF_LOCAL_MQTT_MODE, LOCAL_MQTT_MODE_AUTO)
                if mode == LOCAL_MQTT_MODE_DEVICE_MQTT:
                    hosts.add(str(host).strip())
            stick_host = entry_options.get(CONF_LOCAL_MQTT_STICK_HOST)
            if stick_host:
                hosts.add(str(stick_host).strip())
            data = self.hass.data.get(DOMAIN, {}).get(entry.entry_id, {})
            client = data.get("client") if isinstance(data, dict) else None
            if client is None:
                continue
            try:
                metadata = client.diagnostic_metadata()
            except Exception:
                continue
            ip = _arp_ip_for_mac(metadata.get("Portal MAC"))
            if ip:
                hosts.add(ip)
        return hosts

    async def async_step_local_broker(self, user_input=None):
        """Choose how this device should connect locally."""
        errors = {}
        if user_input is not None:
            mode = user_input.get(CONF_LOCAL_MQTT_MODE, LOCAL_MQTT_MODE_CLOUD)
            stick_host = (user_input.get(CONF_LOCAL_MQTT_STICK_HOST) or "").strip()
            self._options[CONF_LOCAL_MQTT_MODE] = mode
            if stick_host:
                self._options[CONF_LOCAL_MQTT_STICK_HOST] = stick_host
            else:
                self._options.pop(CONF_LOCAL_MQTT_STICK_HOST, None)
            if getattr(self, "_pending_local_mqtt_stick_host", "") == stick_host:
                self._options[CONF_LOCAL_MQTT_CANDIDATE] = stick_host
            self._options[CONF_LOCAL_MQTT_CLOUD_BRIDGE] = bool(
                user_input.get(CONF_LOCAL_MQTT_CLOUD_BRIDGE, False)
            )

            if mode == LOCAL_MQTT_MODE_CLOUD:
                self._clear_local_connection_options()
                return self.async_create_entry(title="", data=self._options)
            if mode == LOCAL_MQTT_MODE_PORTAL_BROKER:
                self._clear_device_mqtt_options()
                return await self.async_step_global_broker()
            if mode == LOCAL_MQTT_MODE_DEVICE_MQTT:
                return await self.async_step_local_device()
            return self.async_create_entry(title="", data=self._options)

        return self._show_local_broker_form()

    def _show_local_broker_form(self, user_input=None, errors=None):
        schema = vol.Schema({
            vol.Optional(
                CONF_LOCAL_MQTT_MODE,
                default=_local_mqtt_mode_form_default(user_input or self._options),
            ): _select_selector(LOCAL_MQTT_MODE_OPTIONS, CONF_LOCAL_MQTT_MODE),
            vol.Optional(
                CONF_LOCAL_MQTT_STICK_HOST,
                default=(user_input or self._options).get(
                    CONF_LOCAL_MQTT_STICK_HOST,
                    getattr(self, "_pending_local_mqtt_stick_host", ""),
                ),
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
        )

    async def async_step_local_device(self, user_input=None):
        """Configure direct MQTT on the device or SmartControl bridge."""
        errors = {}
        if user_input is not None:
            host = (user_input.get(CONF_LOCAL_MQTT_HOST) or "").strip()
            port = int(user_input.get(CONF_LOCAL_MQTT_PORT) or DEFAULT_LOCAL_MQTT_PORT)
            user_val = (user_input.get(CONF_LOCAL_MQTT_USER) or "").strip()
            password = user_input.get(CONF_LOCAL_MQTT_PASSWORD)
            if password in (None, "") and user_val:
                password = self._options.get(CONF_LOCAL_MQTT_PASSWORD, "")
            password = password or ""
            if host:
                probe = await self._async_probe_local_mqtt(
                    host,
                    port,
                    user_val or None,
                    password if user_val else None,
                    LOCAL_MQTT_MODE_DEVICE_MQTT,
                )
                if probe["status"] == "tcp_failed":
                    errors["base"] = "local_mqtt_tcp_failed"
                    return self._show_local_device_form(user_input, errors)
                if probe["status"] == "mqtt_auth_or_acl_failed":
                    errors["base"] = "local_mqtt_auth_failed"
                    return self._show_local_device_form(user_input, errors)

                self._options[CONF_LOCAL_MQTT_HOST] = host
                self._options[CONF_LOCAL_MQTT_PORT] = port
                self._options[CONF_LOCAL_MQTT_LAST_PROBE] = probe
                if user_val:
                    self._options[CONF_LOCAL_MQTT_USER] = user_val
                    self._options[CONF_LOCAL_MQTT_PASSWORD] = password
                else:
                    self._options.pop(CONF_LOCAL_MQTT_USER, None)
                    self._options.pop(CONF_LOCAL_MQTT_PASSWORD, None)
                return self.async_create_entry(title="", data=self._options)

            errors["base"] = "local_mqtt_tcp_failed"
            return self._show_local_device_form(user_input, errors)

        return self._show_local_device_form()

    def _show_local_device_form(self, user_input=None, errors=None):
        values = user_input or self._options
        default_host = values.get(
            CONF_LOCAL_MQTT_HOST,
            self._options.get(
                CONF_LOCAL_MQTT_STICK_HOST,
                getattr(self, "_pending_local_mqtt_stick_host", ""),
            ),
        )
        schema = vol.Schema({
            vol.Required(CONF_LOCAL_MQTT_HOST, default=default_host): str,
            vol.Optional(
                CONF_LOCAL_MQTT_PORT,
                default=values.get(CONF_LOCAL_MQTT_PORT, DEFAULT_LOCAL_MQTT_PORT),
            ): vol.Coerce(int),
            vol.Optional(CONF_LOCAL_MQTT_USER, default=values.get(CONF_LOCAL_MQTT_USER, "")): str,
            vol.Optional(CONF_LOCAL_MQTT_PASSWORD, default=""): str,
        })
        return self.async_show_form(
            step_id="local_device",
            data_schema=schema,
            errors=errors or {},
        )

    async def async_step_global_broker(self, user_input=None):
        """Configure the shared local MQTT broker used by redirected sticks."""
        errors = {}
        global_options = await _async_load_global_broker(self.hass)
        if not global_options:
            global_options = self._legacy_entry_broker_options()
        if user_input is not None:
            host = (user_input.get(CONF_LOCAL_MQTT_HOST) or "").strip()
            if not host:
                errors["base"] = "local_mqtt_tcp_failed"
                return self._show_global_broker_form(user_input, errors)
            port = int(user_input.get(CONF_LOCAL_MQTT_PORT) or DEFAULT_LOCAL_MQTT_PORT)
            user_val = (user_input.get(CONF_LOCAL_MQTT_USER) or "").strip()
            password = user_input.get(CONF_LOCAL_MQTT_PASSWORD)
            if password in (None, "") and user_val:
                password = global_options.get(CONF_LOCAL_MQTT_PASSWORD, "")
            password = password or ""
            probe = await self._async_probe_local_mqtt(
                host,
                port,
                user_val or None,
                password if user_val else None,
                LOCAL_MQTT_MODE_PORTAL_BROKER,
            )
            if probe["status"] == "tcp_failed":
                errors["base"] = "local_mqtt_tcp_failed"
                return self._show_global_broker_form(user_input, errors)
            if probe["status"] == "mqtt_auth_or_acl_failed":
                errors["base"] = "local_mqtt_auth_failed"
                return self._show_global_broker_form(user_input, errors)

            new_global_options = {
                CONF_LOCAL_MQTT_HOST: host,
                CONF_LOCAL_MQTT_PORT: port,
                CONF_LOCAL_MQTT_LAST_PROBE: probe,
            }
            if user_val:
                new_global_options[CONF_LOCAL_MQTT_USER] = user_val
                new_global_options[CONF_LOCAL_MQTT_PASSWORD] = password
            await _async_save_global_broker(self.hass, new_global_options)
            for key in (
                CONF_LOCAL_MQTT_HOST,
                CONF_LOCAL_MQTT_PORT,
                CONF_LOCAL_MQTT_USER,
                CONF_LOCAL_MQTT_PASSWORD,
                CONF_LOCAL_MQTT_LAST_PROBE,
            ):
                self._options.pop(key, None)
            return self.async_create_entry(title="", data=self._options)

        return self._show_global_broker_form(global_options)

    def _legacy_entry_broker_options(self) -> dict:
        if not self._options.get(CONF_LOCAL_MQTT_HOST):
            return {}
        result = {
            CONF_LOCAL_MQTT_HOST: self._options.get(CONF_LOCAL_MQTT_HOST),
            CONF_LOCAL_MQTT_PORT: self._options.get(
                CONF_LOCAL_MQTT_PORT,
                DEFAULT_LOCAL_MQTT_PORT,
            ),
        }
        for key in (
            CONF_LOCAL_MQTT_USER,
            CONF_LOCAL_MQTT_PASSWORD,
            CONF_LOCAL_MQTT_LAST_PROBE,
        ):
            if self._options.get(key):
                result[key] = self._options[key]
        return result

    def _show_global_broker_form(self, values=None, errors=None):
        values = values or {}
        schema = vol.Schema({
            vol.Required(CONF_LOCAL_MQTT_HOST, default=values.get(CONF_LOCAL_MQTT_HOST, "")): str,
            vol.Optional(
                CONF_LOCAL_MQTT_PORT,
                default=values.get(CONF_LOCAL_MQTT_PORT, DEFAULT_LOCAL_MQTT_PORT),
            ): vol.Coerce(int),
            vol.Optional(CONF_LOCAL_MQTT_USER, default=values.get(CONF_LOCAL_MQTT_USER, "")): str,
            vol.Optional(CONF_LOCAL_MQTT_PASSWORD, default=""): str,
        })
        return self.async_show_form(
            step_id="global_broker",
            data_schema=schema,
            errors=errors or {},
        )

    def _clear_local_connection_options(self) -> None:
        for key in (
            CONF_LOCAL_MQTT_HOST,
            CONF_LOCAL_MQTT_PORT,
            CONF_LOCAL_MQTT_USER,
            CONF_LOCAL_MQTT_PASSWORD,
            CONF_LOCAL_MQTT_LAST_PROBE,
            CONF_LOCAL_MQTT_CLOUD_BRIDGE,
            CONF_LOCAL_MQTT_CANDIDATE,
            CONF_LOCAL_MQTT_STICK_HOST,
        ):
            self._options.pop(key, None)

    def _clear_device_mqtt_options(self) -> None:
        for key in (
            CONF_LOCAL_MQTT_HOST,
            CONF_LOCAL_MQTT_PORT,
            CONF_LOCAL_MQTT_USER,
            CONF_LOCAL_MQTT_PASSWORD,
            CONF_LOCAL_MQTT_LAST_PROBE,
        ):
            self._options.pop(key, None)

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
        return dict(DEVICE_KIND_OPTIONS)

    def _shows_climate_options(self, device_kind: str) -> bool:
        return device_kind in (DEVICE_KIND_AUTO, DEVICE_KIND_CLIMATE)
