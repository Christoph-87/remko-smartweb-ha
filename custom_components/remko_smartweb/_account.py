"""Exception classes and RemkoSmartWebAccount."""
from __future__ import annotations

import logging
import threading
import time

import requests

from ._helpers import (
    _pace_account_request,
    _normalize_device_name,
    _extract_device_metadata_from_text,
    _extract_names_from_rest_list,
    _extract_sid_sk_from_text,
    _valid_credential_part,
    _build_mqtt_topic,
)

_LOGGER = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Account
# ---------------------------------------------------------------------------

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
        from . import api as _api_module
        LOGIN_TTL_SEC = _api_module.LOGIN_TTL_SEC

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
        from . import api as _api_module
        LOGIN_URL = _api_module.LOGIN_URL
        BASE = _api_module.BASE

        r = self.account_request(
            "post",
            LOGIN_URL,
            data={"name": self.email, "passwort": self.password},
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (X11; Linux x86_64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                "X-Requested-With": "XMLHttpRequest",
                "Origin": BASE,
                "Referer": f"{BASE}/",
            },
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
        from . import api as _api_module
        BASE = _api_module.BASE
        DEVICE_LIST_TTL_SEC = _api_module.DEVICE_LIST_TTL_SEC

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
