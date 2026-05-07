from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .api import RemkoSmartWebAccount, RemkoSmartWebClient
from .const import (
    DOMAIN,
    CONF_EMAIL,
    CONF_PASSWORD,
    CONF_DEVICE_NAME,
    CONF_DEVICE_PATH,
    CONF_DEVICE_KIND,
    CONF_SCAN_INTERVAL,
    DEVICE_KIND_AUTO,
    DEFAULT_SCAN_INTERVAL,
    PLATFORMS,
)
from .coordinator import RemkoSmartWebCoordinator
from .profiles import get_device_profile

_LOGGER = logging.getLogger(__name__)
ACCOUNT_DATA = "accounts"


def _account_key(email: str, password: str) -> tuple[str, str]:
    return ((email or "").strip().lower(), password or "")


def _get_or_create_account(hass: HomeAssistant, email: str, password: str) -> RemkoSmartWebAccount:
    accounts = hass.data[DOMAIN].setdefault(ACCOUNT_DATA, {})
    key = _account_key(email, password)
    data = accounts.get(key)
    if data is None:
        data = {
            "account": RemkoSmartWebAccount(email=email, password=password),
            "ref_count": 0,
        }
        accounts[key] = data
    data["ref_count"] += 1
    return data["account"]


def _release_account(hass: HomeAssistant, email: str, password: str) -> RemkoSmartWebAccount | None:
    accounts = hass.data.get(DOMAIN, {}).get(ACCOUNT_DATA, {})
    key = _account_key(email, password)
    data = accounts.get(key)
    if data is None:
        return None
    data["ref_count"] -= 1
    if data["ref_count"] > 0:
        return None
    accounts.pop(key, None)
    return data["account"]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    hass.data.setdefault(DOMAIN, {})

    email = entry.data[CONF_EMAIL]
    password = entry.data[CONF_PASSWORD]
    device_name = entry.data[CONF_DEVICE_NAME]
    device_path = entry.data.get(CONF_DEVICE_PATH)
    device_kind = entry.options.get(CONF_DEVICE_KIND, DEVICE_KIND_AUTO)
    scan_interval = entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
    account = _get_or_create_account(hass, email, password)

    client = RemkoSmartWebClient(
        email=email,
        password=password,
        device_name=device_name,
        device_path=device_path,
        device_kind=device_kind,
        account=account,
    )
    coordinator = RemkoSmartWebCoordinator(
        hass,
        client,
        entry_id=entry.entry_id,
        scan_interval=scan_interval,
    )

    try:
        await coordinator.async_load_last_known_data()
        await coordinator.async_config_entry_first_refresh()
    except Exception:
        await hass.async_add_executor_job(client.close)
        released_account = _release_account(hass, email, password)
        if released_account is not None:
            await hass.async_add_executor_job(released_account.close)
        raise

    if not device_path and client.device_path:
        hass.config_entries.async_update_entry(
            entry,
            data={**entry.data, CONF_DEVICE_PATH: client.device_path},
        )

    hass.data[DOMAIN][entry.entry_id] = {
        "client": client,
        "coordinator": coordinator,
        "device_name": device_name,
        "device_profile": get_device_profile(device_name, coordinator.data, device_kind),
    }

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        data = hass.data[DOMAIN].pop(entry.entry_id, None)
        if data and data.get("client"):
            await hass.async_add_executor_job(data["client"].close)
        email = entry.data[CONF_EMAIL]
        password = entry.data[CONF_PASSWORD]
        account = _release_account(hass, email, password)
        if account is not None:
            await hass.async_add_executor_job(account.close)
    return unload_ok
