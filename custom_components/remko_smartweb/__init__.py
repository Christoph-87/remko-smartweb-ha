from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .api import RemkoSmartWebClient
from .const import (
    DOMAIN,
    CONF_EMAIL,
    CONF_PASSWORD,
    CONF_DEVICE_NAME,
    CONF_DEVICE_PATH,
    CONF_SCAN_INTERVAL,
    DEFAULT_SCAN_INTERVAL,
    PLATFORMS,
)
from .coordinator import RemkoSmartWebCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    hass.data.setdefault(DOMAIN, {})

    email = entry.data[CONF_EMAIL]
    password = entry.data[CONF_PASSWORD]
    device_name = entry.data[CONF_DEVICE_NAME]
    device_path = entry.data.get(CONF_DEVICE_PATH)
    scan_interval = entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)

    client = RemkoSmartWebClient(
        email=email,
        password=password,
        device_name=device_name,
        device_path=device_path,
    )
    coordinator = RemkoSmartWebCoordinator(hass, client, scan_interval=scan_interval)

    await coordinator.async_config_entry_first_refresh()

    if not device_path and client.device_path:
        hass.config_entries.async_update_entry(
            entry,
            data={**entry.data, CONF_DEVICE_PATH: client.device_path},
        )

    hass.data[DOMAIN][entry.entry_id] = {
        "client": client,
        "coordinator": coordinator,
        "device_name": device_name,
    }

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        data = hass.data[DOMAIN].pop(entry.entry_id, None)
        if data and data.get("client"):
            await hass.async_add_executor_job(data["client"].close)
    return unload_ok
