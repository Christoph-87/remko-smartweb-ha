from __future__ import annotations

from datetime import timedelta
import logging

from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store

from .api import DeviceNotFound, RemkoSmartWebClient, SmartWebLoginError, UnsupportedPayload
from .const import DOMAIN, DEFAULT_SCAN_INTERVAL

_LOGGER = logging.getLogger(__name__)
MAX_BACKOFF_INTERVAL = 300
CACHE_VERSION = 1
PERSISTENT_ERRORS = (DeviceNotFound, SmartWebLoginError, UnsupportedPayload)


class RemkoSmartWebCoordinator(DataUpdateCoordinator[dict]):
    def __init__(
        self,
        hass: HomeAssistant,
        client: RemkoSmartWebClient,
        entry_id: str,
        scan_interval: int | None = None,
    ) -> None:
        self.client = client
        interval = max(1, scan_interval or DEFAULT_SCAN_INTERVAL)
        self._base_interval = interval
        self._failure_count = 0
        self._store = Store(hass, CACHE_VERSION, f"{DOMAIN}_{entry_id}_last_state")
        self._last_saved_data = None
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=interval),
        )

    async def async_load_last_known_data(self) -> None:
        """Prime the coordinator with the last successful state from HA storage."""
        data = await self._store.async_load()
        if isinstance(data, dict):
            self._last_saved_data = dict(data)
            self.async_set_updated_data(dict(data))

    async def _async_save_last_known_data(self, data: dict) -> None:
        if data == self._last_saved_data:
            return
        self._last_saved_data = dict(data)
        await self._store.async_save(dict(data))

    def _reset_backoff(self) -> None:
        if self._failure_count:
            _LOGGER.debug("Resetting SmartWeb update interval to %s seconds", self._base_interval)
        self._failure_count = 0
        self.update_interval = timedelta(seconds=self._base_interval)

    def _increase_backoff(self) -> None:
        self._failure_count += 1
        interval = min(
            self._base_interval * (2 ** min(self._failure_count, 10)),
            MAX_BACKOFF_INTERVAL,
        )
        if self.update_interval != timedelta(seconds=interval):
            _LOGGER.warning(
                "SmartWeb update failed %s times in a row; backing off polling to %s seconds",
                self._failure_count,
                interval,
            )
        self.update_interval = timedelta(seconds=interval)

    async def _async_update_data(self) -> dict:
        try:
            data = await self.hass.async_add_executor_job(self.client.read_status)
            self._reset_backoff()
            await self._async_save_last_known_data(data)
            return data
        except Exception as err:
            self._increase_backoff()
            # Keep last known data to avoid entities going unavailable on transient failures.
            if self.data:
                _LOGGER.warning("Status update failed, keeping last data: %s", err)
                return self.data
            if isinstance(err, UnsupportedPayload):
                initial_data = self.client.initial_status_if_supported()
                if initial_data:
                    _LOGGER.warning(
                        "Connected to REMKO SmartWeb, but no status values were received yet; "
                        "starting with a pending initial state."
                    )
                    return initial_data
            if isinstance(err, PERSISTENT_ERRORS):
                raise UpdateFailed(str(err)) from err
            if str(err) == "Unable to parse status":
                _LOGGER.warning(
                    "Connected to REMKO SmartWeb, but the device status payload could not be parsed. "
                    "Enable debug logging for custom_components.remko_smartweb to collect diagnostics "
                    "for unsupported devices."
                )
            raise UpdateFailed(str(err)) from err
