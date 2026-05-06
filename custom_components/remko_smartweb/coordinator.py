from __future__ import annotations

from datetime import timedelta
import logging

from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.core import HomeAssistant

from .api import RemkoSmartWebClient
from .const import DOMAIN, DEFAULT_SCAN_INTERVAL

_LOGGER = logging.getLogger(__name__)
MAX_BACKOFF_INTERVAL = 300


class RemkoSmartWebCoordinator(DataUpdateCoordinator[dict]):
    def __init__(self, hass: HomeAssistant, client: RemkoSmartWebClient, scan_interval: int | None = None) -> None:
        self.client = client
        interval = max(1, scan_interval or DEFAULT_SCAN_INTERVAL)
        self._base_interval = interval
        self._failure_count = 0
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=interval),
        )

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
            # Keep device name stable for optimistic updates if needed.
            return data
        except Exception as err:
            self._increase_backoff()
            # Keep last known data to avoid entities going unavailable on transient failures.
            if self.data:
                _LOGGER.warning("Status update failed, keeping last data: %s", err)
                return self.data
            if str(err) == "Unable to parse status":
                _LOGGER.warning(
                    "Connected to REMKO SmartWeb, but the device status payload could not be parsed. "
                    "Enable debug logging for custom_components.remko_smartweb to collect diagnostics "
                    "for unsupported devices."
                )
            raise UpdateFailed(str(err)) from err
