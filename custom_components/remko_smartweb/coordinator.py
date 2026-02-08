from __future__ import annotations

from datetime import timedelta
import logging

from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.core import HomeAssistant

from .api import RemkoSmartWebClient
from .const import DOMAIN, DEFAULT_SCAN_INTERVAL

_LOGGER = logging.getLogger(__name__)


class RemkoSmartWebCoordinator(DataUpdateCoordinator[dict]):
    def __init__(self, hass: HomeAssistant, client: RemkoSmartWebClient, scan_interval: int | None = None) -> None:
        self.client = client
        interval = scan_interval or DEFAULT_SCAN_INTERVAL
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=interval),
        )

    async def _async_update_data(self) -> dict:
        try:
            return await self.hass.async_add_executor_job(self.client.read_status)
        except Exception as err:
            # Keep last known data to avoid entities going unavailable on transient failures.
            if self.data:
                _LOGGER.warning("Status update failed, keeping last data: %s", err)
                return self.data
            raise UpdateFailed(str(err)) from err
