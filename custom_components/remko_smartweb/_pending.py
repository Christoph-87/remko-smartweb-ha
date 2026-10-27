from __future__ import annotations

import logging
from time import monotonic

from homeassistant.helpers.event import async_call_later

_LOGGER = logging.getLogger(__name__)

PENDING_STATE_TIMEOUT = 30.0
READBACK_REFRESH_DELAY = 2.0


class PendingStateMixin:
    """Keep requested state separate from device-confirmed coordinator data."""

    def _init_pending_state(self) -> None:
        self._pending_values: dict = {}
        self._pending_deadline: float | None = None
        self._pending_generation = 0

    def _confirmed_value(self, key: str, default=None):
        coordinator_data = self.coordinator.data
        if not isinstance(coordinator_data, dict):
            return default
        return coordinator_data.get(key, default)

    def _prune_pending_state(self) -> None:
        if not self._pending_values:
            return
        coordinator_data = self.coordinator.data
        if isinstance(coordinator_data, dict):
            for key, value in tuple(self._pending_values.items()):
                if coordinator_data.get(key) == value:
                    self._pending_values.pop(key, None)
        if not self._pending_values:
            self._pending_deadline = None
        elif (
            self._pending_deadline is not None
            and monotonic() >= self._pending_deadline
        ):
            self._clear_pending_state()

    def _display_value(self, key: str, default=None):
        self._prune_pending_state()
        if key in self._pending_values:
            return self._pending_values[key]
        return self._confirmed_value(key, default)

    @property
    def extra_state_attributes(self) -> dict:
        self._prune_pending_state()
        return {
            "pending_confirmation": bool(self._pending_values),
            "pending_values": dict(self._pending_values) or None,
        }

    def _clear_pending_state(self) -> None:
        self._pending_values.clear()
        self._pending_deadline = None

    def _start_pending_state(self, values: dict) -> int:
        self._prune_pending_state()
        self._pending_values.update(values)
        self._pending_deadline = monotonic() + PENDING_STATE_TIMEOUT
        self._pending_generation += 1
        pending_generation = self._pending_generation
        self.async_write_ha_state()

        async def _expire_pending(_now):
            if pending_generation != self._pending_generation:
                return
            self._prune_pending_state()
            if not self._pending_values:
                return
            pending_keys = sorted(self._pending_values)
            self._clear_pending_state()
            _LOGGER.warning(
                "REMKO SmartWeb write confirmation timed out for %s: %s",
                getattr(self, "_attr_unique_id", type(self).__name__),
                pending_keys,
            )
            try:
                await self.coordinator.async_request_refresh()
            finally:
                self.async_write_ha_state()

        async_call_later(
            self.hass,
            PENDING_STATE_TIMEOUT,
            _expire_pending,
        )
        return pending_generation

    def _rollback_pending_state(self, pending_generation: int) -> None:
        if pending_generation != self._pending_generation:
            return
        self._clear_pending_state()
        self.async_write_ha_state()

    def _schedule_readback_refresh(self) -> None:
        async def _do_refresh(_now):
            await self.coordinator.async_request_refresh()

        async_call_later(
            self.hass,
            READBACK_REFRESH_DELAY,
            _do_refresh,
        )
