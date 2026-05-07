from __future__ import annotations

from .base import SmartWebDeviceProfile
from .climate import ClimateDeviceProfile
from .domestic_hot_water import DomesticHotWaterDeviceProfile


def _normalized_name(name: str | None) -> str:
    return (name or "").casefold()


def looks_like_dhw_name(device_name: str | None) -> bool:
    name = _normalized_name(device_name)
    return "brauchwasser" in name or "warmwasser" in name


class AutoDetectDeviceProfile(SmartWebDeviceProfile):
    def __init__(self, device_name: str | None = None) -> None:
        self.device_name = device_name
        self._climate = ClimateDeviceProfile()
        self._dhw = DomesticHotWaterDeviceProfile()

    def parse_c0_status(self, rx_hex: str) -> dict | None:
        return self._climate.parse_c0_status(rx_hex)

    def parse_values_status(self, values: dict) -> dict | None:
        if looks_like_dhw_name(self.device_name):
            return self._dhw.parse_values_status(values) or self._climate.parse_values_status(values)
        climate_status = self._climate.parse_values_status(values)
        if climate_status:
            return climate_status
        return self._dhw.parse_values_status(values)
