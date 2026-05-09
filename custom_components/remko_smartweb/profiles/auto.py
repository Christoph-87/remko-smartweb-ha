from __future__ import annotations

from .base import SmartWebDeviceProfile
from .climate import ClimateDeviceProfile, ReadOnlyAcUartClimateDeviceProfile
from .diagnostics import DiagnosticsDeviceProfile
from .domestic_hot_water import DomesticHotWaterDeviceProfile
from .kwt import KwtDeviceProfile, looks_like_kwt_name
from .lte import LteDeviceProfile, looks_like_lte_name


def _normalized_name(name: str | None) -> str:
    return (name or "").casefold()


def looks_like_dhw_name(device_name: str | None) -> bool:
    name = _normalized_name(device_name)
    return "brauchwasser" in name or "warmwasser" in name or "rbw" in name


def looks_like_climate_name(device_name: str | None) -> bool:
    name = _normalized_name(device_name)
    return any(
        token in name
        for token in (
            "mxw",
            "klima",
            "climate",
            "air conditioner",
            "rkl 495",
            "rkl 355",
            "bl 264",
            "bl 353",
            "aux",
        )
    )


def get_ac_uart_climate_profile(device_name: str | None) -> SmartWebDeviceProfile | None:
    name = _normalized_name(device_name)
    if "rkl 495" in name:
        return ReadOnlyAcUartClimateDeviceProfile("RKL 495 DC", "free_ac_uart")
    if "rkl 355" in name:
        return ReadOnlyAcUartClimateDeviceProfile("RKL 355 DC", "nwt_ac_uart")
    if any(token in name for token in ("bl 264", "bl 353", "bl 354", "aux")):
        return ReadOnlyAcUartClimateDeviceProfile("BL/AUX AC", "aux_ac_uart")
    if any(token in name for token in ("mxw", "klima", "climate", "air conditioner")):
        return ClimateDeviceProfile()
    return None


def looks_like_unsupported_heat_pump_name(device_name: str | None) -> bool:
    name = _normalized_name(device_name)
    return any(
        token in name
        for token in (
            "wpm",
            "wpk",
            "wkm",
            "sqw",
            "waermepumpe",
            "wärmepumpe",
            "modulare_waermepumpe",
            "modulare wärmepumpe",
        )
    )


def get_specialized_profile(device_name: str | None, data: dict | None = None) -> SmartWebDeviceProfile | None:
    if looks_like_dhw_name(device_name):
        return DomesticHotWaterDeviceProfile()
    if looks_like_lte_name(device_name):
        return LteDeviceProfile()
    if looks_like_kwt_name(device_name):
        return KwtDeviceProfile()
    climate_profile = get_ac_uart_climate_profile(device_name)
    if climate_profile is not None:
        return climate_profile
    if looks_like_unsupported_heat_pump_name(device_name):
        return DiagnosticsDeviceProfile()
    if isinstance(data, dict):
        if any(key in data for key in ("target_humidity", "internal_humidity", "internal_temperature")):
            return LteDeviceProfile()
        if any(key in data for key in ("dhw_setpoint", "dhw_top_temperature", "dhw_ambient_temperature", "dhw_mode")):
            return DomesticHotWaterDeviceProfile()
    return None


class AutoDetectDeviceProfile(SmartWebDeviceProfile):
    def __init__(self, device_name: str | None = None) -> None:
        self.device_name = device_name
        self._climate = ClimateDeviceProfile()
        self._dhw = DomesticHotWaterDeviceProfile()
        self._kwt = KwtDeviceProfile()
        self._lte = LteDeviceProfile()

    def parse_c0_status(self, rx_hex: str) -> dict | None:
        return self._climate.parse_c0_status(rx_hex)

    def parse_values_status(self, values: dict) -> dict | None:
        if looks_like_dhw_name(self.device_name):
            return self._dhw.parse_values_status(values) or self._climate.parse_values_status(values)
        if looks_like_lte_name(self.device_name):
            return self._lte.parse_values_status(values)
        if looks_like_kwt_name(self.device_name):
            return self._kwt.parse_values_status(values) or self._climate.parse_values_status(values)
        lte_status = self._lte.parse_values_status(values)
        if lte_status:
            return lte_status
        climate_status = self._climate.parse_values_status(values)
        if climate_status:
            return climate_status
        return self._dhw.parse_values_status(values)
