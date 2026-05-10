from __future__ import annotations

from ..const import DEVICE_KIND_AUTO, DEVICE_KIND_CLIMATE, DEVICE_KIND_DHW, DEVICE_KIND_DIAGNOSTICS
from .auto import (
    AutoDetectDeviceProfile,
    get_ac_uart_climate_profile,
    get_specialized_profile,
    looks_like_climate_name,
    looks_like_dhw_name,
    looks_like_unsupported_heat_pump_name,
)
from .base import NumberDescription, SmartWebDeviceProfile, SensorDescription
from .climate import ClimateDeviceProfile, ReadOnlyAcUartClimateDeviceProfile
from .diagnostics import DiagnosticsDeviceProfile
from .domestic_hot_water import DomesticHotWaterDeviceProfile
from .kwt import KwtDeviceProfile, looks_like_kwt_name
from .lte import LteDeviceProfile, looks_like_lte_name
from .wpm import WpmDeviceProfile, looks_like_wpm_name


def detect_device_kind(device_name: str | None, data: dict | None, configured_kind: str = DEVICE_KIND_AUTO) -> str:
    if configured_kind in (DEVICE_KIND_CLIMATE, DEVICE_KIND_DHW, DEVICE_KIND_DIAGNOSTICS):
        return configured_kind
    if isinstance(data, dict):
        if any(key in data for key in ("dhw_setpoint", "dhw_top_temperature", "dhw_ambient_temperature", "dhw_mode")):
            return DEVICE_KIND_DHW
        if any(key in data for key in ("fan", "swing", "outdoor", "error")):
            return DEVICE_KIND_CLIMATE
    if looks_like_dhw_name(device_name):
        return DEVICE_KIND_DHW
    if looks_like_unsupported_heat_pump_name(device_name):
        return DEVICE_KIND_DIAGNOSTICS
    if looks_like_climate_name(device_name):
        return DEVICE_KIND_CLIMATE
    return DEVICE_KIND_CLIMATE


def get_parser_profile(device_name: str | None, configured_kind: str = DEVICE_KIND_AUTO) -> SmartWebDeviceProfile:
    if configured_kind == DEVICE_KIND_DHW:
        return DomesticHotWaterDeviceProfile()
    if configured_kind == DEVICE_KIND_CLIMATE:
        return ClimateDeviceProfile()
    if configured_kind == DEVICE_KIND_DIAGNOSTICS:
        return DiagnosticsDeviceProfile()
    return AutoDetectDeviceProfile(device_name)


def get_device_profile(
    device_name: str | None,
    data: dict | None,
    configured_kind: str = DEVICE_KIND_AUTO,
) -> SmartWebDeviceProfile:
    if configured_kind == DEVICE_KIND_AUTO:
        specialized = get_specialized_profile(device_name, data)
        if specialized:
            return specialized
    kind = detect_device_kind(device_name, data, configured_kind)
    if kind == DEVICE_KIND_DHW:
        return DomesticHotWaterDeviceProfile()
    if kind == DEVICE_KIND_CLIMATE:
        return ClimateDeviceProfile()
    return DiagnosticsDeviceProfile()


__all__ = [
    "AutoDetectDeviceProfile",
    "ClimateDeviceProfile",
    "DiagnosticsDeviceProfile",
    "DomesticHotWaterDeviceProfile",
    "KwtDeviceProfile",
    "LteDeviceProfile",
    "NumberDescription",
    "ReadOnlyAcUartClimateDeviceProfile",
    "SensorDescription",
    "SmartWebDeviceProfile",
    "WpmDeviceProfile",
    "detect_device_kind",
    "get_ac_uart_climate_profile",
    "get_device_profile",
    "get_parser_profile",
    "get_specialized_profile",
    "looks_like_climate_name",
    "looks_like_dhw_name",
    "looks_like_kwt_name",
    "looks_like_lte_name",
    "looks_like_unsupported_heat_pump_name",
    "looks_like_wpm_name",
]
