from __future__ import annotations

from ..const import DEVICE_KIND_AUTO, DEVICE_KIND_CLIMATE, DEVICE_KIND_DHW, DEVICE_KIND_DIAGNOSTICS
from .auto import AutoDetectDeviceProfile, looks_like_dhw_name
from .base import SmartWebDeviceProfile, SensorDescription
from .climate import ClimateDeviceProfile
from .diagnostics import DiagnosticsDeviceProfile
from .domestic_hot_water import DomesticHotWaterDeviceProfile


def detect_device_kind(device_name: str | None, data: dict | None, configured_kind: str = DEVICE_KIND_AUTO) -> str:
    if configured_kind in (DEVICE_KIND_CLIMATE, DEVICE_KIND_DHW, DEVICE_KIND_DIAGNOSTICS):
        return configured_kind
    if isinstance(data, dict):
        if "dhw_setpoint" in data or "dhw_top_temperature" in data:
            return DEVICE_KIND_DHW
        if any(key in data for key in ("fan", "swing", "outdoor", "error")):
            return DEVICE_KIND_CLIMATE
    if looks_like_dhw_name(device_name):
        return DEVICE_KIND_DHW
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
    "SensorDescription",
    "SmartWebDeviceProfile",
    "detect_device_kind",
    "get_device_profile",
    "get_parser_profile",
    "looks_like_dhw_name",
]
