from __future__ import annotations

from ..const import DEVICE_KIND_DIAGNOSTICS

SensorDescription = tuple[str, str, str | None]
NumberDescription = tuple[str, str, float, float, float, str | None]


class SmartWebDeviceProfile:
    kind = DEVICE_KIND_DIAGNOSTICS
    sensor_descriptions: tuple[SensorDescription, ...] = ()
    number_descriptions: tuple[NumberDescription, ...] = ()
    supports_climate = False
    supports_climate_write = False
    supports_water_heater = False
    supports_value_write = False
    supports_climate_presets = True
    diagnostics_only = False
    profile_name = "Diagnostics"
    protocol_name = "diagnostics"

    def parse_c0_status(self, rx_hex: str) -> dict | None:
        return None

    def parse_values_status(self, values: dict) -> dict | None:
        return None

    def build_value_write(self, overrides: dict) -> dict[str, str] | None:
        return None

    def sensors_for_data(self, data: dict | None) -> list[SensorDescription]:
        present = set(data.keys()) if isinstance(data, dict) else set()
        return [description for description in self.sensor_descriptions if description[0] in present]
