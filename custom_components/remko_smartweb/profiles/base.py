from __future__ import annotations

from ..const import DEVICE_KIND_DIAGNOSTICS

SensorDescription = tuple[str, str, str | None]


class SmartWebDeviceProfile:
    kind = DEVICE_KIND_DIAGNOSTICS
    sensor_descriptions: tuple[SensorDescription, ...] = ()
    supports_climate = False
    diagnostics_only = False

    def parse_c0_status(self, rx_hex: str) -> dict | None:
        return None

    def parse_values_status(self, values: dict) -> dict | None:
        return None

    def sensors_for_data(self, data: dict | None) -> list[SensorDescription]:
        present = set(data.keys()) if isinstance(data, dict) else set()
        return [description for description in self.sensor_descriptions if description[0] in present]
