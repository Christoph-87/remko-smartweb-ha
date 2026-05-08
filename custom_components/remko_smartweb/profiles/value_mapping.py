from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ValueWriteSpec:
    key: str
    value_id: str
    digits: int = 2
    scale: float = 1.0
    enum: dict | None = None

    def encode(self, value) -> str | None:
        if self.enum is not None:
            if value not in self.enum:
                return None
            raw_value = self.enum[value]
        else:
            raw_value = round(float(value) * self.scale)
        max_value = (1 << (self.digits * 4)) - 1
        return f"{max(0, min(max_value, int(raw_value))):0{self.digits}X}"


def build_value_write(overrides: dict, specs: tuple[ValueWriteSpec, ...]) -> dict[str, str] | None:
    values = {}
    for spec in specs:
        if spec.key not in overrides:
            continue
        encoded = spec.encode(overrides[spec.key])
        if encoded is not None:
            values[spec.value_id] = encoded
    return values or None
