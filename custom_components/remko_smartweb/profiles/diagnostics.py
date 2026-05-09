from __future__ import annotations

from ..const import DEVICE_KIND_DIAGNOSTICS
from .base import SmartWebDeviceProfile


class DiagnosticsDeviceProfile(SmartWebDeviceProfile):
    kind = DEVICE_KIND_DIAGNOSTICS
    diagnostics_only = True
    profile_name = "Diagnostics"
    protocol_name = "unsupported_or_unknown"
