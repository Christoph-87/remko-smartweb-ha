from __future__ import annotations

from homeassistant.components.climate import ClimateEntity
from homeassistant.components.climate.const import HVACMode, HVACAction, ClimateEntityFeature
from homeassistant.const import UnitOfTemperature
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.core import HomeAssistant
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.event import async_call_later

from .const import DOMAIN, CONF_MIN_TEMP, CONF_MAX_TEMP, CONF_MODEL, DEFAULT_MIN_TEMP, DEFAULT_MAX_TEMP

HVAC_MAP = {
    "auto": HVACMode.AUTO,
    "cool": HVACMode.COOL,
    "heat": HVACMode.HEAT,
    "dry": HVACMode.DRY,
    "fan": HVACMode.FAN_ONLY,
}

MODE_MAP = {v: k for k, v in HVAC_MAP.items()}
HVAC_BY_PROFILE_MODE = {"off": HVACMode.OFF, **HVAC_MAP}

FAN_MODES = ["auto", "silent", "low", "medium", "high"]
SWING_MODES = ["off", "vertical", "horizontal", "both"]
PRESET_MODES = ["none", "eco", "turbo", "sleep", "bioclean"]


def _infer_min_max_temp(device_name: str) -> tuple[int, int]:
    # Legacy fallback by name; prefer explicit model option in config flow.
    name = (device_name or "").casefold()
    if "brauchwasser" in name or "warmwasser" in name:
        return 30, 65
    name = name.upper()
    for model in ("MXW 204", "MXW 264", "MXW 354", "MXW 524"):
        if model in name:
            return 17, 30
    return DEFAULT_MIN_TEMP, DEFAULT_MAX_TEMP


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities):
    data = hass.data[DOMAIN][entry.entry_id]
    coordinator = data["coordinator"]
    client = data["client"]
    device_name = data["device_name"]
    profile = data["device_profile"]
    if not profile.supports_climate:
        async_add_entities([])
        return
    model = entry.options.get(CONF_MODEL, "other")
    model_defaults = {
        "mxw_204": (17, 30),
        "mxw_264": (17, 30),
        "mxw_354": (17, 30),
        "mxw_524": (17, 30),
        "other": _infer_min_max_temp(device_name),
    }
    inferred_min, inferred_max = model_defaults.get(model, _infer_min_max_temp(device_name))
    min_temp = entry.options.get(CONF_MIN_TEMP, inferred_min)
    max_temp = entry.options.get(CONF_MAX_TEMP, inferred_max)

    async_add_entities([RemkoSmartWebClimate(coordinator, client, device_name, min_temp, max_temp, profile)])


class RemkoSmartWebClimate(CoordinatorEntity, ClimateEntity):
    _attr_has_entity_name = True
    _attr_name = None
    _attr_translation_key = "climate"
    _attr_supported_features = (
        ClimateEntityFeature.TARGET_TEMPERATURE
        | ClimateEntityFeature.FAN_MODE
        | ClimateEntityFeature.SWING_MODE
        | ClimateEntityFeature.TURN_ON
        | ClimateEntityFeature.TURN_OFF
        | ClimateEntityFeature.PRESET_MODE
    )

    _attr_hvac_modes = [
        HVACMode.OFF,
        HVACMode.AUTO,
        HVACMode.COOL,
        HVACMode.HEAT,
        HVACMode.DRY,
        HVACMode.FAN_ONLY,
    ]

    _attr_fan_modes = FAN_MODES
    _attr_swing_modes = SWING_MODES
    _attr_preset_modes = PRESET_MODES
    _attr_target_temperature_step = 1.0

    def __init__(self, coordinator, client, device_name: str, min_temp: int, max_temp: int, profile):
        super().__init__(coordinator)
        self._client = client
        self._profile = profile
        self._attr_min_temp = min_temp
        self._attr_max_temp = max_temp
        if not getattr(profile, "supports_climate_presets", True):
            self._attr_supported_features = self._attr_supported_features & ~ClimateEntityFeature.PRESET_MODE
            self._attr_preset_modes = []
        supported_modes = getattr(profile, "supported_climate_modes", None)
        if supported_modes:
            self._attr_hvac_modes = [
                HVAC_BY_PROFILE_MODE[mode]
                for mode in supported_modes
                if mode in HVAC_BY_PROFILE_MODE
            ]
        if not getattr(profile, "supports_climate_write", False):
            self._attr_supported_features = 0
            self._attr_preset_modes = []
            self._attr_fan_modes = []
            self._attr_swing_modes = []
        self._attr_unique_id = f"{device_name.lower().replace(' ', '_')}_climate"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device_name)},
            name=device_name,
            manufacturer="REMKO",
            model="SmartWeb",
        )

    @property
    def hvac_mode(self) -> HVACMode:
        if self.coordinator.data.get("power") != "ON":
            return HVACMode.OFF
        mode = self.coordinator.data.get("mode")
        return HVAC_MAP.get(mode, HVACMode.AUTO)

    @property
    def hvac_action(self) -> HVACAction | None:
        if self.coordinator.data.get("power") != "ON":
            return HVACAction.OFF
        mode = self.coordinator.data.get("mode")
        if mode == "cool":
            return HVACAction.COOLING
        if mode == "heat":
            return HVACAction.HEATING
        if mode == "dry":
            return HVACAction.DRYING
        if mode == "fan":
            return HVACAction.FAN
        return HVACAction.IDLE

    @property
    def temperature_unit(self) -> UnitOfTemperature:
        unit = self.coordinator.data.get("unit", "C")
        return UnitOfTemperature.FAHRENHEIT if unit == "F" else UnitOfTemperature.CELSIUS

    @property
    def target_temperature(self):
        return self.coordinator.data.get("setpoint")

    @property
    def current_temperature(self):
        return self.coordinator.data.get("room")

    @property
    def fan_mode(self):
        return self.coordinator.data.get("fan")

    @property
    def swing_mode(self):
        return self.coordinator.data.get("swing")

    @property
    def preset_mode(self):
        if not getattr(self._profile, "supports_climate_presets", True):
            return None
        for key in ("eco", "turbo", "sleep", "bioclean"):
            if self.coordinator.data.get(key):
                return key
        return "none"

    async def async_set_hvac_mode(self, hvac_mode: HVACMode):
        if hvac_mode == HVACMode.OFF:
            await self._async_set({"power": False})
            return
        mode = MODE_MAP.get(hvac_mode, "auto")
        await self._async_set({"power": True, "mode": mode})

    async def async_turn_on(self):
        await self._async_set({"power": True})

    async def async_turn_off(self):
        await self._async_set({"power": False})

    async def async_set_temperature(self, **kwargs):
        if (temp := kwargs.get("temperature")) is not None:
            await self._async_set({"setpoint": float(temp)})

    async def async_set_fan_mode(self, fan_mode: str):
        if fan_mode in FAN_MODES:
            await self._async_set({"fan": fan_mode})

    async def async_set_swing_mode(self, swing_mode: str):
        if swing_mode in SWING_MODES:
            await self._async_set({"swing": swing_mode})

    async def async_set_preset_mode(self, preset_mode: str):
        if preset_mode not in PRESET_MODES:
            return
        if preset_mode == "none":
            overrides = {"eco": False, "turbo": False, "sleep": False, "bioclean": False}
        else:
            overrides = {
                "eco": preset_mode == "eco",
                "turbo": preset_mode == "turbo",
                "sleep": preset_mode == "sleep",
                "bioclean": preset_mode == "bioclean",
            }
        await self._async_set(overrides)

    async def _async_set(self, overrides: dict):
        if not getattr(self._profile, "supports_climate_write", False):
            return
        value_write = self._profile.build_value_write(overrides)
        if getattr(self._profile, "supports_value_write", False) and not value_write:
            return
        # HA calls can arrive quickly; we use a single read->write cycle per call.
        # Optimistic UI update to avoid flicker (skip for setpoint changes).
        if self.coordinator.data is not None and "setpoint" not in overrides:
            data = dict(self.coordinator.data)
            for k, v in overrides.items():
                if k == "power":
                    data["power"] = "ON" if v else "OFF"
                else:
                    data[k] = v
            self.coordinator.data = data
            self.async_write_ha_state()
        if value_write:
            await self.hass.async_add_executor_job(self._client.set_value_ids, value_write)
        else:
            await self.hass.async_add_executor_job(self._client.set_values, overrides)

        async def _do_refresh(_now):
            await self.coordinator.async_request_refresh()

        async_call_later(self.hass, 2.0, _do_refresh)
