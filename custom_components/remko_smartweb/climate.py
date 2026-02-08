from __future__ import annotations

from homeassistant.components.climate import ClimateEntity
from homeassistant.components.climate.const import HVACMode, ClimateEntityFeature
from homeassistant.const import UnitOfTemperature
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.core import HomeAssistant
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.event import async_call_later

from .const import DOMAIN

HVAC_MAP = {
    "auto": HVACMode.AUTO,
    "cool": HVACMode.COOL,
    "heat": HVACMode.HEAT,
    "dry": HVACMode.DRY,
    "fan": HVACMode.FAN_ONLY,
}

MODE_MAP = {v: k for k, v in HVAC_MAP.items()}

FAN_MODES = ["auto", "silent", "low", "medium", "high"]
SWING_MODES = ["off", "vertical", "horizontal", "both"]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities):
    data = hass.data[DOMAIN][entry.entry_id]
    coordinator = data["coordinator"]
    client = data["client"]
    device_name = data["device_name"]

    async_add_entities([RemkoSmartWebClimate(coordinator, client, device_name)])


class RemkoSmartWebClimate(CoordinatorEntity, ClimateEntity):
    _attr_supported_features = (
        ClimateEntityFeature.TARGET_TEMPERATURE
        | ClimateEntityFeature.FAN_MODE
        | ClimateEntityFeature.SWING_MODE
        | ClimateEntityFeature.TURN_ON
        | ClimateEntityFeature.TURN_OFF
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
    _attr_min_temp = 16
    _attr_max_temp = 30

    def __init__(self, coordinator, client, device_name: str):
        super().__init__(coordinator)
        self._client = client
        self._attr_name = f"{device_name} Climate"
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

    async def _async_set(self, overrides: dict):
        # HA calls can arrive quickly; we use a single read->write cycle per call.
        await self.hass.async_add_executor_job(self._client.set_values, overrides)
        async_call_later(self.hass, 2.0, lambda *_: self.coordinator.async_request_refresh())
