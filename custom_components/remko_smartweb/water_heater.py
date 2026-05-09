from __future__ import annotations

from homeassistant.components.water_heater import WaterHeaterEntity, WaterHeaterEntityFeature
from homeassistant.const import ATTR_TEMPERATURE, UnitOfTemperature
from homeassistant.core import HomeAssistant
from homeassistant.config_entries import ConfigEntry
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.event import async_call_later
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN

OPERATION_MODES = ["off", "heat", "auto", "eco", "hybrid", "speed_heating", "vacation"]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities):
    data = hass.data[DOMAIN][entry.entry_id]
    coordinator = data["coordinator"]
    client = data["client"]
    device_name = data["device_name"]
    profile = data["device_profile"]
    if not profile.supports_water_heater:
        async_add_entities([])
        return
    async_add_entities([RemkoSmartWebWaterHeater(coordinator, client, device_name, profile)])


class RemkoSmartWebWaterHeater(CoordinatorEntity, WaterHeaterEntity):
    _attr_supported_features = (
        WaterHeaterEntityFeature.TARGET_TEMPERATURE
        | WaterHeaterEntityFeature.OPERATION_MODE
    )
    _attr_operation_list = OPERATION_MODES
    _attr_min_temp = 30
    _attr_max_temp = 65
    _attr_target_temperature_step = 1.0

    def __init__(self, coordinator, client, device_name: str, profile):
        super().__init__(coordinator)
        self._client = client
        self._profile = profile
        self._attr_name = f"{device_name} Water Heater"
        self._attr_unique_id = f"{device_name.lower().replace(' ', '_')}_water_heater"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device_name)},
            name=device_name,
            manufacturer="REMKO",
            model="SmartWeb",
        )

    @property
    def temperature_unit(self) -> UnitOfTemperature:
        unit = self.coordinator.data.get("unit", "C")
        return UnitOfTemperature.FAHRENHEIT if unit == "F" else UnitOfTemperature.CELSIUS

    @property
    def current_temperature(self):
        return self.coordinator.data.get("dhw_top_temperature") or self.coordinator.data.get("room")

    @property
    def target_temperature(self):
        return self.coordinator.data.get("dhw_setpoint") or self.coordinator.data.get("setpoint")

    @property
    def current_operation(self):
        if self.coordinator.data.get("power") == "OFF":
            return "off"
        mode = self.coordinator.data.get("dhw_mode")
        if mode in OPERATION_MODES:
            return mode
        return "heat"

    async def async_set_temperature(self, **kwargs):
        temperature = kwargs.get(ATTR_TEMPERATURE)
        if temperature is None:
            return
        await self._async_set_dhw({"setpoint": float(temperature)})

    async def async_set_operation_mode(self, operation_mode: str):
        if operation_mode not in OPERATION_MODES:
            return
        if operation_mode == "off":
            await self.async_turn_off()
            return
        await self._async_set_dhw({"power": True, "mode": operation_mode})

    async def async_turn_on(self):
        await self._async_set_dhw({"power": True})

    async def async_turn_off(self):
        await self._async_set_dhw({"power": False})

    async def _async_set_dhw(self, overrides: dict):
        values = self._profile.build_value_write(overrides)
        if not values:
            return

        old_data = dict(self.coordinator.data) if self.coordinator.data is not None else None
        if old_data is not None:
            data = dict(self.coordinator.data)
            if "setpoint" in overrides:
                data["dhw_setpoint"] = float(overrides["setpoint"])
                data["setpoint"] = float(overrides["setpoint"])
            if "power" in overrides:
                data["power"] = "ON" if overrides["power"] else "OFF"
                data["dhw_power_state"] = "on" if overrides["power"] else "off"
            if "mode" in overrides:
                data["dhw_mode"] = overrides["mode"]
            self.coordinator.data = data
            self.async_write_ha_state()

        async def _do_refresh(_now):
            await self.coordinator.async_request_refresh()

        try:
            await self.hass.async_add_executor_job(self._client.set_value_ids, values)
        except Exception as err:
            if old_data is not None:
                self.coordinator.data = old_data
                self.async_write_ha_state()
            raise HomeAssistantError(
                "REMKO SmartWeb value write was not confirmed by the device"
            ) from err
        finally:
            async_call_later(self.hass, 2.0, _do_refresh)
