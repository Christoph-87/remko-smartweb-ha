from __future__ import annotations

from homeassistant.components.water_heater import WaterHeaterEntity, WaterHeaterEntityFeature
from homeassistant.const import ATTR_TEMPERATURE, UnitOfTemperature
from homeassistant.core import HomeAssistant
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.event import async_call_later
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN

OPERATION_MODES = ["off", "heat", "auto", "eco", "vacation"]
MODE_VALUE_IDS = {
    "auto": 0x03,
    "heat": 0x06,
    "eco": 0x09,
    "vacation": 0x0C,
}


def _hex_byte(value: int) -> str:
    return f"{max(0, min(0xFF, int(value))):02X}"


def _hex_word(value: int) -> str:
    return f"{max(0, min(0xFFFF, int(value))):04X}"


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities):
    data = hass.data[DOMAIN][entry.entry_id]
    coordinator = data["coordinator"]
    client = data["client"]
    device_name = data["device_name"]
    profile = data["device_profile"]
    if not profile.supports_water_heater:
        async_add_entities([])
        return
    async_add_entities([RemkoSmartWebWaterHeater(coordinator, client, device_name)])


class RemkoSmartWebWaterHeater(CoordinatorEntity, WaterHeaterEntity):
    _attr_supported_features = (
        WaterHeaterEntityFeature.TARGET_TEMPERATURE
        | WaterHeaterEntityFeature.OPERATION_MODE
    )
    _attr_operation_list = OPERATION_MODES
    _attr_min_temp = 30
    _attr_max_temp = 65
    _attr_target_temperature_step = 0.5

    def __init__(self, coordinator, client, device_name: str):
        super().__init__(coordinator)
        self._client = client
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
        values = {}
        if "setpoint" in overrides:
            values["1333"] = _hex_word(round(float(overrides["setpoint"]) * 10))
        if "power" in overrides:
            values["1194"] = _hex_byte(0x01 if overrides["power"] else 0x02)
        if "mode" in overrides and overrides["mode"] in MODE_VALUE_IDS:
            values["1192"] = _hex_byte(MODE_VALUE_IDS[overrides["mode"]])
        if not values:
            return

        if self.coordinator.data is not None:
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

        await self.hass.async_add_executor_job(self._client.set_value_ids, values)

        async def _do_refresh(_now):
            await self.coordinator.async_request_refresh()

        async_call_later(self.hass, 2.0, _do_refresh)
