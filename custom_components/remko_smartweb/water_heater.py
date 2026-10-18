from __future__ import annotations

from datetime import date

from homeassistant.components.water_heater import WaterHeaterEntity, WaterHeaterEntityFeature
from homeassistant.const import ATTR_TEMPERATURE, UnitOfTemperature
from homeassistant.core import HomeAssistant
from homeassistant.config_entries import ConfigEntry
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from ._pending import PendingStateMixin
from .const import DOMAIN

OPERATION_MODES = ["off", "auto", "eco", "hybrid", "speed_heating", "vacation"]


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


class RemkoSmartWebWaterHeater(PendingStateMixin, CoordinatorEntity, WaterHeaterEntity):
    _attr_has_entity_name = True
    _attr_supported_features = (
        WaterHeaterEntityFeature.TARGET_TEMPERATURE
        | WaterHeaterEntityFeature.OPERATION_MODE
    )
    _attr_operation_list = OPERATION_MODES
    _attr_min_temp = 30
    _attr_max_temp = 65
    _attr_target_temperature_step = 0.5
    _attr_translation_key = "domestic_hot_water"

    def __init__(self, coordinator, client, device_name: str, profile):
        super().__init__(coordinator)
        self._client = client
        self._profile = profile
        self._init_pending_state()
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
        return self._display_value("dhw_setpoint") or self._display_value("setpoint")

    @property
    def current_operation(self):
        if self._display_value("power") == "OFF":
            return "off"
        mode = self._display_value("dhw_mode")
        if mode in OPERATION_MODES:
            return mode
        return "auto"

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
        overrides = {"power": True, "mode": operation_mode}
        if operation_mode == "vacation":
            vacation_end_date = self.coordinator.data.get("dhw_vacation_end_date")
            if not vacation_end_date:
                raise HomeAssistantError(
                    "Set the DHW vacation end date before enabling vacation mode"
                )
            try:
                parsed_vacation_end_date = date.fromisoformat(str(vacation_end_date))
            except ValueError as err:
                raise HomeAssistantError(
                    "DHW vacation end date is invalid"
                ) from err
            if parsed_vacation_end_date < date.today():
                raise HomeAssistantError(
                    "DHW vacation end date must not be in the past"
                )
            overrides["vacation_end_date"] = vacation_end_date
        await self._async_set_dhw(overrides)

    async def async_turn_on(self):
        await self._async_set_dhw({"power": True})

    async def async_turn_off(self):
        await self._async_set_dhw({"power": False})

    async def _async_set_dhw(self, overrides: dict):
        values = self._profile.build_value_write(overrides)
        if not values:
            return

        pending_values = {}
        if "setpoint" in overrides:
            pending_values["dhw_setpoint"] = float(overrides["setpoint"])
        if "power" in overrides:
            pending_values["power"] = "ON" if overrides["power"] else "OFF"
        if "mode" in overrides:
            pending_values["dhw_mode"] = overrides["mode"]
        pending_generation = self._start_pending_state(pending_values)

        try:
            await self.hass.async_add_executor_job(self._client.set_value_ids, values)
        except Exception as err:
            self._rollback_pending_state(pending_generation)
            raise HomeAssistantError(
                "REMKO SmartWeb value write was not confirmed by the device"
            ) from err
        finally:
            self._schedule_readback_refresh()
