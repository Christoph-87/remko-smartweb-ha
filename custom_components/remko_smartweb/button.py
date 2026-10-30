from __future__ import annotations

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo, EntityCategory

from .const import DOMAIN


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities):
    data = hass.data[DOMAIN][entry.entry_id]
    profile = data["device_profile"]
    if getattr(profile, "protocol_name", None) != "wpm_modbus":
        return
    async_add_entities(
        [
            RemkoSmartWebRegisterMappingButton(
                data["coordinator"], data["client"], data["device_name"]
            )
        ]
    )


class RemkoSmartWebRegisterMappingButton(ButtonEntity):
    """Start a read-only register change capture."""

    _attr_has_entity_name = True
    _attr_translation_key = "start_register_mapping_capture"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator, client, device_name: str):
        self._coordinator = coordinator
        self._client = client
        self._attr_unique_id = (
            f"{device_name.lower().replace(' ', '_')}_start_register_mapping_capture"
        )
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device_name)},
            name=device_name,
            manufacturer="REMKO",
            model="SmartWeb",
        )

    async def async_press(self) -> None:
        self._client.start_register_mapping_capture()
        self._coordinator.async_set_updated_data(dict(self._coordinator.data or {}))
