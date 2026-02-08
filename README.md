# remko-smartweb-ha

Home Assistant custom integration for REMKO SmartWeb.

**Status:** Beta. Uses cloud polling (MQTT over WebSockets) to read and set values.

## Install (HACS)
1. HACS → Integrations → Menu (⋮) → **Custom repositories**.
2. Add `https://github.com/Christoph-87/remko-smartweb-ha` and select **Integration**.
3. Install **REMKO SmartWeb** from HACS.
4. Restart Home Assistant.
5. Settings → Devices & Services → **Add Integration** → `REMKO SmartWeb`.
6. Enter Email + Password. If multiple devices exist, select the device.

Quick-add link (My Home Assistant):
```text
https://my.home-assistant.io/redirect/config_flow_start/?domain=remko_smartweb
```

## Install (manual)
1. Copy `custom_components/remko_smartweb/` into your Home Assistant config directory.
2. Restart Home Assistant.
3. Go to Settings → Devices & Services → Add Integration → `REMKO SmartWeb`.
4. Enter:
   - Email
   - Password
5. If multiple devices exist, select your device name from the list.

## Entities
- Climate: HVAC mode, target temp, fan, swing, on/off
- Sensors: room temperature, outdoor temperature, setpoint, error code

## Options
- Polling interval (seconds)
- Min/Max temperature (override for UI bounds)
- Indoor unit model (used to set default min/max)

## Temperature limits
- MXW 204/264/354/524 are auto-mapped to 17–30 °C based on the device name.
- Other devices default to 16–30 °C (override in options if needed).

## Notes
- This integration logs in to `smartweb.remko.media` and communicates via MQTT (WebSockets).
- Keep the polling interval reasonable (e.g. 30–60 seconds) to avoid excessive logins.
- It is **not** affiliated with REMKO and may break if the backend changes.
- Because SmartWeb is cloud based, state updates can lag a few seconds after commands.

## Behavior notes
- Commands are applied **optimistically** to keep the UI responsive; a follow-up status read corrects the state if needed.
- Multi-split systems cannot heat and cool different indoor units at the same time. Use automations if you want to enforce a shared mode across devices.

## Troubleshooting
- No entities after install: restart Home Assistant after installing/updating.
- Entities go unavailable: check network access to `smartweb.remko.media:8083` and reduce polling.
- Power toggle feels sluggish: SmartWeb cloud responses can be delayed; try a longer polling interval.

## Releases
- HACS requires a GitHub release tag (e.g. `v0.1.4`).

## Next steps
- Implement API client (login, list devices, MQTT status/read)
- Implement switch + climate service calls
- Add polling / coordinator
