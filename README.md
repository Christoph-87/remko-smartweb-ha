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
- Device type (auto-detect, air conditioner / climate, domestic hot water, diagnostics only)
- Min/Max temperature (override for UI bounds)
- Indoor unit model (used to set default min/max)

## Temperature limits
- MXW 204/264/354/524 are auto-mapped to 17–30 °C based on the device name.
- Domestic hot water devices with `Brauchwasser` or `Warmwasser` in the name default to 30–65 °C.
- Other devices default to 16–30 °C (override in options if needed).

## Device type detection
- New devices can be configured as auto-detect, air conditioner / climate, domestic hot water, or diagnostics only.
- Existing entries without a stored device type continue to use auto-detection.
- Auto-detection uses the SmartWeb device name and the first value snapshot. If it is wrong, change the device type in the integration options.
- Debug mapping logs can still be used for partially supported or unknown devices when debug logging is enabled.
- Diagnostics-only devices do not create control entities, but they can be set up to keep collecting mapping logs.

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

## Request support for a new device
This integration can connect to REMKO SmartWeb devices that are visible in your account, but each device family may expose different values and writable parameters. If your device is not supported yet, the integration can log diagnostic payloads that help map sensors and controls.

1. Add the integration and select the device from your REMKO SmartWeb account.
2. Enable debug logging in Home Assistant:

```yaml
logger:
  default: warning
  logs:
    custom_components.remko_smartweb: debug
```

3. Restart Home Assistant or reload the integration.
4. Let the integration poll the device for a few minutes.
5. If the REMKO SmartWeb app or web UI allows changing values, change one parameter at a time and wait for the integration to poll again after each change. Note what you changed and the approximate time.
6. Download the Home Assistant log and search for `remko_smartweb`.
7. Remove personal or sensitive data before sharing logs. Do not post your email address, password, cookies, session IDs, or access keys.
8. Open an issue and include:
   - Exact REMKO model name, for example `RBW 302 Pro`
   - Device name as shown in REMKO SmartWeb
   - Which sensors you expect
   - Which parameters you want to change from Home Assistant
   - Relevant debug log lines
   - Screenshots of the REMKO SmartWeb UI showing the available values and settings, if possible

Raw diagnostic logs do not automatically add support for a device. They provide the value IDs and payloads needed to implement device-specific sensors, switches, numbers, or selects.

## Releases
- For HACS releases, create a GitHub release whose tag matches the integration version in `custom_components/remko_smartweb/manifest.json`, for example `v0.2.5`.
