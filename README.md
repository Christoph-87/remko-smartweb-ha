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
- Climate: HVAC mode, target temp, fan, swing, presets, on/off for supported air conditioners
- Switches: power and supported device extras such as Turbo, Sleep / Silent Mode, Bioclean, and Frost Protection
- Numbers: writable target humidity / setpoint values where an experimental write mapping exists
- Water heater: target temperature and operation mode for domestic hot water / RBW-style devices
- Sensors: temperatures, setpoints, mode/state values, errors, and device-specific diagnostics where mapped

## Supported device families
Support depends on the SmartWeb device type and the protocol used by the REMKO frontend. Auto-detection uses the portal `TYPE`/`NAME` metadata when available, then falls back to names and received values.

| Device family / model | Detected profile | Development status | Home Assistant support |
| --- | --- | --- | --- |
| MXW 204 / 264 / 354 / 524 and MXW-style SmartWeb climate devices | Generic AC (`default_ac_uart`) | Best supported climate path | Climate entity with power, target temperature, HVAC mode, fan mode, swing mode, presets, and switches for Turbo, Sleep / Silent Mode, Bioclean, and Frost Protection |
| Generic air conditioner names such as `Klima`, `Climate`, `Air Conditioner` | Generic AC (`default_ac_uart`) | Supported when the device uses the same C0 AC UART protocol as MXW | Same as MXW, but device-specific extras still need real-device validation |
| RBW 302 Pro / domestic hot water / `Brauchwasser` / `Warmwasser` | RBW/DHW (`rbw_modbus`) | User-validated, improving | Water heater entity with 0.5 °C target temperature steps, on/off, and modes `heat`, `auto`, `eco`, `hybrid`, `speed_heating`, and `vacation`; temperature sensors where exposed |
| KWT 180 - 300 DC | KWT (`kwt_modbus`) | Partially supported | Climate entity with target temperature, power, mode, fan, and swing writes; read-only sensors for mapped diagnostic values |
| LTE / `Luftentfeuchter` dehumidifier devices | LTE (`lte_ac_uart`) | Experimental ESP write support | Sensors for humidity, temperatures, tank/filter/defrost/compressor states, runtime, energy, and errors where exposed; experimental power switch and target humidity number |
| RKL 495 DC | RKL 495 (`free_ac_uart`) | Experimental ESP write support | Climate entity with experimental ESP `Free_set` UART-frame writes for target temperature, power, supported HVAC modes, fan mode, and swing mode; presets/extras remain disabled |
| RKL 355 DC | RKL 355 (`nwt_ac_uart`) | Experimental ESP write support | Climate entity with experimental ESP `NWT_set` UART-frame writes for target temperature, power, supported HVAC modes, fan mode, and swing mode; presets/extras remain disabled |
| BL 264 - 354 DC / BL 353 DC / AUX | BL/AUX AC (`aux_ac_uart`) | Experimental ESP write support | Climate entity with experimental ESP `Aux_set` UART-frame writes for target temperature, power, HVAC mode, fan mode, and swing mode; presets/extras remain disabled |
| WPM / WPK / WKM / SQW / modular heat pump devices | WPM Heat Pump (`wpm_modbus`) | Experimental diagnostics and ESP write support | Diagnostics sensors plus experimental number/switch entities for mapped setpoints and selected coil values; limited writes for mapped WPM value IDs only |
| Unknown SmartWeb devices | Diagnostics (`unsupported_or_unknown`) | Needs mapping | Diagnostics-only setup for collecting payloads and value IDs |

### Development status notes
- MXW-style climate devices are the current reference implementation for AC controls.
- LED Display is not exposed as a writable MXW SmartWeb control in the bundled frontend JavaScript. Value ID `1298` and C0 `nightLight` are still queried/parsed for diagnostics only.
- RKL, BL/AUX, and NWT-style devices do not use the generic `CLIENT2HOST` value-write path for control in the REMKO frontend. This integration includes a first experimental implementation of the protocol-specific ESP `Tx` UART frames used by `Free_set`, `Aux_set`, and `NWT_set`; real-device validation is still needed.
- LTE devices use the frontend `LTE_set` ESP `Tx` frame for power and target humidity writes.
- WPM/WPK/WKM/SQW heat pump devices expose many writable coils/registers in the frontend JavaScript. This integration only exposes a small experimental subset with known SmartWeb value IDs (`4110`, `4113`, `5774`, `1352`, `2179`) and logs every write frame for feedback. Value ID `5734` is currently parsed as read-only unit state because the frontend map does not use it for writes.

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
- Auto-detection uses SmartWeb portal metadata, the device name, and the first value snapshot. It recognizes common MXW, climate, `Brauchwasser`, `Warmwasser`, `RBW`, `LTE`, `KWT`, RKL, BL/AUX, WPM, WPK, WKM, and SQW names. If it is wrong, change the device type in the integration options.
- The Diagnostics sensor shows the detected profile as its state and exposes profile class, protocol, portal ID/name/type/DEV, write-support status, and the redacted MQTT topic as attributes when available.
- Legacy individual diagnostic entities from earlier versions are removed from Home Assistant's entity registry when the integration is reloaded.
- Debug mapping logs can still be used for partially supported or unknown devices when debug logging is enabled.
- Diagnostics-only devices do not create control entities, but they can be set up to keep collecting mapping logs.

## Notes
- This integration logs in to `smartweb.remko.media` and communicates via MQTT (WebSockets).
- Keep the polling interval reasonable (e.g. 30–60 seconds) to avoid excessive logins.
- It is **not** affiliated with REMKO and may break if the backend changes.
- Because SmartWeb is cloud based, state updates can lag a few seconds after commands.

## Behavior notes
- Commands are applied **optimistically** to keep the UI responsive; a follow-up status read corrects the state if needed.
- Domestic hot water / RBW 302 Pro support has been user-validated for target temperature changes and status updates. REMKO cloud readback can still lag behind the physical device by a few seconds, so write confirmation may be reported as pending when only cached status is available.
- MXW-style climate extra switches are experimental. Turbo has been validated by users; LED Display is intentionally not exposed as a switch because the SmartWeb frontend does not map it back into the generic MXW write command.
- DHW/RBW writes use structured log lines with a shared `write_id`, compact response summaries, readback status, fallback reasons, and mismatches so testers can report useful feedback without a separate MQTT capture.
- RKL / BL / AUX / NWT climate writes are experimental and use protocol-specific ESP `Tx` UART frames instead of generic `CLIENT2HOST` value writes. If a command fails or behaves differently than the REMKO app, share the `REMKO SmartWeb experimental AC UART write` log lines with the shared `write_id` and the Diagnostics sensor attributes.
- LTE and WPM writes are experimental ESP `Tx` writes derived from the bundled frontend JavaScript. Share the `REMKO SmartWeb experimental LTE/WPM write` log lines when testing these paths.
- Multi-split systems cannot heat and cool different indoor units at the same time. Use automations if you want to enforce a shared mode across devices.

## Troubleshooting
- No entities after install: restart Home Assistant after installing/updating.
- Entities go unavailable: check network access to `smartweb.remko.media:8083` and reduce polling.
- Power toggle feels sluggish: SmartWeb cloud responses can be delayed; try a longer polling interval.
- DHW/RBW target temperature or mode does not change: enable debug logging and share the `Experimental REMKO SmartWeb value write` log lines, plus whether the REMKO app changed.
- Climate extra switch does not work: enable debug logging and share the command/readback lines. Include the Diagnostics sensor state and attributes for profile protocol, write support, portal type, and portal DEV.

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
8. Open the Home Assistant details view for the REMKO SmartWeb `Diagnostics` sensor and include a screenshot of its attributes, or copy the relevant attribute values from Developer Tools -> States. Especially useful attributes are `detected_profile`, `profile_class`, `profile_protocol`, `profile_write_support`, `portal_type`, `portal_dev`, and `mqtt_topic`.
9. Open an issue and include:
   - Exact REMKO model name, for example `RBW 302 Pro`
   - Device name as shown in REMKO SmartWeb
   - Which sensors you expect
   - Which parameters you want to change from Home Assistant
   - Diagnostics sensor state and attributes
   - Relevant debug log lines
   - Screenshots of the REMKO SmartWeb UI showing the available values and settings, if possible

Raw diagnostic logs do not automatically add support for a device. They provide the value IDs and payloads needed to implement device-specific sensors, switches, numbers, or selects.

## Releases
- For HACS releases, create a GitHub release whose tag matches the integration version in `custom_components/remko_smartweb/manifest.json`, for example `v0.3.0`.
