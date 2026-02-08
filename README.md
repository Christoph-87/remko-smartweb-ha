# remko-smartweb-ha

Home Assistant custom integration for REMKO SmartWeb.

**Status:** Beta. Uses cloud polling (MQTT over WebSockets) to read and set values.

## Install (manual)
1. Copy `custom_components/remko_smartweb/` into your Home Assistant config directory.
2. Restart Home Assistant.
3. Go to Settings → Devices & Services → Add Integration → `REMKO SmartWeb`.
4. Enter:
   - Email
   - Password
   - Device name (exact name from SmartWeb list)

## Entities
- Climate: HVAC mode, target temp, fan, swing, on/off
- Switches: power, eco, turbo, sleep, bioclean
- Sensors: room temperature, outdoor temperature, setpoint, error code

## Options
- Polling interval (seconds)

## Notes
- This integration logs in to `smartweb.remko.media` and communicates via MQTT (WebSockets).
- Keep the polling interval reasonable (e.g. 30–60 seconds) to avoid excessive logins.
- It is **not** affiliated with REMKO and may break if the backend changes.

## Next steps
- Implement API client (login, list devices, MQTT status/read)
- Implement switch + climate service calls
- Add polling / coordinator
