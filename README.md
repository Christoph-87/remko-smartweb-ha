# remko-smartweb-ha

Home Assistant custom integration for REMKO SmartWeb.

**Status:** Beta. Uses cloud polling (MQTT over WebSockets) to read and set values.

## Install (HACS)
1. HACS → Integrations → Custom repositories.
2. Add `https://github.com/Christoph-87/remko-smartweb-ha` as **Integration**.
3. Install **REMKO SmartWeb**.
4. Restart Home Assistant.

## Install (manual)
1. Copy `custom_components/remko_smartweb/` into your Home Assistant config directory.
2. Restart Home Assistant.
3. Go to Settings → Devices & Services → Add Integration → `REMKO SmartWeb`.
4. Enter:
   - Email
   - Password
5. Select your device name from the list (or type it if no list is available).

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
- Because SmartWeb is cloud based, state updates can lag a few seconds after commands.

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
