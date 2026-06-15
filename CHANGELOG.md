# Changelog

## v0.4.12
- Add Frost Protection as a preset mode in the climate entity — it now appears in the climate card alongside Eco, Turbo, Sleep, and Bioclean and is mutually exclusive with the other presets

## v0.4.11
- Add `User-Agent: Home Assistant` header to the SmartWeb login request — required after a recent REMKO firmware update that rejects login attempts without a User-Agent header (affects WIFI Stick / Klimaanlage devices)
- Add REMKO value ID `1199` to the status query list — Frost Protection state was parsed and the switch entity existed since v0.3.8, but the register was never actually queried, so the entity always showed the wrong state
- Add a Last Synchronisation diagnostic sensor (`last_sync`) that shows the timestamp of the last successful data fetch from the device

## v0.4.8
- Add RBW/DHW sensors for compressor state and electric heater state
- Add diagnostic RBW/DHW runtime sensors for total compressor runtime and total electric heater runtime
- Parse the new values from both SmartWeb value snapshots and direct RBW Modbus register reads

## v0.4.7
- Register the MXW timer Lovelace card route only once per Home Assistant instance
- Fix startup failures when multiple REMKO SmartWeb devices are configured and set up in parallel

## v0.4.6
- Add the Home Assistant `http` component to the integration manifest dependencies
- Fix hassfest validation for the static Lovelace card registration used by the MXW timer card

## v0.4.5
- Fix RBW/DHW Vacation end-date writes by sending the year as the two-digit value expected by the REMKO frontend mapping
- Allow today's date for the DHW vacation end date while rejecting dates in the past
- Remove the unsupported DHW `heat` operation from the Home Assistant water-heater mode list
- Add experimental MXW timer schedule parsing for the six SmartWeb timer slots (`1195`, `1196`, `1197`, `1198`, `1210`, `1211`)
- Add a compact custom Lovelace card and service for editing MXW timer slots with day range, time, active state, and raw mode value
- Keep MXW timer mode values conservative until validated raw values are available for per-timer temperature mapping
- Add regression tests for Vacation date encoding, date validation, DHW operation modes, and MXW timer slot mapping

## v0.4.4
- Add Home Assistant entity translations for climate, domestic hot water, dehumidifier, heat-pump, sensor, switch, number, and date entities
- Add German translations for DHW operation modes, climate fan/swing/preset modes, diagnostic entities, and mapped LTE/KWT/WPM values
- Add a DHW vacation end-date date entity based on the RBW SmartWeb mapping (`1407` / registers `1129`-`1132`)
- Require a configured DHW vacation end date before enabling Vacation mode from the water-heater entity
- Parse RBW vacation end-date status from direct ESP/Modbus reads and write the date before switching the DHW mode to Vacation
- Log RBW raw register mapping changes in debug mode to make future SmartWeb mapping work easier
- Update the README with the new Vacation mode workflow

## v0.4.2
- Replace the separate profile, portal, and MQTT diagnostic entities with one compact Diagnostics sensor whose attributes keep the same metadata
- Remove legacy individual diagnostic entities from Home Assistant's entity registry when setting up the compact Diagnostics sensor
- Keep Diagnostics sensor attributes dynamic so late-discovered portal metadata appears without recreating entities
- Restore 0.5 °C target-temperature steps for domestic hot water / RBW water-heater entities
- Update RBW 302 Pro documentation to reflect user-validated target temperature writes and status updates
- Poll RBW 302 Pro status through the frontend's direct ESP/Modbus read ranges (`1001`, `1091`, `2001`) instead of relying on app-triggered `HOST2CLIENT` values
- Add direct ESP/Modbus status polling for KWT and the exposed WPM values, derived from the frontend read chains
- Add `last_successful_value_update` attributes to regular sensors so transient missing values are easier to diagnose
- Merge partial status reads with the previous state so missing or `null` fields keep their last valid value
- Parse double-encoded MQTT `Rx` payloads to improve automatic polling for devices that return wrapped JSON responses
- Replace large warning-level write payloads with structured write logs that include a shared `write_id`, compact response summaries, readback status, fallback reasons, and mismatches
- Add compact debug poll summaries and one-shot support snapshots for unparseable status responses
- Rename the climate `sleep` extra switch to `Sleep / Silent Mode` so it is easier to find in Home Assistant
- Treat RBW/DHW ESP write confirmation as pending when only cached status is available, avoiding slow fallback attempts and false service-call failures
- Add a first experimental ESP `Tx` write implementation for RKL, BL/AUX, and NWT-style AC UART devices based on the frontend `Free_set`, `Aux_set`, and `NWT_set` frame builders
- Add experimental LTE power / target humidity writes using the frontend `LTE_set` ESP `Tx` frame
- Add experimental WPM/WPK/WKM/SQW write mappings for selected value IDs (`4110`, `4113`, `5774`, `1352`, `2179`) using the frontend Modbus ESP `Tx` path and poll these IDs plus read-only unit state `5734`
- Add number entities for writable target humidity and mapped WPM setpoint values
- Add regression tests for diagnostic sensor creation, double-encoded MQTT responses, and RBW/DHW half-degree temperature steps

## v0.3.8
- Enable Home Assistant switch entities for REMKO SmartWeb climate extras
- Add switches for Turbo, Silent Mode, Bioclean, and Frost Protection when supported by the current data snapshot
- Parse and write the climate frost protection state using REMKO value ID `1199` and the matching C0 payload bit
- Keep LED Display / `nightLight` values as diagnostics only because the MXW SmartWeb frontend does not map value ID `1298` back into a generic AC write command
- Query REMKO value ID `1298` so testers can verify whether SmartWeb exposes the indoor-unit display state
- Hide unsupported extra switches for value-ID based devices when their profile cannot write the corresponding value
- Expand portal type detection for additional REMKO device families found in the bundled frontend JavaScript
- Distinguish RKL 495, RKL 355, and BL/AUX AC UART devices from MXW-style climate devices and keep them read-only until their protocol-specific write paths are implemented
- Add diagnostic sensors for the selected profile class, protocol, and write-support status
- Add tests for climate extras, device metadata extraction, and portal type based profile detection

## v0.3.5
- Read SID, SK, SMT_USER, DEV, NAME, and TYPE from the SmartWeb `smt.html` portal URL when available
- Prefer the portal `TYPE`/`NAME` metadata for early profile selection before MQTT value auto-detection
- Add diagnostic sensors for detected profile, portal ID, portal name, portal type, portal DEV, and redacted MQTT topic
- Reject incomplete SmartWeb MQTT topics so integrations no longer subscribe to `V04P27//...` when SID resolution fails
- Write domestic hot water / RBW target temperature, power, and mode through the same ESP command path used by the REMKO frontend
- Write KWT 180-300 DC setpoint, power, mode, fan, and swing commands through ESP Modbus frames with CRC validation
- Keep CLIENT2HOST value writes as a fallback while preferring device-specific ESP writes for RBW/DHW and KWT devices
- Add tests for MQTT topic validation and RBW/DHW and KWT ESP command generation

## v0.3.4
- Retry device resolution through a fresh `/rest/liste` lookup when SmartWeb status/value responses stay empty or unparseable
- Avoid reusing a stored device path during forced device-list refreshes so stale paths can recover automatically
- Use whole-degree target temperature steps for climate and water-heater entities to match REMKO device behavior
- Report unconfirmed water-heater writes as Home Assistant service errors instead of unexpected websocket exceptions
- Add tests for forced device-list refreshes and whole-degree water-heater behavior

## v0.3.3
- Improve domestic hot water / RBW mode parsing for long padded SmartWeb values so Eco/On states are detected correctly
- Make SmartWeb value writes stricter by ignoring CLIENT2HOST echoes and requiring confirmed HOST2CLIENT readback values
- Roll back optimistic water-heater state updates when a SmartWeb value write is not confirmed
- Include full SmartWeb status query IDs in value-write requests and improve SMT_USER / MQTT credential handling
- Add profile-based SmartWeb value write mappings for DHW/RBW and KWT devices
- Enable KWT climate value writes for target temperature, power, mode, fan, and swing
- Add tests for padded DHW states, write confirmation, query-list payloads, and water-heater rollback behavior

## v0.3.0
- Add read-only profiles for LTE / dehumidifier-style devices and KWT 180-300 DC
- Improve domestic hot water / RBW parsing with setpoint, top/bottom temperature, ambient temperature, mode, and power state
- Add experimental domestic hot water / RBW water-heater entity for target temperature, operation mode, and on/off writes
- Add SmartWeb value-ID write path over CLIENT2HOST with warning-level payload, response, and readback logs for testers
- Expand SmartWeb value polling to include IDs observed in the REMKO frontend for AC, KWT, DHW/RBW, and LTE devices
- Fix SMT_USER and global variable extraction from SmartWeb pages so initial CLIENT2HOST value polling works more reliably
- Add humidity units/device class for percentage sensors

## v0.2.3
- Add diagnostic debug logging for unsupported or not-yet-mapped REMKO SmartWeb devices
- Improve unsupported-device diagnostics with MQTT topic summaries and outgoing Tx echo detection
- Subscribe to CLIENT2HOST during diagnostics and report whether non-Tx MQTT messages were received
- Retry and pace SmartWeb device-list requests to reduce transient setup failures
- Report the underlying SmartWeb device-list reason when setup cannot find a configured device
- Store internal SmartWeb device paths and use them before falling back to name lookup
- Add specific SmartWeb exception types for login, device-list, device-resolution, and unsupported-payload failures
- Add exponential polling backoff based on the configured scan interval, capped at 5 minutes
- Mask likely sensitive values in diagnostic debug logs
- Add instructions and an issue template for new device support requests
- Update repository links and code owner metadata

## v0.2.0
- Increase tail length for HTML parsing
- Fix thread-safety error: replace lambda with async def in async_call_later callbacks

## v0.1.10
- Configurable indoor unit model (MXW 204/264/354/524 or Other)
- Defaults min/max temperature based on selected model

## v0.1.8
- Climate preset modes (eco, turbo, sleep, bioclean)
- HVAC action reporting for nicer UI
- Optimistic updates skip setpoint changes
- My Home Assistant quick-add link in README

## Unreleased
- Remove switch entities in favor of climate preset dropdown
## v0.1.6
- Auto-select device when only one exists
- Configurable min/max temperature bounds in options

## v0.1.4
- Persistent MQTT session for stability
- CLIENT2HOST polling fallback for status
- Auto-detect device selection in config flow
- Delay refresh after SET to reduce UI flicker

## v0.1.3
- Read-before-write with readback after SET

## v0.1.2
- Keep last data on transient update failures

## v0.1.1
- Initial HACS release tag
