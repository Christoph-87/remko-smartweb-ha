# Changelog

## v0.2.2
- Add diagnostic debug logging for unsupported or not-yet-mapped REMKO SmartWeb devices
- Improve unsupported-device diagnostics with MQTT topic summaries and outgoing Tx echo detection
- Subscribe to CLIENT2HOST during diagnostics and report whether non-Tx MQTT messages were received
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
