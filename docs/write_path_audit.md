# Write Path Audit (feature/local-portal-support)

Goal: keep `main` cloud behaviour stable while adding local portal support. Every HA control must have an explicit write path, readback path, and contract test.

Local connection variants and onboarding goals are tracked in
[`local_connection_modes.md`](local_connection_modes.md). The short version:
profiles should produce the same semantic write/read plans regardless of cloud
or local transport; only the transport adapter should handle cloud, local portal
broker, or direct local MQTT differences.

## Profiles

| Profile | Device family | Cloud status path | Cloud write path in main | Feature cloud contract | Local override |
|---|---|---|---|---|---|
| Generic AC / MXW | `ClimateDeviceProfile` | SID `/ESP` -> `/RESP` C0, plus value snapshots | Climate uses C0 `/ESP`; power/fan/mode/swing/setpoint value-write fallback exists; extended switches use C0 | Partial: climate C0, cloud power value-write, cloud client ids | local climate/power/extended switches force C0 `/ESP` to SID command topic |
| Read-only AC UART | `ReadOnlyAcUartClimateDeviceProfile` | SID `/ESP` -> `/RESP` C0 | no value-write | Covered indirectly by C0 tests | same as Generic AC where local command topic exists |
| RBW / DHW | `DomesticHotWaterDeviceProfile` | values and RBW ESP direct readback | water heater/number/date value IDs; direct RBW ESP before fallback | Partial: DHW setpoint/power/mode/vacation tests | no local-specific override yet; should stay cloud-compatible unless local options are enabled |
| KWT | `KwtDeviceProfile` | values and KWT ESP direct readback | climate value IDs; direct KWT ESP before fallback | Covered: entity-level climate temperature, power/mode, fan/swing value IDs; KWT direct ESP value write | no local-specific override yet |
| LTE | `LteDeviceProfile` | values | power and target humidity value IDs | Entity-level power switch and humidity number value IDs covered | no local-specific override yet |
| WPM | `WpmDeviceProfile` | values | numbers/switches value IDs | Entity-level number and switch value IDs covered | no local-specific override yet |
| Diagnostics | `DiagnosticsDeviceProfile` | values/logging only | no writes | n/a | n/a |

## HA Controls

| Platform/control | Profiles | Current write method | Readback/confirmation | Coverage status |
|---|---|---|---|---|
| `climate.set_hvac_mode` | Generic AC/KWT | C0 `/ESP` if C0 available; value-write fallback | `/RESP` / values | Good for Generic AC; KWT entity contract added against `main` value IDs |
| `climate.set_temperature` | Generic AC/KWT | same as climate mode | `/RESP` / values | Good for Generic AC; KWT entity contract added against `main` value IDs |
| `climate.set_fan_mode` | Generic AC/KWT | same as climate mode | `/RESP` / values | KWT entity contract added; Generic AC fan C0 still needs explicit cloud/local contract |
| `climate.set_swing_mode` | Generic AC/KWT | same as climate mode | `/RESP` / values | KWT entity contract added; Generic AC swing C0 still needs explicit cloud/local contract |
| `switch.power` | Generic AC/KWT/LTE? | Cloud: value-write if profile has spec; Local Generic AC: C0 `/ESP` | `/RESP` / values | Generic AC and LTE covered; KWT switch exposure/write path follows KWT climate value IDs |
| `switch.turbo/sleep/eco/frost/bioclean` | Generic AC | C0 `/ESP` | `/RESP` | Entity contract covers all extended C0 switches |
| `switch.beep` | all | local option only, no device write | n/a | Covered |
| WPM switches | WPM | value-write | values | Entity contracts added for `wpm_heat_cool_mode` and `wpm_manual_defrost` value IDs |
| `number.*` | LTE/WPM/etc. | `set_value_ids(build_value_write)` | values | Entity contracts added for LTE humidity and all WPM number keys |
| `date.vacation_end` | DHW | value-write RBW registers | values | Covered |
| `water_heater` controls | DHW | value-write/direct RBW ESP | values/ESP | Covered for key paths |
| `set_mxw_timer_slots` service | Generic AC/MXW | value-write timer IDs | values | Service-level contract covers timer value IDs |

## Required next tests before considering main

1. Cloud contract: Generic AC climate fan/swing/preset uses same topic/payload style as `main`.
2. Cloud contract: all Generic AC extended switches use C0 and do not value-write. Done for `eco`, `frost_protection`, `turbo`, `sleep`, and `bioclean`.
3. Cloud contract: KWT climate service methods write expected value IDs or ESP path unchanged from `main`. Done for temperature, power/mode, fan/swing.
4. Entity contract: LTE number/power writes expected value IDs. Done for humidity number and LTE power switch.
5. Entity contract: WPM number/switch writes expected value IDs. Done for all WPM number keys, heat/cool switch, and manual defrost switch.
6. Service contract: MXW timer service writes expected timer value IDs. Done.
7. Negative contract: local-only behaviour must require `client.uses_local_mqtt() == True`; cloud entries must not use `SMTHA` IDs or local command topics.
