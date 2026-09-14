# Write Path Audit (feature/local-portal-support)

Goal: keep `main` cloud behaviour stable while adding local portal support. Every HA control must have an explicit write path, readback path, and contract test.

## Profiles

| Profile | Device family | Cloud status path | Cloud write path in main | Feature cloud contract | Local override |
|---|---|---|---|---|---|
| Generic AC / MXW | `ClimateDeviceProfile` | SID `/ESP` -> `/RESP` C0, plus value snapshots | Climate uses C0 `/ESP`; power/fan/mode/swing/setpoint value-write fallback exists; extended switches use C0 | Partial: climate C0, cloud power value-write, cloud client ids | local climate/power/extended switches force C0 `/ESP` to SID command topic |
| Read-only AC UART | `ReadOnlyAcUartClimateDeviceProfile` | SID `/ESP` -> `/RESP` C0 | no value-write | Covered indirectly by C0 tests | same as Generic AC where local command topic exists |
| RBW / DHW | `DomesticHotWaterDeviceProfile` | values and RBW ESP direct readback | water heater/number/date value IDs; direct RBW ESP before fallback | Partial: DHW setpoint/power/mode/vacation tests | no local-specific override yet; should stay cloud-compatible unless local options are enabled |
| KWT | `KwtDeviceProfile` | values and KWT ESP direct readback | climate value IDs; direct KWT ESP before fallback | Covered: entity-level climate temperature, power/mode, fan/swing value IDs; KWT direct ESP value write | no local-specific override yet |
| LTE | `LteDeviceProfile` | values | power and target humidity value IDs | Profile encoding covered; entity write path not fully contract-tested | no local-specific override yet |
| WPM | `WpmDeviceProfile` | values | numbers/switches value IDs | Partial: entity-level number and switch value IDs covered | no local-specific override yet |
| Diagnostics | `DiagnosticsDeviceProfile` | values/logging only | no writes | n/a | n/a |

## HA Controls

| Platform/control | Profiles | Current write method | Readback/confirmation | Coverage status |
|---|---|---|---|---|
| `climate.set_hvac_mode` | Generic AC/KWT | C0 `/ESP` if C0 available; value-write fallback | `/RESP` / values | Good for Generic AC; KWT entity contract added against `main` value IDs |
| `climate.set_temperature` | Generic AC/KWT | same as climate mode | `/RESP` / values | Good for Generic AC; KWT entity contract added against `main` value IDs |
| `climate.set_fan_mode` | Generic AC/KWT | same as climate mode | `/RESP` / values | KWT entity contract added; Generic AC fan C0 still needs explicit cloud/local contract |
| `climate.set_swing_mode` | Generic AC/KWT | same as climate mode | `/RESP` / values | KWT entity contract added; Generic AC swing C0 still needs explicit cloud/local contract |
| `switch.power` | Generic AC/KWT/LTE? | Cloud: value-write if profile has spec; Local Generic AC: C0 `/ESP` | `/RESP` / values | Generic AC covered; KWT/LTE switch exposure/write path needs audit |
| `switch.turbo/sleep/eco/frost/bioclean` | Generic AC | C0 `/ESP` | `/RESP` | Entity contract covers all extended C0 switches |
| `switch.beep` | all | local option only, no device write | n/a | Covered |
| WPM switches | WPM | value-write | values | Entity contracts added for `wpm_heat_cool_mode` and `wpm_manual_defrost` value IDs |
| `number.*` | LTE/WPM/etc. | `set_value_ids(build_value_write)` | values | Entity contracts added for LTE humidity and WPM CH setpoint; remaining WPM number keys still profile-only |
| `date.vacation_end` | DHW | value-write RBW registers | values | Covered |
| `water_heater` controls | DHW | value-write/direct RBW ESP | values/ESP | Covered for key paths |
| `set_mxw_timer_slots` service | Generic AC/MXW | value-write timer IDs | values | Profile covered; service write path needs contract |

## Required next tests before considering main

1. Cloud contract: Generic AC climate fan/swing/preset uses same topic/payload style as `main`.
2. Cloud contract: all Generic AC extended switches use C0 and do not value-write. Done for `eco`, `frost_protection`, `turbo`, `sleep`, and `bioclean`.
3. Cloud contract: KWT climate service methods write expected value IDs or ESP path unchanged from `main`. Done for temperature, power/mode, fan/swing.
4. Entity contract: LTE number/power writes expected value IDs. Done for humidity number; LTE power switch still open.
5. Entity contract: WPM number/switch writes expected value IDs. Done for CH setpoint, heat/cool switch, manual defrost switch; remaining WPM number keys still open.
6. Service contract: MXW timer service writes expected timer value IDs.
7. Negative contract: local-only behaviour must require `client.uses_local_mqtt() == True`; cloud entries must not use `SMTHA` IDs or local command topics.
