# REMKO SmartWeb — Home Assistant Integration

[![HACS](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://github.com/hacs/integration)
![Status](https://img.shields.io/badge/status-beta-yellow)
![Version](https://img.shields.io/badge/version-0.4.3-blue)
![IoT class](https://img.shields.io/badge/iot__class-cloud__polling-informational)

Home Assistant integration for REMKO SmartWeb devices. Reads and writes values via cloud polling (MQTT over WebSockets).

---

## Contents

- [Install — HACS](#install--hacs)
- [Install — Manual](#install--manual)
- [Supported devices](#supported-devices)
- [Entities](#entities)
- [Options](#options)
- [Temperature limits](#temperature-limits)
- [Device type detection](#device-type-detection)
- [Troubleshooting](#troubleshooting)
- [Request support for a new device](#request-support-for-a-new-device)
- [Notes](#notes)

---

## Install — HACS

1. HACS → Integrations → Menu (⋮) → **Custom repositories**
2. Add `https://github.com/Christoph-87/remko-smartweb-ha`, select **Integration**
3. Install **REMKO SmartWeb** from HACS
4. Restart Home Assistant
5. Settings → Devices & Services → **Add Integration** → search `REMKO SmartWeb`
6. Enter your Email and Password; select your device if multiple exist

Or use the quick-add button:

[![Add integration](https://my.home-assistant.io/badges/config_flow_start.svg)](https://my.home-assistant.io/redirect/config_flow_start/?domain=remko_smartweb)

---

## Install — Manual

1. Copy `custom_components/remko_smartweb/` into your Home Assistant config directory
2. Restart Home Assistant
3. Settings → Devices & Services → **Add Integration** → `REMKO SmartWeb`
4. Enter Email, Password; select your device if multiple exist

---

## Supported devices

Auto-detection uses portal `TYPE`/`NAME` metadata, then falls back to device name and received values.

| Device family / model | Profile | Status | HA entities |
|---|---|---|---|
| MXW 204 / 264 / 354 / 524 and MXW-style SmartWeb climate devices | `default_ac_uart` | Best supported | Climate: power, target temp, HVAC/fan/swing mode, presets. Switches: Turbo, Sleep/Silent, Bioclean, Frost Protection |
| Generic names (`Klima`, `Climate`, `Air Conditioner`) | `default_ac_uart` | Supported | Same as MXW; device-specific extras need validation |
| RBW 302 Pro / `Brauchwasser` / `Warmwasser` | `rbw_modbus` | User-validated | Water heater: 0.5 °C steps, on/off, modes `heat` / `auto` / `eco` / `hybrid` / `speed_heating` / `vacation`; temperature sensors |
| KWT 180–300 DC | `kwt_modbus` | Partial | Climate: target temp, power, mode, fan, swing; direct ESP/Modbus polling |
| LTE / `Luftentfeuchter` dehumidifiers | `lte_ac_uart` | Experimental | Sensors: humidity, temps, tank/filter/defrost/compressor, runtime, energy, errors. Experimental: power switch, target humidity number |
| RKL 495 DC | `free_ac_uart` | Experimental | Climate: experimental `Free_set` UART writes for temp, power, HVAC/fan/swing; presets disabled |
| RKL 355 DC | `nwt_ac_uart` | Experimental | Climate: experimental `NWT_set` UART writes for temp, power, HVAC/fan/swing; presets disabled |
| BL 264–354 DC / BL 353 DC / AUX | `aux_ac_uart` | Experimental | Climate: experimental `Aux_set` UART writes for temp, power, HVAC/fan/swing; presets disabled |
| WPM / WPK / WKM / SQW / modular heat pumps | `wpm_modbus` | Experimental | Diagnostics sensors; experimental number/switch entities for mapped setpoints and coil values; direct ESP/Modbus polling |
| Unknown SmartWeb devices | `unsupported_or_unknown` | Needs mapping | Diagnostics only — collects payloads and value IDs for future support |

<details>
<summary>Development status notes</summary>

- MXW-style climate devices are the reference implementation for AC controls.
- LED Display is not exposed as a writable MXW SmartWeb control in the bundled frontend JavaScript. Value ID `1298` and C0 `nightLight` are parsed for diagnostics only.
- RKL, BL/AUX, and NWT-style devices do not use the generic `CLIENT2HOST` value-write path. This integration implements protocol-specific ESP `Tx` UART frames (`Free_set`, `Aux_set`, `NWT_set`); real-device validation is still needed.
- LTE devices use the frontend `LTE_set` ESP `Tx` frame for power and target humidity writes.
- WPM/WPK/WKM/SQW devices expose many writable coils/registers in the frontend JavaScript. This integration exposes a small experimental subset with known SmartWeb value IDs (`4110`, `4113`, `5774`, `1352`, `2179`) and logs every write frame for feedback. Value ID `5734` is currently parsed as read-only unit state.
- KWT and WPM status polling uses direct ESP/Modbus read commands derived from the frontend JavaScript. LTE, RKL, BL/AUX, and NWT use the generic SmartWeb value/status read path unless device-specific logs show otherwise.

</details>

---

## Entities

| Entity type | Availability |
|---|---|
| **Climate** | HVAC mode, target temp, fan, swing, presets, on/off — supported air conditioners |
| **Water heater** | Target temperature and operation mode — RBW/DHW devices |
| **Switches** | Power and device extras: Turbo, Sleep/Silent, Bioclean, Frost Protection |
| **Numbers** | Writable target humidity / setpoint values where an experimental write mapping exists |
| **Sensors** | Temperatures, setpoints, mode/state values, errors, and device-specific diagnostics |

---

## Options

| Option | Description |
|---|---|
| Polling interval | Seconds between status updates (recommended: 30–60 s) |
| Device type | Auto-detect, air conditioner / climate, domestic hot water, diagnostics only |
| Min/Max temperature | Override for UI bounds |
| Indoor unit model | Used to set default min/max temperature |

---

## Temperature limits

| Device | Default range |
|---|---|
| MXW 204 / 264 / 354 / 524 (auto-detected by name) | 17–30 °C |
| DHW devices with `Brauchwasser` or `Warmwasser` in name | 30–65 °C |
| All other devices | 16–30 °C |

Override in integration options if the defaults don't fit your device.

---

## Device type detection

- Configurable per integration: auto-detect, air conditioner / climate, domestic hot water, or diagnostics only.
- Auto-detection uses SmartWeb portal metadata → device name → first value snapshot. Recognizes common MXW, `Klima`, `Brauchwasser`, `Warmwasser`, `RBW`, `LTE`, `KWT`, RKL, BL/AUX, WPM, WPK, WKM, and SQW names.
- The **Diagnostics sensor** shows the detected profile as its state and exposes profile class, protocol, portal ID/name/type/DEV, write-support status, and redacted MQTT topic as attributes.
- If auto-detection picks the wrong type, change it in the integration options.
- Legacy individual diagnostic entities from earlier versions are automatically removed from the entity registry on reload.

---

## Troubleshooting

| Symptom | Action |
|---|---|
| No entities after install | Restart Home Assistant after installing or updating |
| Entities go unavailable | Check network access to `smartweb.remko.media:8083`; reduce polling interval |
| Power toggle feels sluggish | SmartWeb cloud responses can be delayed — try a longer polling interval |
| DHW target temperature or mode does not change | Enable debug logging, share the `Experimental REMKO SmartWeb value write` log lines and whether the REMKO app changed |
| Climate extra switch does not work | Enable debug logging, share the command/readback lines and the Diagnostics sensor state/attributes |

Enable debug logging:

```yaml
logger:
  default: warning
  logs:
    custom_components.remko_smartweb: debug
```

<details>
<summary>Behavior notes</summary>

- Commands are applied **optimistically** to keep the UI responsive; a follow-up status read corrects the state if needed.
- Partial status reads are merged with the previous state: missing or `null` fields keep their last valid value.
- Regular sensors expose a `last_successful_value_update` attribute that records when this specific field last received a valid new value.
- DHW/RBW 302 Pro writes use structured log lines with a shared `write_id`, compact response summaries, readback status, fallback reasons, and mismatches so testers can report useful feedback without a separate MQTT capture.
- RBW status reads use the same direct ESP/Modbus read ranges as the REMKO frontend (`1001`, `1091`, `2001`) — automatic updates do not depend on the REMKO app being open. Readback may be reported as pending when only cached status is available.
- MXW Turbo has been user-validated; LED Display is intentionally not exposed because the SmartWeb frontend does not map it back into the generic MXW write command.
- RKL / BL / AUX / NWT climate writes use protocol-specific ESP `Tx` UART frames instead of generic `CLIENT2HOST` value writes. If a command fails or behaves differently than the REMKO app, share the `REMKO SmartWeb experimental AC UART write` log lines (with `write_id`) and the Diagnostics sensor attributes.
- LTE and WPM writes are experimental ESP `Tx` writes derived from the bundled frontend JavaScript. Share the `REMKO SmartWeb experimental LTE/WPM write` log lines when testing these paths.
- Multi-split systems cannot heat and cool different indoor units simultaneously — use automations to enforce a shared mode across devices.

</details>

---

## Request support for a new device

The integration can connect to any REMKO SmartWeb device in your account, but each device family may expose different values and writable parameters. If your device is not yet supported, follow these steps to collect the data needed for mapping.

1. Add the integration and select your device from the REMKO SmartWeb account.
2. Enable debug logging (see above) and restart Home Assistant or reload the integration.
3. Let it poll for a few minutes.
4. If the REMKO app or web UI allows changing values, change **one parameter at a time**, wait for the next poll, and note what you changed and when.
5. Download the Home Assistant log and search for `remko_smartweb`.
6. Remove personal or sensitive data before sharing — **do not post** your email, password, cookies, session IDs, or access keys.
7. Open the **Diagnostics sensor** details view and include a screenshot of its attributes, or copy the values from Developer Tools → States. Most useful attributes: `detected_profile`, `profile_class`, `profile_protocol`, `profile_write_support`, `portal_type`, `portal_dev`, `mqtt_topic`.
8. [Open an issue](https://github.com/Christoph-87/remko-smartweb-ha/issues) and include:
   - Exact REMKO model name (e.g. `RBW 302 Pro`)
   - Device name as shown in REMKO SmartWeb
   - Which sensors you expect
   - Which parameters you want to control from Home Assistant
   - Diagnostics sensor state and attributes
   - Relevant debug log lines
   - Screenshots of the REMKO SmartWeb UI showing available values and settings

> Raw diagnostic logs do not automatically add support for a device. They provide the value IDs and payloads needed to implement device-specific sensors, switches, numbers, or selects.

---

## Notes

- Communicates with `smartweb.remko.media` via MQTT over WebSockets.
- Not affiliated with REMKO — may break if the backend changes.
- Keep the polling interval reasonable (30–60 s) to avoid excessive logins.
- State updates can lag a few seconds after commands because SmartWeb is cloud-based.

---

## Releases

For HACS releases, create a GitHub release whose tag matches the version in `manifest.json` (e.g. `v0.4.3`).
