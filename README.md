# REMKO SmartWeb — Home Assistant Integration

[![HACS](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://github.com/hacs/integration)
![Status](https://img.shields.io/badge/status-stable-green)
![Version](https://img.shields.io/badge/version-v0.5.0-blue)

Control and monitor your REMKO heat pump, air conditioner, or hot water device
from Home Assistant — temperatures, operating modes, switches, and more. The
REMKO Cloud is the default connection; compatible communication modules can
optionally use local MQTT.

> **Not affiliated with REMKO.** This is a community integration and may break if REMKO changes their backend.

---

## Requirements

- A REMKO device with **SmartWeb** connectivity
- An active **REMKO SmartWeb account** (the same login you use in the REMKO app)

---

## Installation

**Via HACS (recommended)**

1. HACS → Integrations → ⋮ → **Custom repositories**
2. Add `https://github.com/Christoph-87/remko-smartweb-ha`, category **Integration**
3. Install **REMKO SmartWeb** and restart Home Assistant

**Then add the integration:**

[![Add to Home Assistant](https://my.home-assistant.io/badges/config_flow_start.svg)](https://my.home-assistant.io/redirect/config_flow_start/?domain=remko_smartweb)

Or go to **Settings → Devices & Services → Add Integration** and search for `REMKO SmartWeb`.

<details>
<summary>Manual installation</summary>

Copy the `custom_components/remko_smartweb/` folder into your Home Assistant config directory and restart.

</details>

### Updating from 0.4.x

Version 0.5.0 substantially changes the integration's internal communication
architecture and adds optional local MQTT. Existing REMKO Cloud setups were
kept backward-compatible as far as possible. If an existing device regresses,
please [open an issue](https://github.com/Christoph-87/remko-smartweb-ha/issues/new/choose)
with the model, diagnostics, and redacted debug log.

Until a fix is available, HACS users can temporarily return to `v0.4.25` via
**HACS → REMKO SmartWeb → ⋮ → Redownload → v0.4.25**, then restart Home
Assistant. Keep the existing config entry; local MQTT settings introduced in
0.5.x are not available on 0.4.x.

---

## Supported devices

| Device | Models | Connection path | Status |
|--------|--------|-----------------|:------:|
| ❄️ **Air conditioner** | MXW 204 / 264 / 354 / 524 | REMKO Cloud | ✅ |
| ❄️ **Air conditioner** | SKW 521 DC, RVD 525 DC | REMKO Cloud | ✅ |
| ❄️ **Air conditioner** | RKL 495 DC | REMKO Cloud | ⚠️ |
| ❄️ **Air conditioner** | RKL 355 DC | REMKO Cloud | ⚠️ |
| ❄️ **Air conditioner** | BL 264–354 DC, BL 353 DC | REMKO Cloud | ⚠️ |
| 🚿 **Domestic hot water** | RBW 302 Pro | REMKO Cloud | ✅ |
| 💧 **Dehumidifier** | LTE series | REMKO Cloud | ⚠️ |
| 🌡️ **Compact heat pump** | KWT 180–300 DC | REMKO Cloud | ⚠️ |
| 🔥 **Heat pump** | WKF/WPM systems | Local MQTT on stick/device | ⚠️ |
| 🔥 **Heat pump** | WSP systems | Local MQTT on stick/device | ⚠️ |

✅ Read and write confirmed &nbsp;·&nbsp; ⚠️ At least one direction is experimental
or device-dependent &nbsp;·&nbsp; ❓ Not yet verified

Devices listed with **REMKO Cloud** may also be usable locally when their
communication module exposes MQTT or when a cloud-style WiFi stick is redirected
to a local broker; see [Local connection modes](docs/local_connection_modes.md).

Current live testing and issue reports confirm full operation for MXW, SKW 521
DC, RVD 525 DC, and RBW 302 Pro. BL writing remains unconfirmed after its fix,
while WKF 120 / WPM 4.26 confirms local reading and only parts of the
experimental write path. The remaining ⚠️ rows have implemented but not fully
field-verified profiles.

Other catalogued models — including MXD, MXT, ATY, ML, additional RVD/RVT/RWT/
RXK/RXT models, MVT systems, WKM/WPK/SQW, HTS Duo, and MWL — are currently ❓
until a user report verifies them. The
[`model catalog`](docs/remko_model_catalog.csv) is research evidence, not a
support guarantee. For split and multi-split systems, the indoor unit is usually
the relevant model.

Unknown SmartWeb devices receive a **Diagnostics sensor** to help add support.

**Domestic hot water note:** REMKO requires a vacation end date before Vacation mode is activated. Set the `DHW vacation end date` date entity first, then select Vacation mode on the water-heater entity.

---

## Connection options

<!-- Generated from docs/diagrams/connection-options.d2 via Kroki. -->
![REMKO SmartWeb connection options: REMKO Cloud, direct local MQTT, and a redirected cloud-style stick](docs/images/connection-options.svg)

Cloud installations do **not** need a local MQTT broker, DNS rewrite, or AdGuard
rule. Local MQTT is opt-in; support is still experimental for some device
families.

There are two local cases:

- **Local MQTT on the stick/device**: the REMKO communication module exposes
  MQTT locally. This is currently seen mainly on heat-pump/SmartControl setups.
- **Redirected cloud-style stick**: a REMKO Cloud WiFi stick connects outward to
  the cloud broker, but DNS redirects only that stick to your local broker.

Local setup still starts from a cloud-discovered REMKO device where possible.
Broker, DNS, app-bridge, verification, and troubleshooting steps are documented
in [Local connection modes](docs/local_connection_modes.md).

### Write confirmation and pending state

Device-bound controls use the same confirmation behavior with the REMKO Cloud,
redirected local portal MQTT, and direct local device MQTT:

- Home Assistant shows a requested value immediately as pending, without
  replacing the last device-confirmed coordinator value.
- A matching device readback confirms the value and clears the pending state.
- A write error, or no matching readback within 30 seconds, restores the last
  confirmed state.
- Entity attributes expose `pending_confirmation` and `pending_values` for
  diagnostics.

Experimental WPM operating-mode selects are only available when their value ID
has actually appeared in device readback. An unavailable select means that the
current device/firmware did not expose the required register; it must not be
used as evidence that switching the corresponding mode is safe. In particular,
WKF/WPM DHW mode readback and DHW hysteresis control remain device-dependent and
unconfirmed unless the device reports the required values.

---

## Troubleshooting

| Problem | What to try |
|---------|-------------|
| No entities after install | Restart Home Assistant |
| Entities unavailable | Check the communication-status diagnostics and, for cloud mode, internet access |
| `SmartWeb returned an empty or unparseable device list from /rest/liste` | Update to the latest version and restart Home Assistant. REMKO may block non-browser HTTP clients; current versions keep a browser-like user agent on the full SmartWeb session, not only during login. |
| `SET readback mismatch` after a command | The device may report the old state for a few seconds after accepting a command. Current versions keep the requested state pending while preserving the last confirmed value, then confirm it from readback or restore the confirmed state after 30 seconds. |
| Local MQTT or a redirected stick does not work | Update to 0.5.0 or later and follow the checks in [Local connection modes](docs/local_connection_modes.md) |
| Commands feel slow | A few seconds of delay is normal on the REMKO Cloud path |
| A control doesn't work | Enable debug logging (see below), try the same action in the REMKO app, then open an issue |

To collect a debug log, open **Settings → Devices & Services → REMKO SmartWeb**,
choose **Enable debug logging**, reproduce the problem, then disable debug
logging to download the log. Remove credentials and personal data before
sharing it.

---

## My device isn't supported — can you add it?

Yes! The integration can connect to any SmartWeb device and collect diagnostic data that helps with mapping new sensors and controls.

1. Add the integration — it creates a **Diagnostics sensor** for unknown devices
2. Enable debug logging and let it run for a few minutes
3. If the REMKO app lets you change a value, change **one thing at a time** and note what and when
4. [Open an issue](https://github.com/Christoph-87/remko-smartweb-ha/issues/new/choose) and include:
   - REMKO model name and device name from the app
   - Diagnostics sensor attributes (`detected_profile`, `portal_type`, `portal_dev`)
   - Relevant lines from the debug log
   - Screenshots from the REMKO app showing available settings

> Remove your email, password, and session IDs before sharing any logs.

---

## Contributing

Device reports, redacted logs, documentation fixes, and read-only sensor mappings
are welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for what to include and how
to keep shared diagnostics safe.
