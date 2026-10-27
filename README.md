# REMKO SmartWeb — Home Assistant Integration

[![HACS](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://github.com/hacs/integration)
![Status](https://img.shields.io/badge/status-beta-yellow)
![Version](https://img.shields.io/badge/version-v0.5.0--beta.19-blue)

Control and monitor your REMKO heat pump, air conditioner, or hot water device from Home Assistant — temperatures, operating modes, switches, and more. Works via the REMKO SmartWeb cloud (internet connection required).

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

---

## Supported devices

| Device | Models | Connection path | Read | Write |
|--------|--------|-----------------|:----:|:-----:|
| ❄️ **Air conditioner** | MXW 204 / 264 / 354 / 524 | REMKO Cloud, redirect observed ⚠️ | ✅ | ✅ |
| ❄️ **Air conditioner** | SKW 521 DC, RVD 525 DC | REMKO Cloud | ✅ | ✅ |
| ❄️ **Air conditioner** | RKL 495 DC | REMKO Cloud | ✅ | ⚠️ |
| ❄️ **Air conditioner** | RKL 355 DC | REMKO Cloud | ✅ | ⚠️ |
| ❄️ **Air conditioner** | BL 264–354 DC, BL 353 DC | REMKO Cloud | ✅ | ⚠️ |
| 🚿 **Domestic hot water** | RBW 302 Pro | REMKO Cloud | ✅ | ✅ |
| 💧 **Dehumidifier** | LTE series | REMKO Cloud | ✅ | ⚠️ |
| 🌡️ **Compact heat pump** | KWT 180–300 DC | REMKO Cloud | ✅ | ⚠️ |
| 🔥 **Heat pump** | WKF/WPM systems | Local MQTT on stick/device ⚠️ | ⚠️ | ⚠️ |
| 🔥 **Heat pump** | WSP systems | Local MQTT on stick/device ⚠️ | ⚠️ | ⚠️ |
| ❄️ **Air conditioner candidates** | MXD 204–524, MXT 355/525, ATY / ATY Deko, ML DC, RVD/RVT/RWT/RXK/RXT DC | Unknown ❓ | ❓ | ❓ |
| ❄️ **Multi-split outdoor unit** | MVT DC | Use matching indoor unit | ❓ | ❓ |
| 🔥 **Heat pump candidates** | WKM / WKM Pro, WPK, SQW 405 Pro, HTS Duo, MWL | Unknown ❓ | ❓ | ❓ |
| ❓ **Other** | Any other SmartWeb device | Diagnostics / unknown ❓ | ⚠️ | — |

✅ Supported &nbsp;·&nbsp; ⚠️ Experimental / device-dependent &nbsp;·&nbsp; ❓ Unknown &nbsp;·&nbsp; — Not available

**Read** = sensor values are shown in Home Assistant.
**Write** = you can change settings (temperature, mode, on/off) from Home Assistant.
Cloud read/write status follows the `main` branch; this branch does not mark a
REMKO Cloud family as fully supported unless both read and write are fully
supported there.

The 0.4.x device families are confirmed through the REMKO SmartWeb cloud path.
The communication module determines the usable path: Cloud-style WiFi sticks use
the REMKO Cloud path, optionally redirected to a local broker; devices with
direct local MQTT use the local MQTT path. The model catalog in
[`docs/remko_model_catalog.csv`](docs/remko_model_catalog.csv) is research
evidence, not a support guarantee. For split and multi-split systems, the indoor
unit series is usually more relevant than the outdoor unit. Architecture notes
are in
[`docs/device_profile_architecture.md`](docs/device_profile_architecture.md).

For unknown devices, the integration creates a **Diagnostics sensor** that logs data payloads — useful for adding support later.

**Domestic hot water note:** REMKO requires a vacation end date before Vacation mode is activated. Set the `DHW vacation end date` date entity first, then select Vacation mode on the water-heater entity.

---

## Experimental local MQTT mode

Cloud-only installations do **not** need a local MQTT broker, DNS rewrite, or
AdGuard rule. Local MQTT is optional and experimental.

There are two local cases:

- **Local MQTT on the stick/device**: the REMKO communication module exposes
  MQTT locally. This is currently seen mainly on heat-pump/SmartControl setups.
- **Redirected cloud-style stick**: a REMKO Cloud WiFi stick connects outward to
  the cloud broker, but DNS redirects only that stick to your local broker.

Local setup still starts from a cloud-discovered REMKO device where possible.
The detailed setup for redirected WiFi sticks, including optional REMKO app
bridging, DNS/broker requirements, diagnostics, and troubleshooting, is
documented in [`docs/local_connection_modes.md`](docs/local_connection_modes.md).

For redirected cloud-style sticks, configure the specific stick IP for each
entry. The integration derives the stick topic from that IP's ARP/MAC mapping
and corrects a stale stored topic when the mapping is unambiguous. This avoids
selecting another device's topic when several sticks share one broker.

The local portal health check treats native `HOST2PORTAL` heartbeats as active
traffic and allows the first heartbeat cycle after startup before warning. The
optional REMKO-app bridge also waits for all three MQTT connection legs instead
of repeatedly rebuilding a bridge that is still connecting.

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
| Entities unavailable | Check internet access · reduce the polling interval in options |
| `SmartWeb returned an empty or unparseable device list from /rest/liste` | Update to the latest version and restart Home Assistant. REMKO may block non-browser HTTP clients; current versions keep a browser-like user agent on the full SmartWeb session, not only during login. |
| `SET readback mismatch` after a command | The device may report the old state for a few seconds after accepting a command. Current versions keep the requested state pending while preserving the last confirmed value, then confirm it from readback or restore the confirmed state after 30 seconds. |
| Local MQTT device accepts commands slowly or times out | Update to a local-portal build that sends ESP SET frames to the SID-based command topic and treats local readback as pending. Also verify Mosquitto listener authentication is separated so the stick's `8883` subscriptions are not denied by the authenticated HA listener. |
| Redirected stick uses the wrong topic on a shared broker | Set the correct **Stick IP candidate** for that integration entry. Current versions derive the expected `SMT...` topic from the stick's ARP/MAC mapping and repair a stale stored topic when the mapping is unambiguous. |
| `no portal poll trigger received yet` appears after startup | Wait for the initial three-minute heartbeat grace period. If the warning appears later, verify the per-stick DNS redirect and confirm that the broker receives that stick's `HOST2PORTAL` topic. |
| Commands feel slow | SmartWeb is cloud-based — a few seconds of delay is normal |
| A control doesn't work | Enable debug logging (see below), try the same action in the REMKO app, then open an issue |

**Enable debug logging** in `configuration.yaml`:

```yaml
logger:
  default: warning
  logs:
    custom_components.remko_smartweb: debug
```

Restart or reload the integration. Logs appear under **Settings → System → Logs**.

---

## My device isn't supported — can you add it?

Yes! The integration can connect to any SmartWeb device and collect diagnostic data that helps with mapping new sensors and controls.

1. Add the integration — it creates a **Diagnostics sensor** for unknown devices
2. Enable debug logging and let it run for a few minutes
3. If the REMKO app lets you change a value, change **one thing at a time** and note what and when
4. [Open an issue](https://github.com/Christoph-87/remko-smartweb-ha/issues) and include:
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
