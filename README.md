# REMKO SmartWeb — Home Assistant Integration

[![HACS](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://github.com/hacs/integration)
![Status](https://img.shields.io/badge/status-beta-yellow)
![Version](https://img.shields.io/badge/version-0.4.19-blue)

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

| Device | Models | Read | Write |
|--------|--------|:----:|:-----:|
| ❄️ **Air conditioner** | MXW 204 / 264 / 354 / 524 | ✅ | ✅ |
| ❄️ **Air conditioner** | SKW 521 DC | ✅ | ✅ |
| ❄️ **Air conditioner** | RVD 525 DC | ✅ | ✅ |
| ❄️ **Air conditioner** | RKL 495 DC | ✅ | ⚠️ |
| ❄️ **Air conditioner** | RKL 355 DC | ✅ | ⚠️ |
| ❄️ **Air conditioner** | BL 264–354 DC, BL 353 DC | ✅ | ⚠️ |
| 🚿 **Domestic hot water** | RBW 302 Pro | ✅ | ✅ |
| 💧 **Dehumidifier** | LTE series | ✅ | ⚠️ |
| 🌡️ **Compact heat pump** | KWT 180–300 DC | ✅ | ⚠️ |
| 🔥 **Modular heat pump** | WPM 400 A Pro, WPK, WKM / WKM Pro, SQW 405 Pro | ⚠️ | ⚠️ |
| ❓ **Other** | Any other SmartWeb device | ⚠️ | — |

✅ Supported &nbsp;·&nbsp; ⚠️ Experimental &nbsp;·&nbsp; — Not available

**Read** = sensor values are shown in Home Assistant.
**Write** = you can change settings (temperature, mode, on/off) from Home Assistant.
Experimental means it works in testing but may behave differently on some units.

For unknown devices, the integration creates a **Diagnostics sensor** that logs data payloads — useful for adding support later.

**Domestic hot water note:** REMKO requires a vacation end date before Vacation mode is activated. Set the `DHW vacation end date` date entity first, then select Vacation mode on the water-heater entity.

---

## Experimental local MQTT mode

This branch also contains experimental support for running a REMKO WiFi stick against a local MQTT broker while other devices continue to use the REMKO cloud.

The local mode is intended for advanced installations where a single WiFi stick is redirected from `smartweb.remko.media` to a local broker. Enable it per device in the integration options:

- `Local MQTT host`
- `Local MQTT port`
- `Local MQTT username`
- `Local MQTT password`

The integration discovers the local stick from its `HOST2PORTAL` announcements and keeps that local topic for status handling. For ESP commands, some sticks subscribe on their normal SID-based SmartWeb topic, so the integration resolves that command topic separately and sends SET frames there.

Home Assistant exposes a diagnostic **Local portal status** sensor for devices with local MQTT options enabled. Use it as the first setup checklist:

| Check | Meaning |
|-------|---------|
| `local_mqtt_configured` | Local MQTT options are enabled for this Config Entry. |
| `local_broker_connected` | Home Assistant connected to the configured MQTT broker and subscribed successfully. |
| `smartweb_device_resolved` | SmartWeb login and device metadata resolution succeeded, so the account still contains the device. |
| `local_topic_discovered` | The redirected stick was discovered on its local `V04P27/SMT...` announcement topic. |
| `command_topic_resolved` | The SID-based `V04P27/<SID>` command topic was resolved for ESP commands. |
| `stick_seen` | The local broker has recently seen stick announcements such as `HOST2PORTAL`. |
| `status_readback_seen` | A status payload or ESP `RESP` has been seen since startup. |

If the sensor state is `incomplete`, open its attributes and follow the first guidance message. Most local setup problems are broker reachability, SmartWeb account/device resolution, MQTT ACL/listener separation, or DNS redirect scope.

Important infrastructure notes:

- Redirect only the intended local stick, not the whole network.
- The stick-side TLS listener commonly uses port `8883` with a certificate for `smartweb.remko.media`.
- If the same Mosquitto instance also serves Home Assistant or other authenticated clients, keep listener authentication separated, for example with `per_listener_settings true`. Otherwise the unauthenticated stick listener can intermittently inherit ACL rules and reject the stick's subscriptions.
- Do not broadly redirect port `8083`. Home Assistant uses `smartweb.remko.media:8083` for REMKO cloud WebSocket sessions; redirecting that port can make cloud devices connect to the local broker instead of REMKO.
- Local mode may not provide an immediate status readback. Commands can therefore be accepted with pending confirmation while the Home Assistant entity updates optimistically.

Cloud-only installations do not need any local MQTT options.

---

## Troubleshooting

| Problem | What to try |
|---------|-------------|
| No entities after install | Restart Home Assistant |
| Entities unavailable | Check internet access · reduce the polling interval in options |
| `SmartWeb returned an empty or unparseable device list from /rest/liste` | Update to the latest version and restart Home Assistant. REMKO may block non-browser HTTP clients; current versions keep a browser-like user agent on the full SmartWeb session, not only during login. |
| `SET readback mismatch` after a climate command | The device may report the old state for a few seconds after accepting a command. Current versions retry the immediate readback and log pending confirmation instead of warning too early. |
| Local MQTT device accepts commands slowly or times out | Update to a local-portal build that sends ESP SET frames to the SID-based command topic and treats local readback as pending. Also verify Mosquitto listener authentication is separated so the stick's `8883` subscriptions are not denied by the authenticated HA listener. |
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
