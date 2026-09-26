# REMKO SmartWeb — Home Assistant Integration

[![HACS](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://github.com/hacs/integration)
![Status](https://img.shields.io/badge/status-beta-yellow)
![Version](https://img.shields.io/badge/version-v0.5.0--beta.5-blue)

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
**Write** = you can change settings (temperature, mode, on/off) from Home Assistant. A per-device **Beep on command** switch controls whether supported AC command frames ask the unit to beep when accepting commands.
Experimental means it works in testing but may behave differently on some units.

For unknown devices, the integration creates a **Diagnostics sensor** that logs data payloads — useful for adding support later.

**Domestic hot water note:** REMKO requires a vacation end date before Vacation mode is activated. Set the `DHW vacation end date` date entity first, then select Vacation mode on the water-heater entity.

---

## Experimental local MQTT mode

Cloud-only installations do **not** need a local MQTT broker, DNS rewrite, or
AdGuard rule. The setup below is only for advanced installations that want to
run one or more REMKO WiFi sticks locally.

There are multiple REMKO local-MQTT architectures:

- **Redirected WiFi stick / local portal broker**: the stick does not expose
  MQTT on its own IP. It normally connects outbound to REMKO's cloud broker.
  Local operation is possible by redirecting only that stick's DNS lookup for
  `smartweb.remko.media` to a local MQTT broker.
- **Direct device MQTT / SmartControl bridge**: some SmartControl/SmartCom
  installations expose a local MQTT path directly on the device IP or through a
  separate bridge. This mode is experimental and needs more real-device testing.

Local setup starts from the normal cloud-discovered REMKO device. Configure it
from the device's integration options:

- `Local connection mode`
  - `Cloud only`
  - `Redirected WiFi stick / local portal broker`
  - `Direct device MQTT / SmartControl bridge`
- `Stick IP address` for validation and mismatch warnings.
- Shared local broker host, port, username, and password for redirected
  WiFi-stick setups.
- `Bridge REMKO app commands through Home Assistant` if the REMKO app should
  keep working while the stick is redirected to the local broker.

For redirected WiFi sticks, the integration discovers the local stick from
`V04P27/SMT.../HOST2PORTAL`. ESP read/write commands still use the normal
SID-based SmartWeb command topic `V04P27/<SID>/ESP` and `/RESP`, so the
integration keeps both topics:

- stick presence topic: `V04P27/SMT<MAC>/HOST2PORTAL`
- command/readback topic: `V04P27/<SID>/ESP` and `V04P27/<SID>/RESP`

When a redirected stick is connected to the local broker, the REMKO app may lose
direct control because the stick is no longer connected to REMKO's cloud broker.
The optional cloud bridge keeps a second cloud MQTT connection open, listens for
cloud app commands on the normal SID command topic, forwards those commands to
the local broker, and mirrors local `RESP`/status frames back to the cloud.

See [`docs/local_connection_modes.md`](docs/local_connection_modes.md) for the
current architecture and onboarding plan.

### Required infrastructure for redirected WiFi sticks

You need two pieces of local infrastructure:

1. **A local MQTT broker** reachable by Home Assistant and by the redirected
   REMKO stick.
2. **A DNS override** that applies only to the selected stick IPs and resolves
   `smartweb.remko.media` to the local MQTT broker IP.

AdGuard Home is one way to do the DNS override. Pi-hole, dnsmasq, Unbound,
router DNS, or another DNS server can also work if it supports per-client or
otherwise tightly scoped overrides.

Do **not** add a broad network-wide rewrite for `smartweb.remko.media`.
Home Assistant and the optional cloud bridge still need to reach REMKO's real
cloud endpoints.

### Mosquitto broker setup

The redirected-stick setup has two different MQTT client types:

- Home Assistant connects to the broker as a normal authenticated client.
- The REMKO sticks connect as if they were connecting to REMKO's cloud broker,
  usually via TLS on port `8883`.

The recommended setup is Mosquitto **2.x**. The example below uses Mosquitto's
v2 dynamic security plugin for the authenticated Home Assistant listener. If you
do not use dynamic security, configure equivalent `password_file` and `acl_file`
rules instead.

Important broker requirements:

- Publish `1883/tcp` for Home Assistant or other authenticated local clients.
- Publish `8883/tcp` for redirected REMKO sticks.
- Use `per_listener_settings true` so the authenticated Home Assistant listener
  and the unauthenticated stick listener do not accidentally share auth/ACL
  rules.
- The stick-facing `8883` listener needs a TLS certificate whose common name or
  subject alternative name matches `smartweb.remko.media`.
- The stick-facing listener must allow the REMKO stick to connect with its
  cloud-style client ID and username.

Minimal Mosquitto example:

```conf
per_listener_settings true

persistence true
persistence_location /mosquitto/data/

# Home Assistant / local clients
listener 1883
allow_anonymous false
plugin /usr/lib/mosquitto_dynamic_security.so
plugin_opt_config_file /mosquitto/config/dynamic-security.json

# Redirected REMKO WiFi sticks
listener 8883
allow_anonymous true
certfile /mosquitto/config/server.crt
keyfile /mosquitto/config/server.key
ciphers DEFAULT:@SECLEVEL=0
```

If you also run a WebSocket listener, keep it separate as well. Do not redirect
REMKO's cloud WebSocket traffic broadly to your broker; Home Assistant uses
REMKO cloud sessions for cloud-only devices and for the cloud bridge.

Example self-signed certificate for a private LAN broker:

```bash
openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
  -keyout server.key \
  -out server.crt \
  -subj "/CN=smartweb.remko.media" \
  -addext "subjectAltName=DNS:smartweb.remko.media"
```

Store `server.crt` and `server.key` where the Mosquitto container can read them
and restart Mosquitto after changing listener settings.

#### About the `smartweb.remko.media` certificate

This part is unusual and worth spelling out: the redirected stick still thinks
it is connecting to REMKO's MQTT broker at `smartweb.remko.media`. DNS only
changes the IP address; it does not change the hostname the stick uses for TLS.
Therefore the local broker must present a certificate for that hostname.

You normally cannot get a public Let's Encrypt or other public CA certificate
for `smartweb.remko.media`, because you do not own that domain. For local
redirect setups, use a private/self-signed certificate whose CN/SAN contains
`smartweb.remko.media`.

The command above creates such a certificate:

- `server.crt` is the certificate Mosquitto presents to redirected sticks.
- `server.key` is the matching private key and must stay private.
- The certificate name must be `smartweb.remko.media`; using your broker's LAN
  hostname or IP address is not enough for sticks that check the TLS hostname.

Observed MXW WiFi sticks accept this local self-signed certificate when the
hostname matches. Other firmware may be stricter. If a stick repeatedly connects
to port `8883` and immediately disconnects during TLS setup, the certificate is
one of the first things to check.

Helpful checks:

```bash
openssl x509 -in server.crt -noout -subject -issuer -dates -ext subjectAltName
openssl s_client -connect <broker-ip>:8883 -servername smartweb.remko.media \
  -showcerts
```

The integration cannot create or install this certificate automatically because
the certificate belongs to the external MQTT broker, not to Home Assistant.
What it can do is report whether the stick reaches the broker, whether
`HOST2PORTAL` appears, and whether the discovered `SMT...` topic matches the
configured stick IP.

### DNS rewrite with AdGuard Home

For redirected WiFi-stick setups, the stick must resolve REMKO's broker hostname
to the local MQTT broker. Scope the rewrite to the selected stick IPs only.

In AdGuard Home, add one custom filtering rule per redirected stick:

```text
||smartweb.remko.media^$client=<stick-ip>,dnsrewrite=<local-broker-ip>
```

Example with three REMKO sticks redirected to a broker on `192.168.2.4`:

```text
||smartweb.remko.media^$client=192.168.2.102,dnsrewrite=192.168.2.4
||smartweb.remko.media^$client=192.168.2.88,dnsrewrite=192.168.2.4
||smartweb.remko.media^$client=192.168.2.89,dnsrewrite=192.168.2.4
```

After saving the rules, reconnect or reboot the selected stick so it performs a
fresh DNS lookup. In AdGuard's query log you should see the selected stick IP
query `smartweb.remko.media` and receive the local broker IP as the rewrite
answer.

The local MQTT status sensor should then start seeing
`V04P27/SMT.../HOST2PORTAL` for that stick. If the discovered `SMT...` topic
does not match the MAC derived from the configured stick IP, the integration
will report a mismatch instead of treating the mapping as healthy.

### Home Assistant diagnostics

Home Assistant exposes a diagnostic **Local MQTT status** sensor for devices
with local MQTT options enabled. Use it as the first setup checklist:

| Check | Meaning |
|-------|---------|
| `local_mqtt_configured` | Local MQTT options are enabled for this Config Entry. |
| `local_broker_connected` | Home Assistant connected to the configured MQTT broker and subscribed successfully. |
| `smartweb_device_resolved` | SmartWeb login and device metadata resolution succeeded, so the account still contains the device. |
| `local_topic_discovered` | The redirected stick was discovered on its local `V04P27/SMT...` announcement topic. |
| `command_topic_resolved` | The SID-based `V04P27/<SID>` command topic was resolved for ESP commands, or direct local MQTT uses the discovered command topic. |
| `stick_seen` | The local broker has recently seen stick/device messages such as `HOST2PORTAL` or `HOST2CLIENT`. |
| `status_readback_seen` | A status payload or ESP `RESP` has been seen since startup. |

If the sensor state is `incomplete`, open its attributes and follow the first
guidance message. Most local setup problems are broker reachability, SmartWeb
account/device resolution, MQTT ACL/listener separation, or DNS redirect scope.

Typical redirected-stick success indicators:

- Mosquitto shows the stick connected from its LAN IP on port `8883`.
- Mosquitto sees `V04P27/SMT<MAC>/HOST2PORTAL`.
- Home Assistant's Local MQTT status sensor becomes `ready`.
- The status attributes show both the `V04P27/SMT...` stick topic and the
  `V04P27/<SID>` command topic.

Local mode may not provide an immediate status readback. Commands can therefore
be accepted with pending confirmation while the Home Assistant entity updates
optimistically.

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
